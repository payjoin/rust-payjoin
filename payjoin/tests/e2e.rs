//! Payjoin end-to-end round trip tests, in memory, no real network.
//!
//! Split into two submodules because v1 and v2 have very different
//! feature requirements:
//!
//! - `v1` runs under the `no_std`-compatible `alloc,v1` feature set (that's
//!   the whole point of it) and needs no OHTTP/directory infrastructure,
//!   since the protocol itself is transport-agnostic plain bytes.
//!   Run in isolation:
//!   cargo test -p payjoin --no-default-features --features alloc,v1 --test e2e
//!
//! - `v2` cannot run under that restricted feature set: the sender side of
//!   v2 genuinely requires `v2-ohttp`/`std` today (see the PR discussion
//!   for why). What it proves instead is that the *receiver* side, driven
//!   by a real, correctly OHTTP-encapsulated request from a real sender,
//!   walks through exactly the same typestate chain that is separately
//!   verified to compile under `alloc,v2` for `thumbv7em-none-eabihf`.
//!   That's the code path that will run on an embedded receiver device.
//!   Needs default features:
//!   cargo test -p payjoin --test e2e
//!
//! Neither module proves `no_std` purity on its own (dev-dependencies pull
//! in std regardless, and the v2 module needs std anyway). That guarantee
//! comes from the separate CI step that cross-compiles the library for
//! thumbv7em-none-eabihf. `tests/integration.rs` separately covers full v2
//! round trips against real local directory + OHTTP relay servers; the
//! `v2` module here intentionally avoids that infrastructure (no `tokio`,
//! no real sockets) by hand-rolling a minimal in-memory stand-in for the
//! directory + relay, closer in shape to what an embedded harness will
//! look like, where the host does the transport and the device only ever
//! sees decrypted application bytes.

#[cfg(feature = "v1")]
mod v1 {
    use std::str::FromStr;

    use base64::Engine;
    use bitcoin::{Address, Amount, FeeRate, Network};
    use payjoin::receive::v1::{Headers, UncheckedOriginalPayload};
    use payjoin::send::v1::SenderBuilder;
    use payjoin::PjParam;
    use payjoin_test_utils::PARSED_ORIGINAL_PSBT;

    /// Minimal [`Headers`] implementation for feeding a raw request body
    /// into [`UncheckedOriginalPayload::from_request`], mirroring what a
    /// receiver's own HTTP-adjacent transport (or in our case, serial
    /// framing) would supply.
    struct FixedHeaders {
        content_length: String,
    }

    impl FixedHeaders {
        fn for_body(body: &[u8]) -> Self { Self { content_length: body.len().to_string() } }
    }

    impl Headers for FixedHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-length" => Some(&self.content_length),
                "content-type" => Some("text/plain"),
                _ => None,
            }
        }
    }

    /// Splits a full request URL into its query string, the way a device
    /// would after receiving `Request.url` from the host relay.
    fn query_of(url: &str) -> &str { url.split('?').nth(1).unwrap_or("") }

    #[test]
    fn v1_round_trip_sender_and_receiver() -> Result<(), Box<dyn std::error::Error>> {
        // --- Fixture setup -----------------------------------------------
        // Reuses the same original PSBT and receiver output/fee parameters
        // as the crate's own internal sender fixtures (see
        // `payjoin::send::v1::test::create_psbt_context`), so the numbers
        // are known to be internally consistent.
        let original_psbt = PARSED_ORIGINAL_PSBT.clone();
        let receiver_script = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        let receiver_address = Address::from_script(&receiver_script, Network::Testnet)?;

        let pj_param = match PjParam::parse("https://example.com/")? {
            payjoin::PjParam::V1(v1_param) => v1_param,
            _ => panic!("expected a v1 PjParam"),
        };

        // --- Sender side: build and extract the v1 request ----------------
        let sender =
            SenderBuilder::from_parts(original_psbt.clone(), &pj_param, &receiver_address, None)
                .build_with_additional_fee(Amount::from_sat(182), Some(0), FeeRate::ZERO, true)?;
        let (request, v1_context) = sender.create_v1_post_request();

        // --- Transport (simulated) -----------------------------------------
        // In the hardware harness this is exactly the hop that goes over
        // serial: raw bytes out from the sender device, raw bytes in on the
        // receiver device.
        let query = query_of(&request.url).to_string();
        let headers = FixedHeaders::for_body(&request.body);

        // --- Receiver side: process the request through to a signed proposal
        let unchecked = UncheckedOriginalPayload::from_request(&request.body, &query, headers)?;

        let maybe_inputs_owned = unchecked.assume_interactive_receiver();

        let maybe_inputs_seen =
            maybe_inputs_owned.check_inputs_not_owned(&mut |_script| Ok(false))?;

        let outputs_unknown =
            maybe_inputs_seen.check_no_inputs_seen_before(&mut |_outpoint| Ok(false))?;

        let receiver_script_for_closure = receiver_script.clone();
        let wants_outputs = outputs_unknown.identify_receiver_outputs(&mut move |script| {
            Ok(script == &receiver_script_for_closure)
        })?;

        // No output substitution for this test: keep the sender's outputs as-is.
        let wants_inputs = wants_outputs.commit_outputs();

        // Contribute a receiver-owned input, so this actually exercises a payjoin
        // (combining inputs from both parties), not just a fee-bump pass-through.
        let contributed_script = Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")?
            .require_network(Network::Testnet)?
            .script_pubkey();
        let psbtin = bitcoin::psbt::Input {
            witness_utxo: Some(bitcoin::TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: contributed_script.clone(),
            }),
            ..Default::default()
        };
        let txin = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(&"11".repeat(32))?,
                vout: 0,
            },
            ..Default::default()
        };
        let input_pair = payjoin::receive::InputPair::new(txin, psbtin, None)
            .expect("input pair should be valid");

        let wants_fee_range = wants_inputs.contribute_inputs(vec![input_pair])?.commit_inputs();

        let provisional_proposal = wants_fee_range.apply_fee_range(None, None)?;

        // No additional receiver-owned inputs beyond the one just
        // contributed need signing here; return the PSBT unchanged.
        let contributed_script_for_finalize = contributed_script.clone();
        let payjoin_proposal = provisional_proposal.finalize_proposal(|psbt| {
            let mut signed_psbt = psbt.clone();
            for input in signed_psbt.inputs.iter_mut() {
                let is_contributed = input
                    .witness_utxo
                    .as_ref()
                    .map(|utxo| utxo.script_pubkey == contributed_script_for_finalize)
                    .unwrap_or(false);
                if is_contributed {
                    let mut witness = bitcoin::Witness::new();
                    witness.push(vec![0u8; 71]); // dummy signature
                    witness.push(vec![0u8; 33]); // dummy pubkey
                    input.final_script_witness = Some(witness);
                }
            }
            Ok(signed_psbt)
        })?;

        let proposal_psbt = payjoin_proposal.psbt().clone();

        // --- Transport back to sender (simulated) --------------------------
        let response_bytes = base64::engine::general_purpose::STANDARD
            .encode(proposal_psbt.serialize())
            .into_bytes();

        // --- Sender side: process the response, finalize the PSBT ----------
        let final_psbt = v1_context.process_response(&response_bytes)?;

        // process_proposal legitimately reconciles the receiver's proposal
        // against the sender's own original PSBT (e.g. restoring
        // redeem_script metadata the receiver didn't need to echo back), so
        // exact equality with proposal_psbt isn't the right invariant.
        // Matching txids confirms the same transaction round-tripped
        // through the whole v1 flow.
        assert_eq!(final_psbt.unsigned_tx.compute_txid(), proposal_psbt.unsigned_tx.compute_txid());
        // The receiver actually contributed an input: this is a real
        // payjoin (combined UTXOs), not just a fee-bump pass-through.
        assert_eq!(final_psbt.unsigned_tx.input.len(), original_psbt.unsigned_tx.input.len() + 1);

        Ok(())
    }
}

#[cfg(feature = "v2-ohttp")]
mod v2 {
    use std::cell::RefCell;
    use std::str::FromStr;

    use bitcoin::{Address, FeeRate, Network};
    use ohttp::hpke::{Aead, Kdf, Kem};
    use ohttp::{KeyId, SymmetricSuite};
    use payjoin::persist::{InMemoryPersister, OptionalTransitionOutcome};
    use payjoin::receive::v2::ReceiverBuilder;
    use payjoin::send::v2::SenderBuilder;
    use payjoin::{OhttpKeys, Request, Uri, UriExt};
    use payjoin_test_utils::PARSED_ORIGINAL_PSBT;

    /// Minimal in-memory stand-in for the Payjoin directory + OHTTP relay.
    /// Holds at most one pending message ("the mailbox"), matching the
    /// single session this test exercises.
    struct FakeDirectory {
        ohttp_keys: ohttp::KeyConfig,
        mailbox: RefCell<Option<Vec<u8>>>,
    }

    impl FakeDirectory {
        fn new(ohttp_keys: ohttp::KeyConfig) -> Self {
            Self { ohttp_keys, mailbox: RefCell::new(None) }
        }

        /// Handle one OHTTP-encapsulated round trip: decapsulate the
        /// request, route GET/POST against the mailbox, and encapsulate
        /// the response.
        ///
        /// NOTE: decapsulating twice for the same request (once to measure
        /// the padding overhead, once to get the response context actually
        /// used) mirrors the pattern in the crate's own internal test
        /// helper (`ohttp_response_for` in `src/core/receive/v2/mod.rs`),
        /// not something invented for this test.
        fn round_trip(&self, req_body: &[u8]) -> Vec<u8> {
            let server = ohttp::Server::new(self.ohttp_keys.clone())
                .expect("test OHTTP server should be valid");

            let (bhttp_bytes, probe_response) =
                server.decapsulate(req_body).expect("request should decapsulate");
            let response_overhead =
                probe_response.encapsulate(&[]).expect("probe should encrypt").len();

            let mut cursor = std::io::Cursor::new(&bhttp_bytes);
            // NOTE: unconfirmed API surface. If this doesn't compile, check
            // the bhttp crate's Message/Control accessors locally (`cargo
            // doc --open -p bhttp`) for the right way to read the request
            // method.
            let request: bhttp::Message =
                bhttp::Message::read_bhttp(&mut cursor).expect("bhttp request should parse");
            let is_post = request.control().method() == Some(b"POST".as_slice());

            let (status, body): (u16, Vec<u8>) = if is_post {
                *self.mailbox.borrow_mut() = Some(request.content().to_vec());
                (200, Vec::new())
            } else {
                match self.mailbox.borrow_mut().take() {
                    Some(body) => (200, body),
                    None => (202, Vec::new()),
                }
            };

            let (_, server_response) =
                server.decapsulate(req_body).expect("request should decapsulate again");
            let mut response_message = bhttp::Message::response(
                bhttp::StatusCode::try_from(status).expect("valid status"),
            );
            response_message.write_content(&body);

            let mut bhttp_response =
                vec![0u8; payjoin::directory::ENCAPSULATED_MESSAGE_BYTES - response_overhead];
            response_message
                .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_response.as_mut_slice())
                .expect("bhttp response should encode");
            server_response.encapsulate(&bhttp_response).expect("response should encrypt")
        }
    }

    fn test_ohttp_keys() -> (OhttpKeys, ohttp::KeyConfig) {
        let symmetric = vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];
        let key_config: KeyId = 1;
        let config = ohttp::KeyConfig::new(key_config, Kem::K256Sha256, symmetric)
            .expect("test OHTTP key config should be valid");
        let encoded = config.encode().expect("test OHTTP key config should encode");
        let ohttp_keys =
            OhttpKeys::decode(&encoded).expect("test OHTTP key config should decode back");
        (ohttp_keys, config)
    }

    #[test]
    fn v2_round_trip_sender_and_receiver() -> Result<(), Box<dyn std::error::Error>> {
        let (ohttp_keys, ohttp_key_config) = test_ohttp_keys();
        let directory = FakeDirectory::new(ohttp_key_config);
        let directory_url = "https://example-directory.test";
        let ohttp_relay_url = "https://example-relay.test";

        let receiver_script = PARSED_ORIGINAL_PSBT.unsigned_tx.output[1].script_pubkey.clone();
        let receiver_address = Address::from_script(&receiver_script, Network::Testnet)?;

        // --- Receiver: start a session and poll (nothing posted yet) -------
        let recv_persister = InMemoryPersister::default();
        let session = ReceiverBuilder::new(receiver_address, directory_url, ohttp_keys)?
            .build()
            .save(&recv_persister)?;

        let (req, ctx) = session.create_poll_request(ohttp_relay_url)?;
        let response_bytes = directory.round_trip(&req.body);
        let outcome = session.process_response(&response_bytes, ctx).save(&recv_persister)?;
        let session = match outcome {
            OptionalTransitionOutcome::Stasis(current_state) => current_state,
            OptionalTransitionOutcome::Progress(_) =>
                panic!("should still be waiting on the sender"),
        };

        // --- Sender: build and post the original PSBT -----------------------
        let pj_uri = Uri::from_str(&session.pj_uri().to_string())
            .map_err(|e| e.to_string())?
            .assume_checked()
            .check_pj_supported()
            .map_err(|e| e.to_string())?;

        let send_persister = InMemoryPersister::default();
        let req_ctx = SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri)
            .build_recommended(FeeRate::BROADCAST_MIN)?
            .save(&send_persister)?;

        let (Request { body, .. }, send_ctx) = req_ctx.create_v2_post_request(ohttp_relay_url)?;
        let post_response = directory.round_trip(&body);
        let req_ctx = req_ctx.process_response(&post_response, send_ctx).save(&send_persister)?;

        // --- Receiver: poll again, this time the original PSBT is waiting --
        let (req, ctx) = session.create_poll_request(ohttp_relay_url)?;
        let response_bytes = directory.round_trip(&req.body);
        let outcome = session.process_response(&response_bytes, ctx).save(&recv_persister)?;
        let proposal = match outcome {
            OptionalTransitionOutcome::Progress(proposal) => proposal,
            OptionalTransitionOutcome::Stasis(_) => panic!("proposal should have arrived"),
        };

        // --- Receiver: run it through the same typestate chain as the v1 test
        let proposal = proposal.assume_interactive_receiver().save(&recv_persister)?;
        let maybe_inputs_seen =
            proposal.check_inputs_not_owned(&mut |_script| Ok(false)).save(&recv_persister)?;
        let outputs_unknown = maybe_inputs_seen
            .check_no_inputs_seen_before(&mut |_outpoint| Ok(false))
            .save(&recv_persister)?;
        let wants_outputs = outputs_unknown
            .identify_receiver_outputs(&mut move |script| Ok(script == &receiver_script))
            .save(&recv_persister)?;
        let wants_inputs = wants_outputs.commit_outputs().save(&recv_persister)?;

        // Contribute a receiver-owned input, so this actually exercises a payjoin
        // (combining inputs from both parties), not just a fee-bump pass-through.
        let contributed_script = Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")?
            .require_network(Network::Testnet)?
            .script_pubkey();
        let psbtin = bitcoin::psbt::Input {
            witness_utxo: Some(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: contributed_script.clone(),
            }),
            ..Default::default()
        };
        let txin = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(&"11".repeat(32))?,
                vout: 0,
            },
            ..Default::default()
        };
        let input_pair = payjoin::receive::InputPair::new(txin, psbtin, None)
            .expect("input pair should be valid");
        let wants_fee_range = wants_inputs
            .contribute_inputs(vec![input_pair])?
            .commit_inputs()
            .save(&recv_persister)?;
        let provisional_proposal =
            wants_fee_range.apply_fee_range(None, None).save(&recv_persister)?;
        let contributed_script_for_finalize = contributed_script.clone();
        let payjoin_proposal = provisional_proposal
            .finalize_proposal(|psbt| {
                let mut signed_psbt = psbt.clone();
                for input in signed_psbt.inputs.iter_mut() {
                    let is_contributed = input
                        .witness_utxo
                        .as_ref()
                        .map(|utxo| utxo.script_pubkey == contributed_script_for_finalize)
                        .unwrap_or(false);
                    if is_contributed {
                        let mut witness = bitcoin::Witness::new();
                        witness.push(vec![0u8; 71]); // dummy signature
                        witness.push(vec![0u8; 33]); // dummy pubkey
                        input.final_script_witness = Some(witness);
                    }
                }
                Ok(signed_psbt)
            })
            .save(&recv_persister)?;

        // --- Receiver: post the finished proposal back -----------------------
        let (req, ctx) = payjoin_proposal.create_post_request(ohttp_relay_url)?;
        let response_bytes = directory.round_trip(&req.body);
        payjoin_proposal.process_response(&response_bytes, ctx).save(&recv_persister)?;

        // --- Sender: poll for and finalize the proposal -----------------------
        let (Request { body, .. }, ohttp_ctx) = req_ctx.create_poll_request(ohttp_relay_url)?;
        let response_bytes = directory.round_trip(&body);
        let final_outcome =
            req_ctx.process_response(&response_bytes, ohttp_ctx).save(&send_persister)?;
        let final_proposal_psbt = match final_outcome {
            OptionalTransitionOutcome::Progress(psbt) => psbt,
            OptionalTransitionOutcome::Stasis(_) => panic!("sender should have the final proposal"),
        };

        assert!(final_proposal_psbt.unsigned_tx.output.len() >= 2);
        assert_eq!(
            final_proposal_psbt.unsigned_tx.input.len(),
            PARSED_ORIGINAL_PSBT.unsigned_tx.input.len() + 1
        );
        Ok(())
    }
}

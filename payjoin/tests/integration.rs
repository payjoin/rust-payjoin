#[cfg(all(feature = "send", feature = "receive"))]
#[cfg(not(feature = "v2"))]
mod integration {
    use std::collections::HashMap;
    use std::env;
    use std::str::FromStr;

    use bitcoin::address::NetworkChecked;
    use bitcoin::psbt::Psbt;
    use bitcoin::{Amount, FeeRate, OutPoint};
    use bitcoind::bitcoincore_rpc;
    use bitcoind::bitcoincore_rpc::core_rpc_json::{AddressType, WalletProcessPsbtResult};
    use bitcoind::bitcoincore_rpc::RpcApi;
    use log::{debug, log_enabled, Level};
    use once_cell::sync::{Lazy, OnceCell};
    use payjoin::bitcoin::base64;
    use payjoin::send::RequestBuilder;
    use payjoin::{PjUriBuilder, Request, Uri};
    use tracing_subscriber::{EnvFilter, FmtSubscriber};
    use url::Url;

    type BoxError = Box<dyn std::error::Error + 'static>;

    static INIT_TRACING: OnceCell<()> = OnceCell::new();

    mod v1 {
        use payjoin::receive::{Headers, PayjoinProposal, UncheckedProposal};

        use super::*;

        static EXAMPLE_URL: Lazy<Url> =
            Lazy::new(|| Url::parse("https://example.com").expect("Invalid Url"));

        #[test]
        fn v1_to_v1() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver()?;

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
            let pj_uri = PjUriBuilder::new(pj_receiver_address, EXAMPLE_URL.to_owned())
                .amount(Amount::ONE_BTC)
                .build();

            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string()).unwrap().assume_checked();
            let psbt = build_original_psbt(&sender, &uri)?;
            debug!("Original psbt: {:#?}", psbt);
            let (req, ctx) = RequestBuilder::from_psbt_and_uri(psbt, uri)?
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .extract_v1()?;
            let headers = HeaderMock::from_vec(&req.body);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let response = handle_pj_request(req, headers, receiver);
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:

            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(&mut response.as_bytes())?;
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;
            Ok(())
        }

        struct HeaderMock(HashMap<String, String>);

        impl Headers for HeaderMock {
            fn get_header(&self, key: &str) -> Option<&str> { self.0.get(key).map(|e| e.as_str()) }
        }

        impl HeaderMock {
            fn from_vec(body: &[u8]) -> HeaderMock {
                let mut h = HashMap::new();
                h.insert("content-type".to_string(), payjoin::V1_REQ_CONTENT_TYPE.to_string());
                h.insert("content-length".to_string(), body.len().to_string());
                HeaderMock(h)
            }
        }

        // Receiver receive and process original_psbt from a sender
        // In production it it will come in as an HTTP request (over ssl or onion)
        fn handle_pj_request(
            req: Request,
            headers: impl Headers,
            receiver: bitcoincore_rpc::Client,
        ) -> String {
            // Receiver receive payjoin proposal, IRL it will be an HTTP request (over ssl or onion)
            let proposal = payjoin::receive::UncheckedProposal::from_request(
                req.body.as_slice(),
                req.url.query().unwrap_or(""),
                headers,
            )
            .unwrap();
            let proposal = handle_proposal(proposal, receiver);
            let psbt = proposal.psbt();
            debug!("Receiver's Payjoin proposal PSBT: {:#?}", &psbt);
            base64::encode(&psbt.serialize())
        }

        fn handle_proposal(
            proposal: UncheckedProposal,
            receiver: bitcoincore_rpc::Client,
        ) -> PayjoinProposal {
            // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
            let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

            // Receive Check 1: Can Broadcast
            let proposal = proposal
                .check_broadcast_suitability(None, |tx| {
                    Ok(receiver
                        .test_mempool_accept(&[bitcoin::consensus::encode::serialize_hex(&tx)])
                        .unwrap()
                        .first()
                        .unwrap()
                        .allowed)
                })
                .expect("Payjoin proposal should be broadcastable");

            // Receive Check 2: receiver can't sign for proposal inputs
            let proposal = proposal
                .check_inputs_not_owned(|input| {
                    let address =
                        bitcoin::Address::from_script(&input, bitcoin::Network::Regtest).unwrap();
                    Ok(receiver.get_address_info(&address).unwrap().is_mine.unwrap())
                })
                .expect("Receiver should not own any of the inputs");

            // Receive Check 3: receiver can't sign for proposal inputs
            let proposal = proposal.check_no_mixed_input_scripts().unwrap();

            // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
            let mut payjoin = proposal
                .check_no_inputs_seen_before(|_| Ok(false))
                .unwrap()
                .identify_receiver_outputs(|output_script| {
                    let address =
                        bitcoin::Address::from_script(&output_script, bitcoin::Network::Regtest)
                            .unwrap();
                    Ok(receiver.get_address_info(&address).unwrap().is_mine.unwrap())
                })
                .expect("Receiver should have at least one output");

            // Select receiver payjoin inputs. TODO Lock them.
            let available_inputs = receiver.list_unspent(None, None, None, None, None).unwrap();
            let candidate_inputs: HashMap<Amount, OutPoint> = available_inputs
                .iter()
                .map(|i| (i.amount, OutPoint { txid: i.txid, vout: i.vout }))
                .collect();

            let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
            let selected_utxo = available_inputs
                .iter()
                .find(|i| i.txid == selected_outpoint.txid && i.vout == selected_outpoint.vout)
                .unwrap();

            //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
            let txo_to_contribute = bitcoin::TxOut {
                value: selected_utxo.amount.to_sat(),
                script_pubkey: selected_utxo.script_pub_key.clone(),
            };
            let outpoint_to_contribute =
                bitcoin::OutPoint { txid: selected_utxo.txid, vout: selected_utxo.vout };
            payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);

            let receiver_substitute_address =
                receiver.get_new_address(None, None).unwrap().assume_checked();
            payjoin.substitute_output_address(receiver_substitute_address);
            let payjoin_proposal = payjoin
                .finalize_proposal(
                    |psbt: &Psbt| {
                        Ok(receiver
                            .wallet_process_psbt(
                                &bitcoin::base64::encode(psbt.serialize()),
                                None,
                                None,
                                Some(false),
                            )
                            .map(|res: WalletProcessPsbtResult| {
                                let psbt = Psbt::from_str(&res.psbt).unwrap();
                                return psbt;
                            })
                            .unwrap())
                    },
                    Some(bitcoin::FeeRate::MIN),
                )
                .unwrap();
            payjoin_proposal
        }

        fn init_tracing() {
            INIT_TRACING.get_or_init(|| {
                let subscriber = FmtSubscriber::builder()
                    .with_env_filter(EnvFilter::from_default_env())
                    .with_test_writer()
                    .finish();

                tracing::subscriber::set_global_default(subscriber)
                    .expect("failed to set global default subscriber");
            });
        }

        fn init_bitcoind_sender_receiver(
        ) -> Result<(bitcoind::BitcoinD, bitcoincore_rpc::Client, bitcoincore_rpc::Client), BoxError>
        {
            let bitcoind_exe = env::var("BITCOIND_EXE")
                .ok()
                .or_else(|| bitcoind::downloaded_exe_path().ok())
                .unwrap();
            let mut conf = bitcoind::Conf::default();
            conf.view_stdout = log_enabled!(Level::Debug);
            let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf)?;
            let receiver = bitcoind.create_wallet("receiver")?;
            let receiver_address =
                receiver.get_new_address(None, Some(AddressType::Bech32))?.assume_checked();
            let sender = bitcoind.create_wallet("sender")?;
            let sender_address =
                sender.get_new_address(None, Some(AddressType::Bech32))?.assume_checked();
            bitcoind.client.generate_to_address(1, &receiver_address)?;
            bitcoind.client.generate_to_address(101, &sender_address)?;

            assert_eq!(
                Amount::from_btc(50.0)?,
                receiver.get_balances()?.mine.trusted,
                "receiver doesn't own bitcoin"
            );

            assert_eq!(
                Amount::from_btc(50.0)?,
                sender.get_balances()?.mine.trusted,
                "sender doesn't own bitcoin"
            );
            Ok((bitcoind, sender, receiver))
        }

        fn build_original_psbt(
            sender: &bitcoincore_rpc::Client,
            pj_uri: &Uri<'_, NetworkChecked>,
        ) -> Result<Psbt, BoxError> {
            let mut outputs = HashMap::with_capacity(1);
            outputs.insert(pj_uri.address.to_string(), pj_uri.amount.unwrap());
            debug!("outputs: {:?}", outputs);
            let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
                lock_unspent: Some(true),
                fee_rate: Some(Amount::from_sat(2000)),
                ..Default::default()
            };
            let psbt = sender
                .wallet_create_funded_psbt(
                    &[], // inputs
                    &outputs,
                    None, // locktime
                    Some(options),
                    None,
                )?
                .psbt;
            let psbt = sender.wallet_process_psbt(&psbt, None, None, None)?.psbt;
            Ok(Psbt::from_str(&psbt)?)
        }

        fn extract_pj_tx(
            sender: &bitcoincore_rpc::Client,
            psbt: Psbt,
        ) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
            let payjoin_base64_string = base64::encode(&psbt.serialize());
            let payjoin_psbt =
                sender.wallet_process_psbt(&payjoin_base64_string, None, None, None)?.psbt;
            let payjoin_psbt = sender.finalize_psbt(&payjoin_psbt, Some(false))?.psbt.unwrap();
            let payjoin_psbt = Psbt::from_str(&payjoin_psbt)?;
            debug!("Sender's Payjoin PSBT: {:#?}", payjoin_psbt);

            Ok(payjoin_psbt.extract_tx())
        }
    }
}

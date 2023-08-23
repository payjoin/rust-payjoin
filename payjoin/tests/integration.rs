#[cfg(all(feature = "send", feature = "receive"))]
mod integration {
    use std::collections::HashMap;
    use std::str::FromStr;

    use bitcoin::psbt::Psbt;
    use bitcoin::{Amount, OutPoint};
    use bitcoind::bitcoincore_rpc;
    use bitcoind::bitcoincore_rpc::core_rpc_json::{AddressType, WalletProcessPsbtResult};
    use bitcoind::bitcoincore_rpc::RpcApi;
    use log::{debug, log_enabled, Level};
    use payjoin::bitcoin::base64;
    use payjoin::receive::Headers;
    use payjoin::send::Request;
    use payjoin::{bitcoin, Error, PjUriExt, Uri, UriExt};

    #[test]
    fn integration_test() {
        let _ = env_logger::try_init();
        let bitcoind_exe = std::env::var("BITCOIND_EXE")
            .ok()
            .or_else(|| bitcoind::downloaded_exe_path().ok())
            .expect("version feature or env BITCOIND_EXE is required for tests");
        let mut conf = bitcoind::Conf::default();
        conf.view_stdout = log_enabled!(Level::Debug);
        let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf).unwrap();
        let receiver = bitcoind.create_wallet("receiver").unwrap();
        let receiver_address =
            receiver.get_new_address(None, Some(AddressType::Bech32)).unwrap().assume_checked();
        let sender = bitcoind.create_wallet("sender").unwrap();
        let sender_address =
            sender.get_new_address(None, Some(AddressType::Bech32)).unwrap().assume_checked();
        bitcoind.client.generate_to_address(1, &receiver_address).unwrap();
        bitcoind.client.generate_to_address(101, &sender_address).unwrap();

        assert_eq!(
            Amount::from_btc(50.0).unwrap(),
            receiver.get_balances().unwrap().mine.trusted,
            "receiver doesn't own bitcoin"
        );

        assert_eq!(
            Amount::from_btc(50.0).unwrap(),
            sender.get_balances().unwrap().mine.trusted,
            "sender doesn't own bitcoin"
        );

        // Receiver creates the payjoin URI
        let pj_receiver_address = receiver.get_new_address(None, None).unwrap().assume_checked();
        let amount = Amount::from_btc(1.0).unwrap();
        let pj_uri_string = format!(
            "{}?amount={}&pj=https://example.com",
            pj_receiver_address.to_qr_uri(),
            amount.to_btc()
        );
        let pj_uri = Uri::from_str(&pj_uri_string).unwrap().assume_checked();
        let pj_uri = pj_uri.check_pj_supported().expect("Bad Uri");

        // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(pj_uri.address.to_string(), pj_uri.amount.unwrap());
        debug!("outputs: {:?}", outputs);
        let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            lock_unspent: Some(true),
            fee_rate: Some(payjoin::bitcoin::Amount::from_sat(2000)),
            ..Default::default()
        };
        let psbt = sender
            .wallet_create_funded_psbt(
                &[], // inputs
                &outputs,
                None, // locktime
                Some(options),
                None,
            )
            .expect("failed to create PSBT")
            .psbt;
        let psbt = sender.wallet_process_psbt(&psbt, None, None, None).unwrap().psbt;
        let psbt = Psbt::from_str(&psbt).unwrap();
        debug!("Original psbt: {:#?}", psbt);
        let pj_params = payjoin::send::Configuration::with_fee_contribution(
            payjoin::bitcoin::Amount::from_sat(10000),
            None,
        );
        let (req, ctx) = pj_uri.create_pj_request(psbt, pj_params).unwrap();
        let headers = HeaderMock::from_vec(&req.body);

        // **********************
        // Inside the Receiver:
        // this data would transit from one party to another over the network in production
        let response = handle_pj_request(req, headers, receiver);
        // this response would be returned as http response to the sender

        // **********************
        // Inside the Sender:
        // Sender checks, signs, finalizes, extracts, and broadcasts
        let checked_payjoin_proposal_psbt = ctx.process_response(&mut response.as_bytes()).unwrap();
        let payjoin_base64_string = base64::encode(&checked_payjoin_proposal_psbt.serialize());
        let payjoin_psbt =
            sender.wallet_process_psbt(&payjoin_base64_string, None, None, None).unwrap().psbt;
        let payjoin_psbt = sender.finalize_psbt(&payjoin_psbt, Some(false)).unwrap().psbt.unwrap();
        let payjoin_psbt = Psbt::from_str(&payjoin_psbt).unwrap();
        debug!("Sender's Payjoin PSBT: {:#?}", payjoin_psbt);

        let payjoin_tx = payjoin_psbt.extract_tx();
        bitcoind.client.send_raw_transaction(&payjoin_tx).unwrap();
    }

    struct HeaderMock(HashMap<String, String>);

    impl Headers for HeaderMock {
        fn get_header(&self, key: &str) -> Option<&str> { self.0.get(key).map(|e| e.as_str()) }
    }

    impl HeaderMock {
        fn from_vec(body: &[u8]) -> HeaderMock {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "text/plain".to_string());
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

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.get_transaction_to_schedule_broadcast();

        // Receive Check 1: Can Broadcast
        let proposal = proposal
            .check_can_broadcast(|tx| {
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
        let psbt = payjoin_proposal.psbt();
        debug!("Receiver's Payjoin proposal PSBT: {:#?}", &psbt);
        base64::encode(&psbt.serialize())
    }
}

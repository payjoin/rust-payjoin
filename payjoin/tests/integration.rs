#[cfg(all(feature = "sender", feature = "receiver"))]
mod integration {
    use std::collections::HashMap;
    use std::str::FromStr;

    use bitcoin::hashes::hex::ToHex;
    use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
    use bitcoin::{consensus, Amount};
    use bitcoind::bitcoincore_rpc;
    use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::AddressType;
    use bitcoind::bitcoincore_rpc::RpcApi;
    use log::{debug, log_enabled, Level};
    use payjoin::receiver::Headers;
    use payjoin::sender::Request;
    use payjoin::{PjUriExt, Uri, UriExt};

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
        let receiver_address = receiver.get_new_address(None, Some(AddressType::Bech32)).unwrap();
        let sender = bitcoind.create_wallet("sender").unwrap();
        let sender_address = sender.get_new_address(None, Some(AddressType::Bech32)).unwrap();
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
        let pj_receiver_address = receiver.get_new_address(None, None).unwrap();
        let amount = Amount::from_btc(1.0).unwrap();
        let pj_uri_string = format!(
            "{}?amount={}&pj=https://example.com",
            pj_receiver_address.to_qr_uri(),
            amount.to_btc()
        );
        let pj_uri = Uri::from_str(&pj_uri_string).unwrap();
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
        let psbt = load_psbt_from_base64(psbt.as_bytes()).unwrap();
        debug!("Original psbt: {:#?}", psbt);
        let pj_params = payjoin::sender::Configuration::with_fee_contribution(
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
        let checked_payjoin_proposal_psbt = ctx.process_response(response.as_bytes()).unwrap();
        let payjoin_base64_string =
            base64::encode(consensus::serialize(&checked_payjoin_proposal_psbt));
        let payjoin_psbt =
            sender.wallet_process_psbt(&payjoin_base64_string, None, None, None).unwrap().psbt;
        let payjoin_psbt = sender.finalize_psbt(&payjoin_psbt, Some(false)).unwrap().psbt.unwrap();
        let payjoin_psbt = load_psbt_from_base64(payjoin_psbt.as_bytes()).unwrap();
        debug!("Sender's PayJoin PSBT: {:#?}", payjoin_psbt);

        let payjoin_tx = payjoin_psbt.extract_tx();
        bitcoind.client.send_raw_transaction(&payjoin_tx).unwrap().first().unwrap();
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
        let proposal = payjoin::receiver::UncheckedProposal::from_request(
            req.body.as_slice(),
            req.url.query().unwrap_or(""),
            headers,
        )
        .unwrap();

        // Receive Check 1: Is Broadcastable
        let original_tx = proposal.get_transaction_to_check_broadcast();
        let tx_is_broadcastable = receiver
            .test_mempool_accept(&[bitcoin::consensus::encode::serialize(&original_tx).to_hex()])
            .unwrap()
            .first()
            .unwrap()
            .allowed;
        assert!(tx_is_broadcastable);
        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let proposal = proposal.assume_tested_and_scheduled_broadcast();

        // ⚠️ TODO Receive checklist Original PSBT Checks ⚠️ shipping this is SAFETY CRITICAL to get out of alpha into beta
        let mut payjoin = proposal
            .assume_inputs_not_owned()
            .assume_no_mixed_input_scripts()
            .assume_no_inputs_seen_before()
            .identify_receiver_outputs(|output_script| {
                let address = bitcoin::Address::from_script(&output_script, bitcoin::Network::Regtest).unwrap();
                receiver.get_address_info(&address).unwrap().is_mine.unwrap()
            }).expect("Receiver should have at least one output");

        // Select receiver payjoin inputs. TODO Lock them.
        let available_inputs = receiver.list_unspent(None, None, None, None, None).unwrap();
        let selected_utxo = available_inputs.first().unwrap(); // naive selection for now, avoid UIH next
        // ⚠️ TODO Select to avoid Unecessary Input and other heuristics. ⚠️ shipping this is SAFETY CRITICAL to get out of alpha into beta
        // This Gist <https://gist.github.com/AdamISZ/4551b947789d3216bacfcb7af25e029e> explains how

        //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
        let txo_to_contribute = bitcoin::TxOut {
            value: selected_utxo.amount.to_sat(),
            script_pubkey: selected_utxo.script_pub_key.clone(),
        };
        let outpoint_to_contribute =
            bitcoin::OutPoint { txid: selected_utxo.txid, vout: selected_utxo.vout };
        payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);

        let receiver_substitute_address = receiver.get_new_address(None, None).unwrap();
        payjoin.substitute_output_address(receiver_substitute_address);

        let payjoin_proposal_psbt = payjoin.extract_psbt(None).expect("failed to apply fees");

        // Sign payjoin psbt
        let payjoin_base64_string = base64::encode(consensus::serialize(&payjoin_proposal_psbt));
        let payjoin_proposal_psbt =
            receiver.wallet_process_psbt(&payjoin_base64_string, None, None, None).unwrap().psbt;
        let payjoin_proposal_psbt =
            receiver.finalize_psbt(&payjoin_proposal_psbt, Some(false)).unwrap().psbt.unwrap();
        let mut payjoin_proposal_psbt =
            load_psbt_from_base64(payjoin_proposal_psbt.as_bytes()).unwrap();

        // clear keypaths
        payjoin_proposal_psbt
            .outputs
            .iter_mut()
            .for_each(|output| output.bip32_derivation = Default::default());

        debug!("Receiver's PayJoin proposal PSBT: {:#?}", payjoin_proposal_psbt);

        base64::encode(consensus::serialize(&payjoin_proposal_psbt))
    }

    fn load_psbt_from_base64(
        mut input: impl std::io::Read,
    ) -> Result<Psbt, payjoin::bitcoin::consensus::encode::Error> {
        use payjoin::bitcoin::consensus::Decodable;

        let mut reader = base64::read::DecoderReader::new(
            &mut input,
            base64::Config::new(base64::CharacterSet::Standard, true),
        );
        Psbt::consensus_decode(&mut reader)
    }
}

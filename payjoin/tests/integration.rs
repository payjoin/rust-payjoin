#[cfg(all(feature = "sender", feature = "receiver"))]
mod integration {
    use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
    use bitcoin::Amount;
    use bitcoind::bitcoincore_rpc;
    use bitcoind::bitcoincore_rpc::RpcApi;
    use log::{debug, log_enabled, Level};
    use payjoin::receiver::Headers;
    use payjoin::{PjUriExt, Uri, UriExt};
    use std::collections::HashMap;
    use std::str::FromStr;

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
        let receiver_address = receiver.get_new_address(None, None).unwrap();
        let sender = bitcoind.create_wallet("sender").unwrap();
        let sender_address = sender.get_new_address(None, None).unwrap();
        bitcoind
            .client
            .generate_to_address(1, &receiver_address)
            .unwrap();
        bitcoind
            .client
            .generate_to_address(101, &sender_address)
            .unwrap();

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
        let psbt = sender
            .wallet_process_psbt(&psbt, None, None, None)
            .unwrap()
            .psbt;
        let psbt = load_psbt_from_base64(psbt.as_bytes()).unwrap();
        debug!("Original psbt: {:#?}", psbt);
        let pj_params = payjoin::sender::Params::with_fee_contribution(
            payjoin::bitcoin::Amount::from_sat(10000),
            None,
        );
        let (req, ctx) = pj_uri.create_pj_request(psbt, pj_params).unwrap();
        let headers = HeaderMock::from_vec(&req.body);

        // Receiver receive payjoin proposal, IRL it will be an HTTP request (over ssl or onion)
        let _proposal =
            payjoin::receiver::UncheckedProposal::from_request(req.body.as_slice(), "", headers)
                .unwrap();

        // TODO
    }

    struct HeaderMock(HashMap<String, String>);

    impl Headers for HeaderMock {
        fn get_header(&self, key: &str) -> Option<&str> {
            self.0.get(key).map(|e| e.as_str())
        }
    }

    impl HeaderMock {
        fn from_vec(body: &[u8]) -> HeaderMock {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "text/plain".to_string());
            h.insert("content-length".to_string(), body.len().to_string());
            HeaderMock(h)
        }
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

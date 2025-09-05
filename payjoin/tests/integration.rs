mod integration {
    use std::collections::HashMap;
    use std::str::FromStr;

    use bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE;
    use bitcoin::psbt::{Input as PsbtInput, Psbt};
    use bitcoin::{Amount, FeeRate, OutPoint, TxIn, TxOut, Weight};
    use payjoin::receive::v1::build_v1_pj_uri;
    use payjoin::receive::InputPair;
    use payjoin::{ImplementationError, OutputSubstitution, PjUri, Request, Uri};
    use payjoin_test_utils::corepc_node::vtype::ListUnspentItem;
    use payjoin_test_utils::corepc_node::AddressType;
    use payjoin_test_utils::{corepc_node, init_bitcoind_sender_receiver, init_tracing, BoxError};
    use serde_json::json;

    const EXAMPLE_URL: &str = "https://example.com";
    /// Transaction weight components for fee calculation
    /// Useful resource: https://bitcoin.stackexchange.com/a/84006
    const TX_HEADER_LEGACY_WEIGHT: u64 = 40;
    const TX_HEADER_WEIGHT: u64 = 42;
    const P2PKH_INPUT_WEIGHT: u64 = 592;
    const NESTED_P2WPKH_INPUT_WEIGHT: u64 = 364;
    const P2WPKH_INPUT_WEIGHT: u64 = 272;
    const P2TR_INPUT_WEIGHT: u64 = 230;
    const P2WPKH_OUTPUT_WEIGHT: u64 = 124;

    #[cfg(feature = "v1")]
    mod v1 {
        use payjoin::send::v1::SenderBuilder;
        use payjoin::UriExt;
        use tracing::debug;

        use super::*;

        #[test]
        fn v1_to_v1_p2pkh() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Legacy),
                Some(AddressType::Legacy),
            )?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_LEGACY_WEIGHT + (P2PKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
            )
            // bitcoin-cli wallet uses signature grinding to save one vbyte on the original PSBT.
            // subtract it here
            - Weight::from_vb_unchecked(1);
            do_v1_to_v1(sender, receiver, expected_weight)
        }

        #[test]
        fn v1_to_v1_nested_p2wpkh() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::P2shSegwit),
                Some(AddressType::P2shSegwit),
            )?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (NESTED_P2WPKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
            );
            do_v1_to_v1(sender, receiver, expected_weight)
        }

        #[test]
        fn v1_to_v1_p2wpkh() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Bech32),
                Some(AddressType::Bech32),
            )?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
            );
            do_v1_to_v1(sender, receiver, expected_weight)
        }

        #[test]
        fn v1_to_v1_taproot() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Bech32m),
                Some(AddressType::Bech32m),
            )?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT
                    + (P2TR_INPUT_WEIGHT * 2)
                    + (P2WPKH_OUTPUT_WEIGHT * 2),
            )
            // bitcoin-cli wallet overestimates taproot inputs in the original PSBT by one vbyte:
            // https://github.com/payjoin/rust-payjoin/issues/369#issuecomment-2657539591
            // add it here
            + Weight::from_vb_unchecked(1);
            do_v1_to_v1(sender, receiver, expected_weight)
        }

        fn do_v1_to_v1(
            sender: corepc_node::Client,
            receiver: corepc_node::Client,
            expected_weight: Weight,
        ) -> Result<(), BoxError> {
            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            let psbt = build_original_psbt(&sender, &uri)?;
            debug!("Original psbt: {psbt:#?}");
            let (req, ctx) = SenderBuilder::new(psbt, uri)
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let response = handle_v1_pj_request(req, headers, &receiver, None, None, None)?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(response.as_bytes())?;
            let network_fees = checked_payjoin_proposal_psbt.fee()?;
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
            assert_eq!(network_fees, expected_fee);
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            assert_eq!(payjoin_tx.input.len(), 2);
            assert_eq!(payjoin_tx.output.len(), 2);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(51.0)?
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(49.0)? - network_fees
            );
            Ok(())
        }

        #[test]
        fn allow_mixed_input_scripts() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Bech32),
                Some(AddressType::P2shSegwit),
            )?;

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            let psbt = build_original_psbt(&sender, &uri)?;
            debug!("Original psbt: {psbt:#?}");
            let (req, _ctx) = SenderBuilder::new(psbt, uri)
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // This should NOT error because the receiver is attempting to introduce mixed input script types
            assert!(handle_v1_pj_request(req, headers, &receiver, None, None, None).is_ok());
            Ok(())
        }
    }

    // not all needs v1
    #[cfg(all(feature = "io", feature = "v2", feature = "v1", feature = "_manual-tls"))]
    mod v2 {
        use std::sync::Arc;
        use std::time::Duration;

        use bitcoin::Address;
        use http::StatusCode;
        use payjoin::persist::NoopSessionPersister;
        use payjoin::receive::v2::{
            replay_event_log as replay_receiver_event_log, PayjoinProposal, Receiver,
            ReceiverBuilder, UncheckedOriginalPayload,
        };
        use payjoin::send::v2::SenderBuilder;
        use payjoin::{OhttpKeys, PjUri, UriExt};
        use payjoin_test_utils::{BoxSendSyncError, InMemoryTestPersister, TestServices};
        use reqwest::{Client, Response};

        use super::*;

        #[tokio::test]
        async fn test_bad_ohttp_keys() -> Result<(), BoxSendSyncError> {
            let bad_ohttp_keys =
                OhttpKeys::from_str("OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC")
                    .expect("Invalid OhttpKeys");
            let mut services = TestServices::initialize().await?;
            let result = tokio::select!(
            err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
            res = try_request_with_bad_keys(&services, bad_ohttp_keys) => res
            );

            assert_eq!(
                result?.headers().get("content-type").expect("content type should be present"),
                "application/problem+json"
            );

            async fn try_request_with_bad_keys(
                services: &TestServices,
                bad_ohttp_keys: OhttpKeys,
            ) -> Result<Response, BoxSendSyncError> {
                let agent = services.http_agent();
                services.wait_for_services_ready().await?;
                let directory = services.directory_url();
                let ohttp_relay = services.ohttp_relay_url();
                let mock_address = Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")?
                    .assume_checked();
                let noop_persister = NoopSessionPersister::default();
                let mut bad_initializer =
                    ReceiverBuilder::new(mock_address, directory, bad_ohttp_keys)?
                        .build()
                        .save(&noop_persister)?;
                let (req, _ctx) = bad_initializer.create_poll_request(&ohttp_relay)?;
                agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await
                    .map_err(|e| e.into())
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_session_expiration() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let result = tokio::select!(
            err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
            err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
            res = do_expiration_tests(&services) => res
            );

            assert!(result.is_ok(), "v2 send receive failed: {:#?}", result.unwrap_err());

            async fn do_expiration_tests(services: &TestServices) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                services.wait_for_services_ready().await?;
                let directory = services.directory_url();
                let ohttp_relay = services.ohttp_relay_url();
                let ohttp_keys = services.fetch_ohttp_keys().await?;
                let recv_noop_persister = NoopSessionPersister::default();
                let send_noop_persister = NoopSessionPersister::default();
                // **********************
                // Inside the Receiver:
                let address = receiver.new_address()?;
                // test session with expiry in the past
                let mut expired_receiver = ReceiverBuilder::new(address, directory, ohttp_keys)?
                    .with_expiry(Duration::from_secs(0))
                    .build()
                    .save(&recv_noop_persister)?;
                match expired_receiver.create_poll_request(&ohttp_relay) {
                    // Internal error types are private, so check against a string
                    Err(err) => assert!(err.to_string().contains("expired")),
                    _ => panic!("Expired receive session should error"),
                };

                // **********************
                // Inside the Sender:
                let psbt = build_original_psbt(&sender, &expired_receiver.pj_uri())?;
                // Test that an expired pj_url errors
                let expired_req_ctx = SenderBuilder::new(psbt, expired_receiver.pj_uri())
                    .build_non_incentivizing(FeeRate::BROADCAST_MIN)?
                    .save(&send_noop_persister)?;

                match expired_req_ctx.create_v2_post_request(ohttp_relay) {
                    // Internal error types are private, so check against a string
                    Err(err) => assert!(err.to_string().contains("expired")),
                    _ => panic!("Expired send session should error"),
                };
                Ok(())
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_err_response() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let result = tokio::select!(
            err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
            err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
            res = process_err_res(&services) => res
            );

            assert!(result.is_ok(), "v2 send receive failed: {:#?}", result.unwrap_err());

            async fn process_err_res(services: &TestServices) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                let agent = services.http_agent();
                services.wait_for_services_ready().await?;
                let directory = services.directory_url();
                let ohttp_keys = services.fetch_ohttp_keys().await?;
                let persister = InMemoryTestPersister::default();
                let sender_persister = NoopSessionPersister::default();
                // **********************
                // Inside the Receiver:
                let address = receiver.new_address()?;

                let mut session = ReceiverBuilder::new(address, directory, ohttp_keys)?
                    .build()
                    .save(&persister)?;
                println!("session: {:#?}", &session);
                // Poll receive request
                let ohttp_relay = services.ohttp_relay_url();
                let (req, ctx) = session.create_poll_request(&ohttp_relay)?;
                let response = agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await?;
                assert!(response.status().is_success(), "error response: {}", response.status());
                let response_body = session
                    .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                    .save(&persister)?;
                // No proposal yet since sender has not responded
                assert!(response_body.is_none());

                // **********************
                // Inside the Sender:
                // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
                let pj_uri = Uri::from_str(&session.pj_uri().to_string())
                    .map_err(|e| e.to_string())?
                    .assume_checked()
                    .check_pj_supported()
                    .map_err(|e| e.to_string())?;
                let psbt = build_sweep_psbt(&sender, &pj_uri)?;
                let req_ctx = SenderBuilder::new(psbt, pj_uri)
                    .build_recommended(FeeRate::BROADCAST_MIN)?
                    .save(&sender_persister)?;
                let (Request { url, body, content_type, .. }, _send_ctx) =
                    req_ctx.create_v2_post_request(ohttp_relay.to_owned())?;
                let response =
                    agent.post(url).header("Content-Type", content_type).body(body).send().await?;
                tracing::info!("Response: {:#?}", &response);
                assert!(response.status().is_success(), "error response: {}", response.status());
                // POST Original PSBT

                // **********************
                // Inside the Receiver:

                // GET fallback psbt
                let (req, ctx) = session.create_poll_request(&ohttp_relay)?;
                let response = agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await?;
                // POST payjoin
                let outcome = session
                    .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                    .save(&persister)?;
                let proposal = outcome.success().expect("proposal should exist");

                // Generate replyable error
                let check_broadcast_suitability = || {
                    proposal
                        .clone()
                        .check_broadcast_suitability(None, |_| Ok(false))
                        .save(&persister)
                };
                let server_error = check_broadcast_suitability()
                    .expect_err("should fail")
                    .api_error()
                    .expect("expected api error");
                // TODO: this should be replaced by comparing the error itself once the error types impl PartialEq
                // Issue: https://github.com/payjoin/rust-payjoin/issues/645
                assert_eq!(
                    server_error.to_string(),
                    "Protocol error: Can't broadcast. PSBT rejected by mempool."
                );

                let (_, session_history) = replay_receiver_event_log(&persister)?;
                let (err_req, err_ctx) = session_history
                    .extract_err_req(ohttp_relay)?
                    .expect("error request should exist");
                let err_response = agent
                    .post(err_req.url)
                    .header("Content-Type", err_req.content_type)
                    .body(err_req.body)
                    .send()
                    .await?;

                let err_bytes = err_response.bytes().await?;
                // Ensure that the error was handled properly
                assert!(payjoin::receive::v2::process_err_res(&err_bytes, err_ctx).is_ok());

                Ok(())
            }

            Ok(())
        }

        #[tokio::test]
        async fn v2_to_v2() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let result = tokio::select!(
            err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
            err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
            res = do_v2_send_receive(&services) => res
            );

            assert!(result.is_ok(), "v2 send receive failed: {:#?}", result.unwrap_err());

            async fn do_v2_send_receive(services: &TestServices) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                let agent = services.http_agent();
                services.wait_for_services_ready().await?;
                let directory = services.directory_url();
                let ohttp_keys = services.fetch_ohttp_keys().await?;
                let recv_persister = NoopSessionPersister::default();
                let send_persister = NoopSessionPersister::default();
                // **********************
                // Inside the Receiver:
                let address = receiver.new_address()?;

                // test session with expiry in the future
                let mut session = ReceiverBuilder::new(address, directory, ohttp_keys)?
                    .build()
                    .save(&recv_persister)?;
                println!("session: {:#?}", &session);
                // Poll receive request
                let ohttp_relay = services.ohttp_relay_url();
                let (req, ctx) = session.create_poll_request(&ohttp_relay)?;
                let response = agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await?;
                assert!(response.status().is_success(), "error response: {}", response.status());
                let response_body = session
                    .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                    .save(&recv_persister)?;
                // No proposal yet since sender has not responded
                assert!(response_body.is_none());

                // **********************
                // Inside the Sender:
                // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
                let pj_uri = Uri::from_str(&session.pj_uri().to_string())
                    .map_err(|e| e.to_string())?
                    .assume_checked()
                    .check_pj_supported()
                    .map_err(|e| e.to_string())?;
                let psbt = build_sweep_psbt(&sender, &pj_uri)?;
                let req_ctx = SenderBuilder::new(psbt, pj_uri)
                    .build_recommended(FeeRate::BROADCAST_MIN)?
                    .save(&send_persister)?;
                let (Request { url, body, content_type, .. }, send_ctx) =
                    req_ctx.create_v2_post_request(ohttp_relay.to_owned())?;
                let response =
                    agent.post(url).header("Content-Type", content_type).body(body).send().await?;
                tracing::info!("Response: {:#?}", &response);
                assert!(response.status().is_success(), "error response: {}", response.status());
                let send_ctx = req_ctx
                    .process_response(&response.bytes().await?, send_ctx)
                    .save(&send_persister)?;
                // POST Original PSBT

                // **********************
                // Inside the Receiver:

                // GET fallback psbt
                let (req, ctx) = session.create_poll_request(&ohttp_relay)?;
                let response = agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await?;
                // POST payjoin
                let outcome = session
                    .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                    .save(&recv_persister)?;
                let proposal = outcome.success().expect("proposal should exist").clone();
                let mut payjoin_proposal = handle_directory_proposal(&receiver, proposal, None)?;
                let (req, ctx) = payjoin_proposal.create_post_request(&ohttp_relay)?;
                let response = agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await?;
                payjoin_proposal
                    .process_response(&response.bytes().await?, ctx)
                    .save(&recv_persister)?;

                // **********************
                // Inside the Sender:
                // Sender checks, signs, finalizes, constructs, and broadcasts
                // Replay post fallback to get the response
                let (Request { url, body, content_type, .. }, ohttp_ctx) =
                    send_ctx.create_poll_request(ohttp_relay.to_owned())?;
                let response =
                    agent.post(url).header("Content-Type", content_type).body(body).send().await?;
                tracing::info!("Response: {:#?}", &response);
                let response = send_ctx
                    .process_response(&response.bytes().await?, ohttp_ctx)
                    .save(&send_persister)
                    .expect("psbt should exist");

                let checked_payjoin_proposal_psbt =
                    response.success().expect("psbt should exist").clone();
                let network_fees = checked_payjoin_proposal_psbt.fee()?;
                let expected_weight = Weight::from_wu(
                    TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT),
                );
                let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
                assert_eq!(network_fees, expected_fee);
                let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
                sender.send_raw_transaction(&payjoin_tx)?;
                tracing::info!("sent");

                // Check resulting transaction and balances
                // Sender sent the entire value of their utxo to receiver (minus fees)
                assert_eq!(payjoin_tx.input.len(), 2);
                assert_eq!(payjoin_tx.output.len(), 1);
                assert_eq!(
                    receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                    Amount::from_btc(100.0)? - network_fees
                );
                assert_eq!(
                    sender.get_balances()?.into_model()?.mine.untrusted_pending,
                    Amount::from_btc(0.0)?
                );
                Ok(())
            }

            Ok(())
        }

        #[test]
        fn v2_to_v1() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let pj_uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            // FIXME this test no longer sends v2 to v1 because that concept is gone and should now be
            // Handled by the implementation. Therefore, the e2e test should now test v2-capable sender
            // successfully sending to v1.
            assert!(matches!(pj_uri.extras.pj_param(), payjoin::PjParam::V1(_)));
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            let req_ctx = payjoin::send::v1::SenderBuilder::new(psbt, pj_uri)
                .build_recommended(FeeRate::BROADCAST_MIN)?;
            let (req, ctx) = req_ctx.create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let response = handle_v1_pj_request(req, headers, &receiver, None, None, None)?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, constructs, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(response.as_bytes())?;
            let network_fees = checked_payjoin_proposal_psbt.fee()?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
            );
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
            assert_eq!(network_fees, expected_fee);
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            assert_eq!(payjoin_tx.input.len(), 2);
            assert_eq!(payjoin_tx.output.len(), 2);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(51.0)?
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(49.0)? - network_fees
            );
            Ok(())
        }

        #[tokio::test]
        async fn v1_to_v2() -> Result<(), BoxSendSyncError> {
            init_tracing();
            let mut services = TestServices::initialize().await?;
            let result = tokio::select!(
            err = services.take_ohttp_relay_handle() => panic!("Ohttp relay exited early: {:?}", err),
            err = services.take_directory_handle() => panic!("Directory server exited early: {:?}", err),
            res = do_v1_to_v2(&services) => res
            );

            assert!(result.is_ok(), "v2 send receive failed: {:#?}", result.unwrap_err());

            async fn do_v1_to_v2(services: &TestServices) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                let agent = services.http_agent();
                services.wait_for_services_ready().await?;
                let directory = services.directory_url();
                let ohttp_keys = services.fetch_ohttp_keys().await?;
                let recv_persister = NoopSessionPersister::default();
                let address = receiver.new_address()?;
                let mut session =
                    ReceiverBuilder::new(address, directory.clone(), ohttp_keys.clone())?
                        .build()
                        .save(&recv_persister)?;

                // **********************
                // Inside the V1 Sender:
                // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
                let pj_uri = Uri::from_str(&session.pj_uri().to_string())
                    .map_err(|e| e.to_string())?
                    .assume_checked()
                    .check_pj_supported()
                    .map_err(|e| e.to_string())?;
                let psbt = build_original_psbt(&sender, &pj_uri)?;
                let req_ctx = payjoin::send::v1::SenderBuilder::new(psbt, pj_uri)
                    .build_with_additional_fee(
                        Amount::from_sat(10000),
                        None,
                        FeeRate::ZERO,
                        false,
                    )?;
                let (Request { url, body, content_type, .. }, send_ctx) =
                    req_ctx.create_v1_post_request();
                tracing::info!("send fallback v1 to offline receiver fail");
                let res = agent
                    .post(url.clone())
                    .header("Content-Type", content_type)
                    .body(body.clone())
                    .send()
                    .await;
                assert!(res?.status() == StatusCode::SERVICE_UNAVAILABLE);

                // **********************
                // Inside the Receiver:
                let agent_clone: Arc<Client> = agent.clone();
                let receiver: Arc<corepc_node::Client> = Arc::new(receiver);
                let receiver_clone = receiver.clone();
                let ohttp_relay = services.ohttp_relay_url();
                let receiver_loop = tokio::task::spawn(async move {
                    let agent_clone = agent_clone.clone();
                    let proposal = loop {
                        let (req, ctx) = session.create_poll_request(&ohttp_relay)?;
                        let response = agent_clone
                            .post(req.url)
                            .header("Content-Type", req.content_type)
                            .body(req.body)
                            .send()
                            .await?;

                        if response.status() == 200 {
                            let proposal = session
                                .clone()
                                .process_response(response.bytes().await?.to_vec().as_slice(), ctx)
                                .save(&recv_persister)?;
                            if let Some(unchecked_proposal) = proposal.success() {
                                break unchecked_proposal.clone();
                            } else {
                                tracing::info!(
                                    "No response yet for POST payjoin request, retrying some seconds"
                                );
                            }
                        } else {
                            tracing::error!("Unexpected response status: {}", response.status());
                            panic!("Unexpected response status: {}", response.status())
                        }
                    };
                    let mut payjoin_proposal =
                        handle_directory_proposal(&receiver_clone, proposal, None)
                            .map_err(|e| e.to_string())?;
                    // Respond with payjoin psbt within the time window the sender is willing to wait
                    // this response would be returned as http response to the sender
                    let (req, ctx) = payjoin_proposal.create_post_request(&ohttp_relay)?;
                    let response = agent_clone
                        .post(req.url)
                        .header("Content-Type", req.content_type)
                        .body(req.body)
                        .send()
                        .await?;
                    payjoin_proposal
                        .process_response(&response.bytes().await?, ctx)
                        .save(&recv_persister)
                        .map_err(|e| e.to_string())?;
                    Ok::<_, BoxSendSyncError>(())
                });

                // **********************
                // send fallback v1 to online receiver
                tracing::info!("send fallback v1 to online receiver should succeed");
                let response =
                    agent.post(url).header("Content-Type", content_type).body(body).send().await?;
                tracing::info!("Response: {:#?}", &response);
                assert!(response.status().is_success(), "error response: {}", response.status());

                let checked_payjoin_proposal_psbt =
                    send_ctx.process_response(&response.bytes().await?)?;
                let network_fees = checked_payjoin_proposal_psbt.fee()?;
                let expected_weight = Weight::from_wu(
                    TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 2) + (P2WPKH_OUTPUT_WEIGHT * 2),
                );
                let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
                assert_eq!(network_fees, expected_fee);
                let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
                sender.send_raw_transaction(&payjoin_tx)?;
                tracing::info!("sent");
                assert!(
                    receiver_loop.await.is_ok(),
                    "The spawned task panicked or returned an error"
                );

                // Check resulting transaction and balances
                assert_eq!(payjoin_tx.input.len(), 2);
                assert_eq!(payjoin_tx.output.len(), 2);
                assert_eq!(
                    receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                    Amount::from_btc(51.0)?
                );
                assert_eq!(
                    sender.get_balances()?.into_model()?.mine.untrusted_pending,
                    Amount::from_btc(49.0)? - network_fees
                );
                Ok(())
            }

            Ok(())
        }

        fn handle_directory_proposal(
            receiver: &corepc_node::Client,
            proposal: Receiver<UncheckedOriginalPayload>,
            custom_inputs: Option<Vec<InputPair>>,
        ) -> Result<Receiver<PayjoinProposal>, BoxError> {
            let noop_persister = NoopSessionPersister::default();

            // Receive Check 1: Can Broadcast
            let proposal = proposal
                .check_broadcast_suitability(None, |tx| {
                    Ok(receiver
                        .test_mempool_accept(std::slice::from_ref(tx))
                        .map_err(ImplementationError::new)?
                        .0
                        .first()
                        .ok_or(ImplementationError::from(
                            "testmempoolaccept should return a result",
                        ))?
                        .allowed)
                })
                .save(&noop_persister)?;

            // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
            let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

            // Receive Check 2: receiver can't sign for proposal inputs
            let proposal = proposal
                .check_inputs_not_owned(&mut |input| {
                    let address = bitcoin::Address::from_script(input, bitcoin::Network::Regtest)
                        .map_err(ImplementationError::new)?;
                    receiver
                        .get_address_info(&address)
                        .map(|info| info.is_mine)
                        .map_err(ImplementationError::new)
                })
                .save(&noop_persister)?;

            // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
            let payjoin = proposal
                .check_no_inputs_seen_before(&mut |_| Ok(false))
                .save(&noop_persister)?
                .identify_receiver_outputs(&mut |output_script| {
                    let address =
                        bitcoin::Address::from_script(output_script, bitcoin::Network::Regtest)
                            .map_err(ImplementationError::new)?;
                    receiver
                        .get_address_info(&address)
                        .map(|info| info.is_mine)
                        .map_err(ImplementationError::new)
                })
                .save(&noop_persister)?;

            let payjoin = payjoin.commit_outputs().save(&noop_persister)?;

            let inputs = match custom_inputs {
                Some(inputs) => inputs,
                None => {
                    let candidate_inputs = receiver
                        .list_unspent()
                        .map_err(ImplementationError::new)?
                        .0
                        .into_iter()
                        .map(input_pair_from_list_unspent);
                    let selected_input =
                        payjoin.try_preserving_privacy(candidate_inputs).map_err(|e| {
                            format!("Failed to make privacy preserving selection: {e:?}")
                        })?;
                    vec![selected_input]
                }
            };
            let payjoin = payjoin
                .contribute_inputs(inputs)
                .map_err(|e| format!("Failed to contribute inputs: {e:?}"))?
                .commit_inputs()
                .save(&noop_persister)?;

            let payjoin = payjoin
                .apply_fee_range(
                    Some(FeeRate::BROADCAST_MIN),
                    Some(FeeRate::from_sat_per_vb_unchecked(2)),
                )
                .save(&noop_persister)?;

            // Sign and finalize the proposal PSBT
            let payjoin = payjoin
                .finalize_proposal(|psbt: &Psbt| {
                    receiver
                        // call RPC manually to pass custom options
                        .call::<corepc_node::vtype::WalletProcessPsbt>(
                            "walletprocesspsbt",
                            &[
                                json!(psbt.to_string()),
                                json!(None as Option<bool>),
                                json!(None as Option<&str>),
                                json!(Some(true)), // check that the receiver properly clears keypaths
                            ],
                        )
                        .map(|res| Psbt::from_str(&res.psbt).expect("psbt should be valid"))
                        .map_err(ImplementationError::new)
                })
                .save(&noop_persister)?;
            Ok(payjoin)
        }

        pub fn build_sweep_psbt(
            sender: &corepc_node::Client,
            pj_uri: &PjUri,
        ) -> Result<Psbt, BoxError> {
            let mut outputs = HashMap::with_capacity(1);
            outputs.insert(pj_uri.address.to_string(), Amount::from_btc(50.0)?.to_btc());
            let options = serde_json::json!({
                "lockUnspents": true,
                // The minimum relay feerate ensures that tests fail if the receiver would add inputs/outputs
                // that cannot be covered by the sender's additional fee contributions.
                "feeRate": Amount::from_sat(DEFAULT_MIN_RELAY_TX_FEE.into()).to_btc(),
                "subtractFeeFromOutputs": [0],
            });
            let psbt = sender
                // call RPC manually to pass custom options
                .call::<corepc_node::vtype::WalletCreateFundedPsbt>(
                    "walletcreatefundedpsbt",
                    &[
                        json!(&[] as &[serde_json::Value]), // inputs
                        json!(&outputs),
                        json!(None as Option<u64>), // locktime
                        json!(options),
                        json!(Some(true)), // check that the sender properly clears keypaths
                    ],
                )?
                .psbt;
            let psbt = sender.wallet_process_psbt(&Psbt::from_str(&psbt)?)?.psbt;
            Ok(Psbt::from_str(&psbt)?)
        }
    }

    #[cfg(feature = "v1")]
    mod batching {
        use payjoin::send::v1::SenderBuilder;
        use payjoin::UriExt;

        use super::*;

        // In this test the receiver consolidates a bunch of UTXOs into the destination output
        #[test]
        fn receiver_consolidates_utxos() -> Result<(), BoxError> {
            init_tracing();
            let (bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
            // Generate more UTXOs for the receiver
            let receiver_address = receiver.new_address_with_type(AddressType::Bech32)?;
            bitcoind.client.generate_to_address(199, &receiver_address)?;
            let receiver_utxos = receiver.list_unspent()?.0;
            assert_eq!(100, receiver_utxos.len(), "receiver doesn't have enough UTXOs");
            assert_eq!(
                Amount::from_btc(3650.0)?, // 50 (starting receiver balance) + 46*50.0 + 52*25.0 (halving occurs every 150 blocks)
                receiver.get_balances()?.into_model()?.mine.trusted,
                "receiver doesn't have enough bitcoin"
            );

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            let psbt = build_original_psbt(&sender, &uri)?;
            tracing::debug!("Original psbt: {psbt:#?}");
            let max_additional_fee = Amount::from_sat(1000);
            let (req, ctx) = SenderBuilder::new(psbt.clone(), uri)
                .build_with_additional_fee(max_additional_fee, None, FeeRate::ZERO, false)?
                .create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let outputs = vec![TxOut {
                value: Amount::from_btc(3650.0)?,
                script_pubkey: receiver.new_address()?.script_pubkey(),
            }];
            let drain_script = outputs[0].script_pubkey.clone();
            let inputs = receiver_utxos.into_iter().map(input_pair_from_list_unspent).collect();
            let response = handle_v1_pj_request(
                req,
                headers,
                &receiver,
                Some(outputs),
                Some(&drain_script),
                Some(inputs),
            )?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(response.as_bytes())?;
            let network_fees = checked_payjoin_proposal_psbt.fee()?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT * 101) + (P2WPKH_OUTPUT_WEIGHT * 2),
            );
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
            assert_eq!(network_fees, expected_fee);
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            // The sender pays (original tx fee + max additional fee)
            let original_tx_fee = psbt.fee()?;
            let sender_fee = original_tx_fee + max_additional_fee;
            // The receiver pays the difference
            let receiver_fee = network_fees - sender_fee;
            assert_eq!(payjoin_tx.input.len(), 101);
            assert_eq!(payjoin_tx.output.len(), 2);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(3651.0)? - receiver_fee
            );
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(49.0)? - sender_fee
            );
            Ok(())
        }

        // In this test the receiver forwards part of the sender payment to another payee
        #[test]
        fn receiver_forwards_payment() -> Result<(), BoxError> {
            init_tracing();
            let (bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
            let third_party = bitcoind.create_wallet("third-party")?;

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.new_address()?;
            let mut pj_uri =
                build_v1_pj_uri(&pj_receiver_address, EXAMPLE_URL, OutputSubstitution::Enabled)?;
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .map_err(|e| e.to_string())?
                .assume_checked()
                .check_pj_supported()
                .map_err(|e| e.to_string())?;
            let psbt = build_original_psbt(&sender, &uri)?;
            tracing::debug!("Original psbt: {psbt:#?}");
            let (req, ctx) = SenderBuilder::new(psbt.clone(), uri)
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .create_v1_post_request();
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let outputs = vec![
                TxOut {
                    value: Amount::from_sat(10000000),
                    script_pubkey: third_party.new_address()?.script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(90000000),
                    script_pubkey: receiver.new_address()?.script_pubkey(),
                },
            ];
            let drain_script = outputs[1].script_pubkey.clone();
            let inputs = vec![];
            let response = handle_v1_pj_request(
                req,
                headers,
                &receiver,
                Some(outputs),
                Some(&drain_script),
                Some(inputs),
            )?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(response.as_bytes())?;
            let network_fees = checked_payjoin_proposal_psbt.fee()?;
            let expected_weight = Weight::from_wu(
                TX_HEADER_WEIGHT + (P2WPKH_INPUT_WEIGHT) + (P2WPKH_OUTPUT_WEIGHT * 3),
            );
            let expected_fee = expected_weight * FeeRate::BROADCAST_MIN;
            assert_eq!(network_fees, expected_fee);
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            // The sender pays original tx fee
            let original_tx_fee = psbt.fee()?;
            let sender_fee = original_tx_fee;
            // The receiver pays the difference
            let receiver_fee = network_fees - sender_fee;
            assert_eq!(payjoin_tx.input.len(), 1);
            assert_eq!(payjoin_tx.output.len(), 3);
            assert_eq!(
                receiver.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(0.9)? - receiver_fee
            );
            assert_eq!(
                third_party.get_balances()?.into_model()?.mine.untrusted_pending,
                Amount::from_btc(0.1)?
            );
            // sender balance is considered "trusted" because all inputs in the transaction were
            // created by their wallet
            assert_eq!(
                sender.get_balances()?.into_model()?.mine.trusted,
                Amount::from_btc(49.0)? - sender_fee
            );
            Ok(())
        }
    }

    fn build_original_psbt(sender: &corepc_node::Client, pj_uri: &PjUri) -> Result<Psbt, BoxError> {
        let mut outputs = HashMap::with_capacity(1);
        outputs
            .insert(pj_uri.address.to_string(), pj_uri.amount.unwrap_or(Amount::ONE_BTC).to_btc());
        let options = json!({
            "lockUnspents": true,
            // The minimum relay feerate ensures that tests fail if the receiver would add inputs/outputs
            // that cannot be covered by the sender's additional fee contributions.
            "feeRate": Amount::from_sat(DEFAULT_MIN_RELAY_TX_FEE.into()).to_btc(),
        });
        let psbt = sender
            // call RPC manually to pass custom options
            .call::<corepc_node::vtype::WalletCreateFundedPsbt>(
                "walletcreatefundedpsbt",
                &[
                    json!(&[] as &[serde_json::Value]), // inputs
                    json!(&outputs),
                    json!(None as Option<u64>), // locktime
                    json!(options),
                    json!(Some(true)), // check that the sender properly clears keypaths
                ],
            )?
            .psbt;
        let psbt = sender.wallet_process_psbt(&Psbt::from_str(&psbt)?)?.psbt;
        Ok(Psbt::from_str(&psbt)?)
    }

    // Receiver receive and process original_psbt from a sender
    // In production it it will come in as an HTTP request (over ssl or onion)
    fn handle_v1_pj_request(
        req: Request,
        headers: impl payjoin::receive::v1::Headers,
        receiver: &corepc_node::Client,
        custom_outputs: Option<Vec<TxOut>>,
        drain_script: Option<&bitcoin::Script>,
        custom_inputs: Option<Vec<InputPair>>,
    ) -> Result<String, BoxError> {
        // Receiver receive payjoin proposal, IRL it will be an HTTP request (over ssl or onion)
        let proposal = payjoin::receive::v1::UncheckedOriginalPayload::from_request(
            req.body.as_slice(),
            req.url.query().unwrap_or(""),
            headers,
        )?;
        let proposal =
            handle_proposal(proposal, receiver, custom_outputs, drain_script, custom_inputs)?;
        let psbt = proposal.psbt();
        tracing::debug!("Receiver's Payjoin proposal PSBT: {psbt:#?}");
        Ok(psbt.to_string())
    }

    fn handle_proposal(
        proposal: payjoin::receive::v1::UncheckedOriginalPayload,
        receiver: &corepc_node::Client,
        custom_outputs: Option<Vec<TxOut>>,
        drain_script: Option<&bitcoin::Script>,
        custom_inputs: Option<Vec<InputPair>>,
    ) -> Result<payjoin::receive::v1::PayjoinProposal, BoxError> {
        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_broadcast_suitability(None, |tx| {
            Ok(receiver
                .test_mempool_accept(std::slice::from_ref(tx))
                .map_err(ImplementationError::new)?
                .0
                .first()
                .ok_or(ImplementationError::from("testmempoolaccept should return a result"))?
                .allowed)
        })?;
        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(&mut |input| {
            let address = bitcoin::Address::from_script(input, bitcoin::Network::Regtest)
                .map_err(ImplementationError::new)?;
            receiver
                .get_address_info(&address)
                .map(|info| info.is_mine)
                .map_err(ImplementationError::new)
        })?;

        // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal
            .check_no_inputs_seen_before(&mut |_| Ok(false))?
            .identify_receiver_outputs(&mut |output_script| {
                let address =
                    bitcoin::Address::from_script(output_script, bitcoin::Network::Regtest)
                        .map_err(ImplementationError::new)?;
                receiver
                    .get_address_info(&address)
                    .map(|info| info.is_mine)
                    .map_err(ImplementationError::new)
            })?;

        let payjoin = match custom_outputs {
            Some(txos) => payjoin.replace_receiver_outputs(
                txos,
                drain_script.expect("drain_script should be provided with custom_outputs"),
            )?,
            None => payjoin.substitute_receiver_script(&receiver.new_address()?.script_pubkey())?,
        }
        .commit_outputs();

        let inputs = match custom_inputs {
            Some(inputs) => inputs,
            None => {
                let candidate_inputs =
                    receiver.list_unspent()?.0.into_iter().map(input_pair_from_list_unspent);
                let selected_input = payjoin
                    .try_preserving_privacy(candidate_inputs)
                    .map_err(|e| format!("Failed to make privacy preserving selection: {e:?}"))?;
                vec![selected_input]
            }
        };
        let payjoin = payjoin
            .contribute_inputs(inputs)
            .map_err(|e| format!("Failed to contribute inputs: {e:?}"))?
            .commit_inputs();
        let payjoin = payjoin.apply_fee_range(
            Some(FeeRate::BROADCAST_MIN),
            Some(FeeRate::from_sat_per_vb_unchecked(2)),
        )?;

        let payjoin_proposal = payjoin.finalize_proposal(|psbt: &Psbt| {
            receiver
                // call RPC manually to pass custom options
                .call::<corepc_node::vtype::WalletProcessPsbt>(
                    "walletprocesspsbt",
                    &[
                        json!(psbt.to_string()),
                        json!(None as Option<bool>),
                        json!(None as Option<&str>),
                        json!(Some(true)), // check that the receiver properly clears keypaths
                    ],
                )
                .map(|res| Psbt::from_str(&res.psbt).expect("psbt should be valid"))
                .map_err(ImplementationError::new)
        })?;
        Ok(payjoin_proposal)
    }

    fn extract_pj_tx(
        sender: &corepc_node::Client,
        psbt: Psbt,
    ) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
        let payjoin_psbt = sender.wallet_process_psbt(&psbt)?.psbt;
        let payjoin_psbt = sender
            .finalize_psbt(&Psbt::from_str(&payjoin_psbt)?)?
            .psbt
            .expect("should contain a PSBT");
        let payjoin_psbt = Psbt::from_str(&payjoin_psbt)?;
        tracing::debug!("Sender's Payjoin PSBT: {payjoin_psbt:#?}");

        Ok(payjoin_psbt.extract_tx()?)
    }

    fn input_pair_from_list_unspent(utxo: ListUnspentItem) -> InputPair {
        let utxo = utxo.into_model().expect("listunspent utxo should be convertible to model type");
        let psbtin = PsbtInput {
            // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
            // witness_utxo, even for non-witness inputs
            witness_utxo: Some(TxOut {
                value: utxo.amount.to_unsigned().expect("amount should be unsigned"),
                script_pubkey: utxo.script_pubkey,
            }),
            redeem_script: utxo.redeem_script,
            //FIXME needs later corepc_node bitcoin version
            //witness_script: utxo.witness_script.clone(),
            ..Default::default()
        };
        let txin = TxIn {
            previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
            ..Default::default()
        };
        InputPair::new(txin, psbtin, None).expect("Input pair should be valid")
    }

    struct HeaderMock(HashMap<String, String>);

    impl payjoin::receive::v1::Headers for HeaderMock {
        fn get_header(&self, key: &str) -> Option<&str> { self.0.get(key).map(|e| e.as_str()) }
    }

    impl HeaderMock {
        fn new(body: &[u8], content_type: &str) -> HeaderMock {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), content_type.to_string());
            h.insert("content-length".to_string(), body.len().to_string());
            HeaderMock(h)
        }
    }
}

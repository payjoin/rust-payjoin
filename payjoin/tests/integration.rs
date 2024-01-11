#[cfg(all(feature = "send", feature = "receive"))]
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
    use payjoin::bitcoin::base64;
    use payjoin::send::{Request, RequestBuilder};
    use payjoin::PayjoinUri;

    type BoxError = Box<dyn std::error::Error>;

    #[cfg(not(feature = "v2"))]
    mod v1 {
        use payjoin::receive::{Headers, PayjoinProposal, UncheckedProposal};
        use payjoin::PayjoinUriBuilder;

        use super::*;

        const EXAMPLE_URL: &str = "https://example.com";

        #[test]
        fn v1_to_v1() -> Result<(), BoxError> {
            let _ = env_logger::try_init();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver()?;

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
            let mut pj_uri = PayjoinUriBuilder::new(
                pj_receiver_address,
                payjoin::Url::parse(EXAMPLE_URL).unwrap(),
            );
            pj_uri.amount(bitcoin::Amount::ONE_BTC);
            let pj_uri = pj_uri.build();
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            debug!("Original psbt: {:#?}", psbt);
            let (req, ctx) = RequestBuilder::from_psbt_and_uri(psbt, pj_uri)?
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
    }

    #[cfg(feature = "v2")]
    mod v2 {
        use std::process::Stdio;
        use std::sync::Arc;

        use payjoin::receive::v2::{Enroller, PayjoinProposal, UncheckedProposal};
        use payjoin::PayjoinUriBuilder;
        use testcontainers::Container;
        use testcontainers_modules::postgres::Postgres;
        use testcontainers_modules::testcontainers::clients::Cli;
        use tokio::process::{Child, Command};
        use tokio::task::spawn_blocking;

        use super::*;

        const PJ_RELAY_URL: &str = "https://localhost:8088";
        const BAD_OHTTP_CONFIG: &str = "AQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM";
        const OH_RELAY_URL: &str = "https://localhost:8088";
        const LOCAL_CERT_FILE: &str = "localhost.der";

        fn decode_ohttp_config(s: &str) -> ohttp::KeyConfig {
            ohttp::KeyConfig::decode(
                &bitcoin::base64::decode_config(s, bitcoin::base64::URL_SAFE).unwrap(),
            )
            .unwrap()
        }

        #[tokio::test]
        async fn v2_to_v2() -> Result<(), BoxError> {
            std::env::set_var("RUST_LOG", "debug");
            let _ = env_logger::builder().is_test(true).try_init();
            let docker = Cli::default();
            let (mut relay, _db) = init_relay(&docker).await;
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver()?;

            // **********************
            // From a connection distinct from the client, perhaps a service provider, or over a VPN or Tor
            // get ohttp-config at PJ_RELAY_URL in spawn_blocking
            let ohttp_config = {
                let response = spawn_blocking(move || {
                    http_agent().get(&format!("{}/ohttp-config", PJ_RELAY_URL)).call()
                })
                .await??;
                response.into_string()?
            };
            debug!("GET'd ohttp-config: {}", ohttp_config);

            // **********************
            // Inside the Receiver:
            // Try enroll with bad relay ohttp-config
            let mut bad_enroller =
                Enroller::from_relay_config(&PJ_RELAY_URL, &BAD_OHTTP_CONFIG, &OH_RELAY_URL);
            let (req, _ctx) = bad_enroller.extract_req()?;
            let res =
                spawn_blocking(move || http_agent().post(req.url.as_str()).send_bytes(&req.body))
                    .await?;
            assert!(res.is_err());
            assert!(
                res.unwrap_err().into_response().unwrap().content_type()
                    == "application/problem+json"
            );

            // Enroll with relay
            let mut enroller =
                Enroller::from_relay_config(&PJ_RELAY_URL, &ohttp_config, &OH_RELAY_URL);
            let (req, ctx) = enroller.extract_req()?;
            let res =
                spawn_blocking(move || http_agent().post(req.url.as_str()).send_bytes(&req.body))
                    .await??;
            assert!(is_success(res.status()));
            let enrolled = enroller.process_res(res.into_reader(), ctx)?;
            let fallback_target = enrolled.fallback_target();
            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
            let ohttp_config = decode_ohttp_config(&ohttp_config);
            let mut pj_uri = PayjoinUriBuilder::new(
                pj_receiver_address,
                payjoin::Url::parse(&fallback_target).unwrap(),
                Some(ohttp_config),
            );
            pj_uri.amount(Amount::ONE_BTC);
            let pj_uri = pj_uri.build();

            // **********************
            // Inside the Sender:
            // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            debug!("Original psbt: {:#?}", psbt);
            let (send_req, send_ctx) = RequestBuilder::from_psbt_and_uri(psbt, pj_uri)?
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .extract_v2(OH_RELAY_URL)?;
            log::info!("send fallback v2");
            log::debug!("Request: {:#?}", &send_req.body);
            let response = {
                let Request { url, body, .. } = send_req.clone();
                spawn_blocking(move || {
                    http_agent()
                        .post(url.as_str())
                        .set("Content-Type", "text/plain")
                        .set("Async", "true")
                        .send_bytes(&body)
                })
                .await??
            };
            log::info!("Response: {:#?}", &response);
            assert!(is_success(response.status()));
            // no response body yet since we are async and pushed fallback_psbt to the buffer

            // **********************
            // Inside the Receiver:

            // GET fallback psbt
            let (req, ctx) = enrolled.extract_req()?;
            let response =
                spawn_blocking(move || http_agent().post(req.url.as_str()).send_bytes(&req.body))
                    .await??;

            // POST payjoin
            let proposal = enrolled.process_res(response.into_reader(), ctx)?.unwrap();
            let payjoin_proposal = handle_relay_proposal(receiver, proposal);
            let (req, ctx) = payjoin_proposal.extract_v2_req()?;
            let response =
                spawn_blocking(move || http_agent().post(req.url.as_str()).send_bytes(&req.body))
                    .await??;
            let mut res = Vec::new();
            response.into_reader().read_to_end(&mut res)?;
            let _response = payjoin_proposal.deserialize_res(res, ctx)?;
            // response should be 204 http

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts

            // Replay post fallback to get the response
            let response = spawn_blocking(move || {
                http_agent().post(send_req.url.as_str()).send_bytes(&send_req.body)
            })
            .await??;
            let checked_payjoin_proposal_psbt =
                send_ctx.process_response(&mut response.into_reader())?.unwrap();
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;
            log::info!("sent");
            relay.kill().await?;
            let output = &relay.wait_with_output().await?;
            log::info!("Status: {}", output.status);
            Ok(())
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[cfg(feature = "v2")]
        async fn v1_to_v2() -> Result<(), BoxError> {
            std::env::set_var("RUST_LOG", "debug");
            let _ = env_logger::builder().is_test(true).try_init();
            let docker = Cli::default();
            let (mut relay, _db) = init_relay(&docker).await;
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver()?;

            // **********************
            // From a connection distinct from the client, perhaps a service provider, or over a VPN or Tor
            // get ohttp-config at PJ_RELAY_URL in spawn_blocking
            let ohttp_config = {
                let response = spawn_blocking(move || {
                    http_agent().get(&format!("{}/ohttp-config", PJ_RELAY_URL)).call()
                })
                .await??;
                response.into_string()?
            };
            debug!("GET'd ohttp-config: {}", ohttp_config);

            // **********************
            // Inside the Receiver:
            // Enroll with relay
            let mut enroller =
                Enroller::from_relay_config(&PJ_RELAY_URL, &ohttp_config, &OH_RELAY_URL);
            let (req, ctx) = enroller.extract_req()?;
            let res =
                spawn_blocking(move || http_agent().post(req.url.as_str()).send_bytes(&req.body))
                    .await??;
            assert!(is_success(res.status()));
            let enrolled = enroller.process_res(res.into_reader(), ctx)?;

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
            let fallback_target = enrolled.fallback_target();
            let ohttp_config = decode_ohttp_config(&ohttp_config);
            let mut pj_uri = PayjoinUriBuilder::new(
                pj_receiver_address,
                payjoin::Url::parse(&fallback_target).unwrap(),
                Some(ohttp_config),
            );
            pj_uri.amount(Amount::ONE_BTC);
            let pj_uri = pj_uri.build();

            // **********************
            // Inside the V1 Sender:
            // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            debug!("Original psbt: {:#?}", psbt);
            let (send_req, send_ctx) = RequestBuilder::from_psbt_and_uri(psbt, pj_uri)?
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .extract_v1()?;
            log::info!("send fallback v1 to offline receiver fail");
            let res = {
                let Request { url, body, .. } = send_req.clone();
                spawn_blocking(move || {
                    http_agent()
                        .post(url.as_str())
                        .set("Content-Type", "text/plain")
                        .send_bytes(&body)
                })
                .await?
            };
            match res {
                Err(ureq::Error::Status(code, _)) => assert_eq!(code, 503),
                _ => panic!("Expected response status code 503, found {:?}", res),
            }

            // **********************
            // Inside the Receiver:
            let receiver_loop = tokio::task::spawn(async move {
                let (response, ctx) = loop {
                    let (req, ctx) = enrolled.extract_req().unwrap();
                    let response = spawn_blocking(move || {
                        http_agent().post(req.url.as_str()).send_bytes(&req.body)
                    })
                    .await??;

                    if response.status() == 200 {
                        debug!("GET'd fallback_psbt");
                        break (response.into_reader(), ctx);
                    } else if response.status() == 202 {
                        log::info!(
                            "No response yet for POST payjoin request, retrying some seconds"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    } else {
                        log::error!("Unexpected response status: {}", response.status());
                        panic!("Unexpected response status: {}", response.status())
                    }
                };
                debug!("handle relay response");
                let proposal = enrolled.process_res(response, ctx).unwrap().unwrap();
                let payjoin_proposal = handle_relay_proposal(receiver, proposal);
                // Respond with payjoin psbt within the time window the sender is willing to wait
                // this response would be returned as http response to the sender
                let (req, ctx) = payjoin_proposal.extract_v2_req().unwrap();
                let response = spawn_blocking(move || {
                    http_agent().post(req.url.as_str()).send_bytes(&req.body)
                })
                .await??;
                let mut res = Vec::new();
                response.into_reader().read_to_end(&mut res)?;
                let _response = payjoin_proposal.deserialize_res(res, ctx).unwrap();
                debug!("Post payjoin_psbt to relay");
                // assert!(_response.status() == 204);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });

            // **********************
            // send fallback v1 to online receiver
            log::info!("send fallback v1 to online receiver should succeed");
            let response = {
                let Request { url, body, .. } = send_req.clone();
                spawn_blocking(move || {
                    http_agent()
                        .post(url.as_str())
                        .set("Content-Type", "text/plain")
                        .send_bytes(&body)
                        .expect("Failed to send request")
                })
                .await?
            };
            log::info!("Response: {:#?}", &response);
            assert!(is_success(response.status()));

            let checked_payjoin_proposal_psbt =
                send_ctx.process_response(&mut response.into_reader())?;
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;
            log::info!("sent");
            assert!(receiver_loop.await.is_ok(), "The spawned task panicked or returned an error");
            relay.kill().await?;
            let output = &relay.wait_with_output().await?;
            log::info!("Status: {}", output.status);
            Ok(())
        }

        async fn init_relay<'a>(docker: &'a Cli) -> (Child, Container<'a, Postgres>) {
            println!("Initializing relay server");
            env::set_var("PJ_RELAY_PORT", "8088");
            env::set_var("PJ_RELAY_TIMEOUT_SECS", "2");
            //env::set_var("PGPASSWORD", "welcome");
            let postgres = docker.run(Postgres::default());
            env::set_var("PJ_DB_HOST", format!("127.0.0.1:{}", postgres.get_host_port_ipv4(5432)));
            println!("Postgres running on {}", postgres.get_host_port_ipv4(5432));
            compile_payjoin_relay().await.wait().await.unwrap();
            let workspace_root = env::var("CARGO_MANIFEST_DIR").unwrap();
            let binary_path = format!("{}/../target/debug/payjoin-relay", workspace_root);
            let mut command = Command::new(binary_path);
            command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
            (command.spawn().unwrap(), postgres)
        }

        async fn compile_payjoin_relay() -> Child {
            // set payjoin relay target dir to payjoin-relay
            let mut command = Command::new("cargo");
            command.stdout(Stdio::inherit()).stderr(Stdio::inherit()).args([
                "build",
                "--package",
                "payjoin-relay",
                "--features",
                "danger-local-https",
            ]);
            command.spawn().unwrap()
        }

        fn handle_relay_proposal(
            receiver: bitcoincore_rpc::Client,
            proposal: UncheckedProposal,
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
            debug!("Receiver's Payjoin proposal PSBT: {:#?}", &payjoin_proposal.psbt());
            payjoin_proposal
        }

        fn http_agent() -> ureq::Agent {
            use rustls::client::ClientConfig;
            use rustls::{Certificate, RootCertStore};
            use ureq::AgentBuilder;

            let mut local_cert_path = std::env::temp_dir();
            local_cert_path.push(LOCAL_CERT_FILE);
            println!("TEST CERT PATH {:?}", &local_cert_path);
            let cert_der = std::fs::read(local_cert_path).unwrap();
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.add(&Certificate(cert_der)).unwrap();
            let client_config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();

            AgentBuilder::new().tls_config(Arc::new(client_config)).build()
        }
    }

    fn init_bitcoind_sender_receiver(
    ) -> Result<(bitcoind::BitcoinD, bitcoincore_rpc::Client, bitcoincore_rpc::Client), BoxError>
    {
        let bitcoind_exe =
            env::var("BITCOIND_EXE").ok().or_else(|| bitcoind::downloaded_exe_path().ok()).unwrap();
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
        pj_uri: &PayjoinUri<'_, NetworkChecked>,
    ) -> Result<Psbt, BoxError> {
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(pj_uri.inner.address.to_string(), pj_uri.inner.amount.unwrap());
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

    fn is_success(status: u16) -> bool { status >= 200 && status < 300 }
}

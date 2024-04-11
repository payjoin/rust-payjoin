#[cfg(feature = "danger-local-https")]
#[cfg(feature = "v2")]
mod v2 {
    use std::collections::HashMap;
    use std::env;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use bitcoin::address::NetworkChecked;
    use bitcoin::psbt::Psbt;
    use bitcoin::{base64, Amount, FeeRate, OutPoint};
    use bitcoind::bitcoincore_rpc::core_rpc_json::{AddressType, WalletProcessPsbtResult};
    use bitcoind::bitcoincore_rpc::{self, RpcApi};
    use log::{log_enabled, Level};
    use once_cell::sync::{Lazy, OnceCell};
    use payjoin::receive::v2::{Enrolled, Enroller, PayjoinProposal, UncheckedProposal};
    use payjoin::send::RequestBuilder;
    use payjoin::{OhttpKeys, PjUriBuilder, Request, Uri};
    use testcontainers_modules::redis::Redis;
    use testcontainers_modules::testcontainers::clients::Cli;
    use tokio::task::spawn_blocking;
    use tracing_subscriber::{EnvFilter, FmtSubscriber};
    use ureq::{Agent, AgentBuilder, Error, Response};
    use url::Url;

    static TESTS_TIMEOUT: Lazy<Duration> = Lazy::new(|| Duration::from_secs(20));
    static WAIT_SERVICE_INTERVAL: Lazy<Duration> = Lazy::new(|| Duration::from_secs(3));
    static INIT_TRACING: OnceCell<()> = OnceCell::new();

    type BoxError = Box<dyn std::error::Error + 'static>;

    #[tokio::test]
    async fn test_bad_ohttp_keys() {
        let bad_ohttp_keys = OhttpKeys::decode(
            &base64::decode_config(
                "AQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM",
                base64::URL_SAFE,
            )
            .expect("invalid base64"),
        )
        .expect("Invalid OhttpKeys");

        std::env::set_var("RUST_LOG", "debug");
        let (cert, key) = local_cert_key();
        let port = find_free_port();
        let directory = Url::parse(&format!("https://localhost:{}", port)).unwrap();
        tokio::select!(
          _ = init_directory(port, (cert.clone(), key)) => assert!(false, "Directory server is long running"),
          res = enroll_with_bad_keys(directory, bad_ohttp_keys, cert) => {
            assert_eq!(
              res.unwrap_err().into_response().unwrap().content_type(),
              "application/problem+json"
            );
          }
        );

        async fn enroll_with_bad_keys(
            directory: Url,
            bad_ohttp_keys: OhttpKeys,
            cert_der: Vec<u8>,
        ) -> Result<Response, Error> {
            let agent = Arc::new(http_agent(cert_der.clone()).unwrap());
            wait_for_service_ready(directory.clone(), agent.clone()).await.unwrap();
            let mock_ohttp_relay = directory.clone(); // pass through to directory
            let mut bad_enroller =
                Enroller::from_directory_config(directory, bad_ohttp_keys, mock_ohttp_relay);
            let (req, _ctx) = bad_enroller.extract_req().expect("Failed to extract request");
            spawn_blocking(move || agent.post(req.url.as_str()).send_bytes(&req.body))
                .await
                .expect("Failed to send request")
        }
    }

    #[tokio::test]
    async fn v2_to_v2() {
        std::env::set_var("RUST_LOG", "debug");
        init_tracing();
        let (cert, key) = local_cert_key();
        let ohttp_relay_port = find_free_port();
        let ohttp_relay = Url::parse(&format!("http://localhost:{}", ohttp_relay_port)).unwrap();
        let directory_port = find_free_port();
        let directory = Url::parse(&format!("https://localhost:{}", directory_port)).unwrap();
        let gateway_origin = http::Uri::from_str(directory.as_str()).unwrap();
        tokio::select!(
          _ = ohttp_relay::listen_tcp(ohttp_relay_port, gateway_origin) => assert!(false, "Ohttp relay is long running"),
          _ = init_directory(directory_port, (cert.clone(), key)) => assert!(false, "Directory server is long running"),
          res = do_v2_send_receive(ohttp_relay, directory, cert) => assert!(res.is_ok())
        );

        async fn do_v2_send_receive(
            ohttp_relay: Url,
            directory: Url,
            cert_der: Vec<u8>,
        ) -> Result<(), BoxError> {
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver()?;
            let agent = Arc::new(http_agent(cert_der.clone())?);
            wait_for_service_ready(ohttp_relay.clone(), agent.clone()).await.unwrap();
            wait_for_service_ready(directory.clone(), agent.clone()).await.unwrap();
            let ohttp_keys =
                fetch_ohttp_keys(ohttp_relay, directory.clone(), cert_der.clone()).await?;

            // **********************
            // Inside the Receiver:
            let mut enrolled =
                enroll_with_directory(directory.clone(), ohttp_keys.clone(), cert_der).await?;
            println!("enrolled: {:#?}", &enrolled);
            let pj_uri_string =
                create_receiver_pj_uri_string(&receiver, ohttp_keys, &enrolled.fallback_target())?;

            // **********************
            // Inside the Sender:
            // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let pj_uri = Uri::from_str(&pj_uri_string).unwrap().assume_checked();
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            // debug!("Original psbt: {:#?}", psbt);
            let (send_req, send_ctx) = RequestBuilder::from_psbt_and_uri(psbt, pj_uri)?
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .extract_v2(directory.to_owned())?; // Mock since we're not
                                                    // log::info!("send fallback v2");
                                                    // log::debug!("Request: {:#?}", &send_req.body);
            let response = {
                let Request { url, body, .. } = send_req.clone();
                let agent_clone = agent.clone();
                spawn_blocking(move || {
                    agent_clone
                        .post(url.as_str())
                        .set("Content-Type", payjoin::V1_REQ_CONTENT_TYPE)
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
            let agent_clone = agent.clone();
            let response =
                spawn_blocking(move || agent_clone.post(req.url.as_str()).send_bytes(&req.body))
                    .await??;

            // POST payjoin
            let proposal = enrolled.process_res(response.into_reader(), ctx)?.unwrap();
            let mut payjoin_proposal = handle_directory_proposal(receiver, proposal);
            let (req, ctx) = payjoin_proposal.extract_v2_req()?;
            let agent_clone = agent.clone();
            let response =
                spawn_blocking(move || agent_clone.post(req.url.as_str()).send_bytes(&req.body))
                    .await??;
            let mut res = Vec::new();
            response.into_reader().read_to_end(&mut res)?;
            let _response = payjoin_proposal.deserialize_res(res, ctx)?;
            // response should be 204 http

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts

            // Replay post fallback to get the response
            let agent_clone = agent.clone();
            let response = spawn_blocking(move || {
                agent_clone.post(send_req.url.as_str()).send_bytes(&send_req.body)
            })
            .await??;
            let checked_payjoin_proposal_psbt =
                send_ctx.process_response(&mut response.into_reader())?.unwrap();
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;
            log::info!("sent");
            Ok(())
        }
    }

    #[tokio::test]
    #[cfg(feature = "v2")]
    async fn v1_to_v2() {
        std::env::set_var("RUST_LOG", "debug");
        init_tracing();
        let (cert, key) = local_cert_key();
        let ohttp_relay_port = find_free_port();
        let ohttp_relay = Url::parse(&format!("http://localhost:{}", ohttp_relay_port)).unwrap();
        let directory_port = find_free_port();
        let directory = Url::parse(&format!("https://localhost:{}", directory_port)).unwrap();
        let gateway_origin = http::Uri::from_str(directory.as_str()).unwrap();
        tokio::select!(
          _ = ohttp_relay::listen_tcp(ohttp_relay_port, gateway_origin) => assert!(false, "Ohttp relay is long running"),
          _ = init_directory(directory_port, (cert.clone(), key)) => assert!(false, "Directory server is long running"),
          res = do_v1_to_v2(ohttp_relay, directory, cert) => assert!(res.is_ok()),
        );

        async fn do_v1_to_v2(
            ohttp_relay: Url,
            directory: Url,
            cert_der: Vec<u8>,
        ) -> Result<(), BoxError> {
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver()?;
            let agent: Arc<Agent> = Arc::new(http_agent(cert_der.clone())?);
            wait_for_service_ready(ohttp_relay.clone(), agent.clone()).await.unwrap();
            wait_for_service_ready(directory.clone(), agent.clone()).await.unwrap();
            let ohttp_keys =
                fetch_ohttp_keys(ohttp_relay, directory.clone(), cert_der.clone()).await?;

            let mut enrolled =
                enroll_with_directory(directory, ohttp_keys.clone(), cert_der.clone()).await?;

            let pj_uri_string =
                create_receiver_pj_uri_string(&receiver, ohttp_keys, &enrolled.fallback_target())?;

            // **********************
            // Inside the V1 Sender:
            // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let pj_uri = Uri::from_str(&pj_uri_string).unwrap().assume_checked();
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            // debug!("Original psbt: {:#?}", psbt);
            let (send_req, send_ctx) = RequestBuilder::from_psbt_and_uri(psbt, pj_uri)?
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .extract_v1()?;
            log::info!("send fallback v1 to offline receiver fail");
            let res = {
                let Request { url, body, .. } = send_req.clone();
                let agent_clone = agent.clone();
                spawn_blocking(move || {
                    agent_clone
                        .post(url.as_str())
                        .set("Content-Type", payjoin::V1_REQ_CONTENT_TYPE)
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
            let agent_clone = agent.clone();
            let receiver_loop = tokio::task::spawn(async move {
                let (response, ctx) = loop {
                    let (req, ctx) = enrolled.extract_req().unwrap();
                    let agent_clone = agent_clone.clone();
                    let response = spawn_blocking(move || {
                        agent_clone.post(req.url.as_str()).send_bytes(&req.body)
                    })
                    .await??;

                    if response.status() == 200 {
                        // debug!("GET'd fallback_psbt");
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
                // debug!("handle directory response");
                let proposal = enrolled.process_res(response, ctx).unwrap().unwrap();
                let mut payjoin_proposal = handle_directory_proposal(receiver, proposal);
                // Respond with payjoin psbt within the time window the sender is willing to wait
                // this response would be returned as http response to the sender
                let (req, ctx) = payjoin_proposal.extract_v2_req().unwrap();
                let response = spawn_blocking(move || {
                    agent_clone.post(req.url.as_str()).send_bytes(&req.body)
                })
                .await??;
                let mut res = Vec::new();
                response.into_reader().read_to_end(&mut res)?;
                let _response = payjoin_proposal.deserialize_res(res, ctx).unwrap();
                // debug!("Post payjoin_psbt to directory");
                // assert!(_response.status() == 204);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });

            // **********************
            // send fallback v1 to online receiver
            log::info!("send fallback v1 to online receiver should succeed");
            let response = {
                let Request { url, body, .. } = send_req.clone();
                let agent_clone = agent.clone();
                spawn_blocking(move || {
                    agent_clone
                        .post(url.as_str())
                        .set("Content-Type", payjoin::V1_REQ_CONTENT_TYPE)
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
            Ok(())
        }
    }

    async fn init_directory(port: u16, local_cert_key: (Vec<u8>, Vec<u8>)) -> Result<(), BoxError> {
        let docker: Cli = Cli::default();
        let timeout = Duration::from_secs(2);
        let db = docker.run(Redis::default());
        let db_host = format!("127.0.0.1:{}", db.get_host_port_ipv4(6379));
        println!("Database running on {}", db.get_host_port_ipv4(6379));
        payjoin_directory::listen_tcp_with_tls(port, db_host, timeout, local_cert_key).await
    }

    // generates or gets a DER encoded localhost cert and key.
    fn local_cert_key() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec![
            "0.0.0.0".to_string(),
            "localhost".to_string(),
        ])
        .expect("Failed to generate cert");
        let cert_der = cert.serialize_der().expect("Failed to serialize cert");
        let key_der = cert.serialize_private_key_der();
        (cert_der, key_der)
    }

    async fn fetch_ohttp_keys(
        ohttp_relay: Url,
        directory: Url,
        cert_der: Vec<u8>,
    ) -> Result<payjoin::OhttpKeys, BoxError> {
        let res = tokio::task::spawn_blocking(move || {
            payjoin_defaults::fetch_ohttp_keys(ohttp_relay.clone(), directory.clone(), cert_der)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
        Ok(res)
    }

    async fn enroll_with_directory(
        directory: Url,
        ohttp_keys: OhttpKeys,
        cert_der: Vec<u8>,
    ) -> Result<Enrolled, BoxError> {
        let mock_ohttp_relay = directory.clone(); // pass through to directory
        let mut enroller = Enroller::from_directory_config(
            directory.clone(),
            ohttp_keys,
            mock_ohttp_relay.clone(),
        );
        let (req, ctx) = enroller.extract_req()?;
        println!("enroll req: {:#?}", &req);
        let res = spawn_blocking(move || {
            http_agent(cert_der).unwrap().post(req.url.as_str()).send_bytes(&req.body)
        })
        .await??;
        assert!(is_success(res.status()));
        Ok(enroller.process_res(res.into_reader(), ctx)?)
    }

    /// The receiver outputs a string to be passed to the sender as a string or QR code
    fn create_receiver_pj_uri_string(
        receiver: &bitcoincore_rpc::Client,
        ohttp_keys: OhttpKeys,
        fallback_target: &str,
    ) -> Result<String, BoxError> {
        let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
        Ok(PjUriBuilder::new(
            pj_receiver_address,
            Url::parse(&fallback_target).unwrap(),
            Some(ohttp_keys),
        )
        .amount(Amount::ONE_BTC)
        .build()
        .to_string())
    }

    fn handle_directory_proposal(
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
        // debug!("Receiver's Payjoin proposal PSBT: {:#?}", &payjoin_proposal.psbt());
        payjoin_proposal
    }

    fn http_agent(cert_der: Vec<u8>) -> Result<Agent, BoxError> {
        Ok(http_agent_builder(cert_der)?.build())
    }

    fn http_agent_builder(cert_der: Vec<u8>) -> Result<AgentBuilder, BoxError> {
        use rustls::client::ClientConfig;
        use rustls::pki_types::CertificateDer;
        use rustls::RootCertStore;

        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.add(CertificateDer::from(cert_der.as_slice()))?;
        let client_config =
            ClientConfig::builder().with_root_certificates(root_cert_store).with_no_client_auth();

        Ok(AgentBuilder::new().tls_config(Arc::new(client_config)))
    }

    fn is_success(status: u16) -> bool { status >= 200 && status < 300 }

    fn find_free_port() -> u16 {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn wait_for_service_ready(
        service_url: Url,
        agent: Arc<Agent>,
    ) -> Result<(), &'static str> {
        let health_url = service_url.join("/health").map_err(|_| "Invalid URL")?;
        let res = spawn_blocking(move || {
            let start = std::time::Instant::now();

            while start.elapsed() < *TESTS_TIMEOUT {
                let request_result = agent.get(health_url.as_str()).call();

                match request_result {
                    Ok(response) if response.status() == 200 => return Ok(()),
                    Err(Error::Status(404, _)) => return Err("Endpoint not found"),
                    _ => std::thread::sleep(*WAIT_SERVICE_INTERVAL),
                }
            }

            Err("Timeout waiting for service to be ready")
        })
        .await
        .map_err(|_| "JoinError")?;
        res
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
        pj_uri: &Uri<'_, NetworkChecked>,
    ) -> Result<Psbt, BoxError> {
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(pj_uri.address.to_string(), pj_uri.amount.unwrap());
        // debug!("outputs: {:?}", outputs);
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
        let payjoin_base64_string = bitcoin::base64::encode(&psbt.serialize());
        let payjoin_psbt =
            sender.wallet_process_psbt(&payjoin_base64_string, None, None, None)?.psbt;
        let payjoin_psbt = sender.finalize_psbt(&payjoin_psbt, Some(false))?.psbt.unwrap();
        let payjoin_psbt = Psbt::from_str(&payjoin_psbt)?;
        // debug!("Sender's Payjoin PSBT: {:#?}", payjoin_psbt);

        Ok(payjoin_psbt.extract_tx())
    }
}

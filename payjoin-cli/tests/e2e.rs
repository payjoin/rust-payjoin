#[cfg(feature = "danger-local-https")]
mod e2e {
    use std::env;
    use std::process::Stdio;

    use bitcoincore_rpc::json::AddressType;
    use bitcoind::bitcoincore_rpc::RpcApi;
    use log::{log_enabled, Level};
    use payjoin::bitcoin::Amount;
    use tokio::fs;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;

    const RECEIVE_SATS: &str = "54321";

    #[cfg(not(feature = "v2"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin() {
        let bitcoind_exe = env::var("BITCOIND_EXE")
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

        let temp_dir = env::temp_dir();
        let receiver_db_path = temp_dir.join("receiver_db");
        let sender_db_path = temp_dir.join("sender_db");
        let receiver_db_path_clone = receiver_db_path.clone();
        let sender_db_path_clone = sender_db_path.clone();

        let payjoin_sent = tokio::spawn(async move {
            let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
            let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
            let cookie_file = &bitcoind.params.cookie_file;
            let port = find_free_port();
            let pj_endpoint = format!("https://localhost:{}", port);
            let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");

            let mut cli_receiver = Command::new(payjoin_cli)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(&cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path_clone)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .arg("--port")
                .arg(&port.to_string())
                .arg("--pj-endpoint")
                .arg(&pj_endpoint)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");

            let stdout =
                cli_receiver.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let mut stdout = tokio::io::stdout();
            let mut bip21 = String::new();

            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout")
            {
                // Write to stdout regardless
                stdout
                    .write_all(format!("{}\n", line).as_bytes())
                    .await
                    .expect("Failed to write to stdout");

                if line.to_ascii_uppercase().starts_with("BITCOIN") {
                    bip21 = line;
                    break;
                }
            }
            log::debug!("Got bip21 {}", &bip21);

            let mut cli_sender = Command::new(payjoin_cli)
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(&cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path_clone)
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");

            let stdout = cli_sender.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);

            let mut lines = reader.lines();
            tokio::spawn(async move {
                let mut stdout = tokio::io::stdout();
                while let Some(line) =
                    lines.next_line().await.expect("Failed to read line from stdout")
                {
                    stdout
                        .write_all(format!("{}\n", line).as_bytes())
                        .await
                        .expect("Failed to write to stdout");
                    if line.contains("Payjoin sent") {
                        let _ = tx.send(true).await;
                        break;
                    }
                }
            });

            let timeout = tokio::time::Duration::from_secs(10);
            let payjoin_sent = tokio::time::timeout(timeout, rx.recv()).await;

            cli_receiver.kill().await.expect("Failed to kill payjoin-cli");
            cli_sender.kill().await.expect("Failed to kill payjoin-cli");
            payjoin_sent
        })
        .await;

        cleanup_temp_file(&receiver_db_path).await;
        cleanup_temp_file(&sender_db_path).await;
        assert!(
            payjoin_sent.unwrap().unwrap_or(Some(false)).unwrap(),
            "Payjoin send was not detected"
        );
    }

    #[cfg(feature = "v2")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin() {
        use std::path::PathBuf;
        use std::str::FromStr;
        use std::sync::Arc;
        use std::time::Duration;

        use http::StatusCode;
        use once_cell::sync::{Lazy, OnceCell};
        use reqwest::{Client, ClientBuilder};
        use testcontainers::clients::Cli;
        use testcontainers_modules::redis::Redis;
        use tokio::process::Child;
        use url::Url;

        type Error = Box<dyn std::error::Error + 'static>;
        type Result<T> = std::result::Result<T, Error>;

        static INIT_TRACING: OnceCell<()> = OnceCell::new();
        static TESTS_TIMEOUT: Lazy<Duration> = Lazy::new(|| Duration::from_secs(20));
        static WAIT_SERVICE_INTERVAL: Lazy<Duration> = Lazy::new(|| Duration::from_secs(3));

        init_tracing();
        let (cert, key) = local_cert_key();
        let ohttp_relay_port = find_free_port();
        let ohttp_relay = Url::parse(&format!("http://localhost:{}", ohttp_relay_port)).unwrap();
        let directory_port = find_free_port();
        let directory = Url::parse(&format!("https://localhost:{}", directory_port)).unwrap();
        let gateway_origin = http::Uri::from_str(directory.as_str()).unwrap();

        let temp_dir = env::temp_dir();
        let receiver_db_path = temp_dir.join("receiver_db");
        let sender_db_path = temp_dir.join("sender_db");
        let result: Result<()> = tokio::select! {
            res = ohttp_relay::listen_tcp(ohttp_relay_port, gateway_origin) => Err(format!("Ohttp relay is long running: {:?}", res).into()),
            res = init_directory(directory_port, (cert.clone(), key)) => Err(format!("Directory server is long running: {:?}", res).into()),
            res = send_receive_cli_async(ohttp_relay, directory, cert, receiver_db_path.clone(), sender_db_path.clone()) => res.map_err(|e| format!("send_receive failed: {:?}", e).into()),
        };

        cleanup_temp_file(&receiver_db_path).await;
        cleanup_temp_file(&sender_db_path).await;
        assert!(result.is_ok(), "{}", result.unwrap_err());

        async fn send_receive_cli_async(
            ohttp_relay: Url,
            directory: Url,
            cert: Vec<u8>,
            receiver_db_path: PathBuf,
            sender_db_path: PathBuf,
        ) -> Result<()> {
            let bitcoind_exe = env::var("BITCOIND_EXE")
                .ok()
                .or_else(|| bitcoind::downloaded_exe_path().ok())
                .expect("version feature or env BITCOIND_EXE is required for tests");
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
            let temp_dir = env::temp_dir();
            let cert_path = temp_dir.join("localhost.der");
            tokio::fs::write(&cert_path, cert.clone()).await?;
            let agent = Arc::new(http_agent(cert.clone()).unwrap());
            wait_for_service_ready(ohttp_relay.clone(), agent.clone()).await?;
            wait_for_service_ready(directory.clone(), agent).await?;

            // fetch for setup here since ohttp_relay doesn't know the certificate for the directory
            // so payjoin-cli is set up with the mock_ohttp_relay which is the directory
            let ohttp_keys =
                payjoin::io::fetch_ohttp_keys(ohttp_relay.clone(), directory.clone(), cert.clone())
                    .await?;
            let ohttp_keys_path = temp_dir.join("ohttp_keys");
            tokio::fs::write(&ohttp_keys_path, ohttp_keys.encode()?).await?;

            let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
            let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
            let cookie_file = &bitcoind.params.cookie_file;

            let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");

            let directory = directory.as_str();
            // Mock ohttp_relay since the ohttp_relay's http client doesn't have the certificate for the directory
            let mock_ohttp_relay = directory;

            let cli_receive_initiator = Command::new(payjoin_cli)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(&cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relay")
                .arg(&mock_ohttp_relay)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .arg("--pj-directory")
                .arg(&directory)
                .arg("--ohttp-keys")
                .arg(&ohttp_keys_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            let bip21 = get_bip21_from_receiver(cli_receive_initiator).await;
            let cli_send_initiator = Command::new(payjoin_cli)
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(&cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relay")
                .arg(&mock_ohttp_relay)
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            let _ = send_until_request_timeout(cli_send_initiator).await;

            let cli_receive_resumer = Command::new(payjoin_cli)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(&cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relay")
                .arg(&mock_ohttp_relay)
                .arg("resume")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            let _ = respond_with_payjoin(cli_receive_resumer).await;

            let cli_send_resumer = Command::new(payjoin_cli)
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(&cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relay")
                .arg(&mock_ohttp_relay)
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            let _ = check_payjoin_sent(cli_send_resumer).await;
            Ok(())
        }

        async fn get_bip21_from_receiver(mut cli_receiver: Child) -> String {
            let stdout =
                cli_receiver.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let mut stdout = tokio::io::stdout();
            let mut bip21 = String::new();

            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout")
            {
                // Write to stdout regardless
                stdout
                    .write_all(format!("{}\n", line).as_bytes())
                    .await
                    .expect("Failed to write to stdout");

                if line.to_ascii_uppercase().starts_with("BITCOIN") {
                    bip21 = line;
                    break;
                }
            }
            log::debug!("Got bip21 {}", &bip21);

            cli_receiver.kill().await.expect("Failed to kill payjoin-cli");
            bip21
        }

        async fn send_until_request_timeout(mut cli_sender: Child) -> Result<()> {
            let stdout = cli_sender.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);

            let mut lines = reader.lines();
            tokio::spawn(async move {
                let mut stdout = tokio::io::stdout();
                while let Some(line) =
                    lines.next_line().await.expect("Failed to read line from stdout")
                {
                    stdout
                        .write_all(format!("{}\n", line).as_bytes())
                        .await
                        .expect("Failed to write to stdout");
                    if line.contains("No response yet.") {
                        let _ = tx.send(true).await;
                        break;
                    }
                }
            });

            let timeout = tokio::time::Duration::from_secs(35);
            let fallback_sent = tokio::time::timeout(timeout, rx.recv()).await?;

            cli_sender.kill().await.expect("Failed to kill payjoin-cli initial sender");

            assert!(fallback_sent.unwrap_or(false), "Fallback send was not detected");
            Ok(())
        }

        async fn respond_with_payjoin(mut cli_receive_resumer: Child) -> Result<()> {
            let stdout =
                cli_receive_resumer.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);

            let mut lines = reader.lines();
            tokio::spawn(async move {
                let mut stdout = tokio::io::stdout();
                while let Some(line) =
                    lines.next_line().await.expect("Failed to read line from stdout")
                {
                    stdout
                        .write_all(format!("{}\n", line).as_bytes())
                        .await
                        .expect("Failed to write to stdout");
                    if line.contains("Response successful") {
                        let _ = tx.send(true).await;
                        break;
                    }
                }
            });

            let timeout = tokio::time::Duration::from_secs(10);
            let response_successful = tokio::time::timeout(timeout, rx.recv()).await?;

            cli_receive_resumer.kill().await.expect("Failed to kill payjoin-cli");

            assert!(response_successful.unwrap_or(false), "Did not respond with Payjoin PSBT");
            Ok(())
        }

        async fn check_payjoin_sent(mut cli_send_resumer: Child) -> Result<()> {
            let stdout =
                cli_send_resumer.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);

            let mut lines = reader.lines();
            tokio::spawn(async move {
                let mut stdout = tokio::io::stdout();
                while let Some(line) =
                    lines.next_line().await.expect("Failed to read line from stdout")
                {
                    stdout
                        .write_all(format!("{}\n", line).as_bytes())
                        .await
                        .expect("Failed to write to stdout");
                    if line.contains("Payjoin sent") {
                        let _ = tx.send(true).await;
                        break;
                    }
                }
            });

            let timeout = tokio::time::Duration::from_secs(10);
            let payjoin_sent = tokio::time::timeout(timeout, rx.recv()).await?;

            cli_send_resumer.kill().await.expect("Failed to kill payjoin-cli");

            assert!(payjoin_sent.unwrap_or(false), "Payjoin send was not detected");
            Ok(())
        }

        async fn wait_for_service_ready(service_url: Url, agent: Arc<Client>) -> Result<()> {
            let health_url = service_url.join("/health").map_err(|_| "Invalid URL")?;
            let start = std::time::Instant::now();

            while start.elapsed() < *TESTS_TIMEOUT {
                let request_result =
                    agent.get(health_url.as_str()).send().await.map_err(|_| "Bad request")?;

                match request_result.status() {
                    StatusCode::OK => {
                        println!("READY {}", service_url);
                        return Ok(());
                    }
                    StatusCode::NOT_FOUND => return Err("Endpoint not found".into()),
                    _ => std::thread::sleep(*WAIT_SERVICE_INTERVAL),
                }
            }

            Err("Timeout waiting for service to be ready".into())
        }

        async fn init_directory(port: u16, local_cert_key: (Vec<u8>, Vec<u8>)) -> Result<()> {
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

        fn http_agent(cert_der: Vec<u8>) -> Result<Client> {
            Ok(http_agent_builder(cert_der)?.build()?)
        }

        fn http_agent_builder(cert_der: Vec<u8>) -> Result<ClientBuilder> {
            Ok(ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .use_rustls_tls()
                .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der.as_slice())?))
        }

        fn init_tracing() {
            INIT_TRACING.get_or_init(|| {
                let subscriber = tracing_subscriber::FmtSubscriber::builder()
                    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                    .with_test_writer()
                    .finish();

                tracing::subscriber::set_global_default(subscriber)
                    .expect("failed to set global default subscriber");
            });
        }
    }

    fn find_free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn cleanup_temp_file(path: &std::path::Path) {
        if let Err(e) = fs::remove_dir_all(path).await {
            eprintln!("Failed to remove {:?}: {}", path, e);
        }
    }
}

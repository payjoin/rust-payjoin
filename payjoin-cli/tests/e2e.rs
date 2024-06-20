#[cfg(feature = "danger-local-https")]
#[cfg(not(feature = "v2"))]
mod e2e {
    use std::env;
    use std::process::Stdio;

    use bitcoind::bitcoincore_rpc::core_rpc_json::AddressType;
    use bitcoind::bitcoincore_rpc::RpcApi;
    use log::{log_enabled, Level};
    use payjoin::bitcoin::Amount;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;

    const RECEIVE_SATS: &str = "54321";

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin() {
        env::set_var("RUST_LOG", "debug");

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

        let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
        let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
        let temp_dir = env::temp_dir();
        let receiver_db_path = temp_dir.join("receiver_db");
        let sender_db_path = temp_dir.join("sender_db");
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
            .arg(&receiver_db_path)
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

        let stdout = cli_receiver.stdout.take().expect("Failed to take stdout of child process");
        let reader = BufReader::new(stdout);
        let mut stdout = tokio::io::stdout();
        let mut bip21 = String::new();

        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout") {
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
            .arg(&sender_db_path)
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
            while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout")
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

        assert!(payjoin_sent.unwrap_or(Some(false)).unwrap(), "Payjoin send was not detected");
    }

    fn find_free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }
}

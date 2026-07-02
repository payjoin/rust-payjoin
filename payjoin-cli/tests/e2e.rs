#[cfg(feature = "_manual-tls")]
mod e2e {
    use std::process::{ExitStatus, Stdio};
    use std::str::FromStr;

    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    use payjoin::bitcoin::Txid;
    use payjoin_test_utils::{init_bitcoind_sender_receiver, BoxError};
    use tempfile::tempdir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::{Child, Command};

    async fn terminate(mut child: tokio::process::Child) -> tokio::io::Result<ExitStatus> {
        let pid = child.id().expect("Failed to get child PID");
        kill(Pid::from_raw(pid as i32), Signal::SIGINT)?;
        // wait for child process to exit completely
        child.wait().await
    }

    const RECEIVE_SATS: &str = "54321";

    /// Helper function to extract BIP21 URI from receiver stdout
    async fn get_bip21_from_receiver(mut cli_receiver: tokio::process::Child) -> String {
        let mut stdout =
            cli_receiver.stdout.take().expect("failed to take stdout of child process");
        let bip21 = wait_for_stdout_match(&mut stdout, |line| {
            line.to_ascii_uppercase().starts_with("BITCOIN")
        })
        .await
        .expect("payjoin-cli receiver should output a bitcoin URI");
        tracing::debug!("Got bip21 {}", &bip21);

        terminate(cli_receiver).await.expect("Failed to kill payjoin-cli");
        bip21
    }

    /// Read lines from `child_stdout` until `match_pattern` is found and the corresponding
    /// line is returned.
    /// Also writes every read line to tokio::io::stdout();
    async fn wait_for_stdout_match<F>(
        child_stdout: &mut tokio::process::ChildStdout,
        match_pattern: F,
    ) -> Option<String>
    where
        F: Fn(&str) -> bool,
    {
        let reader = BufReader::new(child_stdout);
        let mut lines = reader.lines();
        let mut res = None;

        let mut stdout = tokio::io::stdout();
        while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout") {
            // Write all output to tests stdout
            stdout
                .write_all(format!("{line}\n").as_bytes())
                .await
                .expect("Failed to write to stdout");

            if match_pattern(&line) {
                res = Some(line);
                break;
            }
        }

        res
    }

    /// Read all lines from `child_stdout` until EOF and return them joined by newlines.
    /// Also writes every read line to tokio::io::stdout();
    async fn read_all_stdout(child_stdout: &mut tokio::process::ChildStdout) -> String {
        let reader = BufReader::new(child_stdout);
        let mut lines = reader.lines();
        let mut out = String::new();

        let mut stdout = tokio::io::stdout();
        while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout") {
            stdout
                .write_all(format!("{line}\n").as_bytes())
                .await
                .expect("Failed to write to stdout");
            out.push_str(&line);
            out.push('\n');
        }

        out
    }

    async fn send_until_request_timeout(mut cli_sender: Child) -> Result<(), BoxError> {
        let mut stdout = cli_sender.stdout.take().expect("failed to take stdout of child process");
        let timeout = tokio::time::Duration::from_secs(35);
        let res = tokio::time::timeout(
            timeout,
            wait_for_stdout_match(&mut stdout, |line| line.contains("No response yet.")),
        )
        .await?;

        terminate(cli_sender).await.expect("Failed to kill payjoin-cli initial sender");
        assert!(res.is_some(), "Fallback send was not detected");
        Ok(())
    }

    #[cfg(feature = "v1")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin_v1() -> Result<(), BoxError> {
        use payjoin_test_utils::local_cert_key;

        let (bitcoind, _sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;
        let temp_dir = tempdir()?;
        let receiver_db_path = temp_dir.path().join("receiver_db");
        let sender_db_path = temp_dir.path().join("sender_db");

        let payjoin_sent = tokio::spawn(async move {
            let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
            let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
            let cookie_file = &bitcoind.params.cookie_file;
            let pj_endpoint = "https://localhost";
            let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");

            let cert = local_cert_key();
            let cert_path = &temp_dir.path().join("localhost.crt");
            tokio::fs::write(cert_path, cert.cert.der().to_vec())
                .await
                .expect("must be able to write self signed certificate");

            let key_path = &temp_dir.path().join("localhost.key");
            tokio::fs::write(key_path, cert.signing_key.serialize_der())
                .await
                .expect("must be able to write self signed certificate");

            let mut cli_receiver = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--certificate-key")
                .arg(key_path)
                .arg("--bip78")
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .arg("--port")
                .arg("0")
                .arg("--pj-endpoint")
                .arg(pj_endpoint)
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
                    .write_all(format!("{line}\n").as_bytes())
                    .await
                    .expect("Failed to write to stdout");

                if line.to_ascii_uppercase().starts_with("BITCOIN") {
                    bip21 = line;
                    break;
                }
            }
            tracing::debug!("Got bip21 {}", &bip21);

            let mut cli_sender = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--bip78")
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
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
                while let Some(line) =
                    lines.next_line().await.expect("Failed to read line from stdout")
                {
                    stdout
                        .write_all(format!("{line}\n").as_bytes())
                        .await
                        .expect("Failed to write to stdout");
                    if line.contains("Payjoin sent") {
                        let _ = tx.send(true).await;
                        break;
                    }
                }
            });

            let timeout = tokio::time::Duration::from_secs(10);
            let payjoin_sent = tokio::time::timeout(timeout, rx.recv())
                .await
                .unwrap_or(Some(false)) // timed out
                .expect("rx channel closed prematurely"); // recv() returned None

            terminate(cli_receiver).await.expect("Failed to kill payjoin-cli");
            terminate(cli_sender).await.expect("Failed to kill payjoin-cli");

            payjoin_sent
        })
        .await?;

        assert!(payjoin_sent, "Payjoin send was not detected");

        Ok(())
    }

    #[cfg(feature = "v2")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin_v2() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use payjoin_test_utils::{init_tracing, TestServices};
        use tempfile::TempDir;

        type Result<T> = std::result::Result<T, BoxError>;

        init_tracing();
        let mut services = TestServices::initialize_with_relays(3).await?;
        let temp_dir = tempdir()?;

        let result = tokio::select! {
            res = services.take_ohttp_relay_handle() => Err(format!("Ohttp relay is long running: {res:?}").into()),
            res = services.take_directory_handle() => Err(format!("Directory server is long running: {res:?}").into()),
            res = send_receive_cli_async(&services, &temp_dir) => res,
        };

        assert!(result.is_ok(), "send_receive failed: {:#?}", result.unwrap_err());

        async fn send_receive_cli_async(services: &TestServices, temp_dir: &TempDir) -> Result<()> {
            let receiver_db_path = temp_dir.path().join("receiver_db");
            let sender_db_path = temp_dir.path().join("sender_db");
            let (bitcoind, _sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;
            let cert_path = &temp_dir.path().join("localhost.der");
            tokio::fs::write(cert_path, services.cert()).await?;
            services.wait_for_services_ready().await?;
            let ohttp_keys = services.fetch_ohttp_keys().await?;
            let ohttp_keys_path = temp_dir.path().join("ohttp_keys");
            tokio::fs::write(&ohttp_keys_path, ohttp_keys.encode()?).await?;

            let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
            let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
            let cookie_file = &bitcoind.params.cookie_file;

            let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");

            let directory = &services.directory_url();
            let ohttp_relays = &services.ohttp_relay_urls();

            let cli_receive_initiator = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .arg("--pj-directories")
                .arg(directory)
                .arg("--ohttp-keys")
                .arg(&ohttp_keys_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            let bip21 = get_bip21_from_receiver(cli_receive_initiator).await;
            let cli_send_initiator = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("--pj-directory")
                .arg(directory)
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            send_until_request_timeout(cli_send_initiator).await?;

            let cli_receive_resumer = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("--pj-directory")
                .arg(directory)
                .arg("resume")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            respond_with_payjoin(cli_receive_resumer).await?;

            let cli_receive_resumer = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("--pj-directory")
                .arg(directory)
                .arg("resume")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            check_resume_not_completed(cli_receive_resumer).await?;

            let cli_send_resumer = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("--pj-directory")
                .arg(directory)
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            check_payjoin_sent(cli_send_resumer).await?;

            // Need to mine a block
            let funding_address = bitcoind
                .client
                .get_new_address(None, None)?
                .address()
                .expect("address should be valid")
                .assume_checked();
            bitcoind.client.generate_to_address(1, &funding_address)?;

            // Resume the receiver to ensure we monitor for the payjoin proposal
            let cli_receive_resumer = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("--pj-directory")
                .arg(directory)
                .arg("resume")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");

            check_resume_completed(cli_receive_resumer).await?;
            // Check that neither the sender or the receiver have sessions to resume
            let cli_receive_resumer = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("--pj-directory")
                .arg(directory)
                .arg("resume")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            check_resume_has_no_sessions(cli_receive_resumer).await?;
            let cli_send_resumer = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("--pj-directory")
                .arg(directory)
                .arg("resume")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli");
            check_resume_has_no_sessions(cli_send_resumer).await?;
            Ok(())
        }

        async fn respond_with_payjoin(mut cli_receive_resumer: Child) -> Result<()> {
            let mut stdout =
                cli_receive_resumer.stdout.take().expect("Failed to take stdout of child process");
            let timeout = tokio::time::Duration::from_secs(10);
            let res = tokio::time::timeout(
                timeout,
                wait_for_stdout_match(&mut stdout, |line| line.contains("Response successful")),
            )
            .await?;

            terminate(cli_receive_resumer).await.expect("Failed to kill payjoin-cli");
            assert!(res.is_some(), "Did not respond with Payjoin PSBT");
            Ok(())
        }

        async fn check_payjoin_sent(mut cli_send_resumer: Child) -> Result<()> {
            let mut stdout =
                cli_send_resumer.stdout.take().expect("Failed to take stdout of child process");
            let timeout = tokio::time::Duration::from_secs(10);
            let res = tokio::time::timeout(
                timeout,
                wait_for_stdout_match(&mut stdout, |line| line.contains("Payjoin sent")),
            )
            .await?;

            terminate(cli_send_resumer).await.expect("Failed to kill payjoin-cli");
            assert!(res.is_some(), "Payjoin send was not detected");
            Ok(())
        }

        async fn check_resume_has_no_sessions(mut cli_resumer: Child) -> Result<()> {
            let mut stdout =
                cli_resumer.stdout.take().expect("Failed to take stdout of child process");
            let timeout = tokio::time::Duration::from_secs(10);
            let res = tokio::time::timeout(
                timeout,
                wait_for_stdout_match(&mut stdout, |line| line.contains("No sessions to resume.")),
            )
            .await?;

            terminate(cli_resumer).await.expect("Failed to kill payjoin-cli");
            assert!(res.is_some(), "Expected no sessions to resume");
            Ok(())
        }

        async fn check_resume_completed(mut cli_resumer: Child) -> Result<()> {
            let mut stdout =
                cli_resumer.stdout.take().expect("Failed to take stdout of child process");
            let timeout = tokio::time::Duration::from_secs(10);
            let res = tokio::time::timeout(
                timeout,
                wait_for_stdout_match(&mut stdout, |line| {
                    line.starts_with("Session") && line.ends_with("completed.")
                }),
            )
            .await?;

            terminate(cli_resumer).await.expect("Failed to kill payjoin-cli");
            assert!(res.is_some(), "Expected all resumed sessions completed");
            Ok(())
        }

        async fn check_resume_not_completed(mut cli_resumer: Child) -> Result<()> {
            let mut stdout =
                cli_resumer.stdout.take().expect("Failed to take stdout of child process");
            let timeout = tokio::time::Duration::from_secs(10);
            let res = tokio::time::timeout(
                timeout,
                wait_for_stdout_match(&mut stdout, |line| {
                    line.starts_with("Session") && line.ends_with("completed.")
                }),
            )
            .await?;
            terminate(cli_resumer).await.expect("Failed to kill payjoin-cli");
            assert!(res.is_none(), "Expected resumed sessions not yet completed");
            Ok(())
        }
        Ok(())
    }

    #[cfg(all(feature = "v1", feature = "v2", feature = "_manual-tls"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_receive_payjoin_v2_to_v1() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        use payjoin_test_utils::{init_tracing, local_cert_key, TestServices};
        use tempfile::TempDir;

        type Result<T> = std::result::Result<T, BoxError>;

        init_tracing();
        let services = TestServices::initialize_with_relays(3).await?;
        let temp_dir = tempdir()?;

        let result = send_v2_receive_v1_async(&services, &temp_dir).await;
        assert!(result.is_ok(), "v2-to-v1 test failed: {:#?}", result.unwrap_err());

        async fn send_v2_receive_v1_async(
            services: &TestServices,
            temp_dir: &TempDir,
        ) -> Result<()> {
            let receiver_db_path = temp_dir.path().join("receiver_db");
            let sender_db_path = temp_dir.path().join("sender_db");
            let (bitcoind, _sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;

            // Set up certificates for v1 receiver (needs local HTTPS server)
            let cert = local_cert_key();
            let cert_path = &temp_dir.path().join("localhost.crt");
            tokio::fs::write(cert_path, cert.cert.der().to_vec())
                .await
                .expect("must be able to write self signed certificate");

            let key_path = &temp_dir.path().join("localhost.key");
            tokio::fs::write(key_path, cert.signing_key.serialize_der())
                .await
                .expect("must be able to write self signed certificate");

            // Set up v2 services certificates for v2 sender (even though it will fall back to v1)
            let v2_cert_path = &temp_dir.path().join("localhost.der");
            tokio::fs::write(v2_cert_path, services.cert()).await?;
            services.wait_for_services_ready().await?;

            let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
            let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
            let cookie_file = &bitcoind.params.cookie_file;

            let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");
            let pj_endpoint = "https://localhost";

            // Start v1 receiver with --bip78 flag and keep it running
            let mut cli_receive_v1 = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--certificate-key")
                .arg(key_path)
                .arg("--bip78") // Force BIP78 (v1) mode
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .arg("--port")
                .arg("0")
                .arg("--pj-endpoint")
                .arg(pj_endpoint)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli v1 receiver");

            // Extract BIP21 from receiver stdout without terminating the receiver
            let stdout =
                cli_receive_v1.stdout.take().expect("Failed to take stdout of child process");
            let reader = BufReader::new(stdout);
            let mut stdout_writer = tokio::io::stdout();
            let mut bip21 = String::new();
            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout")
            {
                // Write to stdout regardless
                stdout_writer
                    .write_all(format!("{line}\n").as_bytes())
                    .await
                    .expect("Failed to write to stdout");

                if line.to_ascii_uppercase().starts_with("BITCOIN") {
                    bip21 = line;
                    break;
                }
            }
            tracing::debug!("Got v1 bip21 from receiver: {}", &bip21);

            // Start v2 sender (default behavior without --bip78)
            // This will detect the v1 URI and automatically use v1 protocol
            let mut cli_send_v2 = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path) // Use same cert since v2 sender will fallback to v1 protocol
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relays")
                .arg(services.ohttp_relay_urls())
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli v2 sender");

            // Check that v2 sender successfully completes the v1 payjoin
            let sender_stdout =
                cli_send_v2.stdout.take().expect("Failed to take stdout of child process");
            let sender_reader = BufReader::new(sender_stdout);
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);

            let mut sender_lines = sender_reader.lines();
            tokio::spawn(async move {
                let mut stdout = tokio::io::stdout();
                while let Some(line) =
                    sender_lines.next_line().await.expect("Failed to read line from stdout")
                {
                    stdout
                        .write_all(format!("{line}\n").as_bytes())
                        .await
                        .expect("Failed to write to stdout");
                    if line.contains("Payjoin sent") {
                        let _ = tx.send(true).await;
                        break;
                    }
                }
            });

            let timeout = tokio::time::Duration::from_secs(30);
            let payjoin_sent = tokio::time::timeout(timeout, rx.recv())
                .await
                .unwrap_or(Some(false)) // timed out
                .expect("rx channel closed prematurely"); // recv() returned None

            // Clean up both processes
            terminate(cli_receive_v1).await.expect("Failed to kill payjoin-cli v1 receiver");
            terminate(cli_send_v2).await.expect("Failed to kill payjoin-cli v2 sender");

            assert!(payjoin_sent, "Expected payjoin completion or fallback transaction");

            Ok(())
        }

        Ok(())
    }

    #[cfg(feature = "v2")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sender_cancel_v2() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use payjoin_test_utils::{init_tracing, TestServices};
        use tempfile::TempDir;

        type Result<T> = std::result::Result<T, BoxError>;

        init_tracing();
        let mut services = TestServices::initialize_with_relays(3).await?;
        let temp_dir = tempdir()?;

        let result = tokio::select! {
            res = services.take_ohttp_relay_handle() => Err(format!("Ohttp relay is long running: {res:?}").into()),
            res = services.take_directory_handle() => Err(format!("Directory server is long running: {res:?}").into()),
            res = cancel_cli_async(&services, &temp_dir) => res,
        };

        assert!(result.is_ok(), "sender_cancel_v2 failed: {:#?}", result.unwrap_err());

        async fn cancel_cli_async(services: &TestServices, temp_dir: &TempDir) -> Result<()> {
            let sender_db_path = temp_dir.path().join("sender_db");
            let (bitcoind, sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;
            let cert_path = &temp_dir.path().join("localhost.der");
            tokio::fs::write(cert_path, services.cert()).await?;
            services.wait_for_services_ready().await?;
            let ohttp_keys = services.fetch_ohttp_keys().await?;
            let ohttp_keys_path = temp_dir.path().join("ohttp_keys");
            tokio::fs::write(&ohttp_keys_path, ohttp_keys.encode()?).await?;

            let receiver_db_path = temp_dir.path().join("receiver_db");
            let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
            let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
            let cookie_file = &bitcoind.params.cookie_file;
            let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");
            let directory = &services.directory_url();
            let ohttp_relays = &services.ohttp_relay_urls();

            // Get a BIP21 from a receiver then kill it so the sender can never complete payjoin
            let cli_receiver = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .arg("--pj-directories")
                .arg(directory)
                .arg("--ohttp-keys")
                .arg(&ohttp_keys_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli receiver");
            let bip21 = get_bip21_from_receiver(cli_receiver).await;

            // Start sender and let it time out waiting for a response
            let cli_sender = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("--pj-directory")
                .arg(directory)
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli sender");

            send_until_request_timeout(cli_sender).await?;

            // There is only one sender session in progress.
            let session_id = 1i64;

            // Run `payjoin-cli cancel <session-id>`: cancels and broadcasts the fallback tx
            let mut cli_cancel = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("cancel")
                .arg(session_id.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli cancel");

            let mut cancel_stdout =
                cli_cancel.stdout.take().expect("failed to take stdout of cancel");
            let timeout = tokio::time::Duration::from_secs(10);
            let broadcast_line = tokio::time::timeout(
                timeout,
                wait_for_stdout_match(&mut cancel_stdout, |l| {
                    l.contains("Broadcasted fallback transaction txid")
                }),
            )
            .await?;
            terminate(cli_cancel).await.expect("Failed to kill payjoin-cli cancel");
            let subcommand_output = broadcast_line.expect("cancel should broadcast fallback tx");
            let fallback_txid = subcommand_output.split_whitespace().nth(4).unwrap_or("");
            let fallback_txid = Txid::from_str(fallback_txid).expect("valid txid");

            assert!(
                sender.get_raw_transaction(fallback_txid).is_ok(),
                "fallback tx should be in the mempool after cancel"
            );

            // Re-run `cancel` on the now-closed session: the command must still
            // recognize the session exists and report it is already closed.
            let mut cli_cancel_again = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("cancel")
                .arg(session_id.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli cancel on closed session");

            let raw_tx = sender.get_transaction(fallback_txid)?.into_model()?.tx;
            let expected_hex = payjoin::bitcoin::consensus::encode::serialize_hex(&raw_tx);

            let mut cancel_again_stdout = cli_cancel_again
                .stdout
                .take()
                .expect("failed to take stdout of cancel on closed session");
            let cancel_again_output =
                tokio::time::timeout(timeout, read_all_stdout(&mut cancel_again_stdout)).await?;
            terminate(cli_cancel_again)
                .await
                .expect("Failed to kill payjoin-cli cancel on closed session");

            assert!(
                cancel_again_output
                    .contains(&format!("Session {session_id} was already cancelled")),
                "cancel on closed session should reference the session id and report it is already closed; got: {cancel_again_output}"
            );
            assert!(
                cancel_again_output.contains(&expected_hex),
                "cancel on closed session should print the fallback transaction consensus hex; got: {cancel_again_output}"
            );

            Ok(())
        }

        Ok(())
    }

    #[cfg(feature = "v2")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn receiver_cancel_v2() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use payjoin_test_utils::{init_tracing, TestServices};
        use tempfile::TempDir;

        type Result<T> = std::result::Result<T, BoxError>;

        init_tracing();
        let mut services = TestServices::initialize_with_relays(3).await?;
        let temp_dir = tempdir()?;

        let result = tokio::select! {
            res = services.take_ohttp_relay_handle() => Err(format!("Ohttp relay is long running: {res:?}").into()),
            res = services.take_directory_handle() => Err(format!("Directory server is long running: {res:?}").into()),
            res = cancel_cli_async(&services, &temp_dir) => res,
        };

        assert!(result.is_ok(), "receiver_cancel_v2 failed: {:#?}", result.unwrap_err());

        async fn cancel_cli_async(services: &TestServices, temp_dir: &TempDir) -> Result<()> {
            let receiver_db_path = temp_dir.path().join("receiver_db");
            let (bitcoind, _sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;
            let cert_path = &temp_dir.path().join("localhost.der");
            tokio::fs::write(cert_path, services.cert()).await?;
            services.wait_for_services_ready().await?;
            let ohttp_keys = services.fetch_ohttp_keys().await?;
            let ohttp_keys_path = temp_dir.path().join("ohttp_keys");
            tokio::fs::write(&ohttp_keys_path, ohttp_keys.encode()?).await?;

            let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
            let cookie_file = &bitcoind.params.cookie_file;
            let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");
            let directory = &services.directory_url();
            let ohttp_relays = &services.ohttp_relay_urls();

            // Start a receiver and capture its BIP21 so a session is persisted,
            // then leave it parked at Initialized waiting for a proposal.
            let cli_receiver = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .arg("--pj-directories")
                .arg(directory)
                .arg("--ohttp-keys")
                .arg(&ohttp_keys_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli receiver");
            let _bip21 = get_bip21_from_receiver(cli_receiver).await;

            // There is only one receiver session in progress.
            let session_id = 1i64;

            // Run `payjoin-cli cancel <session-id> --role receiver`: the session is at
            // Initialized so there is no fallback transaction to broadcast.
            let mut cli_cancel = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("cancel")
                .arg(session_id.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli cancel");

            let mut cancel_stdout =
                cli_cancel.stdout.take().expect("failed to take stdout of cancel");
            let timeout = tokio::time::Duration::from_secs(10);
            let cancel_line = tokio::time::timeout(
                timeout,
                wait_for_stdout_match(&mut cancel_stdout, |l| {
                    l.contains("No fallback transaction to broadcast")
                }),
            )
            .await?;
            terminate(cli_cancel).await.expect("Failed to kill payjoin-cli cancel");
            let subcommand_output =
                cancel_line.expect("cancel should report no fallback transaction");

            assert!(
                subcommand_output.contains(&format!("Session {session_id} cancelled")),
                "cancel should reference the cancelled session id"
            );

            // Re-run `cancel` on the now-closed session: the command must still
            // recognize the session exists and report it is already closed.
            let mut cli_cancel_again = Command::new(payjoin_cli)
                .arg("--root-certificate")
                .arg(cert_path)
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&receiver_db_path)
                .arg("--ohttp-relays")
                .arg(ohttp_relays)
                .arg("cancel")
                .arg(session_id.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to execute payjoin-cli cancel on closed session");

            let mut cancel_again_stdout = cli_cancel_again
                .stdout
                .take()
                .expect("failed to take stdout of cancel on closed session");
            let cancel_again_line = tokio::time::timeout(
                timeout,
                wait_for_stdout_match(&mut cancel_again_stdout, |l| {
                    l.contains("is already closed")
                }),
            )
            .await?;
            terminate(cli_cancel_again)
                .await
                .expect("Failed to kill payjoin-cli cancel on closed session");
            let cancel_again_output = cancel_again_line
                .expect("cancel on closed session should report it is already closed");

            assert!(
                cancel_again_output.contains(&format!("Session {session_id} is already closed")),
                "cancel on closed session should reference the session id and report it is already closed"
            );

            Ok(())
        }

        Ok(())
    }

    #[cfg(all(feature = "v2", feature = "asmap"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_asmap_ohttp_relay_selection_report() -> Result<(), BoxError> {
        use std::collections::BTreeSet;
        use std::io::Write as _;
        use std::net::IpAddr;
        use std::path::{Path, PathBuf};

        use asmap::Asmap;
        use payjoin::Url;

        const DEFAULT_DIRECTORIES: &[&str] = &[
            "https://payjo.in",
            "https://pj.benalleng.com",
            "https://mailroom.luisschwab.net",
            "https://payjoin.achow101.com",
            "https://payjoin.lab.vinteum.org",
        ];
        const DEFAULT_RELAYS: &[&str] = &[
            "https://payjo.in",
            "https://pj.benalleng.com",
            "https://mailroom.luisschwab.net",
            "https://payjoin.achow101.com",
            "https://payjoin.lab.vinteum.org",
            "https://ohttp.cakewallet.com",
        ];

        #[derive(Debug, Clone)]
        struct UrlAsnReport {
            url: Url,
            ips: Vec<IpAddr>,
            asns: Vec<u32>,
        }

        fn env_urls(name: &str, defaults: &[&str]) -> Result<Vec<Url>, BoxError> {
            let values = std::env::var(name)
                .ok()
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| defaults.iter().map(|value| value.to_string()).collect());

            values
                .into_iter()
                .map(|value| {
                    Url::parse(&value)
                        .map_err(|err| format!("{name} contains {value}: {err}").into())
                })
                .collect()
        }

        fn url_origin(url: &Url) -> String {
            let mut origin = format!("{}://{}", url.scheme(), url.host_str());
            if let Some(port) = url.port() {
                origin.push(':');
                origin.push_str(&port.to_string());
            }
            origin
        }

        fn known_default_port(url: &Url) -> Option<u16> {
            match url.scheme() {
                "https" => Some(443),
                "http" => Some(80),
                _ => None,
            }
        }

        fn toml_string(value: impl AsRef<str>) -> String { format!("{:?}", value.as_ref()) }

        async fn discover_public_ip() -> Result<IpAddr, BoxError> {
            if let Ok(ip) = std::env::var("PAYJOIN_LIVE_PUBLIC_IP") {
                return ip.parse::<IpAddr>().map_err(|err| {
                    format!("PAYJOIN_LIVE_PUBLIC_IP is not a valid IP address: {err}").into()
                });
            }

            for service in ["https://api.ipify.org", "https://checkip.amazonaws.com"] {
                match reqwest::get(service).await {
                    Ok(response) if response.status().is_success() => {
                        let body = response.text().await?;
                        if let Ok(ip) = body.trim().parse::<IpAddr>() {
                            return Ok(ip);
                        }
                    }
                    _ => {}
                }
            }

            Err("failed to discover public IP; set PAYJOIN_LIVE_PUBLIC_IP".into())
        }

        async fn resolve_url_asns(url: &Url, asmap: &Asmap) -> Result<UrlAsnReport, BoxError> {
            let port = url
                .port()
                .or_else(|| known_default_port(url))
                .ok_or_else(|| format!("{} has no known default port", url.as_str()))?;
            let host = url.host_str();
            let mut ips = if let Ok(ip) = host.parse::<IpAddr>() {
                vec![ip]
            } else {
                tokio::net::lookup_host((host, port))
                    .await?
                    .map(|addr| addr.ip())
                    .collect::<Vec<_>>()
            };
            ips.sort();
            ips.dedup();

            let mut asns = ips.iter().map(|ip| asmap.lookup(*ip)).collect::<Vec<_>>();
            asns.sort();
            asns.dedup();
            Ok(UrlAsnReport { url: url.clone(), ips, asns })
        }

        fn format_asns(asns: &[u32]) -> String {
            asns.iter().map(|asn| asn.to_string()).collect::<Vec<_>>().join(", ")
        }

        fn format_ips(ips: &[IpAddr]) -> String {
            ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
        }

        fn status_for_directory(
            report: &UrlAsnReport,
            selected_directory: &str,
            user_asn: u32,
        ) -> &'static str {
            if report.asns.contains(&0) {
                "unmapped ASN"
            } else if report.asns.contains(&user_asn) {
                "excluded: user ASN"
            } else if url_origin(&report.url) == selected_directory {
                "selected"
            } else {
                "available"
            }
        }

        fn status_for_relay(
            report: &UrlAsnReport,
            user_asn: u32,
            directory_asns: &[u32],
        ) -> &'static str {
            if report.asns.contains(&0) {
                "unmapped ASN"
            } else if report.asns.contains(&user_asn) {
                "excluded: user ASN"
            } else if report.asns.iter().any(|asn| directory_asns.contains(asn)) {
                "excluded: directory ASN"
            } else if report.asns.len() != 1 {
                "mixed or unmapped ASN"
            } else {
                "eligible"
            }
        }

        fn write_report(path: &Path, report: &str) -> Result<(), BoxError> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, report)?;
            Ok(())
        }

        fn append_github_summary(report: &str) -> Result<(), BoxError> {
            let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") else {
                return Ok(());
            };
            let mut summary =
                std::fs::OpenOptions::new().create(true).append(true).open(summary_path)?;
            writeln!(summary, "\n{report}")?;
            Ok(())
        }

        fn live_cli_command(
            payjoin_cli: &str,
            temp_dir: &tempfile::TempDir,
            xdg_config_dir: &Path,
        ) -> Command {
            let mut command = Command::new(payjoin_cli);
            command
                .current_dir(temp_dir.path())
                .env("XDG_CONFIG_HOME", xdg_config_dir)
                .env("RUST_LOG", "info")
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            command
        }

        async fn try_get_bip21_from_receiver(mut child: Child) -> Result<Option<String>, BoxError> {
            let mut stdout = child.stdout.take().expect("failed to take child stdout");
            let bip21 = tokio::time::timeout(
                tokio::time::Duration::from_secs(60),
                wait_for_stdout_match(&mut stdout, |line| {
                    line.to_ascii_uppercase().starts_with("BITCOIN")
                }),
            )
            .await
            .ok()
            .flatten();

            if bip21.is_some() {
                terminate(child).await.expect("Failed to kill payjoin-cli");
            } else {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }

            Ok(bip21)
        }

        async fn wait_for_line_and_terminate(
            child: Child,
            timeout: tokio::time::Duration,
            expected: &'static str,
        ) -> Result<(), BoxError> {
            assert!(
                try_wait_for_line_and_terminate(child, timeout, expected).await?,
                "expected child output to contain {expected:?}"
            );
            Ok(())
        }

        async fn try_wait_for_line_and_terminate(
            mut child: Child,
            timeout: tokio::time::Duration,
            expected: &'static str,
        ) -> Result<bool, BoxError> {
            let mut stdout = child.stdout.take().expect("failed to take child stdout");
            let matched = match tokio::time::timeout(
                timeout,
                wait_for_stdout_match(&mut stdout, |line| line.contains(expected)),
            )
            .await
            {
                Ok(line) => line.is_some(),
                Err(_) => false,
            };

            if matched {
                terminate(child).await.expect("Failed to kill payjoin-cli");
            } else {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }

            Ok(matched)
        }

        payjoin_test_utils::init_tracing();

        let default_asmap_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("latest_asmap.dat");
        let asmap_path = std::env::var("PAYJOIN_LIVE_ASMAP_FILE")
            .map(PathBuf::from)
            .unwrap_or(default_asmap_path);
        let asmap = Asmap::from_file(&asmap_path)?;
        let public_ip = discover_public_ip().await?;
        let user_asn = asmap.lookup(public_ip);
        if user_asn == 0 {
            return Err(
                format!("ASMap did not map public IP {public_ip}; use a newer ASMap").into()
            );
        }

        let directories = env_urls("PAYJOIN_LIVE_DIRECTORIES", DEFAULT_DIRECTORIES)?;
        let relays = env_urls("PAYJOIN_LIVE_OHTTP_RELAYS", DEFAULT_RELAYS)?;
        let mut directory_reports = Vec::with_capacity(directories.len());
        for directory in &directories {
            directory_reports.push(resolve_url_asns(directory, &asmap).await?);
        }
        let mut relay_reports = Vec::with_capacity(relays.len());
        for relay in &relays {
            relay_reports.push(resolve_url_asns(relay, &asmap).await?);
        }

        let temp_dir = tempdir()?;
        let xdg_config_dir = temp_dir.path().join("xdg");
        let sender_db_path = temp_dir.path().join("sender_db");

        let (bitcoind, _sender, _receiver) = init_bitcoind_sender_receiver(None, None)?;
        let receiver_rpchost = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
        let sender_rpchost = format!("http://{}/wallet/sender", bitcoind.params.rpc_socket);
        let cookie_file = &bitcoind.params.cookie_file;
        let payjoin_cli = env!("CARGO_BIN_EXE_payjoin-cli");

        let candidate_directories = directory_reports
            .iter()
            .filter(|report| !report.asns.contains(&0))
            .filter(|report| !report.asns.contains(&user_asn))
            .filter(|report| report.asns.len() == 1)
            .collect::<Vec<_>>();
        if candidate_directories.is_empty() {
            return Err("No live directories remain after ASMap user-AS filtering".into());
        }

        let mut receiver_db_path = None;
        let mut bip21 = None;
        let mut selected_directory = None;
        let mut runtime_relays = vec![];
        for (index, directory) in candidate_directories.iter().enumerate() {
            let mut usable_relays = vec![];
            for relay in &relays {
                match payjoin::io::fetch_ohttp_keys(relay.as_str(), directory.url.as_str()).await {
                    Ok(_) => usable_relays.push(relay.clone()),
                    Err(error) => eprintln!(
                        "live ASMap e2e: relay {} failed key-fetch probe for {}: {error}",
                        relay, directory.url
                    ),
                }
            }
            if usable_relays.is_empty() {
                eprintln!(
                    "live ASMap e2e: no relays could fetch OHTTP keys for {}, trying next directory",
                    directory.url
                );
                continue;
            }
            let relays_config =
                usable_relays.iter().map(|url| toml_string(url.as_str())).collect::<Vec<_>>();
            let config = format!(
                r#"[v2]
pj_directories = [{}]
ohttp_relays = [{}]

[v2.asmap]
asmap_file = {}
user_public_ips = [{}]
"#,
                toml_string(directory.url.as_str()),
                relays_config.join(", "),
                toml_string(asmap_path.display().to_string()),
                toml_string(public_ip.to_string()),
            );
            tokio::fs::write(temp_dir.path().join("config.toml"), config).await?;

            let attempt_db_path = temp_dir.path().join(format!("receiver_db_{index}"));
            let mut cli_receiver = live_cli_command(payjoin_cli, &temp_dir, &xdg_config_dir);
            let cli_receiver = cli_receiver
                .arg("--rpchost")
                .arg(&receiver_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&attempt_db_path)
                .arg("receive")
                .arg(RECEIVE_SATS)
                .spawn()
                .expect("Failed to execute payjoin-cli live receiver");

            match try_get_bip21_from_receiver(cli_receiver).await? {
                Some(uri) => {
                    receiver_db_path = Some(attempt_db_path);
                    bip21 = Some(uri);
                    selected_directory = Some(url_origin(&directory.url));
                    runtime_relays = usable_relays;
                    break;
                }
                None => {
                    eprintln!(
                        "live ASMap e2e: {} did not produce a BIP21, trying next directory",
                        directory.url
                    );
                }
            }
        }
        let receiver_db_path =
            receiver_db_path.ok_or("No live directory produced a receiver BIP21")?;
        let bip21 = bip21.ok_or("No live directory produced a receiver BIP21")?;
        let selected_directory = selected_directory.ok_or("No live directory was selected")?;
        let runtime_relay_urls =
            runtime_relays.iter().map(|url| url.as_str().to_owned()).collect::<Vec<_>>();
        let selected_directory_asns = directory_reports
            .iter()
            .find(|report| url_origin(&report.url) == selected_directory)
            .map(|report| report.asns.clone())
            .unwrap_or_default();

        let mut cli_sender = live_cli_command(payjoin_cli, &temp_dir, &xdg_config_dir);
        let cli_sender = cli_sender
            .arg("--rpchost")
            .arg(&sender_rpchost)
            .arg("--cookie-file")
            .arg(cookie_file)
            .arg("--db-path")
            .arg(&sender_db_path)
            .arg("send")
            .arg(&bip21)
            .arg("--fee-rate")
            .arg("1")
            .spawn()
            .expect("Failed to execute payjoin-cli live sender");
        wait_for_line_and_terminate(
            cli_sender,
            tokio::time::Duration::from_secs(60),
            "Posted Original PSBT",
        )
        .await?;

        let mut cli_receive_resumer = live_cli_command(payjoin_cli, &temp_dir, &xdg_config_dir);
        let cli_receive_resumer = cli_receive_resumer
            .arg("--rpchost")
            .arg(&receiver_rpchost)
            .arg("--cookie-file")
            .arg(cookie_file)
            .arg("--db-path")
            .arg(&receiver_db_path)
            .arg("resume")
            .spawn()
            .expect("Failed to execute payjoin-cli live receiver resume");
        wait_for_line_and_terminate(
            cli_receive_resumer,
            tokio::time::Duration::from_secs(60),
            "Response successful",
        )
        .await?;

        let mut payjoin_sent = false;
        for attempt in 1..=3 {
            let mut cli_send_resumer = live_cli_command(payjoin_cli, &temp_dir, &xdg_config_dir);
            let cli_send_resumer = cli_send_resumer
                .arg("--rpchost")
                .arg(&sender_rpchost)
                .arg("--cookie-file")
                .arg(cookie_file)
                .arg("--db-path")
                .arg(&sender_db_path)
                .arg("send")
                .arg(&bip21)
                .arg("--fee-rate")
                .arg("1")
                .spawn()
                .expect("Failed to execute payjoin-cli live sender resume");
            if try_wait_for_line_and_terminate(
                cli_send_resumer,
                tokio::time::Duration::from_secs(60),
                "Payjoin sent",
            )
            .await?
            {
                payjoin_sent = true;
                break;
            }
            eprintln!("live ASMap e2e: sender resume attempt {attempt} did not complete");
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
        assert!(payjoin_sent, "live sender resume did not complete after retry attempts");

        let mut report = String::new();
        report.push_str("# Live AS-Aware OHTTP Relay Selection E2E\n\n");
        report.push_str(&format!(
            "- Runner public IP: `{public_ip}`\n- Runner/user ASN: `AS{user_asn}`\n- ASMap file: `{}`\n- Selected directory: `{selected_directory}`\n\n",
            asmap_path.display()
        ));

        report.push_str("## Directories\n\n");
        report.push_str("| URL | Resolved IPs | ASNs | Status |\n");
        report.push_str("|---|---|---:|---|\n");
        for directory in &directory_reports {
            report.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} |\n",
                directory.url,
                format_ips(&directory.ips),
                format_asns(&directory.asns),
                status_for_directory(directory, &selected_directory, user_asn),
            ));
        }

        report.push_str("\n## OHTTP Relays\n\n");
        report.push_str("| URL | Resolved IPs | ASNs | Status after selected directory |\n");
        report.push_str("|---|---|---:|---|\n");
        for relay in &relay_reports {
            report.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} |\n",
                relay.url,
                format_ips(&relay.ips),
                format_asns(&relay.asns),
                status_for_relay(relay, user_asn, &selected_directory_asns),
            ));
        }

        let distinct_directory_asns = directory_reports
            .iter()
            .flat_map(|report| report.asns.iter().copied())
            .collect::<BTreeSet<_>>();
        let distinct_relay_asns = relay_reports
            .iter()
            .flat_map(|report| report.asns.iter().copied())
            .collect::<BTreeSet<_>>();
        report.push_str("\n## Key Finding\n\n");
        report.push_str(&format!(
            "Observed `{}` trusted directories across `{}` ASNs and `{}` OHTTP relays across `{}` ASNs. \
             The live receiver selected `{selected_directory}` and the runtime config used `{}` relays \
             that passed the live key-fetch probe: `{}`. Actual OHTTP relay attempts are printed \
             in the test runner log as `Trying OHTTP ... via relay ...`.\n",
            directory_reports.len(),
            distinct_directory_asns.len(),
            relay_reports.len(),
            distinct_relay_asns.len(),
            runtime_relay_urls.len(),
            runtime_relay_urls.join("`, `"),
        ));

        let report_path = PathBuf::from("target/live-asmap-ohttp-relay-selection-e2e.md");
        write_report(&report_path, &report)?;
        append_github_summary(&report)?;
        println!("{report}");
        println!("Live ASMap OHTTP relay selection report written to {}", report_path.display());

        Ok(())
    }
}

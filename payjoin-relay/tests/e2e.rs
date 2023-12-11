use std::env;
use std::process::Stdio;

use bitcoind::bitcoincore_rpc::core_rpc_json::AddressType;
use bitcoind::bitcoincore_rpc::RpcApi;
use log::{log_enabled, Level};
use payjoin::bitcoin::Amount;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::clients::Cli;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const PJ_RELAY_URL: &str = "https://localhost:8088";
const OH_RELAY_URL: &str = "https://localhost:8088";
const RECEIVE_SATS: &str = "54321";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "danger-local-https")]
async fn e2e() {
    // Compile payjoin-cli with default features
    let mut compile_v1 = compile_payjoin_cli(false).await;
    // Compile payjoin-cli with v2 features
    let mut compile_v2 = compile_payjoin_cli(true).await;

    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("PJ_RELAY_PORT", "8088");
    std::env::set_var("PJ_RELAY_TIMEOUT_SECS", "1");
    let _ = env_logger::builder().is_test(true).try_init();
    let docker = Cli::default();
    let node = docker.run(Postgres::default());
    std::env::set_var("PJ_DB_HOST", format!("localhost:{}", node.get_host_port_ipv4(5432)));

    let bitcoind_exe = std::env::var("BITCOIND_EXE")
        .ok()
        .or_else(|| bitcoind::downloaded_exe_path().ok())
        .expect("version feature or env BITCOIND_EXE is required for tests");
    let mut conf = bitcoind::Conf::default();
    conf.view_stdout = log_enabled!(Level::Debug);
    let mut relay = Command::new(env!("CARGO_BIN_EXE_payjoin-relay"))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to execute payjoin-relay");
    log::debug!("Relay started");
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

    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to build reqwest http client");

    // **********************
    // From a connection distinct from the client, perhaps a service provider, or over a VPN or Tor
    let response = http
        .get(format!("{}/ohttp-config", PJ_RELAY_URL))
        .send()
        .await
        .expect("Failed to send request");
    let ohttp_config = response.text().await.expect("Failed to read response");
    log::debug!("Got ohttp-config {}", &ohttp_config);

    let receiver_rpchost = format!("{}/wallet/receiver", bitcoind.params.rpc_socket);
    let sender_rpchost = format!("{}/wallet/sender", bitcoind.params.rpc_socket);

    let cookie_file = &bitcoind.params.cookie_file;

    // Paths to the compiled binaries
    let v1_status = compile_v1.wait().await.unwrap();
    let v2_status = compile_v2.wait().await.unwrap();
    assert!(v1_status.success(), "Process did not exit successfully");
    assert!(v2_status.success(), "Process did not exit successfully");

    let v2_receiver = "target/v2/debug/payjoin";
    let v1_sender = "target/v1/debug/payjoin";

    let mut cli_receiver = Command::new(v2_receiver)
        .arg("--rpchost")
        .arg(&receiver_rpchost)
        .arg("--cookie-file")
        .arg(&cookie_file)
        .arg("--ohttp-config")
        .arg(&ohttp_config)
        .arg("--ohttp-proxy")
        .arg(OH_RELAY_URL)
        .arg("receive")
        .arg(RECEIVE_SATS)
        .arg("--endpoint")
        .arg(PJ_RELAY_URL)
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

        // Check if it's the line we're interested in
        if line.starts_with("BITCOIN") {
            bip21 = line;
            break;
        }
    }
    log::debug!("Got bip21 {}", &bip21);
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(line) = lines.next_line().await.expect("Failed to read line from stdout") {
            // Continue to write to stdout
            stdout
                .write_all(format!("{}\n", line).as_bytes())
                .await
                .expect("Failed to write to stdout");

            if line.contains("Transaction sent") {
                log::debug!("HOLY MOLY BATMAN! Transaction sent!")
            }
        }
    });

    let mut cli_sender = Command::new(v1_sender)
        .arg("--rpchost")
        .arg(&sender_rpchost)
        .arg("--cookie-file")
        .arg(&cookie_file)
        .arg("--ohttp-config")
        .arg(&ohttp_config)
        .arg("--ohttp-proxy")
        .arg(OH_RELAY_URL)
        .arg("send")
        .arg(&bip21)
        .arg("--fee_rate")
        .arg("1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to execute payjoin-cli");

    // delay 10 seconds
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    relay.kill().await.expect("Failed to kill payjoin-relay");
    cli_receiver.kill().await.expect("Failed to kill payjoin-cli");
    cli_sender.kill().await.expect("Failed to kill payjoin-cli");
}

async fn compile_payjoin_cli(feature_v2: bool) -> Child {
    let target_dir = if feature_v2 { "target/v2" } else { "target/v1" };

    env::set_var("CARGO_TARGET_DIR", target_dir);

    let mut command = Command::new("cargo");
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit()).args([
        "build",
        "--package",
        "payjoin-cli",
    ]);

    if feature_v2 {
        command.args(["--features", "v2"]);
    }
    command.spawn().unwrap()
}

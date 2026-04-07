//! End-to-end coverage for the `esplora` wallet backend.
//!
//! Exercises the same three flows as `tests/e2e.rs` (v1, v2, v2→v1
//! fallback) but drives the CLI with `--descriptor` / `--esplora-url`
//! instead of `--rpchost` / `--cookie-file`. Each test spins up its
//! own bitcoind + electrs-esplora fixture (`common::EsploraFixture`)
//! so they can run in parallel. v2 flows additionally reuse
//! `payjoin_test_utils::TestServices` for the ohttp relay + directory.

#![cfg(all(feature = "esplora", feature = "v1", feature = "_manual-tls"))]

mod common;

use std::process::Stdio;
use std::time::Duration;

use common::{terminate, wait_for_line, EsploraFixture, Side, RECEIVE_SATS};
use payjoin_test_utils::{local_cert_key, BoxSendSyncError};
use tempfile::tempdir;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_receive_payjoin_v1_esplora() -> Result<(), BoxSendSyncError> {
    let fx = EsploraFixture::new().await?;
    let temp_dir = tempdir()?;
    let dir = temp_dir.path();
    let receiver_db = dir.join("receiver_db");
    let sender_db = dir.join("sender_db");

    let cert = local_cert_key();
    let cert_path = dir.join("localhost.crt");
    let key_path = dir.join("localhost.key");
    tokio::fs::write(&cert_path, cert.cert.der().to_vec()).await?;
    tokio::fs::write(&key_path, cert.signing_key.serialize_der()).await?;

    let mut cli_receiver = fx
        .cli(Side::Receiver, &receiver_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--certificate-key")
        .arg(&key_path)
        .arg("--bip78")
        .arg("receive")
        .arg(RECEIVE_SATS)
        .arg("--port")
        .arg("0")
        .arg("--pj-endpoint")
        .arg("https://localhost")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn payjoin-cli v1 receiver");

    let bip21 = wait_for_line(
        &mut cli_receiver,
        Duration::from_secs(30),
        "v1 receiver BIP21 URI",
        |line| line.to_ascii_uppercase().starts_with("BITCOIN"),
    )
    .await?;
    tracing::debug!("Got bip21 {}", &bip21);

    let mut cli_sender = fx
        .cli(Side::Sender, &sender_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--bip78")
        .arg("send")
        .arg(&bip21)
        .arg("--fee-rate")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn payjoin-cli v1 sender");

    let _ = wait_for_line(
        &mut cli_sender,
        Duration::from_secs(30),
        "'Payjoin sent' from v1 sender",
        |line| line.contains("Payjoin sent"),
    )
    .await?;

    terminate(cli_receiver).await;
    terminate(cli_sender).await;
    Ok(())
}

#[cfg(feature = "v2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_receive_payjoin_v2_esplora() -> Result<(), BoxSendSyncError> {
    use payjoin_test_utils::{init_tracing, TestServices};

    init_tracing();
    let fx = EsploraFixture::new().await?;
    let mut services = TestServices::initialize().await?;
    let temp_dir = tempdir()?;

    tokio::select! {
        res = services.take_ohttp_relay_handle() =>
            Err::<(), BoxSendSyncError>(format!("ohttp relay is long running: {res:?}").into()),
        res = services.take_directory_handle() =>
            Err(format!("directory server is long running: {res:?}").into()),
        res = run_v2(&fx, &services, temp_dir.path()) => res,
    }
}

#[cfg(feature = "v2")]
async fn run_v2(
    fx: &EsploraFixture,
    services: &payjoin_test_utils::TestServices,
    dir: &std::path::Path,
) -> Result<(), BoxSendSyncError> {
    let receiver_db = dir.join("receiver_db");
    let sender_db = dir.join("sender_db");

    let cert_path = dir.join("localhost.der");
    tokio::fs::write(&cert_path, services.cert()).await?;
    services.wait_for_services_ready().await?;
    let ohttp_keys = services.fetch_ohttp_keys().await?;
    let ohttp_keys_path = dir.join("ohttp_keys");
    tokio::fs::write(&ohttp_keys_path, ohttp_keys.encode()?).await?;

    let directory = services.directory_url();
    let ohttp_relay = services.ohttp_relay_url();

    // 1. Receiver initiator — enrolls with the directory and prints
    //    the BIP21 URI, then exits (v2 push-style).
    let mut receiver_init = fx
        .cli(Side::Receiver, &receiver_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--ohttp-relays")
        .arg(&ohttp_relay)
        .arg("receive")
        .arg(RECEIVE_SATS)
        .arg("--pj-directory")
        .arg(&directory)
        .arg("--ohttp-keys")
        .arg(&ohttp_keys_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn v2 receiver initiator");

    let bip21 = wait_for_line(
        &mut receiver_init,
        Duration::from_secs(30),
        "v2 receiver BIP21 URI",
        |line| line.to_ascii_uppercase().starts_with("BITCOIN"),
    )
    .await?;
    terminate(receiver_init).await;

    // 2. Sender initial attempt — polls for a response and eventually
    //    hits "No response yet." before its long-poll elapses.
    let mut sender_init = fx
        .cli(Side::Sender, &sender_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--ohttp-relays")
        .arg(&ohttp_relay)
        .arg("send")
        .arg(&bip21)
        .arg("--fee-rate")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn v2 sender initiator");

    let _ = wait_for_line(
        &mut sender_init,
        Duration::from_secs(45),
        "'No response yet.' from sender",
        |line| line.contains("No response yet."),
    )
    .await?;
    terminate(sender_init).await;

    // 3. Receiver resumer — picks up the pending session, responds to
    //    the sender's request with a payjoin PSBT.
    let mut receiver_resume = fx
        .cli(Side::Receiver, &receiver_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--ohttp-relays")
        .arg(&ohttp_relay)
        .arg("resume")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn v2 receiver resumer");

    let _ = wait_for_line(
        &mut receiver_resume,
        Duration::from_secs(30),
        "'Response successful' from receiver",
        |line| line.contains("Response successful"),
    )
    .await?;
    terminate(receiver_resume).await;

    // 4. Sender resumer — finalizes and broadcasts, logs "Payjoin sent".
    let mut sender_resume = fx
        .cli(Side::Sender, &sender_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--ohttp-relays")
        .arg(&ohttp_relay)
        .arg("send")
        .arg(&bip21)
        .arg("--fee-rate")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn v2 sender resumer");

    let _ = wait_for_line(
        &mut sender_resume,
        Duration::from_secs(30),
        "'Payjoin sent' from v2 sender",
        |line| line.contains("Payjoin sent"),
    )
    .await?;
    terminate(sender_resume).await;

    // 5. Mine a block and resume the receiver so it picks up the
    //    confirmation and closes the session out.
    fx.mine_one()?;

    let mut receiver_final = fx
        .cli(Side::Receiver, &receiver_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--ohttp-relays")
        .arg(&ohttp_relay)
        .arg("resume")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn v2 receiver final resumer");

    let _ = wait_for_line(
        &mut receiver_final,
        Duration::from_secs(30),
        "'All resumed sessions completed.'",
        |line| line.contains("All resumed sessions completed."),
    )
    .await?;
    terminate(receiver_final).await;

    // 6. Both sides should now report no more sessions to resume.
    let mut receiver_empty = fx
        .cli(Side::Receiver, &receiver_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--ohttp-relays")
        .arg(&ohttp_relay)
        .arg("resume")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn v2 receiver empty-resume check");

    let _ = wait_for_line(
        &mut receiver_empty,
        Duration::from_secs(30),
        "receiver 'No sessions to resume.'",
        |line| line.contains("No sessions to resume."),
    )
    .await?;
    terminate(receiver_empty).await;

    let mut sender_empty = fx
        .cli(Side::Sender, &sender_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--ohttp-relays")
        .arg(&ohttp_relay)
        .arg("resume")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn v2 sender empty-resume check");

    let _ = wait_for_line(
        &mut sender_empty,
        Duration::from_secs(30),
        "sender 'No sessions to resume.'",
        |line| line.contains("No sessions to resume."),
    )
    .await?;
    terminate(sender_empty).await;

    Ok(())
}

/// Mirror of `e2e::send_receive_payjoin_v2_to_v1`: a v1 receiver
/// listens on HTTPS, and a v2-mode sender (no `--bip78`) auto-detects
/// the v1 URI emitted by the receiver and falls back to the BIP78
/// transport to complete the payjoin.
#[cfg(feature = "v2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_receive_payjoin_v2_to_v1_esplora() -> Result<(), BoxSendSyncError> {
    use payjoin_test_utils::{init_tracing, TestServices};

    init_tracing();
    let fx = EsploraFixture::new().await?;
    let services = TestServices::initialize().await?;
    let temp_dir = tempdir()?;
    let dir = temp_dir.path();

    // v1 receiver listens over HTTPS with its own self-signed cert.
    let cert = local_cert_key();
    let cert_path = dir.join("localhost.crt");
    let key_path = dir.join("localhost.key");
    tokio::fs::write(&cert_path, cert.cert.der().to_vec()).await?;
    tokio::fs::write(&key_path, cert.signing_key.serialize_der()).await?;

    // Make sure the v2 services the sender reaches for (before
    // deciding to fall back) are actually up.
    services.wait_for_services_ready().await?;

    let receiver_db = dir.join("receiver_db");
    let sender_db = dir.join("sender_db");

    let mut cli_receive_v1 = fx
        .cli(Side::Receiver, &receiver_db)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--certificate-key")
        .arg(&key_path)
        .arg("--bip78")
        .arg("receive")
        .arg(RECEIVE_SATS)
        .arg("--port")
        .arg("0")
        .arg("--pj-endpoint")
        .arg("https://localhost")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn v1 receiver");

    let bip21 = wait_for_line(
        &mut cli_receive_v1,
        Duration::from_secs(30),
        "v1 receiver BIP21 URI",
        |line| line.to_ascii_uppercase().starts_with("BITCOIN"),
    )
    .await?;
    tracing::debug!("Got v1 bip21 from receiver: {}", &bip21);

    // v2 sender, no `--bip78`: should detect the v1 BIP21 URI and
    // fall back to the BIP78 transport against the receiver's HTTPS
    // listener, same as tests/e2e.rs::send_receive_payjoin_v2_to_v1.
    let ohttp_relay = services.ohttp_relay_url();
    let mut cli_send_v2 = fx
        .cli(Side::Sender, &sender_db)
        .arg("--root-certificate")
        .arg(&cert_path) // receiver's self-signed cert, for the v1 fallback
        .arg("--ohttp-relays")
        .arg(&ohttp_relay)
        .arg("send")
        .arg(&bip21)
        .arg("--fee-rate")
        .arg("1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn v2 sender");

    let _ = wait_for_line(
        &mut cli_send_v2,
        Duration::from_secs(45),
        "'Payjoin sent' from v2→v1 sender",
        |line| line.contains("Payjoin sent"),
    )
    .await?;

    terminate(cli_receive_v1).await;
    terminate(cli_send_v2).await;
    Ok(())
}

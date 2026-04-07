//! Shared fixture and process-orchestration helpers for the esplora
//! e2e tests. Kept in `tests/common/` so cargo picks it up as a module
//! of `e2e_esplora.rs` rather than compiling it as its own test target.

#![allow(dead_code)]

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::{Address as BtcAddress, Amount as BtcAmount, Network as BdkNetwork};
use bdk_wallet::{KeychainKind, Wallet as BdkWallet};
use electrsd::corepc_node::{Conf as NodeConf, Node};
use electrsd::ElectrsD;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use payjoin_test_utils::BoxSendSyncError;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

pub const RECEIVE_SATS: &str = "54321";

#[derive(Copy, Clone)]
pub enum Side {
    Sender,
    Receiver,
}

/// A bitcoind + electrs-esplora fixture with two disjoint BIP84 BDK
/// descriptor wallets funded on regtest. Every esplora e2e test owns
/// an independent instance of this struct, so they can run in parallel
/// without clobbering each other's chain state.
pub struct EsploraFixture {
    pub bitcoind: Node,
    pub electrsd: ElectrsD,
    pub esplora_url: String,
    pub sender_desc: String,
    pub sender_change: String,
    pub receiver_desc: String,
    pub receiver_change: String,
    funding_addr: BtcAddress,
}

impl EsploraFixture {
    pub async fn new() -> Result<Self, BoxSendSyncError> {
        let (sender_desc, sender_change) = descriptors_for(1);
        let (receiver_desc, receiver_change) = descriptors_for(2);
        let sender_addr_str = first_external_address(&sender_desc, &sender_change);
        let receiver_addr_str = first_external_address(&receiver_desc, &receiver_change);

        // 1. Start bitcoind via the corepc-node version electrsd was
        //    built against so ElectrsD::with_conf accepts it.
        let bitcoind_exe = electrsd::corepc_node::exe_path()?;
        let mut conf = NodeConf::default();
        conf.view_stdout = false;
        let bitcoind = Node::with_conf(bitcoind_exe, &conf)?;
        let rpc = &bitcoind.client;

        // 2. Mine 101 blocks to a funding address and send 1 BTC to
        //    each descriptor's first external address, then mine one
        //    more block so the outputs are confirmed.
        let funding_addr = rpc.new_address()?;
        rpc.generate_to_address(101, &funding_addr)?;

        let one_btc = BtcAmount::from_btc(1.0)?;
        let sender_addr = BtcAddress::from_str(&sender_addr_str)?.assume_checked();
        let receiver_addr = BtcAddress::from_str(&receiver_addr_str)?.assume_checked();
        rpc.send_to_address(&sender_addr, one_btc)?;
        rpc.send_to_address(&receiver_addr, one_btc)?;
        rpc.generate_to_address(1, &funding_addr)?;
        let tip = rpc.get_block_count()?.0;

        // 3. Launch electrs-esplora pointing at the same bitcoind.
        let electrs_exe = electrsd::exe_path().map_err(|e| format!("electrs exe: {e}"))?;
        let mut el_conf = electrsd::Conf::default();
        el_conf.http_enabled = true;
        let electrsd = ElectrsD::with_conf(electrs_exe, &bitcoind, &el_conf)?;
        let raw_esplora =
            electrsd.esplora_url.clone().expect("esplora_a33e97e1 feature must expose esplora_url");
        let esplora_url = if raw_esplora.starts_with("http") {
            raw_esplora
        } else {
            format!("http://{raw_esplora}")
        };
        wait_for_esplora_height(&esplora_url, tip).await?;

        Ok(Self {
            bitcoind,
            electrsd,
            esplora_url,
            sender_desc,
            sender_change,
            receiver_desc,
            receiver_change,
            funding_addr,
        })
    }

    /// Mine one block to the fixture's funding address. Useful for v2
    /// flows that need to advance the chain after a payjoin is sent so
    /// the receiver picks up the confirmation.
    pub fn mine_one(&self) -> Result<(), BoxSendSyncError> {
        self.bitcoind.client.generate_to_address(1, &self.funding_addr)?;
        Ok(())
    }

    /// Build a `payjoin-cli` command pre-populated with the flags every
    /// esplora test needs (wallet descriptor pair, esplora URL, network,
    /// db path). Callers chain on subcommand- and transport-specific
    /// arguments before `.spawn()`.
    pub fn cli(&self, side: Side, db_path: &Path) -> Command {
        let bin = env!("CARGO_BIN_EXE_payjoin-cli");
        let (desc, change) = match side {
            Side::Sender => (&self.sender_desc, &self.sender_change),
            Side::Receiver => (&self.receiver_desc, &self.receiver_change),
        };
        let mut cmd = Command::new(bin);
        cmd.arg("--descriptor")
            .arg(desc)
            .arg("--change-descriptor")
            .arg(change)
            .arg("--esplora-url")
            .arg(&self.esplora_url)
            .arg("--network")
            .arg("regtest")
            .arg("--db-path")
            .arg(db_path);
        cmd
    }
}

fn descriptors_for(tag: u8) -> (String, String) {
    let seed = [tag; 32];
    let xprv = Xpriv::new_master(BdkNetwork::Regtest, &seed).expect("valid master key");
    let xprv_str = xprv.to_string();
    let recv = format!("wpkh({}/84h/1h/0h/0/*)", xprv_str);
    let change = format!("wpkh({}/84h/1h/0h/1/*)", xprv_str);
    (recv, change)
}

fn first_external_address(desc: &str, change: &str) -> String {
    let mut wallet = BdkWallet::create(desc.to_owned(), change.to_owned())
        .network(BdkNetwork::Regtest)
        .create_wallet_no_persist()
        .expect("build wallet");
    wallet.reveal_next_address(KeychainKind::External).address.to_string()
}

async fn wait_for_esplora_height(url: &str, target: u64) -> Result<(), BoxSendSyncError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let client = reqwest::Client::new();
    let endpoint = format!("{}/blocks/tip/height", url.trim_end_matches('/'));
    loop {
        if let Ok(resp) = client.get(&endpoint).send().await {
            if let Ok(text) = resp.text().await {
                if let Ok(h) = text.trim().parse::<u64>() {
                    if h >= target {
                        return Ok(());
                    }
                }
            }
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("esplora never reached height {target}").into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// SIGINT a child and wait for it to exit. Ignores send/wait errors —
/// the child may already be gone by the time we get here.
pub async fn terminate(mut child: Child) {
    if let Some(pid) = child.id() {
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
    }
    let _ = child.wait().await;
}

/// Spawn a background task that drains a child's stdout for its
/// lifetime, forwarding every line to the test process's stdout and
/// sending the first line matching `predicate` through a oneshot.
///
/// Keeping the drain task alive past the first match is important:
/// if we stopped reading, the child's next stdout write would hit
/// EPIPE and the child would crash — catastrophic for long-running
/// v1 receivers that must keep serving requests after logging a URI.
pub fn match_line_background<F>(
    child: &mut Child,
    predicate: F,
) -> tokio::sync::oneshot::Receiver<Option<String>>
where
    F: Fn(&str) -> bool + Send + 'static,
{
    let stdout = child.stdout.take().expect("child stdout piped");
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        let mut out = tokio::io::stdout();
        let mut tx = Some(tx);
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = out.write_all(format!("{line}\n").as_bytes()).await;
            if tx.is_some() && predicate(&line) {
                let _ = tx.take().unwrap().send(Some(line));
            }
        }
        if let Some(sender) = tx.take() {
            let _ = sender.send(None);
        }
    });
    rx
}

/// Convenience wrapper around `match_line_background` with a timeout
/// and a human-readable label for error messages.
pub async fn wait_for_line<F>(
    child: &mut Child,
    timeout: Duration,
    label: &'static str,
    predicate: F,
) -> Result<String, BoxSendSyncError>
where
    F: Fn(&str) -> bool + Send + 'static,
{
    let rx = match_line_background(child, predicate);
    tokio::time::timeout(timeout, rx)
        .await
        .map_err(|_| format!("timed out waiting for {label}"))?
        .map_err(|_| format!("stdout drain task for {label} dropped"))?
        .ok_or_else(|| format!("{label} never appeared on stdout").into())
}

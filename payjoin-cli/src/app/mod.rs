use std::collections::HashMap;

use anyhow::{anyhow, Ok, Result};
use bitcoincore_rpc::bitcoin::Amount;
use clap::builder;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::FeeRate;
use payjoin::{bitcoin, PjUri};
use tokio::signal;
use tokio::sync::watch;

pub mod config;
pub mod wallet;
use crate::app::config::Config;
use crate::app::wallet::BitcoindWallet;

#[cfg(feature = "v1")]
pub(crate) mod v1;
#[cfg(feature = "v2")]
pub(crate) mod v2;

#[cfg(feature = "_manual-tls")]
pub const LOCAL_CERT_FILE: &str = "localhost.der";

#[async_trait::async_trait]
pub trait App: Send + Sync {
    fn new(config: Config) -> Result<Self>
    where
        Self: Sized;
    fn wallet(&self) -> BitcoindWallet;
    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()>;
    async fn receive_payjoin(&self, amount: Amount) -> Result<()>;
    #[cfg(feature = "v2")]
    async fn resume_payjoins(&self) -> Result<()>;

    fn create_original_psbt(&self, uri: &PjUri, fee_rate: FeeRate) -> Result<Psbt> {
        let amount = uri.amount.ok_or_else(|| anyhow!("please specify the amount in the Uri"))?;

        // wallet_create_funded_psbt requires a HashMap<address: String, Amount>
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(uri.address.to_string(), amount);

        self.wallet().create_psbt(outputs, fee_rate, true)
    }

    fn process_pj_response(&self, psbt: Psbt) -> Result<bitcoin::Txid> {
        log::debug!("Proposed psbt: {psbt:#?}");

        let signed = self.wallet().process_psbt(&psbt)?;
        let tx = self.wallet().finalize_psbt(&signed)?;

        let txid = self.wallet().broadcast_tx(&tx)?;

        println!("Payjoin sent. TXID: {txid}");
        Ok(txid)
    }
}

#[cfg(feature = "_manual-tls")]
fn http_agent(cert: Option<Vec<u8>>) -> Result<reqwest::Client> {
    match cert {
        Some(cert_der) => build_http_agent_with_cert(&cert_der),
        None =>
            if let Ok(base64_cert) = std::env::var("MANUAL_TLS_CERT") {
                let cert_der = base64::decode(base64_cert)?;
                build_http_agent_with_cert(&cert_der)
            } else {
                Err(anyhow::anyhow!("No certificate provided for manual TLS mode"))
            },
    }
}

#[cfg(not(feature = "_manual-tls"))]
fn http_agent() -> Result<reqwest::Client> { Ok(reqwest::Client::builder().build()?) }

#[cfg(feature = "_manual-tls")]
fn build_http_agent_with_cert(cert_der: &[u8]) -> Result<reqwest::Client> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add(rustls::pki_types::CertificateDer::from(cert_der))?;
    Ok(reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der)?)
        .build()?)
}

#[cfg(feature = "_manual-tls")]
fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::generate_simple_self_signed;
    let cert = generate_simple_self_signed(vec!["localhost".into()])?;
    Ok((cert.serialize_der()?, cert.serialize_private_key_der()))
}

#[cfg(feature = "_manual-tls")]
pub fn create_http_client_with_server_cert(server_cert: Vec<u8>) -> Result<reqwest::Client> {
    http_agent(Some(server_cert))
}

// #[cfg(not(feature = "manual-tls"))]
// pub fn create_http_client_with_server_cert(_server_cert: Vec<u8>) -> Result<reqwest::Client> {
//     http_agent()
// }
async fn handle_interrupt(tx: watch::Sender<()>) {
    if let Err(e) = signal::ctrl_c().await {
        eprintln!("Error setting up Ctrl-C handler: {e}");
    }
    let _ = tx.send(());
}

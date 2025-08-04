use std::collections::HashMap;

use anyhow::{anyhow, Result};
use bitcoincore_rpc::bitcoin::Amount;
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

#[cfg(feature = "_danger-local-https")]
fn http_agent(config: &Config) -> Result<reqwest::Client> {
    Ok(http_agent_builder(config.root_certificate.as_ref())?.build()?)
}

#[cfg(not(feature = "_danger-local-https"))]
fn http_agent(_config: &Config) -> Result<reqwest::Client> { Ok(reqwest::Client::new()) }

#[cfg(feature = "_danger-local-https")]
fn http_agent_builder(
    root_cert_path: Option<&std::path::PathBuf>,
) -> Result<reqwest::ClientBuilder> {
    let mut builder = reqwest::ClientBuilder::new().use_rustls_tls();

    if let Some(root_cert_path) = root_cert_path {
        let cert_der = std::fs::read(root_cert_path)?;
        builder =
            builder.add_root_certificate(reqwest::tls::Certificate::from_der(cert_der.as_slice())?)
    }
    Ok(builder)
}

async fn handle_interrupt(tx: watch::Sender<()>) {
    if let Err(e) = signal::ctrl_c().await {
        eprintln!("Error setting up Ctrl-C handler: {e}");
    }
    let _ = tx.send(());
}

use std::collections::HashMap;

use anyhow::Result;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{self, Address, Amount, FeeRate};
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
    async fn new(config: Config) -> Result<Self>
    where
        Self: Sized;
    fn wallet(&self) -> BitcoindWallet;
    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()>;
    async fn receive_payjoin(&self, amount: Amount) -> Result<()>;
    #[cfg(feature = "v2")]
    async fn resume_payjoins(&self) -> Result<()>;
    #[cfg(feature = "v2")]
    async fn history(&self) -> Result<()>;

    fn create_original_psbt(
        &self,
        address: &Address,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> Result<Psbt> {
        // Check if wallet has spendable UTXOs before attempting to create PSBT
        if !self.wallet().has_spendable_utxos()? {
            return Err(anyhow::anyhow!(
                "No spendable UTXOs available in wallet. Please ensure your wallet has confirmed funds."
            ));
        }

        // wallet_create_funded_psbt requires a HashMap<address: String, Amount>
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(address.to_string(), amount);

        self.wallet().create_psbt(outputs, fee_rate, true)
    }

    fn process_pj_response(&self, psbt: Psbt) -> Result<bitcoin::Txid> {
        tracing::trace!("Proposed psbt: {psbt:#?}");

        let signed = self.wallet().process_psbt(&psbt)?;
        let tx = signed.extract_tx()?;

        let txid = self.wallet().broadcast_tx(&tx)?;

        println!("Payjoin sent. TXID: {txid}");
        Ok(txid)
    }
}

#[cfg(feature = "_manual-tls")]
fn http_agent(config: &Config) -> Result<reqwest::Client> {
    Ok(http_agent_builder(config.root_certificate.as_ref())?.build()?)
}

#[cfg(not(feature = "_manual-tls"))]
fn http_agent(_config: &Config) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().http1_only().build()?)
}

#[cfg(feature = "_manual-tls")]
fn http_agent_builder(
    root_cert_path: Option<&std::path::PathBuf>,
) -> Result<reqwest::ClientBuilder> {
    let mut builder = reqwest::ClientBuilder::new().use_rustls_tls().http1_only();

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

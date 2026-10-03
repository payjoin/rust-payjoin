use std::collections::HashMap;

use anyhow::Result;
use payjoin::bitcoin::address::NetworkUnchecked;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{self, Address, Amount, FeeRate, Transaction, TxOut};
use tokio::signal;
use tokio::sync::watch;

pub mod config;
pub mod wallet;
use crate::app::config::Config;
use crate::app::wallet::BitcoindWallet;
use crate::cli::CutThrough;
#[cfg(feature = "v2")]
use crate::cli::Role;
#[cfg(feature = "v2")]
use crate::db::v2::SessionId;

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
    async fn resume_payjoins(&self, session_id: Option<SessionId>) -> Result<()>;
    #[cfg(feature = "v2")]
    async fn history(&self) -> Result<()>;
    #[cfg(feature = "v2")]
    async fn cancel(
        &self,
        session_id: SessionId,
        no_broadcast: bool,
        role: Option<Role>,
    ) -> Result<()>;

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
        Ok(txid)
    }
}

/// The receiver's own output in the sender's original transaction.
///
/// `WantsOutputs` does not expose the outputs it is about to replace, so
/// callers capture this earlier, while the original transaction is still
/// reachable, using the same ownership predicate the library uses.
pub(crate) fn find_receiver_output(
    wallet: &BitcoindWallet,
    original_tx: &Transaction,
) -> Result<TxOut> {
    for txout in &original_tx.output {
        if wallet.is_mine(&txout.script_pubkey)? {
            return Ok(txout.clone());
        }
    }
    Err(anyhow::anyhow!("no receiver output found in the original transaction"))
}

/// The output forwarding part of the payment onward, with its address checked
/// against the wallet's network.
pub(crate) fn forward_output(wallet: &BitcoindWallet, cut_through: &CutThrough) -> Result<TxOut> {
    let address = cut_through
        .address
        .parse::<Address<NetworkUnchecked>>()?
        .require_network(wallet.network()?)?;
    Ok(TxOut {
        value: Amount::from_sat(cut_through.amount_sat),
        script_pubkey: address.script_pubkey(),
    })
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

use std::collections::{HashMap, HashSet};

use anyhow::{bail, Result};
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{self, Address, Amount, FeeRate, OutPoint};
use tokio::signal;
use tokio::sync::watch;

pub mod config;
pub mod wallet;
use crate::app::config::Config;
use crate::app::wallet::BitcoindWallet;
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

    /// Sign the receiver's proposal and broadcast it.
    ///
    /// The proposal is refused before signing if any input that is not in
    /// `original_tx` belongs to this wallet, so the sender signs only its
    /// original inputs, as BIP 78 requires.
    fn process_pj_response(
        &self,
        original_tx: &bitcoin::Transaction,
        proposal: Psbt,
    ) -> Result<bitcoin::Txid> {
        tracing::trace!("Proposed psbt: {proposal:#?}");

        ensure_no_added_input_is_ours(&self.wallet(), original_tx, &proposal)?;

        let signed = self.wallet().process_psbt(&proposal)?;
        let tx = signed.extract_tx()?;

        let txid = self.wallet().broadcast_tx(&tx)?;
        Ok(txid)
    }
}

/// Fail if an input that is not in `original_tx` spends a coin of this
/// wallet, judged both by the wallet's own record of the outpoint and by the
/// previous output the proposal supplies for it.
fn ensure_no_added_input_is_ours(
    wallet: &BitcoindWallet,
    original_tx: &bitcoin::Transaction,
    proposal: &Psbt,
) -> Result<()> {
    let original_outpoints: HashSet<OutPoint> =
        original_tx.input.iter().map(|txin| txin.previous_output).collect();
    for (txin, psbtin) in proposal.unsigned_tx.input.iter().zip(&proposal.inputs) {
        let outpoint = txin.previous_output;
        if original_outpoints.contains(&outpoint) {
            continue;
        }
        let supplied_prevouts = psbtin.witness_utxo.iter().chain(
            psbtin.non_witness_utxo.as_ref().and_then(|tx| tx.output.get(outpoint.vout as usize)),
        );
        let mut ours = wallet.is_my_outpoint(&outpoint)?;
        for prevout in supplied_prevouts {
            ours |= wallet.is_mine(&prevout.script_pubkey)?;
        }
        if ours {
            bail!(
                "Refusing to sign the payjoin proposal: input {outpoint} was not in the original transaction but belongs to this wallet"
            );
        }
    }
    Ok(())
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

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{self, base64};
use payjoin::send::RequestContext;
use payjoin::PjUri;

pub mod config;
use crate::app::config::AppConfig;

#[cfg(not(feature = "v2"))]
pub(crate) mod v1;
#[cfg(feature = "v2")]
pub(crate) mod v2;

#[cfg(feature = "danger-local-https")]
pub const LOCAL_CERT_FILE: &str = "localhost.der";

#[async_trait::async_trait]
pub trait App {
    fn new(config: AppConfig) -> Result<Self>
    where
        Self: Sized;
    fn bitcoind(&self) -> Result<bitcoincore_rpc::Client>;
    async fn send_payjoin(&self, bip21: &str, fee_rate: &f32) -> Result<()>;
    async fn receive_payjoin(self, amount_arg: &str) -> Result<()>;

    fn create_pj_request(&self, uri: &PjUri, fee_rate: &f32) -> Result<RequestContext> {
        let amount = uri.amount.ok_or_else(|| anyhow!("please specify the amount in the Uri"))?;

        // wallet_create_funded_psbt requires a HashMap<address: String, Amount>
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(uri.address.to_string(), amount);
        let fee_rate_sat_per_kwu = fee_rate * 250.0_f32;
        let fee_rate: bitcoin::FeeRate =
            bitcoin::FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64);
        let fee_sat_per_kvb =
            fee_rate.to_sat_per_kwu().checked_mul(4).ok_or(anyhow!("Invalid fee rate"))?;
        let fee_per_kvb = Amount::from_sat(fee_sat_per_kvb);
        log::debug!("Fee rate sat/kvb: {}", fee_per_kvb.display_in(bitcoin::Denomination::Satoshi));
        let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            lock_unspent: Some(true),
            fee_rate: Some(fee_per_kvb),
            ..Default::default()
        };
        let psbt = self
            .bitcoind()?
            .wallet_create_funded_psbt(
                &[], // inputs
                &outputs,
                None, // locktime
                Some(options),
                None,
            )
            .context("Failed to create PSBT")?
            .psbt;
        let psbt = self
            .bitcoind()?
            .wallet_process_psbt(&psbt, None, None, None)
            .with_context(|| "Failed to process PSBT")?
            .psbt;
        let psbt = Psbt::from_str(&psbt).with_context(|| "Failed to load PSBT from base64")?;
        log::debug!("Original psbt: {:#?}", psbt);
        let req_ctx = payjoin::send::RequestBuilder::from_psbt_and_uri(psbt, uri.clone())
            .with_context(|| "Failed to build payjoin request")?
            .build_recommended(fee_rate)
            .with_context(|| "Failed to build payjoin request")?;

        Ok(req_ctx)
    }

    fn process_pj_response(&self, psbt: Psbt) -> Result<bitcoin::Txid> {
        log::debug!("Proposed psbt: {:#?}", psbt);
        let psbt = self
            .bitcoind()?
            .wallet_process_psbt(&serialize_psbt(&psbt), None, None, None)
            .with_context(|| "Failed to process PSBT")?
            .psbt;
        let tx = self
            .bitcoind()?
            .finalize_psbt(&psbt, Some(true))
            .with_context(|| "Failed to finalize PSBT")?
            .hex
            .ok_or_else(|| anyhow!("Incomplete PSBT"))?;
        let txid = self
            .bitcoind()?
            .send_raw_transaction(&tx)
            .with_context(|| "Failed to send raw transaction")?;
        println!("Payjoin sent. TXID: {}", txid);
        Ok(txid)
    }
}

fn try_contributing_inputs(
    payjoin: &mut payjoin::receive::ProvisionalProposal,
    bitcoind: &bitcoincore_rpc::Client,
) -> Result<()> {
    use bitcoin::OutPoint;

    let available_inputs = bitcoind
        .list_unspent(None, None, None, None, None)
        .context("Failed to list unspent from bitcoind")?;
    let candidate_inputs: HashMap<Amount, OutPoint> = available_inputs
        .iter()
        .map(|i| (i.amount, OutPoint { txid: i.txid, vout: i.vout }))
        .collect();

    let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
    let selected_utxo = available_inputs
        .iter()
        .find(|i| i.txid == selected_outpoint.txid && i.vout == selected_outpoint.vout)
        .context("This shouldn't happen. Failed to retrieve the privacy preserving utxo from those we provided to the seclector.")?;
    log::debug!("selected utxo: {:#?}", selected_utxo);

    //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
    let txo_to_contribute = bitcoin::TxOut {
        value: selected_utxo.amount.to_sat(),
        script_pubkey: selected_utxo.script_pub_key.clone(),
    };
    let outpoint_to_contribute =
        bitcoin::OutPoint { txid: selected_utxo.txid, vout: selected_utxo.vout };
    payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);
    Ok(())
}

struct Headers<'a>(&'a hyper::HeaderMap);
impl payjoin::receive::Headers for Headers<'_> {
    fn get_header(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|v| v.to_str()).transpose().ok().flatten()
    }
}

fn serialize_psbt(psbt: &Psbt) -> String { base64::encode(psbt.serialize()) }

#[cfg(feature = "danger-local-https")]
fn http_agent() -> Result<reqwest::Client> { Ok(http_agent_builder()?.build()?) }

#[cfg(not(feature = "danger-local-https"))]
fn http_agent() -> Result<reqwest::Client> { Ok(reqwest::Client::new()) }

#[cfg(feature = "danger-local-https")]
fn http_agent_builder() -> Result<reqwest::ClientBuilder> {
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;

    let cert_der = read_local_cert()?;
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(CertificateDer::from(cert_der.as_slice()))?;
    Ok(reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der.as_slice())?))
}

#[cfg(feature = "danger-local-https")]
fn read_local_cert() -> Result<Vec<u8>> {
    let mut local_cert_path = std::env::temp_dir();
    local_cert_path.push(LOCAL_CERT_FILE);
    Ok(std::fs::read(local_cert_path)?)
}

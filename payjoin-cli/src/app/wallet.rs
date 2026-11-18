use std::collections::HashMap;
#[cfg(feature = "v2")]
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Context, Result};
use bitcoind_async_client::corepc_types::model::ListUnspentItem;
use bitcoind_async_client::traits::{Broadcaster, Reader, Signer, Wallet};
use bitcoind_async_client::types::{CreateRawTransactionOutput, WalletCreateFundedPsbtOptions};
use bitcoind_async_client::{Auth, Client as AsyncBitcoinRpc};
use payjoin::bitcoin::psbt::{Input, Psbt};
use payjoin::bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Script, Transaction, TxIn, TxOut, Txid,
};
use payjoin::receive::InputPair;

/// One address entry from listreceivedbyaddress.
#[cfg(feature = "v2")]
#[derive(Debug, serde::Deserialize)]
struct ReceivedByAddress {
    txids: Vec<String>,
}

/// Bitcoin Core 32 returns a version 2 PSBT from `walletcreatefundedpsbt`
/// unless asked otherwise.
const PSBT_V2_DEFAULT_CORE_VERSION: u64 = 320000;

/// Whether a node of this version, in Bitcoin Core's numeric format, returns
/// version 2 PSBTs by default.
fn defaults_to_psbt_v2(core_version: u64) -> bool { core_version >= PSBT_V2_DEFAULT_CORE_VERSION }

/// Builds the walletcreatefundedpsbt arguments that request a version 0 PSBT
/// and let the wallet choose the inputs.
///
/// The first five match what bitcoind-async-client sends. Arguments: inputs,
/// outputs, locktime, options, bip32derivs, version, psbt_version.
fn funded_psbt_v0_params(
    outputs: &[CreateRawTransactionOutput],
    locktime: u32,
    options: &WalletCreateFundedPsbtOptions,
) -> Result<[serde_json::Value; 7]> {
    Ok([
        serde_json::json!([]),
        serde_json::to_value(outputs).context("Failed to serialize outputs")?,
        serde_json::json!(locktime),
        serde_json::to_value(options).context("Failed to serialize options")?,
        serde_json::Value::Null,
        serde_json::Value::Null,
        serde_json::json!(0),
    ])
}

/// The part of the getnetworkinfo result used to tell Bitcoin Core versions
/// apart.
#[derive(Debug, serde::Deserialize)]
struct NetworkInfo {
    version: u64,
}

/// The part of the walletcreatefundedpsbt result used by `create_psbt`.
#[derive(Debug, serde::Deserialize)]
struct FundedPsbt {
    psbt: String,
}

#[derive(Clone)]
pub struct BitcoindWallet {
    rpc: Arc<AsyncBitcoinRpc>,
    /// The node's version as reported by getnetworkinfo, fetched on first use.
    core_version: Arc<OnceLock<u64>>,
}

impl BitcoindWallet {
    pub async fn new(config: &crate::app::config::BitcoindConfig) -> Result<Self> {
        let auth = match &config.cookie {
            Some(cookie) if cookie.as_os_str().is_empty() =>
                return Err(anyhow!(
                    "Cookie authentication enabled but no cookie path provided in config.toml"
                )),
            Some(cookie) => Auth::CookieFile(cookie.into()),
            None => Auth::UserPass(config.rpcuser.clone(), config.rpcpassword.clone()),
        };

        let rpc = AsyncBitcoinRpc::new(config.rpchost.to_string(), auth, None, None, None)?;

        Ok(Self { rpc: Arc::new(rpc), core_version: Arc::new(OnceLock::new()) })
    }
}

impl BitcoindWallet {
    /// Returns the node's version in Bitcoin Core's numeric format, e.g.
    /// 320100 for 32.1.0.
    ///
    /// The node is asked once and the answer is reused.
    fn core_version(&self) -> Result<u64> {
        if let Some(version) = self.core_version.get() {
            return Ok(*version);
        }
        let info: NetworkInfo = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.call_raw("getnetworkinfo", &[]).await })
        })
        .context("Failed to get the node version")?;
        Ok(*self.core_version.get_or_init(|| info.version))
    }

    /// Create a PSBT with the given outputs and fee rate
    pub fn create_psbt(
        &self,
        outputs: HashMap<String, Amount>,
        fee_rate: FeeRate,
        lock_unspent: bool,
    ) -> Result<Psbt> {
        tracing::debug!("Fee rate sat/vb: {}", fee_rate);

        let options = WalletCreateFundedPsbtOptions {
            fee_rate: Some(fee_rate),
            lock_unspents: Some(lock_unspent),
            replaceable: None,
            conf_target: None,
        };

        // Set locktime to current block height for anti-fee-sniping
        // This is to follow wallet fingerprinting best practices and set and opinionated
        // default for external wallet integrations to follow along with
        let locktime = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { self.rpc.get_block_count().await })
        })? as u32;

        let outputs = outputs
            .iter()
            .map(|(k, v)| CreateRawTransactionOutput::AddressAmount {
                address: k.clone(),
                amount: v.to_btc(),
            })
            .collect::<Vec<_>>();

        // Sync wrapper around async call - use tokio handle to avoid deadlock
        let funded = if defaults_to_psbt_v2(self.core_version()?) {
            // rust-bitcoin cannot parse the version 2 PSBT this node returns
            // by default.
            // TODO: use the typed call once bitcoind-async-client can pass
            // psbt_version.
            let params = funded_psbt_v0_params(&outputs, locktime, &options)?;
            let result: FundedPsbt = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { self.rpc.call_raw("walletcreatefundedpsbt", &params).await })
            })
            .context("Failed to create funded PSBT")?;
            result.psbt
        } else {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.rpc
                        .wallet_create_funded_psbt(
                            &[], // inputs
                            &outputs,
                            Some(locktime),
                            Some(options),
                            None,
                        )
                        .await
                })
            })?
            .psbt
            .to_string()
        };

        let processed = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.wallet_process_psbt(&funded, None, None, None).await })
        })?
        .psbt;

        Ok(processed)
    }

    /// Process a PSBT, validating and signing inputs owned by this wallet
    ///
    /// Does not include bip32 derivations in the PSBT
    pub fn process_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
        let psbt_str = psbt.to_string();
        let processed = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.rpc.wallet_process_psbt(&psbt_str, Some(true), None, None).await
            })
        })?;
        Ok(processed.psbt)
    }

    pub fn can_broadcast(&self, tx: &Transaction) -> Result<bool> {
        let mempool_results = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.test_mempool_accept(tx).await })
        })?;

        mempool_results
            .results
            .first()
            .map(|result| result.reject_reason.is_none())
            .ok_or_else(|| anyhow!("No mempool results returned on broadcast check"))
    }

    /// Broadcast a raw transaction
    pub fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.send_raw_transaction(tx, None).await })
        })
        .context("Failed to broadcast transaction")
    }

    /// Check if an outpoint belongs to this wallet.
    ///
    /// The scriptPubKey is resolved from the wallet's own record of the funding
    /// transaction and then checked for key ownership. This covers coins that
    /// `listunspent` omits, such as locked and unconfirmed coins.
    pub fn is_my_outpoint(&self, outpoint: &OutPoint) -> Result<bool> {
        let funding_tx = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match self.rpc.get_transaction(&outpoint.txid).await {
                    Ok(res) => Ok(Some(res.tx)),
                    Err(e) if e.is_tx_not_found() => Ok(None),
                    Err(e) => Err(e),
                }
            })
        })
        .context("Failed to look up outpoint funding transaction")?;
        match funding_tx.as_ref().and_then(|tx| tx.output.get(outpoint.vout as usize)) {
            Some(txout) => self.is_mine(&txout.script_pubkey),
            None => Ok(false),
        }
    }

    /// Check if a script belongs to this wallet.
    pub fn is_mine(&self, script: &Script) -> Result<bool> {
        if let Ok(address) = Address::from_script(script, self.network()?) {
            let info = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { self.rpc.get_address_info(&address).await })
            })
            .context("Failed to get address info")?;
            Ok(info.is_mine)
        } else {
            Ok(false)
        }
    }

    /// Returns a wallet transaction and its confirmation count, which is
    /// negative if it conflicts with a confirmed transaction.
    #[cfg(feature = "v2")]
    pub fn get_wallet_transaction(&self, txid: &Txid) -> Result<Option<(Transaction, i64)>> {
        let res = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match self.rpc.get_transaction(txid).await {
                    Ok(rpc_res) => Ok(Some((rpc_res.tx, rpc_res.confirmations))),
                    Err(e) if e.is_tx_not_found() => Ok(None),
                    Err(e) => Err(e),
                }
            })
        })?;
        Ok(res)
    }

    /// Returns the txids of all wallet transactions paying `address`,
    /// including unconfirmed ones.
    #[cfg(feature = "v2")]
    pub fn txids_paying(&self, address: &Address) -> Result<Vec<Txid>> {
        // bitcoind-async-client has no wrapper for listreceivedbyaddress.
        // Arguments: minconf, include_empty, include_watchonly, address_filter.
        let params = [
            serde_json::json!(0),
            serde_json::json!(false),
            serde_json::json!(true),
            serde_json::json!(address.to_string()),
        ];
        let received: Vec<ReceivedByAddress> = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.call_raw("listreceivedbyaddress", &params).await })
        })
        .context("Failed to list transactions received by address")?;

        received
            .into_iter()
            .flat_map(|entry| entry.txids)
            .map(|txid| Txid::from_str(&txid).context("Invalid txid from listreceivedbyaddress"))
            .collect()
    }

    /// Get a new address from the wallet
    pub fn get_new_address(&self) -> Result<Address> {
        let addr = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { self.rpc.get_new_address().await })
        })
        .context("Failed to get new address")?;
        Ok(addr)
    }

    /// List unspent UTXOs
    pub fn list_unspent(&self) -> Result<Vec<InputPair>> {
        let unspent = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.list_unspent(None, None, None, None, None).await })
        })
        .context("Failed to list unspent")?;
        // Skip UTXOs whose input weight cannot be predicted before signing
        // (e.g. P2WSH, legacy P2SH, bare scripts) rather than failing the
        // whole candidate list.
        let candidate_inputs = unspent
            .0
            .into_iter()
            .filter_map(|utxo| match input_pair_from_corepc(utxo) {
                Ok(pair) => Some(pair),
                Err(e) => {
                    tracing::warn!("Skipping UTXO unusable for payjoin: {e:#}");
                    None
                }
            })
            .collect();
        Ok(candidate_inputs)
    }

    /// Check if wallet has any spendable UTXOs
    pub fn has_spendable_utxos(&self) -> Result<bool> {
        let unspent = self.list_unspent()?;
        Ok(!unspent.is_empty())
    }

    /// Get the network this wallet is operating on
    pub fn network(&self) -> Result<Network> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { self.rpc.network().await })
        })
        .map_err(|e| anyhow!("Failed to get blockchain info: {e}"))
    }
}

pub fn input_pair_from_corepc(utxo: ListUnspentItem) -> Result<InputPair> {
    let txout = TxOut {
        value: Amount::from_btc(utxo.amount.to_btc()).expect("Valid amount"),
        script_pubkey: utxo.script_pubkey,
    };
    let outpoint = OutPoint { txid: utxo.txid, vout: utxo.vout };

    if txout.script_pubkey.is_p2tr() {
        // bitcoin core wallets spend the taproot key path by default
        return InputPair::new_p2tr_keyspend(txout, outpoint)
            .context("Failed to create taproot key-spend input pair");
    }

    let psbtin = Input {
        // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
        // witness_utxo, even for non-witness inputs
        witness_utxo: Some(txout),
        redeem_script: utxo.redeem_script,
        ..Default::default()
    };
    let txin = TxIn { previous_output: outpoint, ..Default::default() };
    InputPair::new(txin, psbtin, None).context("Failed to create input pair")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psbt_v2_is_the_default_from_core_32() {
        assert!(!defaults_to_psbt_v2(290000));
        assert!(!defaults_to_psbt_v2(310100));
        assert!(defaults_to_psbt_v2(320000));
        assert!(defaults_to_psbt_v2(320100));
    }

    #[test]
    fn funded_psbt_params_request_version_0() -> Result<()> {
        let outputs = [CreateRawTransactionOutput::AddressAmount {
            address: "bcrt1q0ql9q6egpxx52vv8fm3xhhgz2cxr874tgfznc5".to_string(),
            amount: 0.001,
        }];
        let options = WalletCreateFundedPsbtOptions {
            fee_rate: Some(FeeRate::from_sat_per_kwu(375)),
            lock_unspents: Some(true),
            replaceable: None,
            conf_target: None,
        };

        let params = funded_psbt_v0_params(&outputs, 101, &options)?;

        assert_eq!(params[0], serde_json::json!([]));
        assert_eq!(
            params[1],
            serde_json::json!([{ "bcrt1q0ql9q6egpxx52vv8fm3xhhgz2cxr874tgfznc5": 0.001 }])
        );
        assert_eq!(params[2], serde_json::json!(101));
        // 375 sat/kwu is 1.5 sat/vB, the unit of Bitcoin Core's fee_rate option.
        assert_eq!(params[3], serde_json::json!({ "fee_rate": 1.5, "lockUnspents": true }));
        assert_eq!(params[4], serde_json::Value::Null);
        assert_eq!(params[5], serde_json::Value::Null);
        assert_eq!(params[6], serde_json::json!(0));
        Ok(())
    }
}

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use payjoin::bitcoin::consensus::encode::{deserialize, serialize_hex};
use payjoin::bitcoin::consensus::Encodable;
use payjoin::bitcoin::psbt::{Input, Psbt};
use payjoin::bitcoin::{
    self, Address, Amount, FeeRate, Network, OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut,
    Txid,
};
use payjoin::receive::InputPair;
use serde_json::json;

use crate::app::rpc::{AsyncBitcoinRpc, Auth};

/// Implementation of PayjoinWallet for bitcoind using async RPC client
#[derive(Clone)]
pub struct BitcoindWallet {
    rpc: Arc<AsyncBitcoinRpc>,
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

        let rpc = AsyncBitcoinRpc::new(config.rpchost.to_string(), auth).await?;

        Ok(Self { rpc: Arc::new(rpc) })
    }
}

impl BitcoindWallet {
    /// Create a PSBT with the given outputs and fee rate
    pub fn create_psbt(
        &self,
        outputs: HashMap<String, Amount>,
        fee_rate: FeeRate,
        lock_unspent: bool,
    ) -> Result<Psbt> {
        let fee_sat_per_vb = fee_rate.to_sat_per_vb_ceil();
        log::debug!("Fee rate sat/vb: {}", fee_sat_per_vb);

        let options = json!({
            "lockUnspents": lock_unspent,
            "fee_rate": fee_sat_per_vb
        });

        // Sync wrapper around async call - use tokio handle to avoid deadlock
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.rpc
                    .wallet_create_funded_psbt(
                        &[], // inputs
                        &outputs,
                        None, // locktime
                        Some(options),
                        None,
                    )
                    .await
            })
        })?;

        let processed = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.rpc.wallet_process_psbt(&result.psbt, None, None, None).await
            })
        })?;

        Psbt::from_str(&processed.psbt).context("Failed to load PSBT from base64")
    }

    /// Process a PSBT, validating and signing inputs owned by this wallet
    ///
    /// Does not include bip32 derivations in the PSBT
    pub fn process_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
        let psbt_str = psbt.to_string();
        let processed = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.rpc.wallet_process_psbt(&psbt_str, None, None, Some(false)).await
            })
        })
        .context("Failed to process PSBT")?;
        Psbt::from_str(&processed.psbt).context("Failed to parse processed PSBT")
    }

    /// Finalize a PSBT and extract the transaction
    pub fn finalize_psbt(&self, psbt: &Psbt) -> Result<Transaction> {
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.finalize_psbt(&psbt.to_string(), Some(true)).await })
        })
        .context("Failed to finalize PSBT")?;
        let hex_str = result.hex.ok_or_else(|| anyhow!("Incomplete PSBT"))?;
        use bitcoin::hex::FromHex;
        let hex_bytes = Vec::<u8>::from_hex(&hex_str).context("Failed to decode hex")?;
        let tx = deserialize(&hex_bytes)?;
        Ok(tx)
    }

    pub fn can_broadcast(&self, tx: &Transaction) -> Result<bool> {
        let raw_tx = serialize_hex(&tx);
        let mempool_results = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.test_mempool_accept(&[raw_tx]).await })
        })?;

        mempool_results
            .first()
            .map(|result| result.allowed)
            .ok_or_else(|| anyhow!("No mempool results returned on broadcast check"))
    }

    /// Broadcast a raw transaction
    pub fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid> {
        let mut serialized_tx = Vec::new();
        tx.consensus_encode(&mut serialized_tx)?;
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.send_raw_transaction(&serialized_tx).await })
        })
        .context("Failed to broadcast transaction")
    }

    /// Check if a script belongs to this wallet
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

    /// Get a new address from the wallet
    pub fn get_new_address(&self) -> Result<Address> {
        let addr = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.get_new_address(None, None).await })
        })
        .context("Failed to get new address")?;
        Ok(addr.assume_checked())
    }

    /// List unspent UTXOs
    pub fn list_unspent(&self) -> Result<Vec<InputPair>> {
        let unspent = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.list_unspent(None, None, None, None, None).await })
        })
        .context("Failed to list unspent")?;
        Ok(unspent.into_iter().map(input_pair_from_corepc).collect())
    }

    /// Get the network this wallet is operating on
    pub fn network(&self) -> Result<Network> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { self.rpc.network().await })
        })
        .map_err(|_| anyhow!("Failed to get blockchain info"))
    }
}

pub fn input_pair_from_corepc(utxo: crate::app::rpc::ListUnspentResult) -> InputPair {
    let psbtin = Input {
        // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
        // witness_utxo, even for non-witness inputs
        witness_utxo: Some(TxOut {
            value: Amount::from_btc(utxo.amount).expect("Valid amount"),
            script_pubkey: ScriptBuf::from_hex(&utxo.script_pubkey).expect("Valid script"),
        }),
        redeem_script: utxo
            .redeem_script
            .as_ref()
            .map(|s| ScriptBuf::from_hex(s).expect("Valid script")),
        witness_script: None, // Not available in this version
        ..Default::default()
    };
    let txin = TxIn {
        previous_output: OutPoint { txid: utxo.txid.parse().expect("Valid txid"), vout: utxo.vout },
        ..Default::default()
    };
    InputPair::new(txin, psbtin, None).expect("Input pair should be valid")
}

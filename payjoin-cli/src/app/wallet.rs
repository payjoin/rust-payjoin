use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use crate::app::rpc::{AsyncBitcoinRpc, Auth};
use anyhow::{anyhow, Context, Result};
use payjoin::bitcoin::consensus::encode::{deserialize, serialize_hex};
use payjoin::bitcoin::consensus::Encodable;
use payjoin::bitcoin::psbt::{Input, Psbt};
use payjoin::bitcoin::{
    self, Address, Amount, Denomination, FeeRate, Network, OutPoint, Script, ScriptBuf,
    Transaction, TxIn, TxOut, Txid,
};
use payjoin::receive::InputPair;
use serde_json::json;

/// Implementation of PayjoinWallet for bitcoind using async RPC client with sync wrapper
#[derive(Clone)]
pub struct BitcoindWallet {
    rpc: Arc<AsyncBitcoinRpc>,
    runtime_handle: tokio::runtime::Handle,
}

impl BitcoindWallet {
    pub fn new(config: &crate::app::config::BitcoindConfig) -> Result<Self> {
        let auth = match &config.cookie {
            Some(cookie) if cookie.as_os_str().is_empty() => {
                return Err(anyhow!(
                    "Cookie authentication enabled but no cookie path provided in config.toml"
                ))
            }
            Some(cookie) => Auth::CookieFile(cookie.into()),
            None => Auth::UserPass(config.rpcuser.clone(), config.rpcpassword.clone()),
        };

        let rpc = AsyncBitcoinRpc::new(config.rpchost.to_string(), auth)?;
        let runtime_handle = tokio::runtime::Handle::current();

        Ok(Self { rpc: Arc::new(rpc), runtime_handle })
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
        let fee_sat_per_kvb =
            fee_rate.to_sat_per_kwu().checked_mul(4).ok_or_else(|| anyhow!("Invalid fee rate"))?;
        let fee_per_kvb = Amount::from_sat(fee_sat_per_kvb);
        log::debug!("Fee rate sat/kvb: {}", fee_per_kvb.display_in(Denomination::Satoshi));

        let options = json!({
            "lockUnspents": lock_unspent,
            "feeRate": fee_per_kvb.to_btc()
        });

        // Sync wrapper around async call
        let result = self.runtime_handle.block_on(self.rpc.wallet_create_funded_psbt(
            &[], // inputs
            &outputs,
            None, // locktime
            Some(options),
            None,
        ))?;

        let processed = self.runtime_handle.block_on(self.rpc.wallet_process_psbt(
            &result.psbt,
            None,
            None,
            None,
        ))?;

        Psbt::from_str(&processed.psbt).context("Failed to load PSBT from base64")
    }

    /// Process a PSBT, validating and signing inputs owned by this wallet
    ///
    /// Does not include bip32 derivations in the PSBT
    pub fn process_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
        let psbt_str = psbt.to_string();
        let processed = self
            .runtime_handle
            .block_on(self.rpc.wallet_process_psbt(&psbt_str, None, None, Some(false)))
            .context("Failed to process PSBT")?;
        Psbt::from_str(&processed.psbt).context("Failed to parse processed PSBT")
    }

    /// Finalize a PSBT and extract the transaction
    pub fn finalize_psbt(&self, psbt: &Psbt) -> Result<Transaction> {
        let result = self
            .runtime_handle
            .block_on(self.rpc.finalize_psbt(&psbt.to_string(), Some(true)))
            .context("Failed to finalize PSBT")?;
        let hex_str = result.hex.ok_or_else(|| anyhow!("Incomplete PSBT"))?;
        use bitcoin::hex::FromHex;
        let hex_bytes = Vec::<u8>::from_hex(&hex_str).context("Failed to decode hex")?;
        let tx = deserialize(&hex_bytes)?;
        Ok(tx)
    }

    pub fn can_broadcast(&self, tx: &Transaction) -> Result<bool> {
        let raw_tx = serialize_hex(&tx);
        let mempool_results =
            self.runtime_handle.block_on(self.rpc.test_mempool_accept(&[raw_tx]))?;
        match mempool_results.first() {
            Some(result) => {
                if let Some(first_result) = result.results.first() {
                    Ok(first_result.allowed)
                } else {
                    Ok(false)
                }
            }
            None => Err(anyhow!("No mempool results returned on broadcast check",)),
        }
    }

    /// Broadcast a raw transaction
    pub fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid> {
        let mut serialized_tx = Vec::new();
        tx.consensus_encode(&mut serialized_tx)?;
        self.runtime_handle
            .block_on(self.rpc.send_raw_transaction(&serialized_tx))
            .context("Failed to broadcast transaction")
    }

    /// Check if a script belongs to this wallet
    pub fn is_mine(&self, script: &Script) -> Result<bool> {
        if let Ok(address) = Address::from_script(script, self.network()?) {
            let info = self
                .runtime_handle
                .block_on(self.rpc.get_address_info(&address))
                .context("Failed to get address info")?;
            Ok(info.is_mine)
        } else {
            Ok(false)
        }
    }

    /// Get a new address from the wallet
    pub fn get_new_address(&self) -> Result<Address> {
        let addr = self
            .runtime_handle
            .block_on(self.rpc.get_new_address(None, None))
            .context("Failed to get new address")?;
        Ok(addr)
    }

    /// List unspent UTXOs
    pub fn list_unspent(&self) -> Result<Vec<InputPair>> {
        let unspent = self
            .runtime_handle
            .block_on(self.rpc.list_unspent(None, None, None, None, None))
            .context("Failed to list unspent")?;
        Ok(unspent.into_iter().map(input_pair_from_corepc).collect())
    }

    /// Get the network this wallet is operating on
    pub fn network(&self) -> Result<Network> {
        self.runtime_handle
            .block_on(self.rpc.network())
            .map_err(|_| anyhow!("Failed to get blockchain info"))
    }
}

pub fn input_pair_from_corepc(utxo: corepc_types::v26::ListUnspentItem) -> InputPair {
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
        previous_output: OutPoint {
            txid: utxo.txid.parse().expect("Valid txid"),
            vout: utxo.vout as u32,
        },
        ..Default::default()
    };
    InputPair::new(txin, psbtin, None).expect("Input pair should be valid")
}

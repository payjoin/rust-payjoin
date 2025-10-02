use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bitcoind_async_client::traits::{Broadcaster, Reader, Signer, Wallet};
use bitcoind_async_client::types::{
    CreateRawTransactionOutput, ListUnspent, WalletCreateFundedPsbtOptions,
};
use bitcoind_async_client::{Auth, Client as AsyncBitcoinRpc};
use payjoin::bitcoin::psbt::{Input, Psbt};
use payjoin::bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use payjoin::receive::InputPair;

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

        let rpc = AsyncBitcoinRpc::new(config.rpchost.to_string(), auth, None, None)?;

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
        tracing::debug!("Fee rate sat/vb: {}", fee_sat_per_vb);

        let options = WalletCreateFundedPsbtOptions {
            fee_rate: Some(fee_sat_per_vb as f64),
            lock_unspents: Some(lock_unspent),
            replaceable: None,
            conf_target: None,
        };

        // Sync wrapper around async call - use tokio handle to avoid deadlock
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.rpc
                    .wallet_create_funded_psbt(
                        &[], // inputs
                        &outputs
                            .iter()
                            .map(|(k, v)| CreateRawTransactionOutput::AddressAmount {
                                address: k.clone(),
                                amount: v.to_btc(),
                            })
                            .collect::<Vec<_>>(),
                        None, // locktime
                        Some(options),
                        None,
                    )
                    .await
            })
        })?;

        let processed = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.rpc.wallet_process_psbt(&result.psbt.to_string(), None, None, None).await
            })
        })?
        .psbt
        .expect("should have processed valid PSBT");

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
        processed.psbt.ok_or_else(|| anyhow!("Insane PSBT"))
    }

    pub fn can_broadcast(&self, tx: &Transaction) -> Result<bool> {
        let mempool_results = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.test_mempool_accept(tx).await })
        })?;

        mempool_results
            .first()
            .map(|result| result.reject_reason.is_none())
            .ok_or_else(|| anyhow!("No mempool results returned on broadcast check"))
    }

    /// Broadcast a raw transaction
    pub fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.send_raw_transaction(tx).await })
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
            Ok(info.is_mine.unwrap_or(false))
        } else {
            Ok(false)
        }
    }

    #[cfg(feature = "v2")]
    pub fn is_outpoint_spent(&self, outpoint: &OutPoint) -> Result<bool> {
        let _ = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                // Note: explicitly ignore txouts in the mempool. Those should be considered spent for our purposes
                .block_on(async {
                    match self.rpc.get_tx_out(&outpoint.txid, outpoint.vout, false).await {
                        Ok(_) => Ok(true),
                        Err(e) =>
                            if e.is_missing_or_invalid_input() {
                                Ok(false)
                            } else {
                                Err(e)
                            },
                    }
                })
        })?;
        Ok(true)
    }

    #[cfg(feature = "v2")]
    pub fn get_raw_transaction(
        &self,
        txid: &Txid,
    ) -> Result<Option<payjoin::bitcoin::Transaction>> {
        let raw_tx = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match self.rpc.get_transaction(txid).await {
                    Ok(tx) => Ok(Some(tx.hex)),
                    Err(e) =>
                        if e.is_tx_not_found() {
                            Ok(None)
                        } else {
                            Err(e)
                        },
                }
            })
        })?;
        Ok(raw_tx)
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

pub fn input_pair_from_corepc(utxo: ListUnspent) -> InputPair {
    let psbtin = Input {
        // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
        // witness_utxo, even for non-witness inputs
        witness_utxo: Some(TxOut {
            value: utxo.amount,
            script_pubkey: ScriptBuf::from_hex(&utxo.script_pubkey).expect("Valid script"),
        }),
        redeem_script: None,
        witness_script: None, // Not available in this version
        ..Default::default()
    };
    let txin = TxIn {
        previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
        ..Default::default()
    };
    InputPair::new(txin, psbtin, None).expect("Input pair should be valid")
}

use std::collections::HashMap;
use std::sync::Arc;

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

        let rpc = AsyncBitcoinRpc::new(config.rpchost.to_string(), auth, None, None, None)?;

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
        tracing::debug!("Fee rate sat/vb: {}", fee_rate);

        let options = WalletCreateFundedPsbtOptions {
            fee_rate: Some(fee_rate),
            lock_unspents: Some(lock_unspent),
            replaceable: None,
            conf_target: None,
        };

        // walletcreatefundedpsbt does not anti-fee-snipe; do it here.
        let info = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.rpc.get_blockchain_info().await })
        })?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is before the Unix epoch")
            .as_secs();
        let locktime =
            anti_fee_sniping_locktime(info.blocks, info.time, info.initial_block_download, now);

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
                        Some(locktime),
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

    #[cfg(feature = "v2")]
    pub fn get_raw_transaction(
        &self,
        txid: &Txid,
    ) -> Result<Option<payjoin::bitcoin::Transaction>> {
        let raw_tx = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match self.rpc.get_transaction(txid).await {
                    Ok(rpc_res) => Ok(Some(rpc_res.tx)),
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
        Ok(unspent.0.into_iter().map(input_pair_from_corepc).collect())
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

pub fn input_pair_from_corepc(utxo: ListUnspentItem) -> InputPair {
    let psbtin = Input {
        // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
        // witness_utxo, even for non-witness inputs
        witness_utxo: Some(TxOut {
            value: Amount::from_btc(utxo.amount.to_btc()).expect("Valid amount"),
            script_pubkey: utxo.script_pubkey,
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

/// nLockTime mirroring Core's `DiscourageFeeSniping`/`IsCurrentForAntiFeeSniping`: the tip,
/// occasionally backdated for delayed-broadcast privacy, or 0 on a stale/IBD tip to avoid a
/// stale-locktime fingerprint.
fn anti_fee_sniping_locktime(
    tip_height: u32,
    tip_time: Option<u32>,
    in_ibd: bool,
    now_secs: u64,
) -> u32 {
    const MAX_TIP_AGE_SECS: u64 = 8 * 60 * 60;
    let current = !in_ibd
        && tip_time.is_some_and(|t| now_secs.saturating_sub(u64::from(t)) <= MAX_TIP_AGE_SECS);
    if !current {
        return 0;
    }
    use payjoin::bitcoin::key::rand::Rng;
    let mut rng = payjoin::bitcoin::key::rand::thread_rng();
    if rng.gen_range(0..10) == 0 {
        tip_height.saturating_sub(rng.gen_range(0..100))
    } else {
        tip_height
    }
}

#[cfg(test)]
mod tests {
    use super::anti_fee_sniping_locktime;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn fresh_tip_covers_both_branches() {
        let tip = 800_000;
        let lts: Vec<u32> = (0..1_000)
            .map(|_| anti_fee_sniping_locktime(tip, Some(NOW as u32), false, NOW))
            .collect();
        assert!(
            lts.iter().all(|&lt| (tip - 99..=tip).contains(&lt)),
            "a locktime fell outside [{}, {tip}]",
            tip - 99
        );
        assert!(lts.contains(&tip), "never hit the no-backdate branch");
        assert!(lts.iter().any(|&lt| lt < tip), "never hit the backdate branch");
    }

    #[test]
    fn backdate_saturates_at_low_tip() {
        let tip = 50;
        for _ in 0..1_000 {
            let lt = anti_fee_sniping_locktime(tip, Some(NOW as u32), false, NOW);
            assert!(lt <= tip, "locktime {lt} exceeds tip {tip} (underflow?)");
        }
    }

    #[test]
    fn stale_ibd_or_unknown_tip_returns_zero() {
        let tip = 800_000;
        let stale = (NOW - 8 * 60 * 60 - 1) as u32;
        assert_eq!(anti_fee_sniping_locktime(tip, Some(stale), false, NOW), 0);
        assert_eq!(anti_fee_sniping_locktime(tip, Some(NOW as u32), true, NOW), 0);
        assert_eq!(anti_fee_sniping_locktime(tip, None, false, NOW), 0);
    }
}

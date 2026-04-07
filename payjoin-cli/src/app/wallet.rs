use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use payjoin::bitcoin::psbt::Psbt as PayjoinPsbt;
use payjoin::bitcoin::{Address, Amount, FeeRate, Network, Script, Transaction, Txid};
use payjoin::receive::InputPair;

pub trait PayjoinWallet: Send + Sync {
    fn create_psbt(
        &self,
        outputs: HashMap<String, Amount>,
        fee_rate: FeeRate,
        lock_unspent: bool,
    ) -> Result<PayjoinPsbt>;

    fn process_psbt(&self, psbt: &PayjoinPsbt) -> Result<PayjoinPsbt>;

    fn can_broadcast(&self, tx: &Transaction) -> Result<bool>;

    fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid>;

    fn is_mine(&self, script: &Script) -> Result<bool>;

    #[cfg(feature = "v2")]
    fn get_raw_transaction(&self, txid: &Txid) -> Result<Option<payjoin::bitcoin::Transaction>>;

    fn get_new_address(&self) -> Result<Address>;

    fn list_unspent(&self) -> Result<Vec<InputPair>>;

    fn has_spendable_utxos(&self) -> Result<bool>;

    fn network(&self) -> Result<Network>;
}

#[cfg(feature = "esplora")]
mod esplora_backend {
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    use anyhow::{anyhow, Result};
    use bdk_esplora::esplora_client::Builder;
    use bdk_esplora::{esplora_client, EsploraAsyncExt};
    use bdk_wallet::bitcoin::ScriptBuf;
    use bdk_wallet::signer::SignOptions;
    use bdk_wallet::{KeychainKind, Wallet as BdkWalletInner};
    use payjoin::bitcoin::psbt::{Input, Psbt};
    use payjoin::bitcoin::{
        Address, Amount, FeeRate, Network, OutPoint, Transaction, TxIn, TxOut, Txid,
    };
    use payjoin::receive::InputPair;

    use crate::app::wallet::PayjoinWallet;

    #[derive(Clone)]
    pub struct BdkWallet {
        wallet: Arc<Mutex<BdkWalletInner>>,
        esplora_client: Arc<esplora_client::AsyncClient>,
    }

    impl BdkWallet {
        pub fn new(
            descriptor: &str,
            change_descriptor: Option<&str>,
            network: Network,
            esplora_url: &str,
        ) -> Result<Self> {
            let bdk_network = match network {
                Network::Bitcoin => bdk_wallet::bitcoin::Network::Bitcoin,
                Network::Testnet => bdk_wallet::bitcoin::Network::Testnet,
                Network::Signet => bdk_wallet::bitcoin::Network::Signet,
                Network::Regtest => bdk_wallet::bitcoin::Network::Regtest,
                Network::Testnet4 => bdk_wallet::bitcoin::Network::Testnet4,
            };

            let change_desc = super::derive_change_descriptor(descriptor, change_descriptor);

            let wallet = BdkWalletInner::create(descriptor.to_owned(), change_desc)
                .network(bdk_network)
                .create_wallet_no_persist()
                .map_err(|e| anyhow!("Failed to create wallet: {}", e))?;

            let esplora_client = Builder::new(esplora_url)
                .build_async()
                .map_err(|e| anyhow!("Failed to create esplora client: {}", e))?;

            let this = Self {
                wallet: Arc::new(Mutex::new(wallet)),
                esplora_client: Arc::new(esplora_client),
            };
            this.sync()?;
            Ok(this)
        }

        pub fn sync(&self) -> Result<()> {
            let request = {
                let wallet = self.wallet.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
                wallet.start_full_scan()
            };

            let update = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.esplora_client
                        .full_scan(request, 10, 5)
                        .await
                        .map_err(|e| anyhow!("Failed to sync wallet: {}", e))
                })
            })?;

            let mut wallet = self.wallet.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            wallet.apply_update(update).map_err(|e| anyhow!("Failed to apply update: {}", e))?;
            Ok(())
        }
    }

    impl PayjoinWallet for BdkWallet {
        fn create_psbt(
            &self,
            outputs: HashMap<String, Amount>,
            fee_rate: FeeRate,
            _lock_unspent: bool,
        ) -> Result<Psbt> {
            let mut wallet = self.wallet.lock().map_err(|e| anyhow!("Lock error: {}", e))?;

            let mut builder = wallet.build_tx();
            for (address, amount) in outputs {
                let bdk_addr = bdk_wallet::bitcoin::Address::from_str(&address)
                    .map_err(|e| anyhow!("Invalid address: {}", e))?;
                let checked_addr = bdk_addr.assume_checked();
                builder.add_recipient(checked_addr.script_pubkey(), amount);
            }
            builder.fee_rate(fee_rate);

            let psbt =
                builder.finish().map_err(|e| anyhow!("Failed to build transaction: {}", e))?;
            let psbt_hex = psbt.to_string();
            let psbt: Psbt =
                Psbt::from_str(&psbt_hex).map_err(|e| anyhow!("Failed to parse PSBT: {}", e))?;
            Ok(psbt)
        }

        fn process_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
            let wallet = self.wallet.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            let psbt_hex = psbt.to_string();
            let mut bdk_psbt = bdk_wallet::bitcoin::Psbt::from_str(&psbt_hex)
                .map_err(|e| anyhow!("Failed to parse PSBT: {}", e))?;
            let sign_options = SignOptions { trust_witness_utxo: true, ..SignOptions::default() };
            // In payjoin, sign() will return finalized=false because the
            // counterparty's inputs are not yet signed — that's fine. We only
            // need BDK to sign the inputs it owns.
            wallet
                .sign(&mut bdk_psbt, sign_options)
                .map_err(|e| anyhow!("Failed to sign PSBT: {}", e))?;
            let signed_psbt_hex = bdk_psbt.to_string();
            let signed_psbt: Psbt = Psbt::from_str(&signed_psbt_hex)
                .map_err(|e| anyhow!("Failed to parse signed PSBT: {}", e))?;
            Ok(signed_psbt)
        }

        fn can_broadcast(&self, _tx: &Transaction) -> Result<bool> { Ok(true) }

        fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid> {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.esplora_client
                        .broadcast(tx)
                        .await
                        .map_err(|e| anyhow!("Failed to broadcast transaction: {}", e))
                })
            })?;
            Ok(tx.compute_txid())
        }

        fn is_mine(&self, script: &payjoin::bitcoin::Script) -> Result<bool> {
            let wallet = self.wallet.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            let script = ScriptBuf::from_bytes(script.as_bytes().to_vec());
            Ok(wallet.is_mine(script))
        }

        #[cfg(feature = "v2")]
        fn get_raw_transaction(
            &self,
            _txid: &Txid,
        ) -> Result<Option<payjoin::bitcoin::Transaction>> {
            Ok(None)
        }

        fn get_new_address(&self) -> Result<Address> {
            let mut wallet = self.wallet.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            let address_info = wallet.reveal_next_address(KeychainKind::External);
            let addr_str = address_info.address.to_string();
            Ok(Address::from_str(&addr_str)?.assume_checked())
        }

        fn list_unspent(&self) -> Result<Vec<InputPair>> {
            let wallet = self.wallet.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            let unspents: Vec<_> = wallet.list_unspent().collect();

            unspents
                .into_iter()
                .map(|utxo| {
                    let psbtin = Input {
                        witness_utxo: Some(TxOut {
                            value: utxo.txout.value,
                            script_pubkey: utxo.txout.script_pubkey,
                        }),
                        ..Default::default()
                    };
                    let txin = TxIn {
                        previous_output: OutPoint {
                            txid: utxo.outpoint.txid,
                            vout: utxo.outpoint.vout,
                        },
                        ..Default::default()
                    };
                    InputPair::new(txin, psbtin, None)
                        .map_err(|e| anyhow!("Invalid input pair: {}", e))
                })
                .collect()
        }

        fn has_spendable_utxos(&self) -> Result<bool> {
            let unspent = self.list_unspent()?;
            Ok(!unspent.is_empty())
        }

        fn network(&self) -> Result<Network> {
            let wallet = self.wallet.lock().map_err(|e| anyhow!("Lock error: {}", e))?;
            match wallet.network() {
                bdk_wallet::bitcoin::Network::Bitcoin => Ok(Network::Bitcoin),
                bdk_wallet::bitcoin::Network::Testnet => Ok(Network::Testnet),
                bdk_wallet::bitcoin::Network::Signet => Ok(Network::Signet),
                bdk_wallet::bitcoin::Network::Regtest => Ok(Network::Regtest),
                _ => Ok(Network::Testnet),
            }
        }
    }

    pub use BdkWallet as BdkWalletImpl;
}

#[cfg(all(feature = "bitcoind", not(feature = "esplora")))]
mod bitcoind_backend {
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

    use super::PayjoinWallet;

    #[derive(Clone, Debug)]
    pub struct BitcoindWallet {
        rpc: Arc<AsyncBitcoinRpc>,
    }

    impl BitcoindWallet {
        pub fn new(config: &crate::app::config::BitcoindConfig) -> Result<Self> {
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

    impl PayjoinWallet for BitcoindWallet {
        fn create_psbt(
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

            let locktime = Some(tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { self.rpc.get_block_count().await })
            })? as u32);

            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.rpc
                        .wallet_create_funded_psbt(
                            &[],
                            &outputs
                                .iter()
                                .map(|(k, v)| CreateRawTransactionOutput::AddressAmount {
                                    address: k.clone(),
                                    amount: v.to_btc(),
                                })
                                .collect::<Vec<_>>(),
                            locktime,
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

        fn process_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
            let psbt_str = psbt.to_string();
            let processed = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.rpc.wallet_process_psbt(&psbt_str, Some(true), None, None).await
                })
            })?;
            Ok(processed.psbt)
        }

        fn can_broadcast(&self, tx: &Transaction) -> Result<bool> {
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

        fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid> {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { self.rpc.send_raw_transaction(tx).await })
            })
            .context("Failed to broadcast transaction")
        }

        fn is_mine(&self, script: &Script) -> Result<bool> {
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
        fn get_raw_transaction(
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

        fn get_new_address(&self) -> Result<Address> {
            let addr = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { self.rpc.get_new_address().await })
            })
            .context("Failed to get new address")?;
            Ok(addr)
        }

        fn list_unspent(&self) -> Result<Vec<InputPair>> {
            let unspent = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async { self.rpc.list_unspent(None, None, None, None, None).await })
            })
            .context("Failed to list unspent")?;
            Ok(unspent.0.into_iter().map(input_pair_from_corepc).collect())
        }

        fn has_spendable_utxos(&self) -> Result<bool> {
            let unspent = self.list_unspent()?;
            Ok(!unspent.is_empty())
        }

        fn network(&self) -> Result<Network> {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async { self.rpc.network().await })
            })
            .map_err(|e| anyhow!("Failed to get blockchain info: {e}"))
        }
    }

    pub(crate) fn input_pair_from_corepc(utxo: ListUnspentItem) -> InputPair {
        let psbtin = Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_btc(utxo.amount.to_btc()).expect("Valid amount"),
                script_pubkey: utxo.script_pubkey,
            }),
            redeem_script: None,
            witness_script: None,
            ..Default::default()
        };
        let txin = TxIn {
            previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
            ..Default::default()
        };
        InputPair::new(txin, psbtin, None).expect("Input pair should be valid")
    }

    pub use BitcoindWallet as BitcoindWalletImpl;
}

#[cfg(feature = "esplora")]
pub(crate) fn parse_network(name: Option<&str>) -> Result<Network> {
    use anyhow::anyhow;
    match name {
        // Mainnet currently disabled until an ohttp wrapper is available to encrypt
        // messages. https://github.com/bitcoindevkit/rust-esplora-client/pull/145
        Some("mainnet") | Some("bitcoin") | None => Err(anyhow!("Mainnet disabled for esplora")),
        Some("testnet") => Ok(Network::Testnet),
        Some("testnet4") => Ok(Network::Testnet4),
        Some("signet") => Ok(Network::Signet),
        Some("regtest") => Ok(Network::Regtest),
        Some(n) => Err(anyhow!("Unknown network: {}", n)),
    }
}

/// Derive a change descriptor from the receive descriptor when one is not
/// supplied. Assumes the BIP44-family `.../0/*` external chain convention
/// and rewrites that final step to `/1/*`. Handles both the raw-key form
/// (`tprv.../0/*`) and wrapped forms (`wpkh(tprv.../0/*)`), with or
/// without a trailing `#checksum`. The checksum is dropped on rewrite —
/// BDK recomputes it. If the descriptor does not match either shape it is
/// returned unchanged (BDK will then use the same keychain for both).
#[cfg(feature = "esplora")]
pub(crate) fn derive_change_descriptor(descriptor: &str, change: Option<&str>) -> String {
    if let Some(c) = change {
        return c.to_owned();
    }
    let body = descriptor.rsplit_once('#').map(|(b, _)| b).unwrap_or(descriptor);
    if let Some(base) = body.strip_suffix("/0/*") {
        format!("{base}/1/*")
    } else if let Some(inner) = body.strip_suffix(')') {
        if let Some(base) = inner.strip_suffix("/0/*") {
            format!("{base}/1/*)")
        } else {
            descriptor.to_owned()
        }
    } else {
        descriptor.to_owned()
    }
}

#[cfg(feature = "esplora")]
pub fn create_wallet(config: &super::config::Config) -> Result<Arc<dyn PayjoinWallet>> {
    use anyhow::anyhow;

    use crate::app::wallet::esplora_backend::BdkWalletImpl;
    let wallet_config = config
        .wallet
        .as_ref()
        .ok_or_else(|| anyhow!("wallet config required. Set --descriptor and --esplora-url"))?;
    let network = parse_network(wallet_config.network.as_deref())?;
    let descriptor = wallet_config
        .descriptor
        .as_ref()
        .ok_or_else(|| anyhow!("--descriptor required for esplora backend"))?;
    let esplora_url = wallet_config
        .esplora_url
        .as_ref()
        .ok_or_else(|| anyhow!("--esplora-url required for esplora backend"))?;
    Ok(Arc::new(BdkWalletImpl::new(
        descriptor,
        wallet_config.change_descriptor.as_deref(),
        network,
        esplora_url,
    )?))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "esplora")]
    use super::*;

    #[cfg(feature = "esplora")]
    #[test]
    fn parse_network_rejects_unknown() {
        let err = parse_network(Some("liquid")).unwrap_err();
        assert!(err.to_string().contains("Unknown network"));
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn derive_change_descriptor_cases() {
        // Explicit change descriptor overrides any derivation
        let receive = "wpkh(tprv.../0/*)";
        let change = Some("wpkh(tprv.../2/*)");
        assert_eq!(derive_change_descriptor(receive, change), "wpkh(tprv.../2/*)");

        // Raw `.../0/*` suffix should produce a change descriptor
        let receive = "[fingerprint/84h/1h/0h]tprvFOO/0/*";
        let change = None;
        assert_eq!(derive_change_descriptor(receive, change), "[fingerprint/84h/1h/0h]tprvFOO/1/*",);

        // Wrapped `wpkh(.../0/*)`.
        let receive = "wpkh([fingerprint/84h/1h/0h]tprvFOO/0/*)";
        let change = None;
        assert_eq!(
            derive_change_descriptor(receive, change),
            "wpkh([fingerprint/84h/1h/0h]tprvFOO/1/*)",
        );

        // Wrapped + checksum: checksum is dropped on rewrite.
        let receive = "wpkh([fingerprint/84h/1h/0h]tprvFOO/0/*)#abcd1234";
        let change = None;
        assert_eq!(
            derive_change_descriptor(receive, change),
            "wpkh([fingerprint/84h/1h/0h]tprvFOO/1/*)",
        );

        // No external-chain suffix is a direct passthrough.
        let receive = "wpkh(tprv.../*)";
        let change = None;
        assert_eq!(derive_change_descriptor(receive, change), "wpkh(tprv.../*)");
    }

    #[cfg(feature = "esplora")]
    #[test]
    fn bdk_wallet_new_rejects_invalid_descriptor() {
        // Constructing a BdkWallet with garbage should fail before any network
        // I/O is attempted, so this test is hermetic.
        use super::esplora_backend::BdkWallet;
        let res = BdkWallet::new("not a descriptor", None, Network::Regtest, "http://127.0.0.1:1");
        assert!(res.is_err());
    }

    #[cfg(all(feature = "bitcoind", not(feature = "esplora")))]
    #[test]
    fn bitcoind_wallet_new_rejects_empty_cookie() {
        use url::Url;

        use crate::app::config::BitcoindConfig;
        use crate::app::wallet::bitcoind_backend::BitcoindWalletImpl;
        let config = BitcoindConfig {
            rpchost: Url::parse("http://localhost").unwrap(),
            rpcuser: "user".to_string(),
            rpcpassword: "pass".to_string(),
            cookie: Some(std::path::PathBuf::from("")),
        };
        let result = BitcoindWalletImpl::new(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Cookie authentication enabled but no cookie path"));
    }
}

#[cfg(all(feature = "bitcoind", not(feature = "esplora")))]
pub fn create_wallet(config: &super::config::Config) -> Result<Arc<dyn PayjoinWallet>> {
    use crate::app::wallet::bitcoind_backend::BitcoindWalletImpl;
    Ok(Arc::new(BitcoindWalletImpl::new(&config.bitcoind)?))
}

#[cfg(all(not(feature = "esplora"), not(feature = "bitcoind")))]
pub fn create_wallet(_config: &super::config::Config) -> Result<Arc<dyn PayjoinWallet>> {
    Err(anyhow::anyhow!("No wallet backend enabled. Enable esplora or bitcoind feature."))
}

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use corepc_types::v26::{WalletCreateFundedPsbt, WalletProcessPsbt};
use payjoin::bitcoin::{Address, Amount, Network, Txid};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Authentication method for Bitcoin Core RPC
#[derive(Clone, Debug)]
pub enum Auth {
    UserPass(String, String),
    CookieFile(PathBuf),
}

/// Internal async Bitcoin RPC client using reqwest
pub struct AsyncBitcoinRpc {
    client: Client,
    url: String,
    username: String,
    password: String,
}

impl AsyncBitcoinRpc {
    pub async fn new(url: String, auth: Auth) -> Result<Self> {
        let client =
            Client::builder().use_rustls_tls().build().context("Failed to create HTTP client")?;

        // Load credentials once at initialization - no repeated file I/O
        let (username, password) = match auth {
            Auth::UserPass(user, pass) => (user, pass),
            Auth::CookieFile(path) => {
                let cookie = tokio::fs::read_to_string(&path)
                    .await
                    .with_context(|| format!("Failed to read cookie file: {path:?}"))?;
                let parts: Vec<&str> = cookie.trim().split(':').collect();
                if parts.len() != 2 {
                    return Err(anyhow!("Invalid cookie format in file: {path:?}"));
                }
                (parts[0].to_string(), parts[1].to_string())
            }
        };

        Ok(Self { client, url, username, password })
    }

    /// Get base URL without wallet path for blockchain-level calls
    fn get_base_url(&self) -> String {
        if let Some(pos) = self.url.find("/wallet/") {
            self.url[..pos].to_string()
        } else {
            self.url.clone()
        }
    }

    /// Make a JSON-RPC call to Bitcoin Core
    async fn call_rpc<T>(&self, method: &str, params: serde_json::Value) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        // Determine which URL to use based on the method
        // Blockchain/network calls go to base URL, wallet calls go to wallet URL
        let url = match method {
            "getblockchaininfo" | "getnetworkinfo" | "getmininginfo" | "getblockcount"
            | "getbestblockhash" | "getblock" | "getblockhash" | "gettxout" => self.get_base_url(),
            _ => self.url.clone(),
        };

        let request_body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let request = self
            .client
            .post(&url)
            .json(&request_body)
            .basic_auth(&self.username, Some(&self.password));

        let response =
            request.send().await.with_context(|| format!("RPC '{method}': connection failed"))?;

        let json = response
            .json::<RpcResponse<T>>()
            .await
            .with_context(|| format!("RPC '{method}': invalid response"))?;

        match json {
            RpcResponse::Success { result, .. } => Ok(result),
            RpcResponse::Error { error, .. } =>
                Err(anyhow!("RPC '{}' failed: {}", method, error.message)),
        }
    }

    pub async fn wallet_create_funded_psbt(
        &self,
        inputs: &[Value],
        outputs: &HashMap<String, Amount>,
        locktime: Option<u32>,
        options: Option<Value>,
        bip32derivs: Option<bool>,
    ) -> Result<WalletCreateFundedPsbt> {
        let outputs_btc: HashMap<String, f64> =
            outputs.iter().map(|(addr, amount)| (addr.clone(), amount.to_btc())).collect();

        let locktime = locktime.unwrap_or(0);
        let options = options.unwrap_or_else(|| json!({}));
        let bip32derivs = bip32derivs.unwrap_or(true);

        let params = json!([inputs, outputs_btc, locktime, options, bip32derivs]);
        self.call_rpc("walletcreatefundedpsbt", params).await
    }

    pub async fn wallet_process_psbt(
        &self,
        psbt: &str,
        sign: Option<bool>,
        sighash_type: Option<String>,
        bip32derivs: Option<bool>,
    ) -> Result<WalletProcessPsbt> {
        let sign = sign.unwrap_or(true);
        let sighash_type = sighash_type.unwrap_or_else(|| "ALL".to_string());
        let bip32derivs = bip32derivs.unwrap_or(true);

        let params = json!([psbt, sign, sighash_type, bip32derivs]);
        self.call_rpc("walletprocesspsbt", params).await
    }

    pub async fn finalize_psbt(
        &self,
        psbt: &str,
        extract: Option<bool>,
    ) -> Result<FinalizePsbtResult> {
        let extract = extract.unwrap_or(true);
        let params = json!([psbt, extract]);
        self.call_rpc("finalizepsbt", params).await
    }

    pub async fn test_mempool_accept(
        &self,
        rawtxs: &[String],
    ) -> Result<Vec<TestMempoolAcceptResult>> {
        let params = json!([rawtxs]);
        self.call_rpc("testmempoolaccept", params).await
    }

    pub async fn send_raw_transaction(&self, hex: &[u8]) -> Result<Txid> {
        use payjoin::bitcoin::hex::DisplayHex;
        let hex_string = hex.to_lower_hex_string();
        let params = json!([hex_string]);
        let txid_string: String = self.call_rpc("sendrawtransaction", params).await?;
        Ok(txid_string.parse()?)
    }

    pub async fn get_address_info(&self, address: &Address) -> Result<GetAddressInfoResult> {
        let params = json!([address.to_string()]);
        self.call_rpc("getaddressinfo", params).await
    }

    pub async fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<&str>,
    ) -> Result<Address<payjoin::bitcoin::address::NetworkUnchecked>> {
        let params = if label.is_none() && address_type.is_none() {
            json!([])
        } else {
            json!([label, address_type])
        };

        let address_string: String = self.call_rpc("getnewaddress", params).await?;
        let addr: payjoin::bitcoin::Address<payjoin::bitcoin::address::NetworkUnchecked> =
            address_string.parse().context("Failed to parse address")?;
        Ok(addr)
    }

    pub async fn list_unspent(
        &self,
        minconf: Option<u32>,
        maxconf: Option<u32>,
        addresses: Option<&[Address]>,
        include_unsafe: Option<bool>,
        query_options: Option<Value>,
    ) -> Result<Vec<ListUnspentResult>> {
        let addresses_str: Option<Vec<String>> =
            addresses.map(|addrs| addrs.iter().map(|a| a.to_string()).collect());
        let params = json!([minconf, maxconf, addresses_str, include_unsafe, query_options]);
        self.call_rpc("listunspent", params).await
    }

    pub async fn get_blockchain_info(&self) -> Result<serde_json::Value> {
        let params = json!([]);
        self.call_rpc("getblockchaininfo", params).await
    }

    pub async fn network(&self) -> Result<Network> {
        let info = self.get_blockchain_info().await?;
        let chain = info["chain"].as_str().ok_or_else(|| anyhow!("Missing chain field"))?;
        match chain {
            "main" => Ok(Network::Bitcoin),
            "test" => Ok(Network::Testnet),
            "regtest" => Ok(Network::Regtest),
            "signet" => Ok(Network::Signet),
            other => Err(anyhow!("Unknown network: {}", other)),
        }
    }
}

/// JSON-RPC response envelope
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum RpcResponse<T> {
    Success { result: T, error: Option<Value>, id: Value },
    Error { result: Option<Value>, error: RpcError, id: Value },
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcError {
    code: i32,
    message: String,
}

/// Result type for testmempoolaccept RPC call - minimal struct for our use case
#[derive(Debug, Deserialize)]
pub struct TestMempoolAcceptResult {
    pub allowed: bool,
    // Ignore additional fields that Bitcoin Core v29 may include
}

/// Result type for getaddressinfo RPC call - minimal struct for our use case
#[derive(Debug, Deserialize)]
pub struct GetAddressInfoResult {
    #[serde(rename = "ismine")]
    pub is_mine: bool,
}

/// Result type for listunspent RPC call - compatible with both v26 and v29+
#[derive(Debug, Deserialize)]
pub struct ListUnspentResult {
    pub txid: String,
    pub vout: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    pub amount: f64,
    // Optional fields for compatibility with newer Bitcoin Core versions
    #[serde(rename = "redeemScript")]
    pub redeem_script: Option<String>,
    // Ignore additional fields that Bitcoin Core v29+ may include
}

/// Result type for finalizepsbt RPC call - compatible with both v26 and v29+
#[derive(Debug, Deserialize)]
pub struct FinalizePsbtResult {
    pub hex: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const TEST_AMOUNT_SATS: u64 = 100_000;
    const INVALID_ADDRESS: &str = "invalid_bitcoin_address_12345";

    fn assert_rpc_error_format(error_msg: &str, method: &str, expected_keywords: &[&str]) {
        assert!(error_msg.contains(method));
        assert!(expected_keywords.iter().any(|&keyword| error_msg.contains(keyword)));
    }

    #[tokio::test]
    async fn test_rpc_error_messages_invalid_bitcoin_address() {
        use payjoin_test_utils::init_bitcoind;

        let bitcoind = init_bitcoind().expect("Bitcoin Core required for this test");
        let rpc_url = format!("http://127.0.0.1:{}", bitcoind.params.rpc_socket.port());
        let auth = Auth::CookieFile(bitcoind.params.cookie_file.clone());
        let rpc = AsyncBitcoinRpc::new(rpc_url, auth).await.unwrap();

        let outputs = HashMap::from([(
            INVALID_ADDRESS.to_string(),
            payjoin::bitcoin::Amount::from_sat(TEST_AMOUNT_SATS),
        )]);

        let error = rpc
            .wallet_create_funded_psbt(&[], &outputs, None, None, None)
            .await
            .expect_err("Should fail due to invalid address");
        let error_msg = error.to_string();
        println!("{error_msg}");

        assert_rpc_error_format(
            &error_msg,
            "walletcreatefundedpsbt",
            &["address", "Invalid", "invalid"],
        );
    }

    #[tokio::test]
    async fn test_rpc_error_messages_insufficient_funds() {
        use payjoin_test_utils::init_bitcoind;

        let bitcoind = init_bitcoind().expect("Bitcoin Core required for this test");
        let _wallet = bitcoind.create_wallet("empty_wallet").unwrap();
        let rpc_url =
            format!("http://127.0.0.1:{}/wallet/empty_wallet", bitcoind.params.rpc_socket.port());
        let auth = Auth::CookieFile(bitcoind.params.cookie_file.clone());
        let rpc = AsyncBitcoinRpc::new(rpc_url, auth).await.unwrap();

        let valid_address =
            rpc.get_new_address(None, None).await.unwrap().assume_checked_ref().to_string();
        let outputs =
            HashMap::from([(valid_address, payjoin::bitcoin::Amount::from_sat(TEST_AMOUNT_SATS))]);

        let error = rpc
            .wallet_create_funded_psbt(&[], &outputs, None, None, None)
            .await
            .expect_err("Should fail due to insufficient funds");
        let error_msg = error.to_string();
        println!("{error_msg}");

        assert_rpc_error_format(
            &error_msg,
            "walletcreatefundedpsbt",
            &["fund", "balance", "amount", "Insufficient"],
        );
    }
}

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use corepc_types::v26::{
    FinalizePsbt, GetAddressInfo, GetBlockchainInfo, ListUnspentItem, TestMempoolAccept,
    WalletCreateFundedPsbt, WalletProcessPsbt,
};
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
    auth: Auth,
}

impl AsyncBitcoinRpc {
    pub fn new(url: String, auth: Auth) -> Result<Self> {
        let client =
            Client::builder().use_rustls_tls().build().context("Failed to create HTTP client")?;

        Ok(Self { client, url, auth })
    }

    /// Make a JSON-RPC call to Bitcoin Core
    async fn call_rpc<T>(&self, method: &str, params: Value) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let request_body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let mut request = self.client.post(&self.url).json(&request_body);

        // Add authentication
        match &self.auth {
            Auth::UserPass(user, pass) => {
                request = request.basic_auth(user, Some(pass));
            }
            Auth::CookieFile(path) => {
                let cookie = std::fs::read_to_string(path)
                    .with_context(|| format!("Failed to read cookie file: {path:?}"))?;
                let parts: Vec<&str> = cookie.trim().split(':').collect();
                if parts.len() != 2 {
                    return Err(anyhow!("Invalid cookie format"));
                }
                request = request.basic_auth(parts[0], Some(parts[1]));
            }
        }

        let response = request.send().await.context("Failed to send RPC request")?;

        if !response.status().is_success() {
            return Err(anyhow!("RPC request failed with status: {}", response.status()));
        }

        let json: RpcResponse<T> = response.json().await.context("Failed to parse RPC response")?;

        match json {
            RpcResponse::Success { result, .. } => Ok(result),
            RpcResponse::Error { error, .. } => Err(anyhow!("RPC error: {:?}", error)),
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
        let params = json!([inputs, outputs, locktime, options, bip32derivs]);
        self.call_rpc("walletcreatefundedpsbt", params).await
    }

    pub async fn wallet_process_psbt(
        &self,
        psbt: &str,
        sign: Option<bool>,
        sighash_type: Option<String>,
        bip32derivs: Option<bool>,
    ) -> Result<WalletProcessPsbt> {
        let params = json!([psbt, sign, sighash_type, bip32derivs]);
        self.call_rpc("walletprocesspsbt", params).await
    }

    pub async fn finalize_psbt(&self, psbt: &str, extract: Option<bool>) -> Result<FinalizePsbt> {
        let params = json!([psbt, extract]);
        self.call_rpc("finalizepsbt", params).await
    }

    pub async fn test_mempool_accept(&self, rawtxs: &[String]) -> Result<Vec<TestMempoolAccept>> {
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

    pub async fn get_address_info(&self, address: &Address) -> Result<GetAddressInfo> {
        let params = json!([address.to_string()]);
        self.call_rpc("getaddressinfo", params).await
    }

    pub async fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<&str>,
    ) -> Result<Address> {
        let params = json!([label, address_type]);
        let address_string: String = self.call_rpc("getnewaddress", params).await?;
        let addr: payjoin::bitcoin::Address<payjoin::bitcoin::address::NetworkUnchecked> =
            address_string.parse().context("Failed to parse address")?;
        Ok(addr.assume_checked())
    }

    pub async fn list_unspent(
        &self,
        minconf: Option<u32>,
        maxconf: Option<u32>,
        addresses: Option<&[Address]>,
        include_unsafe: Option<bool>,
        query_options: Option<Value>,
    ) -> Result<Vec<ListUnspentItem>> {
        let addresses_str: Option<Vec<String>> =
            addresses.map(|addrs| addrs.iter().map(|a| a.to_string()).collect());
        let params = json!([minconf, maxconf, addresses_str, include_unsafe, query_options]);
        self.call_rpc("listunspent", params).await
    }

    pub async fn get_blockchain_info(&self) -> Result<GetBlockchainInfo> {
        let params = json!([]);
        self.call_rpc("getblockchaininfo", params).await
    }

    pub async fn network(&self) -> Result<Network> {
        let info = self.get_blockchain_info().await?;
        match info.chain.as_str() {
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

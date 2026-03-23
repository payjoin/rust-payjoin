use std::sync::Arc;

use payjoin_test_utils::corepc_node::{self, AddressType};
use serde_json::Value;

#[derive(uniffi::Object)]
pub struct BitcoindEnv {
    pub bitcoind: Arc<BitcoindInstance>,
    pub receiver: Arc<RpcClient>,
    pub sender: Arc<RpcClient>,
}

#[uniffi::export]
impl BitcoindEnv {
    pub fn get_receiver(&self) -> Arc<RpcClient> { self.receiver.clone() }

    pub fn get_sender(&self) -> Arc<RpcClient> { self.sender.clone() }

    pub fn get_bitcoind(&self) -> Arc<BitcoindInstance> { self.bitcoind.clone() }
}

#[derive(uniffi::Object)]
pub struct BitcoindInstance {
    _inner: corepc_node::Node,
}

#[derive(uniffi::Object)]
pub struct RpcClient {
    inner: corepc_node::Client,
}

#[uniffi::export]
impl RpcClient {
    pub fn call(&self, method: String, params: Vec<Option<String>>) -> Result<String, FfiError> {
        let parsed_params: Vec<Value> = params
            .into_iter()
            .map(|param| match param {
                Some(p) => serde_json::from_str(&p).unwrap_or(Value::String(p)),
                None => Value::Null,
            })
            .collect();

        let result = self
            .inner
            .call::<Value>(&method, &parsed_params)
            .map_err(|e| FfiError::new(format!("RPC call failed: {e}")))?;

        serde_json::to_string(&result)
            .map_err(|e| FfiError::new(format!("Serialization error: {e}")))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, uniffi::Error)]
pub enum FfiError {
    #[error("Init error: {0}")]
    InitError(String),
    #[error("Rpc error: {0}")]
    RpcError(String),
    #[error("{0}")]
    Message(String),
}

impl FfiError {
    pub fn new(msg: impl Into<String>) -> Self { FfiError::Message(msg.into()) }
}

#[uniffi::export]
pub fn init_bitcoind_sender_receiver() -> Result<Arc<BitcoindEnv>, FfiError> {
    let (bitcoind, receiver, sender) = payjoin_test_utils::init_bitcoind_sender_receiver(
        Some(AddressType::Bech32),
        Some(AddressType::Bech32),
    )
    .map_err(|e| FfiError::InitError(e.to_string()))?;

    Ok(Arc::new(BitcoindEnv {
        bitcoind: Arc::new(BitcoindInstance { _inner: bitcoind }),
        receiver: Arc::new(RpcClient { inner: receiver }),
        sender: Arc::new(RpcClient { inner: sender }),
    }))
}

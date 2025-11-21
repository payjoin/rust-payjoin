#![deny(clippy::all)]

use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use payjoin_test_utils::corepc_node::AddressType;
use serde_json::Value;

#[napi]
pub struct BitcoindEnv {
    bitcoind: BitcoindInstance,
    receiver: RpcClient,
    sender: RpcClient,
}

#[napi]
impl BitcoindEnv {
    #[napi]
    pub fn get_bitcoind(&self) -> BitcoindInstance { self.bitcoind.clone() }

    #[napi]
    pub fn get_receiver(&self) -> RpcClient { self.receiver.clone() }

    #[napi]
    pub fn get_sender(&self) -> RpcClient { self.sender.clone() }
}

#[napi]
#[derive(Clone)]
pub struct BitcoindInstance {
    _inner: Arc<payjoin_test_utils::corepc_node::Node>,
}

#[napi]
#[derive(Clone)]
pub struct RpcClient {
    inner: Arc<payjoin_test_utils::corepc_node::Client>,
}

#[napi]
impl RpcClient {
    #[napi]
    pub fn call(&self, method: String, params: Vec<Option<String>>) -> Result<String> {
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
            .map_err(|e| Error::from_reason(format!("RPC call failed: {}", e)))?;

        serde_json::to_string(&result)
            .map_err(|e| Error::from_reason(format!("Serialization error: {}", e)))
    }
}

#[napi]
pub struct TestServices {
    inner: Arc<tokio::sync::Mutex<payjoin_test_utils::TestServices>>,
    _runtime: Arc<tokio::runtime::Runtime>,
}

#[napi]
impl TestServices {
    #[napi(constructor)]
    pub fn new() -> Result<Self> {
        let runtime = Arc::new(
            tokio::runtime::Runtime::new()
                .map_err(|e| Error::from_reason(format!("Failed to create runtime: {}", e)))?,
        );

        let inner = runtime.block_on(async {
            payjoin_test_utils::TestServices::initialize()
                .await
                .map_err(|e| Error::from_reason(format!("Initialization failed: {}", e)))
        })?;

        Ok(TestServices { inner: Arc::new(tokio::sync::Mutex::new(inner)), _runtime: runtime })
    }

    #[napi]
    pub fn cert(&self) -> Buffer {
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        let cert = runtime.block_on(async { self.inner.lock().await.cert() });
        Buffer::from(cert)
    }

    #[napi]
    pub fn directory_url(&self) -> String {
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        runtime.block_on(async { self.inner.lock().await.directory_url() })
    }

    #[napi]
    pub fn ohttp_relay_url(&self) -> String {
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        runtime.block_on(async { self.inner.lock().await.ohttp_relay_url() })
    }

    #[napi]
    pub fn ohttp_gateway_url(&self) -> String {
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        runtime.block_on(async { self.inner.lock().await.ohttp_gateway_url() })
    }

    #[napi]
    pub fn wait_for_services_ready(&self) -> Result<()> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| Error::from_reason(format!("Failed to create runtime: {}", e)))?;

        runtime.block_on(async {
            self.inner
                .lock()
                .await
                .wait_for_services_ready()
                .await
                .map_err(|e| Error::from_reason(format!("Services not ready: {}", e)))
        })
    }

    #[napi]
    pub fn fetch_ohttp_keys(&self) -> Result<Buffer> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| Error::from_reason(format!("Failed to create runtime: {}", e)))?;

        runtime.block_on(async {
            self.inner
                .lock()
                .await
                .fetch_ohttp_keys()
                .await
                .map_err(|e| Error::from_reason(format!("Failed to fetch OHTTP keys: {}", e)))
                .and_then(|keys| {
                    keys.encode().map(Buffer::from).map_err(|e| {
                        Error::from_reason(format!("Failed to encode OHTTP keys: {}", e))
                    })
                })
        })
    }
}

#[napi]
pub fn init_bitcoind_sender_receiver() -> Result<BitcoindEnv> {
    let (bitcoind, receiver, sender) = payjoin_test_utils::init_bitcoind_sender_receiver(
        Some(AddressType::Bech32),
        Some(AddressType::Bech32),
    )
    .map_err(|e| Error::from_reason(format!("Failed to initialize bitcoind: {}", e)))?;

    Ok(BitcoindEnv {
        bitcoind: BitcoindInstance { _inner: Arc::new(bitcoind) },
        receiver: RpcClient { inner: Arc::new(receiver) },
        sender: RpcClient { inner: Arc::new(sender) },
    })
}

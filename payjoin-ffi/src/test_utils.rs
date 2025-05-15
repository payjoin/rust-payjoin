use std::io;
use std::sync::Arc;

use bitcoin_ffi::Psbt;
use bitcoincore_rpc::RpcApi;
use bitcoind::bitcoincore_rpc;
use bitcoind::bitcoincore_rpc::json::AddressType;
use lazy_static::lazy_static;
use payjoin_test_utils::{
    EXAMPLE_URL, INVALID_PSBT, ORIGINAL_PSBT, PARSED_ORIGINAL_PSBT, PARSED_PAYJOIN_PROPOSAL,
    PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO, PAYJOIN_PROPOSAL, PAYJOIN_PROPOSAL_WITH_SENDER_INFO,
    QUERY_PARAMS, RECEIVER_INPUT_CONTRIBUTION,
};
use serde_json::Value;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use crate::Url;

lazy_static! {
    static ref RUNTIME: Arc<std::sync::Mutex<Runtime>> =
        Arc::new(std::sync::Mutex::new(Runtime::new().expect("Failed to create Tokio runtime")));
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct BitcoindEnv {
    pub bitcoind: Arc<BitcoindInstance>,
    pub receiver: Arc<RpcClient>,
    pub sender: Arc<RpcClient>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl BitcoindEnv {
    pub fn get_receiver(&self) -> Arc<RpcClient> {
        self.receiver.clone()
    }

    pub fn get_sender(&self) -> Arc<RpcClient> {
        self.sender.clone()
    }

    pub fn get_bitcoind(&self) -> Arc<BitcoindInstance> {
        self.bitcoind.clone()
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct BitcoindInstance {
    _inner: bitcoind::BitcoinD,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct RpcClient {
    inner: bitcoincore_rpc::Client,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl RpcClient {
    pub fn call(&self, method: String, params: Vec<Option<String>>) -> Result<String, FfiError> {
        let parsed_params: Vec<Value> = params
            .into_iter()
            .map(|param| {
                match param {
                    Some(p) => serde_json::from_str(&p).unwrap_or(Value::String(p)),
                    None => Value::Null,
                }
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

#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum FfiError {
    #[error("Init error: {0}")]
    InitError(String),
    #[error("Rpc error: {0}")]
    RpcError(String),
    #[error("{0}")]
    Message(String),
}

impl FfiError {
    pub fn new(msg: impl Into<String>) -> Self {
        FfiError::Message(msg.into())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct BoxSendSyncError(#[from] payjoin_test_utils::BoxSendSyncError);

impl From<io::Error> for BoxSendSyncError {
    fn from(err: io::Error) -> Self {
        payjoin_test_utils::BoxSendSyncError::from(err).into()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn init_tracing() {
    payjoin_test_utils::init_tracing();
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct JoinHandle(
    #[allow(dead_code)]
    Arc<tokio::task::JoinHandle<Result<(), payjoin_test_utils::BoxSendSyncError>>>,
);

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct TestServices(pub(crate) Mutex<payjoin_test_utils::TestServices>);

impl From<payjoin_test_utils::TestServices> for TestServices {
    fn from(value: payjoin_test_utils::TestServices) -> Self {
        Self(Mutex::new(value))
    }
}

impl From<TestServices> for payjoin_test_utils::TestServices {
    fn from(value: TestServices) -> Self {
        value.0.into_inner()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl TestServices {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn initialize() -> Result<Self, BoxSendSyncError> {
        let runtime = RUNTIME.lock().expect("Lock should not be poisoned");
        let service = runtime.block_on(async {
            payjoin_test_utils::TestServices::initialize().await.map_err(|e| {
                eprintln!("Initialization failed: {e}");
                BoxSendSyncError::from(e)
            })
        })?;
        Ok(TestServices(Mutex::new(service)))
    }

    pub fn cert(&self) -> Vec<u8> {
        let runtime = RUNTIME.lock().expect("Lock should not be poisoned");
        runtime.block_on(async { self.0.lock().await.cert() })
    }

    pub fn directory_url(&self) -> Url {
        let runtime = RUNTIME.lock().expect("Lock should not be poisoned");
        runtime.block_on(async { self.0.lock().await.directory_url().into() })
    }

    pub fn take_directory_handle(&self) -> JoinHandle {
        let runtime = RUNTIME.lock().expect("Lock should not be poisoned");
        runtime
            .block_on(async { JoinHandle(Arc::new(self.0.lock().await.take_directory_handle())) })
    }

    pub fn ohttp_relay_url(&self) -> Url {
        let runtime = RUNTIME.lock().expect("Lock should not be poisoned");
        runtime.block_on(async { self.0.lock().await.ohttp_relay_url().into() })
    }

    pub fn ohttp_gateway_url(&self) -> Url {
        let runtime = RUNTIME.lock().expect("Lock should not be poisoned");
        runtime.block_on(async { self.0.lock().await.ohttp_gateway_url().into() })
    }

    pub fn take_ohttp_relay_handle(&self) -> JoinHandle {
        let runtime = RUNTIME.lock().expect("Lock should not be poisoned");
        runtime
            .block_on(async { JoinHandle(Arc::new(self.0.lock().await.take_ohttp_relay_handle())) })
    }

    pub fn wait_for_services_ready(&self) -> Result<(), BoxSendSyncError> {
        let runtime = RUNTIME.lock().expect("Lock should not be poisoned");
        runtime.block_on(async {
            self.0
                .lock()
                .await
                .wait_for_services_ready()
                .await
                .map_err(|e| payjoin_test_utils::BoxSendSyncError::from(e).into())
        })
    }

    pub fn fetch_ohttp_keys(&self) -> Result<crate::OhttpKeys, crate::io::IoError> {
        let runtime = RUNTIME.lock().expect("Lock should not be poisoned");
        runtime.block_on(async {
            self.0.lock().await.fetch_ohttp_keys().await.map_err(Into::into).map(Into::into)
        })
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
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

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn example_url() -> Url {
    EXAMPLE_URL.clone().into()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn query_params() -> String {
    QUERY_PARAMS.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn original_psbt() -> String {
    ORIGINAL_PSBT.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn invalid_psbt() -> String {
    INVALID_PSBT.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn payjoin_proposal() -> String {
    PAYJOIN_PROPOSAL.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn payjoin_proposal_with_sender_info() -> String {
    PAYJOIN_PROPOSAL_WITH_SENDER_INFO.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn receiver_input_contribution() -> String {
    RECEIVER_INPUT_CONTRIBUTION.to_string()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parsed_original_psbt() -> Psbt {
    PARSED_ORIGINAL_PSBT.clone().into()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parsed_payjoin_proposal() -> Psbt {
    PARSED_PAYJOIN_PROPOSAL.clone().into()
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parsed_payjoin_proposal_with_sender_info() -> Psbt {
    PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO.clone().into()
}

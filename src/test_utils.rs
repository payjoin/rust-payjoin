use std::sync::Arc;

use payjoin_test_utils::{
    EXAMPLE_URL, INVALID_PSBT, ORIGINAL_PSBT, PARSED_ORIGINAL_PSBT, PARSED_PAYJOIN_PROPOSAL,
    PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO, PAYJOIN_PROPOSAL, PAYJOIN_PROPOSAL_WITH_SENDER_INFO,
    QUERY_PARAMS, RECEIVER_INPUT_CONTRIBUTION,
};
use tokio::sync::Mutex;

use crate::Url;

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct BoxSendSyncError(#[from] payjoin_test_utils::BoxSendSyncError);

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
    pub async fn initialize() -> Result<Self, BoxSendSyncError> {
        Ok(payjoin_test_utils::TestServices::initialize().await?.into())
    }

    pub async fn cert(&self) -> Vec<u8> {
        self.0.lock().await.cert()
    }

    pub async fn directory_url(&self) -> Url {
        self.0.lock().await.directory_url().into()
    }

    pub async fn take_directory_handle(&self) -> JoinHandle {
        JoinHandle(Arc::new(self.0.lock().await.take_directory_handle()))
    }

    pub async fn ohttp_relay_url(&self) -> Url {
        self.0.lock().await.ohttp_relay_url().into()
    }

    pub async fn ohttp_gateway_url(&self) -> Url {
        self.0.lock().await.ohttp_gateway_url().into()
    }

    pub async fn take_ohttp_relay_handle(&self) -> JoinHandle {
        JoinHandle(Arc::new(self.0.lock().await.take_ohttp_relay_handle()))
    }

    pub async fn wait_for_services_ready(&self) -> Result<(), BoxSendSyncError> {
        self.0
            .lock()
            .await
            .wait_for_services_ready()
            .await
            .map_err(|e| payjoin_test_utils::BoxSendSyncError::from(e).into())
    }

    pub async fn fetch_ohttp_keys(&self) -> Result<crate::OhttpKeys, crate::io::IoError> {
        self.0.lock().await.fetch_ohttp_keys().await.map_err(Into::into).map(Into::into)
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Debug)]
pub struct Psbt(#[allow(dead_code)] pub(crate) std::sync::Mutex<payjoin::bitcoin::Psbt>);

impl From<payjoin::bitcoin::Psbt> for Psbt {
    fn from(psbt: payjoin::bitcoin::Psbt) -> Self {
        Self(std::sync::Mutex::new(psbt))
    }
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

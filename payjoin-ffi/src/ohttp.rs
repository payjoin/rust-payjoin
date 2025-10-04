pub use error::OhttpError;

pub mod error {
    #[derive(Debug, thiserror::Error, uniffi::Object)]
    #[error(transparent)]
    pub struct OhttpError(#[from] ohttp::Error);
}

impl From<payjoin::OhttpKeys> for OhttpKeys {
    fn from(value: payjoin::OhttpKeys) -> Self { Self(value) }
}
impl From<OhttpKeys> for payjoin::OhttpKeys {
    fn from(value: OhttpKeys) -> Self { value.0 }
}
#[derive(Debug, Clone, uniffi::Object)]
pub struct OhttpKeys(payjoin::OhttpKeys);

#[uniffi::export]
impl OhttpKeys {
    /// Decode an OHTTP KeyConfig
    #[uniffi::constructor]
    pub fn decode(bytes: Vec<u8>) -> Result<Self, OhttpError> {
        payjoin::OhttpKeys::decode(bytes.as_slice()).map(Into::into).map_err(Into::into)
    }
}

use std::sync::Mutex;

#[derive(uniffi::Object)]
pub struct ClientResponse(Mutex<Option<ohttp::ClientResponse>>);

impl From<&ClientResponse> for ohttp::ClientResponse {
    fn from(value: &ClientResponse) -> Self {
        let mut data_guard = value.0.lock().unwrap();
        Option::take(&mut *data_guard).expect("ClientResponse moved out of memory")
    }
}

impl From<ohttp::ClientResponse> for ClientResponse {
    fn from(value: ohttp::ClientResponse) -> Self { Self(Mutex::new(Some(value))) }
}

pub use error::OhttpError;

pub mod error {
    #[derive(Debug, thiserror::Error, uniffi::Object)]
    #[uniffi::export(Debug, Display)]
    #[error(transparent)]
    pub struct OhttpError(#[from] payjoin::OhttpKeysError);
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
pub struct ClientResponse(Mutex<Option<payjoin::OhttpResponse>>);

impl From<&ClientResponse> for payjoin::OhttpResponse {
    fn from(value: &ClientResponse) -> Self {
        let mut data_guard = value.0.lock().unwrap();
        Option::take(&mut *data_guard).expect("ClientResponse moved out of memory")
    }
}

impl From<payjoin::OhttpResponse> for ClientResponse {
    fn from(value: payjoin::OhttpResponse) -> Self { Self(Mutex::new(Some(value))) }
}

#[cfg(all(test, feature = "_test-utils"))]
impl ClientResponse {
    /// A placeholder context for tests that never process a response.
    ///
    /// Consuming it panics like any other context that has already been moved
    /// out of memory, so it must only be used where the response is discarded.
    pub(crate) fn dangling() -> Self { Self(Mutex::new(None)) }
}

pub use error::OhttpError;

pub mod error {
    #[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
    #[error("OHTTP error: {message}")]
    pub struct OhttpError {
        message: String,
    }
    impl From<ohttp::Error> for OhttpError {
        fn from(value: ohttp::Error) -> Self { OhttpError { message: format!("{value:?}") } }
    }
    impl From<String> for OhttpError {
        fn from(value: String) -> Self { OhttpError { message: value } }
    }
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

    /// Create an OHTTP KeyConfig from a string
    #[uniffi::constructor]
    pub fn from_string(s: String) -> Result<Self, OhttpError> {
        let res = payjoin::OhttpKeys::from_str(s.as_str())
            .map_err(|e| OhttpError::from(e.to_string()))?;
        Ok(Self(res))
    }
}

use std::str::FromStr;
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

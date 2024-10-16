use crate::error::PayjoinError;

impl From<payjoin::OhttpKeys> for OhttpKeys {
    fn from(value: payjoin::OhttpKeys) -> Self {
        Self(value)
    }
}
impl From<OhttpKeys> for payjoin::OhttpKeys {
    fn from(value: OhttpKeys) -> Self {
        value.0
    }
}
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Debug, Clone)]
pub struct OhttpKeys(pub payjoin::OhttpKeys);

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl OhttpKeys {
    /// Decode an OHTTP KeyConfig
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn decode(bytes: Vec<u8>) -> Result<Self, PayjoinError> {
        payjoin::OhttpKeys::decode(bytes.as_slice()).map(|e| e.into()).map_err(|e| e.into())
    }
}

use std::sync::Mutex;

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ClientResponse(Mutex<Option<ohttp::ClientResponse>>);

impl From<&ClientResponse> for ohttp::ClientResponse {
    fn from(value: &ClientResponse) -> Self {
        let mut data_guard = value.0.lock().unwrap();
        Option::take(&mut *data_guard).expect("ClientResponse moved out of memory")
    }
}

impl From<ohttp::ClientResponse> for ClientResponse {
    fn from(value: ohttp::ClientResponse) -> Self {
        Self(Mutex::new(Some(value)))
    }
}

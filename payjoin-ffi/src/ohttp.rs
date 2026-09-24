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

/// The OHTTP context needed to decapsulate the response to one request.
///
/// A context can process exactly one response. Passing it to a second
/// `process_response` call returns [`ClientResponseError::AlreadyUsed`].
#[derive(uniffi::Object)]
pub struct ClientResponse(Mutex<Option<payjoin::OhttpResponse>>);

/// Error returned when a [`ClientResponse`] is passed to more than one
/// `process_response` call.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ClientResponseError {
    /// The OHTTP context was already used to process a response. Create a
    /// new request to get a fresh context before retrying.
    #[error("OHTTP response context was already used")]
    AlreadyUsed,
}

impl TryFrom<&ClientResponse> for payjoin::OhttpResponse {
    type Error = ClientResponseError;

    fn try_from(value: &ClientResponse) -> Result<Self, Self::Error> {
        let mut data_guard = value.0.lock().unwrap();
        Option::take(&mut *data_guard).ok_or(ClientResponseError::AlreadyUsed)
    }
}

impl From<payjoin::OhttpResponse> for ClientResponse {
    fn from(value: payjoin::OhttpResponse) -> Self { Self(Mutex::new(Some(value))) }
}

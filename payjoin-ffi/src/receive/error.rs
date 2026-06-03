use std::sync::Arc;

use payjoin::receive;

use crate::error::{FfiValidationError, ImplementationError};
use crate::uri::error::IntoUrlError;

/// The top-level error type for the payjoin receiver
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum ReceiverError {
    /// Error in underlying protocol function
    #[error("Protocol error: {0}")]
    Protocol(Arc<ProtocolError>),
    /// Error arising due to the specific receiver implementation
    ///
    /// e.g. database errors, network failures, wallet errors
    #[error("Implementation error: {0}")]
    Implementation(Arc<ImplementationError>),
    /// Error that may occur when converting a some type to a URL
    #[error("IntoUrl error: {0}")]
    IntoUrl(Arc<IntoUrlError>),
    /// Catch-all for unhandled error variants
    #[error("An unexpected error occurred")]
    Unexpected,
}

impl From<receive::Error> for ReceiverError {
    fn from(value: receive::Error) -> Self {
        use ReceiverError::*;

        match value {
            receive::Error::Protocol(e) => Protocol(Arc::new(ProtocolError(e))),
            receive::Error::Implementation(e) =>
                Implementation(Arc::new(ImplementationError::from(e))),
            _ => Unexpected,
        }
    }
}

/// Returns `true` if the receiver error is caused by an expired v2 session.
///
/// Mirrors [`payjoin::receive::Error::is_expired`] so bindings that catch the
/// top-level `ReceiverError` can branch on expiry without matching the Display
/// string. uniffi attaches methods to Object types, not to error enums, so the
/// predicate is exposed as a free function over the caught error.
#[uniffi::export]
pub fn receiver_error_is_expired(error: &ReceiverError) -> bool {
    match error {
        ReceiverError::Protocol(e) =>
            matches!(&e.0, receive::ProtocolError::V2(session) if session.is_expired()),
        _ => false,
    }
}

/// Error that may occur during state machine transitions
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[error(transparent)]
pub enum ReceiverPersistedError {
    /// rust-payjoin receiver error
    #[error(transparent)]
    Receiver(ReceiverError),
    /// Storage error that could occur at application storage layer
    #[error(transparent)]
    Storage(Arc<ImplementationError>),
}

impl From<ImplementationError> for ReceiverPersistedError {
    fn from(value: ImplementationError) -> Self { ReceiverPersistedError::Storage(Arc::new(value)) }
}

macro_rules! impl_persisted_error_from {
    (
        $api_error_ty:ty,
        $receiver_arm:expr
    ) => {
        impl<S, E> From<payjoin::persist::PersistedError<$api_error_ty, S, E>>
            for ReceiverPersistedError
        where
            S: std::error::Error + Send + Sync + 'static,
            E: std::fmt::Debug,
        {
            fn from(err: payjoin::persist::PersistedError<$api_error_ty, S, E>) -> Self {
                if err.storage_error_ref().is_some() {
                    if let Some(storage_err) = err.storage_error() {
                        return ReceiverPersistedError::from(ImplementationError::new(storage_err));
                    }
                    return ReceiverPersistedError::Receiver(ReceiverError::Unexpected);
                }
                if let Some(api_err) = err.api_error() {
                    return ReceiverPersistedError::Receiver($receiver_arm(api_err));
                }
                ReceiverPersistedError::Receiver(ReceiverError::Unexpected)
            }
        }
    };
}

impl_persisted_error_from!(receive::ProtocolError, |api_err: receive::ProtocolError| {
    ReceiverError::Protocol(Arc::new(api_err.into()))
});

impl_persisted_error_from!(receive::Error, |api_err: receive::Error| api_err.into());

impl_persisted_error_from!(payjoin::IntoUrlError, |api_err: payjoin::IntoUrlError| {
    ReceiverError::IntoUrl(Arc::new(api_err.into()))
});

/// Error that may occur when building a receiver session.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum ReceiverBuilderError {
    /// The provided Bitcoin address is invalid.
    #[error("Invalid Bitcoin address: {0}")]
    InvalidAddress(Arc<AddressParseError>),
    /// Error that may occur when converting a value into a URL.
    #[error("Invalid directory URL: {0}")]
    IntoUrl(Arc<IntoUrlError>),
}

impl From<payjoin::IntoUrlError> for ReceiverBuilderError {
    fn from(value: payjoin::IntoUrlError) -> Self {
        ReceiverBuilderError::IntoUrl(Arc::new(value.into()))
    }
}

impl From<payjoin::bitcoin::address::ParseError> for ReceiverBuilderError {
    fn from(value: payjoin::bitcoin::address::ParseError) -> Self {
        ReceiverBuilderError::InvalidAddress(Arc::new(value.into()))
    }
}

/// Error parsing a Bitcoin address.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error("Invalid Bitcoin address: {msg}")]
pub struct AddressParseError {
    msg: String,
}

impl From<payjoin::bitcoin::address::ParseError> for AddressParseError {
    fn from(value: payjoin::bitcoin::address::ParseError) -> Self {
        AddressParseError { msg: value.to_string() }
    }
}

/// The replyable error type for the payjoin receiver, representing failures need to be
/// returned to the sender.
///
/// The error handling is designed to:
/// 1. Provide structured error responses for protocol-level failures
/// 2. Hide implementation details of external errors for security
/// 3. Support proper error propagation through the receiver stack
/// 4. Provide errors according to BIP-78 JSON error specifications for return
///    after conversion into [`JsonReply`]
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct ProtocolError(#[from] receive::ProtocolError);

/// The standard format for errors that can be replied as JSON.
///
/// The JSON output includes the following fields:
/// ```json
/// {
///     "errorCode": "specific-error-code",
///     "message": "Human readable error message"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct JsonReply(receive::JsonReply);

impl From<JsonReply> for receive::JsonReply {
    fn from(value: JsonReply) -> Self { value.0 }
}

impl From<receive::JsonReply> for JsonReply {
    fn from(value: receive::JsonReply) -> Self { Self(value) }
}

impl From<ProtocolError> for JsonReply {
    fn from(value: ProtocolError) -> Self { Self((&value.0).into()) }
}

/// Error that may occur during a v2 session typestate change
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct SessionError(#[from] receive::v2::SessionError);

#[uniffi::export]
impl SessionError {
    /// Returns `true` if the session has expired.
    pub fn is_expired(&self) -> bool { self.0.is_expired() }
}

/// Protocol error raised during output substitution.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct OutputSubstitutionProtocolError(#[from] receive::OutputSubstitutionError);

/// Error that may occur when output substitution fails.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OutputSubstitutionError {
    #[error(transparent)]
    Protocol(Arc<OutputSubstitutionProtocolError>),
    #[error(transparent)]
    FfiValidation(FfiValidationError),
}

impl From<receive::OutputSubstitutionError> for OutputSubstitutionError {
    fn from(value: receive::OutputSubstitutionError) -> Self {
        OutputSubstitutionError::Protocol(Arc::new(value.into()))
    }
}

impl From<FfiValidationError> for OutputSubstitutionError {
    fn from(value: FfiValidationError) -> Self { OutputSubstitutionError::FfiValidation(value) }
}

/// Error that may occur when coin selection fails.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct SelectionError(#[from] receive::SelectionError);

/// Error that may occur when input contribution fails.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct InputContributionError(#[from] receive::InputContributionError);

/// Error validating a PSBT Input
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct PsbtInputError(#[from] receive::PsbtInputError);

/// Error constructing an [`InputPair`](crate::InputPair).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum InputPairError {
    /// Provided outpoint could not be parsed.
    #[error("Invalid outpoint (txid={txid}, vout={vout})")]
    InvalidOutPoint { txid: String, vout: u32 },
    /// PSBT input failed validation in the core library.
    #[error("Invalid PSBT input: {0}")]
    InvalidPsbtInput(Arc<PsbtInputError>),
    /// Input failed validation in the FFI layer.
    #[error("Invalid input: {0}")]
    FfiValidation(FfiValidationError),
}

impl InputPairError {
    pub fn invalid_outpoint(txid: String, vout: u32) -> Self {
        InputPairError::InvalidOutPoint { txid, vout }
    }
}

impl From<FfiValidationError> for InputPairError {
    fn from(value: FfiValidationError) -> Self { InputPairError::FfiValidation(value) }
}

/// Error that may occur when a receiver event log is replayed
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct ReceiverReplayError(
    #[from] payjoin::error::ReplayError<receive::v2::ReceiveSession, receive::v2::SessionEvent>,
);

#[uniffi::export]
impl ReceiverReplayError {
    /// Returns `true` if the event log could not be replayed because the
    /// session has expired.
    pub fn is_expired(&self) -> bool { self.0.is_expired() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_and_replay_errors_expose_is_expired() {
        // uniffi Objects expose the core predicate to bindings.
        let _: fn(&SessionError) -> bool = SessionError::is_expired;
        let _: fn(&ReceiverReplayError) -> bool = ReceiverReplayError::is_expired;
    }

    #[cfg(feature = "_test-utils")]
    #[test]
    fn receiver_error_expiry_predicate() {
        use std::str::FromStr;
        use std::time::Duration;

        use payjoin::bitcoin::Address;
        use payjoin::persist::InMemoryPersister;
        use payjoin::receive::v2::{ReceiverBuilder, SessionEvent};
        use payjoin::OhttpKeys;
        use payjoin_test_utils::{EXAMPLE_URL, KEM, KEY_ID, SYMMETRIC};

        // Build a receiver whose session is already expired, then surface the
        // expiry error through the public polling API.
        let address = Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
            .expect("valid address")
            .assume_checked();
        let ohttp_keys = OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid keys"),
        );
        let persister = InMemoryPersister::<SessionEvent>::default();
        let receiver = ReceiverBuilder::new(address, EXAMPLE_URL, ohttp_keys)
            .expect("valid builder")
            .with_expiration(Duration::from_secs(0))
            .build()
            .save(&persister)
            .expect("in-memory persister is infallible");
        let expired =
            receiver.create_poll_request(EXAMPLE_URL).map(|_| ()).expect_err("session is expired");
        assert!(receiver_error_is_expired(&ReceiverError::from(expired)));

        // A non-expiry error is not reported as expired.
        let other = ReceiverError::from(receive::Error::Implementation(
            payjoin::ImplementationError::from("not an expiry error"),
        ));
        assert!(!receiver_error_is_expired(&other));
    }
}

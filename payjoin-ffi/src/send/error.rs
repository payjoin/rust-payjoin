use std::sync::Arc;

use payjoin::bitcoin::psbt::PsbtParseError as CorePsbtParseError;
use payjoin::send;

use crate::error::{
    DirectoryResponseError, FfiValidationError, HpkeError, ImplementationError,
    OhttpEncapsulationError,
};

/// Error building a Sender from a SenderBuilder.
///
/// This error is unrecoverable.
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
#[error("Error initializing the sender: {msg}")]
pub struct BuildSenderError {
    msg: String,
}

impl From<PsbtParseError> for BuildSenderError {
    fn from(value: PsbtParseError) -> Self { BuildSenderError { msg: value.to_string() } }
}

impl From<send::BuildSenderError> for BuildSenderError {
    fn from(value: send::BuildSenderError) -> Self { BuildSenderError { msg: value.to_string() } }
}

/// FFI-visible PSBT parsing error surfaced at the sender boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PsbtParseError {
    /// The provided PSBT string could not be parsed.
    #[error("Invalid PSBT: {0}")]
    InvalidPsbt(String),
}

impl From<CorePsbtParseError> for PsbtParseError {
    fn from(value: CorePsbtParseError) -> Self { PsbtParseError::InvalidPsbt(value.to_string()) }
}

/// Raised when inputs provided to the sender are malformed or sender build fails.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SenderInputError {
    #[error(transparent)]
    Psbt(PsbtParseError),
    #[error(transparent)]
    Build(Arc<BuildSenderError>),
    #[error(transparent)]
    FfiValidation(FfiValidationError),
}

impl From<FfiValidationError> for SenderInputError {
    fn from(value: FfiValidationError) -> Self { SenderInputError::FfiValidation(value) }
}

/// Error returned when request could not be created.
///
/// This error can currently only happen due to programmer mistake.
/// `unwrap()`ing it is thus considered OK in Rust but you may achieve nicer message by displaying
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CreateRequestErrorKind {
    Url,
    Hpke,
    OhttpEncapsulation,
    Expired,
    Other,
}

impl From<send::v2::CreateRequestErrorKind> for CreateRequestErrorKind {
    fn from(value: send::v2::CreateRequestErrorKind) -> Self {
        match value {
            send::v2::CreateRequestErrorKind::Url => Self::Url,
            send::v2::CreateRequestErrorKind::Hpke => Self::Hpke,
            send::v2::CreateRequestErrorKind::OhttpEncapsulation => Self::OhttpEncapsulation,
            send::v2::CreateRequestErrorKind::Expired => Self::Expired,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct CreateRequestError {
    kind: CreateRequestErrorKind,
    message: String,
    hpke_error: Option<Arc<HpkeError>>,
    ohttp_error: Option<Arc<OhttpEncapsulationError>>,
}

impl From<send::v2::CreateRequestError> for CreateRequestError {
    fn from(value: send::v2::CreateRequestError) -> Self {
        Self {
            kind: value.kind().into(),
            message: value.to_string(),
            hpke_error: value.hpke_error().map(|error| Arc::new(error.into())),
            ohttp_error: value.ohttp_error().map(|error| Arc::new(error.into())),
        }
    }
}

#[uniffi::export]
impl CreateRequestError {
    pub fn kind(&self) -> CreateRequestErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }

    pub fn hpke_error(&self) -> Option<Arc<HpkeError>> { self.hpke_error.clone() }

    pub fn ohttp_error(&self) -> Option<Arc<OhttpEncapsulationError>> { self.ohttp_error.clone() }
}

/// Error returned for v2-specific payload encapsulation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EncapsulationErrorKind {
    Hpke,
    DirectoryResponse,
    Other,
}

impl From<send::v2::EncapsulationErrorKind> for EncapsulationErrorKind {
    fn from(value: send::v2::EncapsulationErrorKind) -> Self {
        match value {
            send::v2::EncapsulationErrorKind::Hpke => Self::Hpke,
            send::v2::EncapsulationErrorKind::DirectoryResponse => Self::DirectoryResponse,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct EncapsulationError {
    kind: EncapsulationErrorKind,
    message: String,
    hpke_error: Option<Arc<HpkeError>>,
    directory_response_error: Option<Arc<DirectoryResponseError>>,
}

impl From<send::v2::EncapsulationError> for EncapsulationError {
    fn from(value: send::v2::EncapsulationError) -> Self {
        Self {
            kind: value.kind().into(),
            message: value.to_string(),
            hpke_error: value.hpke_error().map(|error| Arc::new(error.into())),
            directory_response_error: value
                .directory_response_error()
                .map(|error| Arc::new(error.into())),
        }
    }
}

#[uniffi::export]
impl EncapsulationError {
    pub fn kind(&self) -> EncapsulationErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }

    pub fn hpke_error(&self) -> Option<Arc<HpkeError>> { self.hpke_error.clone() }

    pub fn directory_response_error(&self) -> Option<Arc<DirectoryResponseError>> {
        self.directory_response_error.clone()
    }
}

/// Error that may occur when the response from receiver is malformed.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct ValidationError(#[from] send::ValidationError);

/// Represent an error returned by Payjoin receiver.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ResponseError {
    /// `WellKnown` Errors are defined in the [`BIP78::ReceiverWellKnownError`] spec.
    ///
    /// It is safe to display `WellKnown` errors to end users.
    ///
    /// [`BIP78::ReceiverWellKnownError`]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Receivers_well_known_errors
    #[error("A receiver error occurred: {0}")]
    WellKnown(Arc<WellKnownError>),

    /// Errors caused by malformed responses.
    #[error("An error occurred due to a malformed response: {0}")]
    Validation(Arc<ValidationError>),

    /// `Unrecognized` Errors are NOT defined in the [`BIP78::ReceiverWellKnownError`] spec.
    ///
    /// It is NOT safe to display `Unrecognized` errors to end users as they could be used
    /// maliciously to phish a non technical user. Only display them in debug logs.
    ///
    /// [`BIP78::ReceiverWellKnownError`]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Receivers_well_known_errors
    #[error("An unrecognized error occurred")]
    Unrecognized { error_code: String, msg: String },
}

impl From<send::ResponseError> for ResponseError {
    fn from(value: send::ResponseError) -> Self {
        match value {
            send::ResponseError::WellKnown(e) => ResponseError::WellKnown(Arc::new(e.into())),
            send::ResponseError::Validation(e) => ResponseError::Validation(Arc::new(e.into())),
            send::ResponseError::Unrecognized { error_code, message } =>
                ResponseError::Unrecognized { error_code, msg: message },
        }
    }
}

/// A well-known error that can be safely displayed to end users.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct WellKnownError(#[from] send::WellKnownError);

/// Error that may occur when the sender session event log is replayed
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct SenderReplayError(
    #[from] payjoin::error::ReplayError<send::v2::SendSession, send::v2::SessionEvent>,
);

/// Error that may occur during state machine transitions
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[error(transparent)]
pub enum SenderPersistedError {
    /// rust-payjoin sender Encapsulation error
    #[error(transparent)]
    EncapsulationError(Arc<EncapsulationError>),
    /// rust-payjoin sender response error
    #[error(transparent)]
    ResponseError(ResponseError),
    /// Sender Build error
    #[error(transparent)]
    BuildSenderError(Arc<BuildSenderError>),
    /// Storage error that could occur at application storage layer
    #[error(transparent)]
    Storage(Arc<ImplementationError>),
    /// Unexpected error
    #[error("An unexpected error occurred")]
    Unexpected,
}

impl From<ImplementationError> for SenderPersistedError {
    fn from(value: ImplementationError) -> Self { SenderPersistedError::Storage(Arc::new(value)) }
}

impl<S> From<payjoin::persist::PersistedError<send::v2::EncapsulationError, S>>
    for SenderPersistedError
where
    S: std::error::Error + Send + Sync + 'static,
{
    fn from(err: payjoin::persist::PersistedError<send::v2::EncapsulationError, S>) -> Self {
        if err.storage_error_ref().is_some() {
            if let Some(storage_err) = err.storage_error() {
                return SenderPersistedError::from(ImplementationError::new(storage_err));
            }
            return SenderPersistedError::Unexpected;
        }
        if let Some(api_err) = err.api_error() {
            return SenderPersistedError::EncapsulationError(Arc::new(api_err.into()));
        }
        SenderPersistedError::Unexpected
    }
}

impl<S> From<payjoin::persist::PersistedError<send::ResponseError, S>> for SenderPersistedError
where
    S: std::error::Error + Send + Sync + 'static,
{
    fn from(err: payjoin::persist::PersistedError<send::ResponseError, S>) -> Self {
        if err.storage_error_ref().is_some() {
            if let Some(storage_err) = err.storage_error() {
                return SenderPersistedError::from(ImplementationError::new(storage_err));
            }
            return SenderPersistedError::Unexpected;
        }
        if let Some(api_err) = err.api_error() {
            return SenderPersistedError::ResponseError(api_err.into());
        }
        SenderPersistedError::Unexpected
    }
}

impl<S> From<payjoin::persist::PersistedError<send::BuildSenderError, S>> for SenderPersistedError
where
    S: std::error::Error + Send + Sync + 'static,
{
    fn from(err: payjoin::persist::PersistedError<send::BuildSenderError, S>) -> Self {
        if err.storage_error_ref().is_some() {
            if let Some(storage_err) = err.storage_error() {
                return SenderPersistedError::from(ImplementationError::new(storage_err));
            }
            return SenderPersistedError::Unexpected;
        }
        if let Some(api_err) = err.api_error() {
            return SenderPersistedError::BuildSenderError(Arc::new(api_err.into()));
        }
        SenderPersistedError::Unexpected
    }
}

#[cfg(all(test, feature = "_test-utils"))]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use payjoin::bitcoin::{Address, FeeRate};
    use payjoin::persist::NoopSessionPersister;
    use payjoin::receive::v2::ReceiverBuilder;
    use payjoin::send::v2::SenderBuilder;
    use payjoin::OhttpKeys;
    use payjoin_test_utils::{EXAMPLE_URL, KEM, KEY_ID, PARSED_ORIGINAL_PSBT, SYMMETRIC};

    use super::*;

    fn sender_with_reply_key(
        expiration: Duration,
    ) -> payjoin::send::v2::Sender<send::v2::WithReplyKey> {
        let address = Address::from_str("2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7")
            .expect("valid address")
            .assume_checked();
        let ohttp_keys = OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        );
        let pj_uri = ReceiverBuilder::new(address, EXAMPLE_URL, ohttp_keys)
            .expect("receiver builder should succeed")
            .with_expiration(expiration)
            .build()
            .save(&NoopSessionPersister::default())
            .expect("receiver transition should persist")
            .pj_uri();

        SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri)
            .build_recommended(FeeRate::BROADCAST_MIN)
            .expect("sender builder should succeed")
            .save(&NoopSessionPersister::default())
            .expect("sender transition should persist")
    }

    #[test]
    fn test_create_request_error_exposes_expired_kind() {
        let sender = sender_with_reply_key(Duration::ZERO);
        let error = match sender.create_v2_post_request(EXAMPLE_URL) {
            Err(error) => CreateRequestError::from(error),
            Ok(_) => panic!("expired sender request should fail"),
        };

        assert_eq!(error.kind(), CreateRequestErrorKind::Expired);
        assert_eq!(error.message(), "session expired");
        assert!(error.hpke_error().is_none());
        assert!(error.ohttp_error().is_none());
    }

    #[test]
    fn test_encapsulation_error_exposes_directory_response_details() {
        let sender = sender_with_reply_key(Duration::from_secs(60));
        let (_, post_ctx) =
            sender.create_v2_post_request(EXAMPLE_URL).expect("request creation should succeed");
        let error = sender
            .process_response(&[], post_ctx)
            .save(&NoopSessionPersister::default())
            .expect_err("empty response should fail");
        let error = EncapsulationError::from(
            error.api_error().expect("encapsulation error should be available"),
        );

        assert_eq!(error.kind(), EncapsulationErrorKind::DirectoryResponse);
        let directory =
            error.directory_response_error().expect("directory response details should be present");
        assert_eq!(directory.kind(), crate::error::DirectoryResponseErrorKind::InvalidSize);
        assert_eq!(directory.invalid_size(), Some(0));
        assert!(directory.ohttp_error().is_none());
        assert!(error.hpke_error().is_none());
    }
}

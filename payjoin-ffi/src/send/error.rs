use std::sync::Arc;

use payjoin::bitcoin::psbt::PsbtParseError;
use payjoin::send;

use crate::error::ImplementationError;

/// Error building a Sender from a SenderBuilder.
///
/// This error is unrecoverable.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error initializing the sender: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct BuildSenderError {
    msg: String,
}

impl From<PsbtParseError> for BuildSenderError {
    fn from(value: PsbtParseError) -> Self { BuildSenderError { msg: value.to_string() } }
}

impl From<send::BuildSenderError> for BuildSenderError {
    fn from(value: send::BuildSenderError) -> Self { BuildSenderError { msg: value.to_string() } }
}

/// Error returned when request could not be created.
///
/// This error can currently only happen due to programmer mistake.
/// `unwrap()`ing it is thus considered OK in Rust but you may achieve nicer message by displaying
/// it.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CreateRequestError(#[from] send::v2::CreateRequestError);

/// Error returned for v2-specific payload encapsulation errors.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct EncapsulationError(#[from] send::v2::EncapsulationError);

/// Error that may occur when the response from receiver is malformed.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ValidationError(#[from] send::ValidationError);

/// Represent an error returned by Payjoin receiver.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
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
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct WellKnownError(#[from] send::WellKnownError);

/// Error that may occur when the sender session event log is replayed
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SenderReplayError(#[from] send::v2::ReplayError);

/// Error that may occur during state machine transitions
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
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

impl<S> From<payjoin::persist::PersistedError<send::v2::EncapsulationError, S>> for SenderPersistedError
where
    S: std::error::Error,
{
    fn from(err: payjoin::persist::PersistedError<send::v2::EncapsulationError, S>) -> Self {
        if let Some(storage_err) = err.storage_error_ref() {
            return SenderPersistedError::Storage(Arc::new(ImplementationError::from(
                storage_err.to_string(),
            )));
        }
        if let Some(api_err) = err.api_error() {
            return SenderPersistedError::EncapsulationError(Arc::new(api_err.into()));
        }
        SenderPersistedError::Unexpected
    }
}

impl<S> From<payjoin::persist::PersistedError<send::ResponseError, S>> for SenderPersistedError
where
    S: std::error::Error,
{
    fn from(err: payjoin::persist::PersistedError<send::ResponseError, S>) -> Self {
        if let Some(storage_err) = err.storage_error_ref() {
            return SenderPersistedError::Storage(Arc::new(ImplementationError::from(
                storage_err.to_string(),
            )));
        }
        if let Some(api_err) = err.api_error() {
            return SenderPersistedError::ResponseError(api_err.into());
        }
        SenderPersistedError::Unexpected
    }
}

impl<S> From<payjoin::persist::PersistedError<send::BuildSenderError, S>> for SenderPersistedError
where
    S: std::error::Error,
{
    fn from(err: payjoin::persist::PersistedError<send::BuildSenderError, S>) -> Self {
        if let Some(storage_err) = err.storage_error_ref() {
            return SenderPersistedError::Storage(Arc::new(ImplementationError::from(
                storage_err.to_string(),
            )));
        }
        if let Some(api_err) = err.api_error() {
            return SenderPersistedError::BuildSenderError(Arc::new(api_err.into()));
        }
        SenderPersistedError::Unexpected
    }
}

use std::sync::Arc;

use payjoin::bitcoin::psbt::PsbtParseError as CorePsbtParseError;
use payjoin::send;

use crate::error::{FfiValidationError, ImplementationError};

/// Error building a Sender from a SenderBuilder.
///
/// This error is unrecoverable.
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display, Eq)]
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
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct CreateRequestError(#[from] send::v2::CreateRequestError);

#[uniffi::export]
impl CreateRequestError {
    /// Returns `true` if the request could not be created because the session
    /// has expired.
    pub fn is_expired(&self) -> bool { self.0.is_expired() }
}

/// Error returned for v2-specific payload decapsulation errors.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct DecapsulationError(#[from] send::v2::DecapsulationError);

/// Error that may occur when the response from receiver is malformed.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
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
            // `send::ResponseError` is non_exhaustive; surface any future
            // variant as an unrecognized error rather than failing to build.
            other =>
                ResponseError::Unrecognized { error_code: String::new(), msg: other.to_string() },
        }
    }
}

/// BIP-78 well-known error code, surfaced to bindings so senders can branch
/// on the code instead of parsing the Display string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ErrorCode {
    /// The payjoin endpoint is not available for now.
    Unavailable,
    /// The receiver added some inputs but could not bump the fee.
    NotEnoughMoney,
    /// This version of payjoin is not supported.
    VersionUnsupported,
    /// The receiver rejected the original PSBT.
    OriginalPsbtRejected,
    /// A well-known code newer than this binding understands.
    Unrecognized,
}

impl From<send::ErrorCode> for ErrorCode {
    fn from(value: send::ErrorCode) -> Self {
        match value {
            send::ErrorCode::Unavailable => ErrorCode::Unavailable,
            send::ErrorCode::NotEnoughMoney => ErrorCode::NotEnoughMoney,
            send::ErrorCode::VersionUnsupported => ErrorCode::VersionUnsupported,
            send::ErrorCode::OriginalPsbtRejected => ErrorCode::OriginalPsbtRejected,
            // `send::ErrorCode` is non_exhaustive; map codes this binding does
            // not yet know to Unrecognized.
            _ => ErrorCode::Unrecognized,
        }
    }
}

/// A well-known error that can be safely displayed to end users.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct WellKnownError(#[from] send::WellKnownError);

#[uniffi::export]
impl WellKnownError {
    /// Return the BIP-78 well-known error code, letting senders branch on it
    /// instead of parsing the Display string.
    pub fn code(&self) -> ErrorCode { self.0.code().into() }
}

/// Error that may occur when the sender session event log is replayed
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[uniffi::export(Debug, Display)]
#[error(transparent)]
pub struct SenderReplayError(
    #[from] payjoin::error::ReplayError<send::v2::SendSession, send::v2::SessionEvent>,
);

#[uniffi::export]
impl SenderReplayError {
    /// Returns `true` if the event log could not be replayed because the
    /// session has expired.
    pub fn is_expired(&self) -> bool { self.0.is_expired() }
}

/// Error raised by a sender state machine transition
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[error(transparent)]
pub enum SenderError {
    /// rust-payjoin sender Decapsulation error
    #[error(transparent)]
    Decapsulation(Arc<DecapsulationError>),
    /// rust-payjoin sender response error
    #[error(transparent)]
    Response(ResponseError),
    /// Sender Build error
    #[error(transparent)]
    BuildSender(Arc<BuildSenderError>),
    /// Unexpected error
    #[error("An unexpected error occurred")]
    Unexpected,
}

/// Error that may occur during state machine transitions
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[error(transparent)]
pub enum SenderPersistedError {
    /// A transient error: nothing was persisted, and the failed transition
    /// can be retried by calling it again on the same sender object
    #[error(transparent)]
    Transient(SenderError),
    /// A fatal error: the session is closed or has moved to an error state
    #[error(transparent)]
    Fatal(SenderError),
    /// Storage error that could occur at application storage layer
    #[error(transparent)]
    Storage(Arc<ImplementationError>),
}

impl From<ImplementationError> for SenderPersistedError {
    fn from(value: ImplementationError) -> Self { SenderPersistedError::Storage(Arc::new(value)) }
}

macro_rules! impl_sender_persisted_error_from {
    (
        $api_error_ty:ty,
        $sender_arm:expr
    ) => {
        impl<S, C> From<payjoin::persist::PersistedError<$api_error_ty, S, (), C>>
            for SenderPersistedError
        where
            S: std::error::Error + Send + Sync + 'static,
            C: std::fmt::Debug,
        {
            fn from(err: payjoin::persist::PersistedError<$api_error_ty, S, (), C>) -> Self {
                if err.storage_error_ref().is_some() {
                    if let Some(storage_err) = err.storage_error() {
                        return SenderPersistedError::from(ImplementationError::new(storage_err));
                    }
                    return SenderPersistedError::Fatal(SenderError::Unexpected);
                }
                let is_transient = err.is_transient();
                if let Some(api_err) = err.api_error() {
                    let sender_err = $sender_arm(api_err);
                    return if is_transient {
                        SenderPersistedError::Transient(sender_err)
                    } else {
                        SenderPersistedError::Fatal(sender_err)
                    };
                }
                SenderPersistedError::Fatal(SenderError::Unexpected)
            }
        }
    };
}

impl_sender_persisted_error_from!(
    send::v2::DecapsulationError,
    |api_err: send::v2::DecapsulationError| SenderError::Decapsulation(Arc::new(api_err.into()))
);

impl_sender_persisted_error_from!(send::ResponseError, |api_err: send::ResponseError| {
    SenderError::Response(api_err.into())
});

impl_sender_persisted_error_from!(send::BuildSenderError, |api_err: send::BuildSenderError| {
    SenderError::BuildSender(Arc::new(api_err.into()))
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_error_exposes_is_expired() {
        // A non-expiry CreateRequestError delegates to the core predicate.
        let err = CreateRequestError::from(send::v2::CreateRequestError::from(
            payjoin::IntoUrlError::BadScheme,
        ));
        assert!(!err.is_expired());

        // The accessor is also exposed on the sender replay error.
        let _: fn(&SenderReplayError) -> bool = SenderReplayError::is_expired;
    }

    #[test]
    fn well_known_error_exposes_code() {
        use payjoin::send::ErrorCode as Core;
        assert_eq!(ErrorCode::from(Core::Unavailable), ErrorCode::Unavailable);
        assert_eq!(ErrorCode::from(Core::NotEnoughMoney), ErrorCode::NotEnoughMoney);
        assert_eq!(ErrorCode::from(Core::VersionUnsupported), ErrorCode::VersionUnsupported);
        assert_eq!(ErrorCode::from(Core::OriginalPsbtRejected), ErrorCode::OriginalPsbtRejected);

        // The accessor is exposed on the binding's WellKnownError.
        let _: fn(&WellKnownError) -> ErrorCode = WellKnownError::code;
    }
}

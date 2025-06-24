use std::sync::Arc;

use payjoin::receive;

use crate::error::ImplementationError;
use crate::uri::error::IntoUrlError;

/// The top-level error type for the payjoin receiver
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum Error {
    /// Errors that can be replied to the sender
    #[error("Replyable error: {0}")]
    ReplyToSender(Arc<ReplyableError>),
    /// V2-specific errors that are infeasable to reply to the sender
    #[error("Unreplyable error: {0}")]
    V2(Arc<SessionError>),
    /// Error that may occur when converting a some type to a URL
    #[error("IntoUrl error: {0}")]
    IntoUrl(Arc<IntoUrlError>),
    /// Catch-all for unhandled error variants
    #[error("An unexpected error occurred")]
    Unexpected,
}

impl From<receive::Error> for Error {
    fn from(value: receive::Error) -> Self {
        match value {
            receive::Error::ReplyToSender(e) => Error::ReplyToSender(Arc::new(ReplyableError(e))),
            receive::Error::V2(e) => Error::V2(Arc::new(SessionError(e))),
            _ => Error::Unexpected,
        }
    }
}

/// Error that may occur during state machine transitions
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ReceiverPersistedError {
    /// rust-payjoin receiver error
    #[error(transparent)]
    Receiver(Error),
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
        impl<S> From<payjoin::persist::PersistedError<$api_error_ty, S>> for ReceiverPersistedError
        where
            S: std::error::Error,
        {
            fn from(err: payjoin::persist::PersistedError<$api_error_ty, S>) -> Self {
                if let Some(storage_err) = err.storage_error_ref() {
                    return ReceiverPersistedError::Storage(Arc::new(ImplementationError::from(
                        storage_err.to_string(),
                    )));
                }
                if let Some(api_err) = err.api_error() {
                    return ReceiverPersistedError::Receiver($receiver_arm(api_err));
                }
                ReceiverPersistedError::Receiver(Error::Unexpected)
            }
        }
    };
}

impl_persisted_error_from!(receive::ReplyableError, |api_err: receive::ReplyableError| {
    Error::ReplyToSender(Arc::new(api_err.into()))
});

impl_persisted_error_from!(receive::Error, |api_err: receive::Error| api_err.into());

impl_persisted_error_from!(payjoin::IntoUrlError, |api_err: payjoin::IntoUrlError| Error::IntoUrl(
    Arc::new(api_err.into())
));

/// The replyable error type for the payjoin receiver, representing failures need to be
/// returned to the sender.
///
/// The error handling is designed to:
/// 1. Provide structured error responses for protocol-level failures
/// 2. Hide implementation details of external errors for security
/// 3. Support proper error propagation through the receiver stack
/// 4. Provide errors according to BIP-78 JSON error specifications for return
///    after conversion into [`JsonReply`]
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ReplyableError(#[from] receive::ReplyableError);

/// The standard format for errors that can be replied as JSON.
///
/// The JSON output includes the following fields:
/// ```json
/// {
///     "errorCode": "specific-error-code",
///     "message": "Human readable error message"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct JsonReply(receive::JsonReply);

impl From<JsonReply> for receive::JsonReply {
    fn from(value: JsonReply) -> Self { value.0 }
}

impl From<receive::JsonReply> for JsonReply {
    fn from(value: receive::JsonReply) -> Self { Self(value) }
}

impl From<ReplyableError> for JsonReply {
    fn from(value: ReplyableError) -> Self { Self((&value.0).into()) }
}

/// Error that may occur during a v2 session typestate change
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SessionError(#[from] receive::v2::SessionError);

/// Error that may occur when output substitution fails.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct OutputSubstitutionError(#[from] receive::OutputSubstitutionError);

/// Error that may occur when coin selection fails.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SelectionError(#[from] receive::SelectionError);

/// Error that may occur when input contribution fails.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct InputContributionError(#[from] receive::InputContributionError);

/// Error validating a PSBT Input
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PsbtInputError(#[from] receive::PsbtInputError);

/// Error that may occur when a receiver event log is replayed
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ReceiverReplayError(#[from] receive::v2::ReplayError);

use std::sync::Arc;

use payjoin::receive;

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
    fn from(value: JsonReply) -> Self {
        value.0
    }
}

impl From<ReplyableError> for JsonReply {
    fn from(value: ReplyableError) -> Self {
        Self(value.0.into())
    }
}

/// Error arising due to the specific receiver implementation
///
/// e.g. database errors, network failures, wallet errors
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ImplementationError(#[from] receive::ImplementationError);

impl From<String> for ImplementationError {
    fn from(value: String) -> Self {
        Self(value.into())
    }
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

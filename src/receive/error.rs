use std::sync::Arc;

use payjoin::receive;

/// The top-level error type for the payjoin receiver
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum Error {
    /// Errors that can be replied to the sender
    #[error("Replyable error: {0}")]
    ReplyToSender(ReplyableError),
    /// V2-specific errors that are infeasable to reply to the sender
    #[error("Unreplyable error: {msg}")]
    V2 { msg: String },
    /// Catch-all for unhandled error variants
    #[error("An unexpected error occurred")]
    Unexpected,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ReplyableError {
    /// Error arising from validation of the original PSBT payload
    #[error("Error while validating original PSBT payload: {msg}")]
    Payload { msg: String },
    /// Protocol-specific errors for BIP-78 v1 requests (e.g. HTTP request validation, parameter checks)
    #[error("Error while validating V1 request: {msg}")]
    V1 { msg: String },
    /// Error arising due to the specific receiver implementation
    ///
    /// e.g. database errors, network failures, wallet errors
    #[error(transparent)]
    Implementation(Arc<ImplementationError>),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error occurred in receiver implementation: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ImplementationError {
    msg: String,
}

impl From<receive::Error> for Error {
    fn from(value: receive::Error) -> Self {
        match value {
            receive::Error::ReplyToSender(e) => Error::ReplyToSender(e.into()),
            receive::Error::V2(_) => Error::V2 { msg: value.to_string() },
            _ => Error::Unexpected,
        }
    }
}

impl From<receive::ReplyableError> for ReplyableError {
    fn from(value: receive::ReplyableError) -> Self {
        match value {
            receive::ReplyableError::Payload(_) => {
                ReplyableError::Payload { msg: value.to_string() }
            }
            receive::ReplyableError::V1(_) => ReplyableError::V1 { msg: value.to_string() },
            receive::ReplyableError::Implementation(_) => {
                ReplyableError::Implementation(Arc::new(ImplementationError {
                    msg: value.to_string(),
                }))
            }
        }
    }
}

/// Error that may occur when output substitution fails.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Output substition error: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct OutputSubstitutionError {
    msg: String,
}

impl From<receive::OutputSubstitutionError> for OutputSubstitutionError {
    fn from(value: receive::OutputSubstitutionError) -> Self {
        OutputSubstitutionError { msg: value.to_string() }
    }
}

/// Error that may occur when coin selection fails.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error occurred during coin selection: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SelectionError {
    msg: String,
}

impl From<receive::SelectionError> for SelectionError {
    fn from(value: receive::SelectionError) -> Self {
        SelectionError { msg: value.to_string() }
    }
}

/// Error that may occur when input contribution fails.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Input contribution error: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct InputContributionError {
    msg: String,
}

impl From<receive::InputContributionError> for InputContributionError {
    fn from(value: receive::InputContributionError) -> Self {
        InputContributionError { msg: value.to_string() }
    }
}

/// Error validating a PSBT Input
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error validating PSBT input: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PsbtInputError {
    msg: String,
}

impl From<receive::PsbtInputError> for PsbtInputError {
    fn from(value: receive::PsbtInputError) -> Self {
        PsbtInputError { msg: value.to_string() }
    }
}

impl From<String> for ImplementationError {
    fn from(msg: String) -> Self {
        ImplementationError { msg }
    }
}

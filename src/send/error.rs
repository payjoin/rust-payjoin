use std::sync::Arc;

use payjoin::bitcoin::psbt::PsbtParseError;
use payjoin::send;

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
    fn from(value: PsbtParseError) -> Self {
        BuildSenderError { msg: value.to_string() }
    }
}

impl From<send::BuildSenderError> for BuildSenderError {
    fn from(value: send::BuildSenderError) -> Self {
        BuildSenderError { msg: value.to_string() }
    }
}

/// Error returned when request could not be created.
///
/// This error can currently only happen due to programmer mistake.
/// `unwrap()`ing it is thus considered OK in Rust but you may achieve nicer message by displaying
/// it.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error creating the request: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct CreateRequestError {
    msg: String,
}

impl From<send::v2::CreateRequestError> for CreateRequestError {
    fn from(value: send::v2::CreateRequestError) -> Self {
        CreateRequestError { msg: value.to_string() }
    }
}

/// Error returned for v2-specific payload encapsulation errors.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error encapsulating the request: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct EncapsulationError {
    msg: String,
}

impl From<send::v2::EncapsulationError> for EncapsulationError {
    fn from(value: send::v2::EncapsulationError) -> Self {
        EncapsulationError { msg: value.to_string() }
    }
}

/// Error that may occur when the response from receiver is malformed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error validating the receiver response: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ValidationError {
    msg: String,
}

/// Represent an error returned by Payjoin receiver.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ResponseError {
    /// `WellKnown` Errors are defined in the [`BIP78::ReceiverWellKnownError`] spec.
    ///
    /// It is safe to display `WellKnown` errors to end users.
    ///
    /// [`BIP78::ReceiverWellKnownError`]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Receivers_well_known_errors
    #[error("A receiver error occurred: ")]
    WellKnown(WellKnownError),

    /// Errors caused by malformed responses.
    #[error("An error occurred due to a malformed response: ")]
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
            send::ResponseError::WellKnown(e) => ResponseError::WellKnown(e.into()),
            send::ResponseError::Validation(e) => {
                ResponseError::Validation(Arc::new(ValidationError { msg: e.to_string() }))
            }
            send::ResponseError::Unrecognized { error_code, message } => {
                ResponseError::Unrecognized { error_code, msg: message }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum WellKnownError {
    #[error("The payjoin endpoint is not available for now.")]
    Unavailable { msg: String },
    #[error("The receiver added some inputs but could not bump the fee of the payjoin proposal.")]
    NotEnoughMoney { msg: String },
    #[error("This version of payjoin is not supported. Use version {supported:?}.")]
    VersionUnsupported { msg: String, supported: Vec<u64> },
    #[error("The receiver rejected the original PSBT.")]
    OriginalPsbtRejected { msg: String },
    #[error("An unexpected error occurred")]
    Unexpected,
}

impl From<send::WellKnownError> for WellKnownError {
    fn from(value: send::WellKnownError) -> Self {
        match value {
            send::WellKnownError::Unavailable(m) => WellKnownError::Unavailable { msg: m },
            send::WellKnownError::NotEnoughMoney(m) => WellKnownError::NotEnoughMoney { msg: m },
            send::WellKnownError::VersionUnsupported { message, supported } => {
                WellKnownError::VersionUnsupported { msg: message, supported }
            }
            send::WellKnownError::OriginalPsbtRejected(m) => {
                WellKnownError::OriginalPsbtRejected { msg: m }
            }
            _ => WellKnownError::Unexpected,
        }
    }
}

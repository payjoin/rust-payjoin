use std::fmt::Debug;

use payjoin::bitcoin::psbt::PsbtParseError;
use payjoin::receive::{
    ImplementationError, InputContributionError, OutputSubstitutionError, PsbtInputError,
    ReplyableError, SelectionError,
};
use payjoin::send::v2::{CreateRequestError, EncapsulationError};
use payjoin::send::{BuildSenderError, ResponseError as PdkResponseError, ValidationError};
use payjoin::IntoUrlError;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum PayjoinError {
    #[error("Error while parsing the string: {msg} ")]
    InvalidAddress { msg: String },
    #[error("Error while parsing the script: {msg}")]
    InvalidScript { msg: String },
    #[error("{msg}")]
    NetworkValidation { msg: String },
    #[error("Error encountered while decoding PSBT: {msg} ")]
    PsbtParseError { msg: String },

    #[error("Response error: {msg:?}")]
    ResponseError { msg: String },

    ///Error that may occur when the request from sender is malformed.
    ///This is currently opaque type because we aren’t sure which variants will stay. You can only display it.
    #[error("Error encountered while processing the sender's request : {msg}")]
    RequestError { msg: String },

    ///Error that may occur when the request from sender is malformed.
    #[error("Error encountered while decoding transaction data : {msg}")]
    TransactionError { msg: String },
    // To be returned as HTTP 500
    #[error("HTTP 500 : {msg}")]
    ServerError { msg: String },

    ///Error that may occur when coin selection fails.
    #[error("Error occurred during coin selection: {msg}")]
    SelectionError { msg: String },

    ///Error returned when request could not be created.
    ///This error can currently only happen due to programmer mistake.
    #[error("Error creating the request: {msg}")]
    CreateRequestError { msg: String },

    /// Error building a Sender from a SenderBuilder.
    /// This error is unrecoverable.
    #[error("Error building the sender: {msg}")]
    BuildSenderError { msg: String },

    #[error("Error parsing the Pj URL: {msg}")]
    PjParseError { msg: String },

    #[error("{msg}")]
    PjNotSupported { msg: String },

    #[error("Malformed response from receiver: {msg}")]
    ValidationError { msg: String },

    #[error("V2Error: {msg}")]
    V2Error { msg: String },

    #[error("Unexpected error occurred: {msg}")]
    UnexpectedError { msg: String },

    #[error("{msg}")]
    OhttpError { msg: String },

    #[error("{msg}")]
    UrlError { msg: String },

    #[error("{msg}")]
    IoError { msg: String },

    #[error("{msg}")]
    OutputSubstitutionError { msg: String },

    #[error("{msg}")]
    InputContributionError { msg: String },

    #[error("{msg}")]
    InputPairError { msg: String },

    #[error("{msg}")]
    SerdeJsonError { msg: String },

    ///Error that can be replied to the sender
    #[error("Replyable error occurred: {msg}")]
    ReplyableError { msg: String },

    #[error("Error converting to URL: {msg}")]
    IntoUrlError { msg: String },

    #[error("Error encapsulating payload: {msg}")]
    EncapsulationError { msg: String },

    #[error("Implementation error: {msg}")]
    ImplementationError { msg: String },
}

macro_rules! impl_from_error {
    ($($src:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$src> for PayjoinError {
                fn from(value: $src) -> Self {
                    PayjoinError::$variant { msg: value.to_string() }
                }
            }
        )*
    };
}

impl_from_error! {
    ohttp::Error => OhttpError,
    PsbtParseError => PsbtParseError,
    payjoin::bitcoin::consensus::encode::Error => TransactionError,
    payjoin::bitcoin::address::ParseError => InvalidAddress,
    ValidationError => ValidationError,
    OutputSubstitutionError => OutputSubstitutionError,
    PsbtInputError => InputPairError,
    serde_json::Error => SerdeJsonError,
}

#[cfg(feature = "uniffi")]
impl From<uniffi::UnexpectedUniFFICallbackError> for PayjoinError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        PayjoinError::UnexpectedError { msg: value.to_string() }
    }
}

impl From<PdkResponseError> for PayjoinError {
    fn from(value: PdkResponseError) -> Self {
        PayjoinError::ResponseError { msg: format!("{:?}", value) }
    }
}

impl From<SelectionError> for PayjoinError {
    fn from(value: SelectionError) -> Self {
        PayjoinError::SelectionError { msg: format!("{:?}", value) }
    }
}

impl From<payjoin::receive::Error> for PayjoinError {
    fn from(value: payjoin::receive::Error) -> Self {
        match value {
            payjoin::receive::Error::ReplyToSender(e) => e.into(),
            payjoin::receive::Error::V2(e) => PayjoinError::V2Error { msg: e.to_string() },
            _ => Self::UnexpectedError { msg: "Unhandled receive error variant".to_string() },
        }
    }
}

impl From<payjoin::io::Error> for PayjoinError {
    fn from(value: payjoin::io::Error) -> Self {
        PayjoinError::IoError { msg: value.to_string() }
    }
}

impl From<ReplyableError> for PayjoinError {
    fn from(value: ReplyableError) -> Self {
        PayjoinError::ReplyableError { msg: format!("{:?}", value) }
    }
}

impl From<IntoUrlError> for PayjoinError {
    fn from(value: IntoUrlError) -> Self {
        PayjoinError::IntoUrlError { msg: format!("{:?}", value) }
    }
}

impl From<InputContributionError> for PayjoinError {
    fn from(value: InputContributionError) -> Self {
        PayjoinError::InputContributionError { msg: format!("{:?}", value) }
    }
}

impl From<ImplementationError> for PayjoinError {
    fn from(value: ImplementationError) -> Self {
        PayjoinError::ImplementationError { msg: format!("{:?}", value) }
    }
}

impl From<CreateRequestError> for PayjoinError {
    fn from(value: CreateRequestError) -> Self {
        PayjoinError::CreateRequestError { msg: format!("{:?}", value) }
    }
}

impl From<BuildSenderError> for PayjoinError {
    fn from(value: BuildSenderError) -> Self {
        PayjoinError::BuildSenderError { msg: format!("{:?}", value) }
    }
}

impl From<EncapsulationError> for PayjoinError {
    fn from(value: EncapsulationError) -> Self {
        PayjoinError::EncapsulationError { msg: format!("{:?}", value) }
    }
}

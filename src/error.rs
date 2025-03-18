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
    #[error("Error while parsing the string: {message} ")]
    InvalidAddress { message: String },
    #[error("Error while parsing the script: {message}")]
    InvalidScript { message: String },
    #[error("{message}")]
    NetworkValidation { message: String },
    #[error("Error encountered while decoding PSBT: {message} ")]
    PsbtParseError { message: String },

    #[error("Response error: {message:?}")]
    ResponseError { message: String },

    ///Error that may occur when the request from sender is malformed.
    ///This is currently opaque type because we aren’t sure which variants will stay. You can only display it.
    #[error("Error encountered while processing the sender's request : {message}")]
    RequestError { message: String },

    ///Error that may occur when the request from sender is malformed.
    #[error("Error encountered while decoding transaction data : {message}")]
    TransactionError { message: String },
    // To be returned as HTTP 500
    #[error("HTTP 500 : {message}")]
    ServerError { message: String },

    ///Error that may occur when coin selection fails.
    #[error("Error occurred during coin selection: {message}")]
    SelectionError { message: String },

    ///Error returned when request could not be created.
    ///This error can currently only happen due to programmer mistake.
    #[error("Error creating the request: {message}")]
    CreateRequestError { message: String },

    /// Error building a Sender from a SenderBuilder.
    /// This error is unrecoverable.
    #[error("Error building the sender: {message}")]
    BuildSenderError { message: String },

    #[error("Error parsing the Pj URL: {message}")]
    PjParseError { message: String },

    #[error("{message}")]
    PjNotSupported { message: String },

    #[error("Malformed response from receiver: {message}")]
    ValidationError { message: String },

    #[error("V2Error: {message}")]
    V2Error { message: String },

    #[error("Unexpected error occurred: {message}")]
    UnexpectedError { message: String },

    #[error("{message}")]
    OhttpError { message: String },

    #[error("{message}")]
    UrlError { message: String },

    #[error("{message}")]
    IoError { message: String },

    #[error("{message}")]
    OutputSubstitutionError { message: String },

    #[error("{message}")]
    InputContributionError { message: String },

    #[error("{message}")]
    InputPairError { message: String },

    #[error("{message}")]
    SerdeJsonError { message: String },

    ///Error that can be replied to the sender
    #[error("Replyable error occurred: {message}")]
    ReplyableError { message: String },

    #[error("Error converting to URL: {message}")]
    IntoUrlError { message: String },

    #[error("Error encapsulating payload: {message}")]
    EncapsulationError { message: String },

    #[error("Implementation error: {message}")]
    ImplementationError { message: String },
}

macro_rules! impl_from_error {
    ($($src:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$src> for PayjoinError {
                fn from(value: $src) -> Self {
                    PayjoinError::$variant { message: value.to_string() }
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
        PayjoinError::UnexpectedError { message: value.to_string() }
    }
}

impl From<PdkResponseError> for PayjoinError {
    fn from(value: PdkResponseError) -> Self {
        PayjoinError::ResponseError { message: format!("{:?}", value) }
    }
}

impl From<SelectionError> for PayjoinError {
    fn from(value: SelectionError) -> Self {
        PayjoinError::SelectionError { message: format!("{:?}", value) }
    }
}

impl From<payjoin::receive::Error> for PayjoinError {
    fn from(value: payjoin::receive::Error) -> Self {
        match value {
            payjoin::receive::Error::ReplyToSender(e) => e.into(),
            payjoin::receive::Error::V2(e) => PayjoinError::V2Error { message: e.to_string() },
            _ => Self::UnexpectedError { message: "Unhandled receive error variant".to_string() },
        }
    }
}

impl From<payjoin::io::Error> for PayjoinError {
    fn from(value: payjoin::io::Error) -> Self {
        PayjoinError::IoError { message: value.to_string() }
    }
}

impl From<ReplyableError> for PayjoinError {
    fn from(value: ReplyableError) -> Self {
        PayjoinError::ReplyableError { message: format!("{:?}", value) }
    }
}

impl From<IntoUrlError> for PayjoinError {
    fn from(value: IntoUrlError) -> Self {
        PayjoinError::IntoUrlError { message: format!("{:?}", value) }
    }
}

impl From<InputContributionError> for PayjoinError {
    fn from(value: InputContributionError) -> Self {
        PayjoinError::InputContributionError { message: format!("{:?}", value) }
    }
}

impl From<ImplementationError> for PayjoinError {
    fn from(value: ImplementationError) -> Self {
        PayjoinError::ImplementationError { message: format!("{:?}", value) }
    }
}

impl From<CreateRequestError> for PayjoinError {
    fn from(value: CreateRequestError) -> Self {
        PayjoinError::CreateRequestError { message: format!("{:?}", value) }
    }
}

impl From<BuildSenderError> for PayjoinError {
    fn from(value: BuildSenderError) -> Self {
        PayjoinError::BuildSenderError { message: format!("{:?}", value) }
    }
}

impl From<EncapsulationError> for PayjoinError {
    fn from(value: EncapsulationError) -> Self {
        PayjoinError::EncapsulationError { message: format!("{:?}", value) }
    }
}

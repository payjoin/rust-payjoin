use std::fmt::Debug;

use payjoin::bitcoin::psbt::PsbtParseError;
use payjoin::receive::{RequestError, SelectionError};
use payjoin::send::{CreateRequestError, ResponseError as PdkResponseError, ValidationError};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PayjoinError {
    #[error("Error while parsing the string: {message} ")]
    InvalidAddress { message: String },
    #[error("Error while parsing the script: {message}")]
    InvalidScript { message: String },
    #[error("{message}")]
    NetworkValidation { message: String },
    #[error("Error encountered while decoding PSBT: {message} ")]
    PsbtParseError { message: String },

    #[error("Response error: {message}")]
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
    payjoin::bitcoin::address::Error => InvalidAddress,
    RequestError => RequestError,
    PdkResponseError => ResponseError,
    ValidationError => ValidationError,
    CreateRequestError => CreateRequestError,
    uniffi::UnexpectedUniFFICallbackError => UnexpectedError,
}

impl From<SelectionError> for PayjoinError {
    fn from(value: SelectionError) -> Self {
        PayjoinError::SelectionError { message: format!("{:?}", value) }
    }
}

impl From<payjoin::Error> for PayjoinError {
    fn from(value: payjoin::Error) -> Self {
        match value {
            payjoin::Error::BadRequest(e) => e.into(),
            payjoin::Error::Server(e) => PayjoinError::ServerError { message: e.to_string() },
            payjoin::Error::V2(e) => PayjoinError::V2Error { message: format!("{:?}", e) },
        }
    }
}

use std::fmt::Debug;

use payjoin::bitcoin::psbt::PsbtParseError;
use payjoin::receive::{RequestError, SelectionError};
use payjoin::send::{CreateRequestError, ResponseError as PdkResponseError, ValidationError};
use url::ParseError;

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
    #[error("Error that may occur when coin selection fails: {message}")]
    SelectionError { message: String },

    ///Error returned when request could not be created.
    ///This error can currently only happen due to programmer mistake.
    #[error("Error creating the request: {message}")]
    CreateRequestError { message: String },

    #[error("Error parsing the Pj URL: {message}")]
    PjParseError { message: String },

    #[error("{message}")]
    PjNotSupported { message: String },

    #[error("Malformed response from receiver is : {message}")]
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

impl From<ParseError> for PayjoinError {
    fn from(value: ParseError) -> Self {
        PayjoinError::UrlError { message: value.to_string() }
    }
}

impl From<ohttp::Error> for PayjoinError {
    fn from(value: ohttp::Error) -> Self {
        PayjoinError::OhttpError { message: value.to_string() }
    }
}
impl From<PsbtParseError> for PayjoinError {
    fn from(value: PsbtParseError) -> Self {
        PayjoinError::PsbtParseError { message: value.to_string() }
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
impl From<payjoin::bitcoin::consensus::encode::Error> for PayjoinError {
    fn from(value: payjoin::bitcoin::consensus::encode::Error) -> Self {
        PayjoinError::TransactionError { message: value.to_string() }
    }
}

impl From<payjoin::bitcoin::address::Error> for PayjoinError {
    fn from(value: payjoin::bitcoin::address::Error) -> Self {
        PayjoinError::InvalidAddress { message: value.to_string() }
    }
}
impl From<RequestError> for PayjoinError {
    fn from(value: RequestError) -> Self {
        PayjoinError::RequestError { message: value.to_string() }
    }
}
impl From<SelectionError> for PayjoinError {
    fn from(value: SelectionError) -> Self {
        PayjoinError::SelectionError { message: format!("{:?}", value) }
    }
}
impl From<PdkResponseError> for PayjoinError {
    fn from(value: PdkResponseError) -> Self {
        PayjoinError::ResponseError { message: value.to_string() }
    }
}
impl From<ValidationError> for PayjoinError {
    fn from(value: ValidationError) -> Self {
        PayjoinError::ValidationError { message: value.to_string() }
    }
}
impl From<CreateRequestError> for PayjoinError {
    fn from(value: CreateRequestError) -> Self {
        PayjoinError::CreateRequestError { message: value.to_string() }
    }
}
impl From<uniffi::UnexpectedUniFFICallbackError> for PayjoinError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedError { message: e.reason }
    }
}

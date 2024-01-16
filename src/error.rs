use std::fmt::Debug;

use bitcoincore_rpc::bitcoin::block::ValidationError;
use payjoin::bitcoin::psbt::PsbtParseError;
use payjoin::receive::{RequestError, SelectionError};
use payjoin::send::{CreateRequestError, ResponseError as PdkResponseError};
use payjoin::Error;

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
}

// #[derive(Debug, PartialEq, Eq, thiserror::Error)]
// pub enum OhttpError{
// 	#[error("{message}")]
// 	AeadError{ message: String },
//
// 	#[error("{message}")]
// 	CryptoError{ message: String },
//
// 	#[error("Error was found in the format")]
// 	FormatError,
//
// 	#[error("{message}")]
// 	HpkeError{ message: String },
//
// 	#[error("An internal error occurred")]
// 	InternalError,
//
// 	#[error("The wrong type of key was provided for the selected KEM")]
// 	InvalidKeyTypeError,
//
// 	#[error("The wrong KEM was specified")]
// 	InvalidKemError,
//
// 	#[error("{message}")]
// 	IoError{ message: String },
//
// 	#[error("The key ID was invalid")]
// 	KeyIdError,
//
// 	#[error("A field was truncated")]
// 	TruncatedError,
//
// 	#[error("The configuration was not supported")]
// 	UnsupportedError,
//
// 	#[error("The configuration contained too many symmetric suites")]
// 	TooManySymmetricSuitesError,
// }

// impl From<ohttp::Error> for OhttpError{
// 	fn from(value: ohttp::Error) -> Self {
// 		match value {
// 			ohttp::Error::Aead(e) => OhttpError::AeadError{message:e.to_string()},
// 			ohttp::Error::Format =>  OhttpError::FormatError,
// 			ohttp::Error::Internal => OhttpError::InternalError,
// 			ohttp::Error::InvalidKeyType => OhttpError::InvalidKeyTypeError,
// 			ohttp::Error::InvalidKem => OhttpError::InvalidKemError,
// 			ohttp::Error::Io(e) => OhttpError::IoError{message:e.to_string()},
// 			ohttp::Error::KeyId => OhttpError::KeyIdError,
// 			ohttp::Error::Truncated => OhttpError::TruncatedError,
// 			ohttp::Error::Unsupported => OhttpError::UnsupportedError,
// 			ohttp::Error::TooManySymmetricSuites => OhttpError::TooManySymmetricSuitesError,
// 			ohttp::Error::Hpke(e) => OhttpError::HpkeError{message:e.to_string()}
// 		}
// 	}
// }

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

impl From<Error> for PayjoinError {
    fn from(value: Error) -> Self {
        match value {
            Error::BadRequest(e) => e.into(),
            Error::Server(e) => PayjoinError::ServerError { message: e.to_string() },
            Error::V2(e) => PayjoinError::V2Error { message: format!("{:?}", e) },
        }
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

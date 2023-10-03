use payjoin::bitcoin::psbt::PsbtParseError;
use payjoin::receive::RequestError;
use payjoin::Error;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PayjoinError {
	#[error("Error while parsing the string: {message} ")]
	InvalidAddress { message: String },
	#[error("Error while parsing the script: {message}")]
	InvalidScript { message: String },

	#[error("Error encountered while decoding PSBT: {message} ")]
	PsbtParseError { message: String },

	#[error("Receive error: {message}")]
	ReceiveError { message: String },

	///Error that may occur when the request from sender is malformed.
	///This is currently opaque type because we aren’t sure which variants will stay. You can only display it.
	#[error("Error encountered while processing the sender's request : {message}")]
	RequestError { message: String },

	///Error that may occur when the request from sender is malformed.
	#[error("Error encountered while decoding tranaction data : {message}")]
	TransactionError { message: String },
	// To be returned as HTTP 500
	#[error("HTTP 500 : {message}")]
	ServerError { message: String },

	///Error that may occur when coin selection fails.
	#[error("Error that may occur when coin selection fails.")]
	SelectionError,

	///Error returned when request could not be created.
	///This error can currently only happen due to programmer mistake.
	#[error("Error creating the request: {message}")]
	CreateRequestError { message: String },

	#[error("Error parsing the Pj URL:: {message}")]
	PjParseError { message: String },

	#[error("{message}")]
	PjNotSupported { message: String },

	#[error("Malformed response from receiver is : {message}")]
	ContextValidationError { message: String },

	#[error("Unexpected error occurred: {message}")]
	UnexpectedError { message: String },
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
		}
	}
}

impl From<RequestError> for PayjoinError {
	fn from(value: RequestError) -> Self {
		PayjoinError::RequestError { message: value.to_string() }
	}
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PayjoinError {
	fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
		Self::UnexpectedError { message: e.reason }
	}
}

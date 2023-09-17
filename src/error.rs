use payjoin::bitcoin::psbt::PsbtParseError;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
	#[error("Error while parsing the string: {0}")]
	InvalidAddress(String),

	#[error("Invalid script: {0}")]
	InvalidScript(String),

	#[error("Error encountered while decoding PSBT : {0}")]
	PsbtParseError(String),

	#[error("Receive error : {0}")]
	ReceiveError(String),

	///Error that may occur when the request from sender is malformed.
	///This is currently opaque type because we aren’t sure which variants will stay. You can only display it.
	#[error("Error encountered while processing the sender's request : {0}")]
	RequestError(String),

	// ///Error that may occur when the request from sender is malformed.
	// #[error("Error encountered while decoding tranaction data : {0}")]
	// TransactionError(String),
	///Error that may occur when coin selection fails.
	#[error("Selection error : {0}")]
	SelectionError(String),

	///Error returned when request could not be created.
	///This error can currently only happen due to programmer mistake.
	#[error("Error creating the request: {0}")]
	CreateRequestError(String),

	#[error("Error parsing the Pj URL: {0}")]
	PjParseError(String),

	#[error("{0}")]
	PjNotSupported(String),

	// #[error("Malformed response from receiver is : {0}")] ContextValidationError(String),
	#[error("Unexpected error occured: {0}")]
	UnexpectedError(String),
}

impl From<PsbtParseError> for Error {
	fn from(value: PsbtParseError) -> Self {
		Error::PsbtParseError(value.to_string())
	}
}

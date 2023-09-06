use std::fmt;

use payjoin::bitcoin::psbt::PsbtParseError;
use payjoin::receive::RequestError;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// Error encountered during PSBT decoding from Base64 string.
	PsbtParseError(String),
	ReceiveError(String),
	///Error that may occur when the request from sender is malformed.
	///This is currently opaque type because we aren’t sure which variants will stay. You can only display it.
	RequestError(String),
	///Error that may occur when coin selection fails.
	SelectionError(String),
	///Error returned when request could not be created.
	///This error can currently only happen due to programmer mistake.
	CreateRequestError(String),
	PjParseError(String),
	UnexpectedError(String),
}
impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Error::ReceiveError(e) => write!(f, "ReceiveError: {}", e),
			Error::RequestError(e) => write!(f, "RequestError: {}", e),
			Error::SelectionError(e) => write!(f, "SelectionError: {}", e),
			Error::CreateRequestError(e) => write!(f, "CreateRequestError: {}", e),
			Error::PjParseError(e) => write!(f, "PjParseError: {}", e),
			Error::PsbtParseError(e) => write!(f, "PsbtParseError: {}", e),
			Error::UnexpectedError(e) => write!(f, "UnexpectedError: {}", e),
		}
	}
}
impl std::error::Error for Error {}
impl From<RequestError> for Error {
	fn from(value: RequestError) -> Self {
		Error::RequestError(value.to_string())
	}
}
impl From<PsbtParseError> for Error {
	fn from(value: PsbtParseError) -> Self {
		Error::PsbtParseError(value.to_string())
	}
}
impl From<payjoin::Error> for Error {
	fn from(value: payjoin::Error) -> Self {
		Error::UnexpectedError(value.to_string())
	}
}

use core::fmt;
use std::error;

use crate::receive::error::ValidationError;

/// Error that occurs during validation of an incoming v1 payjoin request.
///
/// This type provides a stable public API for v1 request validation errors while keeping internal
/// error variants private. It handles validation of:
/// - PSBT parsing and validation
/// - I/O operations during request processing
/// - HTTP headers (Content-Type, Content-Length)
///
/// The error messages are formatted as JSON strings according to the BIP-78 spec with appropriate
/// error codes and human-readable messages.
#[derive(Debug)]
pub struct RequestError(InternalRequestError);

#[derive(Debug)]
pub(crate) enum InternalRequestError {
    /// I/O error while reading the request body
    Io(std::io::Error),
    /// A required HTTP header is missing from the request
    MissingHeader(&'static str),
    /// The Content-Type header has an invalid value
    InvalidContentType(String),
    /// The Content-Length header could not be parsed as a number
    InvalidContentLength(std::num::ParseIntError),
    /// The Content-Length value exceeds the maximum allowed size
    ContentLengthTooLarge(u64),
}

impl From<InternalRequestError> for RequestError {
    fn from(value: InternalRequestError) -> Self { RequestError(value) }
}

impl From<InternalRequestError> for super::Error {
    fn from(e: InternalRequestError) -> Self { super::Error::Validation(e.into()) }
}

impl From<InternalRequestError> for ValidationError {
    fn from(e: InternalRequestError) -> Self { ValidationError::V1(e.into()) }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn write_error(
            f: &mut fmt::Formatter,
            code: &str,
            message: impl fmt::Display,
        ) -> fmt::Result {
            write!(f, r#"{{ "errorCode": "{}", "message": "{}" }}"#, code, message)
        }

        match &self.0 {
            InternalRequestError::Io(e) => write_error(f, "io-error", e),
            InternalRequestError::MissingHeader(header) =>
                write_error(f, "missing-header", format!("Missing header: {}", header)),
            InternalRequestError::InvalidContentType(content_type) => write_error(
                f,
                "invalid-content-type",
                format!("Invalid content type: {}", content_type),
            ),
            InternalRequestError::InvalidContentLength(e) =>
                write_error(f, "invalid-content-length", e),
            InternalRequestError::ContentLengthTooLarge(length) => write_error(
                f,
                "content-length-too-large",
                format!("Content length too large: {}.", length),
            ),
        }
    }
}

impl error::Error for RequestError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalRequestError::Io(e) => Some(e),
            InternalRequestError::InvalidContentLength(e) => Some(e),
            InternalRequestError::MissingHeader(_) => None,
            InternalRequestError::InvalidContentType(_) => None,
            InternalRequestError::ContentLengthTooLarge(_) => None,
        }
    }
}

use core::fmt;
use std::error;

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

/// A stable classification for BIP 78 v1 request validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestErrorKind {
    /// A required HTTP header was missing.
    MissingHeader,
    /// The content type was invalid.
    InvalidContentType,
    /// The content length header could not be parsed.
    InvalidContentLength,
    /// The declared content length did not match the request body.
    ContentLengthMismatch,
}

#[derive(Debug)]
pub(crate) enum InternalRequestError {
    /// A required HTTP header is missing from the request
    MissingHeader(&'static str),
    /// The Content-Type header has an invalid value
    InvalidContentType(String),
    /// The Content-Length header could not be parsed as a number
    InvalidContentLength(std::num::ParseIntError),
    /// The Content-Length value does not match the actual body length
    ContentLengthMismatch { expected: usize, actual: usize },
}

impl From<InternalRequestError> for RequestError {
    fn from(value: InternalRequestError) -> Self { RequestError(value) }
}

impl RequestError {
    /// Returns the stable classification of the request validation error.
    pub fn kind(&self) -> RequestErrorKind {
        match &self.0 {
            InternalRequestError::MissingHeader(_) => RequestErrorKind::MissingHeader,
            InternalRequestError::InvalidContentType(_) => RequestErrorKind::InvalidContentType,
            InternalRequestError::InvalidContentLength(_) => RequestErrorKind::InvalidContentLength,
            InternalRequestError::ContentLengthMismatch { .. } =>
                RequestErrorKind::ContentLengthMismatch,
        }
    }

    /// Returns the missing header name, if the request failed due to a missing header.
    pub fn header_name(&self) -> Option<&str> {
        match &self.0 {
            InternalRequestError::MissingHeader(header) => Some(header),
            _ => None,
        }
    }

    /// Returns the invalid content type, if present.
    pub fn invalid_content_type(&self) -> Option<&str> {
        match &self.0 {
            InternalRequestError::InvalidContentType(content_type) => Some(content_type.as_str()),
            _ => None,
        }
    }

    /// Returns the declared content length when the request body length mismatched.
    pub fn expected_content_length(&self) -> Option<usize> {
        match &self.0 {
            InternalRequestError::ContentLengthMismatch { expected, .. } => Some(*expected),
            _ => None,
        }
    }

    /// Returns the actual request body length when the request body length mismatched.
    pub fn actual_content_length(&self) -> Option<usize> {
        match &self.0 {
            InternalRequestError::ContentLengthMismatch { actual, .. } => Some(*actual),
            _ => None,
        }
    }
}

impl From<InternalRequestError> for super::ProtocolError {
    fn from(e: InternalRequestError) -> Self { super::ProtocolError::V1(e.into()) }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalRequestError::MissingHeader(header) => write!(f, "Missing header: {header}"),
            InternalRequestError::InvalidContentType(content_type) =>
                write!(f, "Invalid content type: {content_type}"),
            InternalRequestError::InvalidContentLength(e) => write!(f, "{e}"),
            InternalRequestError::ContentLengthMismatch { expected, actual } =>
                write!(f, "Content length mismatch: expected {expected}, got {actual}."),
        }
    }
}

impl error::Error for RequestError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalRequestError::InvalidContentLength(e) => Some(e),
            InternalRequestError::MissingHeader(_) => None,
            InternalRequestError::InvalidContentType(_) => None,
            InternalRequestError::ContentLengthMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_error_missing_header_accessor() {
        let error = RequestError::from(InternalRequestError::MissingHeader("Content-Type"));

        assert_eq!(error.kind(), RequestErrorKind::MissingHeader);
        assert_eq!(error.header_name(), Some("Content-Type"));
        assert_eq!(error.invalid_content_type(), None);
        assert_eq!(error.expected_content_length(), None);
        assert_eq!(error.actual_content_length(), None);
    }

    #[test]
    fn test_request_error_content_length_accessor() {
        let error = RequestError::from(InternalRequestError::ContentLengthMismatch {
            expected: 42,
            actual: 41,
        });

        assert_eq!(error.kind(), RequestErrorKind::ContentLengthMismatch);
        assert_eq!(error.expected_content_length(), Some(42));
        assert_eq!(error.actual_content_length(), Some(41));
    }
}

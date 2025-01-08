use core::fmt;
use std::error;

use crate::ohttp::OhttpEncapsulationError;

/// Error that may occur when the v2 request from sender is malformed.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct RequestError(InternalRequestError);

#[derive(Debug)]
pub(crate) enum InternalRequestError {
    /// Serde deserialization failed
    ParsePsbt(bitcoin::psbt::PsbtParseError),
    Utf8(std::string::FromUtf8Error),
}

impl From<InternalRequestError> for RequestError {
    fn from(value: InternalRequestError) -> Self { RequestError(value) }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalRequestError::*;
        fn write_error(
            f: &mut fmt::Formatter,
            code: &str,
            message: impl fmt::Display,
        ) -> fmt::Result {
            write!(f, r#"{{ "errorCode": "{}", "message": "{}" }}"#, code, message)
        }

        match &self.0 {
            ParsePsbt(e) => write_error(f, "Error parsing PSBT:", e),
            Utf8(e) => write_error(f, "Error parsing PSBT:", e),
        }
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalRequestError::*;

        match &self.0 {
            ParsePsbt(e) => Some(e),
            Utf8(e) => Some(e),
        }
    }
}

impl From<InternalRequestError> for super::Error {
    fn from(e: InternalRequestError) -> Self { super::Error::Validation(e.into()) }
}

#[derive(Debug)]
pub struct SessionError(InternalSessionError);

#[derive(Debug)]
pub(crate) enum InternalSessionError {
    /// The session has expired
    Expired(std::time::SystemTime),
    /// OHTTP Encapsulation failed
    OhttpEncapsulation(OhttpEncapsulationError),
    /// Unexpected response size
    UnexpectedResponseSize(usize),
    /// Unexpected status code
    UnexpectedStatusCode(http::StatusCode),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalSessionError::Expired(expiry) => write!(f, "Session expired at {:?}", expiry),
            InternalSessionError::OhttpEncapsulation(e) =>
                write!(f, "OHTTP Encapsulation Error: {}", e),
            InternalSessionError::UnexpectedResponseSize(size) => write!(
                f,
                "Unexpected response size {}, expected {} bytes",
                size,
                crate::ohttp::ENCAPSULATED_MESSAGE_BYTES
            ),
            InternalSessionError::UnexpectedStatusCode(status) =>
                write!(f, "Unexpected status code: {}", status),
        }
    }
}

impl error::Error for SessionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalSessionError::Expired(_) => None,
            InternalSessionError::OhttpEncapsulation(e) => Some(e),
            InternalSessionError::UnexpectedResponseSize(_) => None,
            InternalSessionError::UnexpectedStatusCode(_) => None,
        }
    }
}

impl From<InternalSessionError> for SessionError {
    fn from(e: InternalSessionError) -> Self { SessionError(e) }
}

impl From<OhttpEncapsulationError> for SessionError {
    fn from(e: OhttpEncapsulationError) -> Self {
        SessionError(InternalSessionError::OhttpEncapsulation(e))
    }
}

impl From<crate::hpke::HpkeError> for super::Error {
    fn from(e: crate::hpke::HpkeError) -> Self { super::Error::Implementation(Box::new(e)) }
}

impl From<crate::ohttp::OhttpEncapsulationError> for super::Error {
    fn from(e: crate::ohttp::OhttpEncapsulationError) -> Self {
        super::Error::Implementation(Box::new(e))
    }
}

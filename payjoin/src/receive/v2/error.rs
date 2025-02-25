use core::fmt;
use std::error;

use super::Error::V2;
use crate::hpke::HpkeError;
use crate::ohttp::OhttpEncapsulationError;
use crate::receive::error::Error;
use crate::IntoUrlError;

#[derive(Debug)]
pub struct CreateRecieverError(CreateRecieverInternalError);

impl std::error::Error for CreateRecieverError {}

impl std::fmt::Display for CreateRecieverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CreateRecieverInternalError::*;

        match &self.0 {
            InvalidUrl(e) => write!(f, "Invalid URL: {}", e),
            PersisterError(e) => write!(f, "Persister error: {}", e),
        }
    }
}

impl From<CreateRecieverError> for Error {
    fn from(e: CreateRecieverError) -> Self { Error::Creation(e) }
}

#[derive(Debug)]
pub(crate) enum CreateRecieverInternalError {
    InvalidUrl(IntoUrlError),
    PersisterError(Box<dyn std::error::Error + Send + Sync>),
}

impl From<CreateRecieverInternalError> for CreateRecieverError {
    fn from(value: CreateRecieverInternalError) -> Self { CreateRecieverError(value) }
}

impl From<CreateRecieverInternalError> for Error {
    fn from(value: CreateRecieverInternalError) -> Self { CreateRecieverError(value).into() }
}

/// Error that may occur during a v2 session typestate change
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct SessionError(InternalSessionError);

impl From<InternalSessionError> for SessionError {
    fn from(value: InternalSessionError) -> Self { SessionError(value) }
}

impl From<InternalSessionError> for Error {
    fn from(e: InternalSessionError) -> Self { V2(e.into()) }
}

#[derive(Debug)]
pub(crate) enum InternalSessionError {
    /// Url parsing failed
    ParseUrl(crate::into_url::Error),
    /// The session has expired
    Expired(std::time::SystemTime),
    /// OHTTP Encapsulation failed
    OhttpEncapsulation(OhttpEncapsulationError),
    /// Hybrid Public Key Encryption failed
    Hpke(HpkeError),
    /// Unexpected response size
    UnexpectedResponseSize(usize),
    /// Unexpected status code
    UnexpectedStatusCode(http::StatusCode),
}

impl From<crate::into_url::Error> for SessionError {
    fn from(e: crate::into_url::Error) -> Self { InternalSessionError::ParseUrl(e).into() }
}

impl From<std::time::SystemTime> for Error {
    fn from(e: std::time::SystemTime) -> Self { InternalSessionError::Expired(e).into() }
}

impl From<OhttpEncapsulationError> for Error {
    fn from(e: OhttpEncapsulationError) -> Self {
        InternalSessionError::OhttpEncapsulation(e).into()
    }
}

impl From<HpkeError> for Error {
    fn from(e: HpkeError) -> Self { InternalSessionError::Hpke(e).into() }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalSessionError::*;

        match &self.0 {
            ParseUrl(e) => write!(f, "URL parsing failed: {}", e),
            Expired(expiry) => write!(f, "Session expired at {:?}", expiry),
            OhttpEncapsulation(e) => write!(f, "OHTTP Encapsulation Error: {}", e),
            Hpke(e) => write!(f, "Hpke decryption failed: {}", e),
            UnexpectedResponseSize(size) => write!(
                f,
                "Unexpected response size {}, expected {} bytes",
                size,
                crate::directory::ENCAPSULATED_MESSAGE_BYTES
            ),
            UnexpectedStatusCode(status) => write!(f, "Unexpected status code: {}", status),
        }
    }
}

impl error::Error for SessionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalSessionError::*;

        match &self.0 {
            ParseUrl(e) => Some(e),
            Expired(_) => None,
            OhttpEncapsulation(e) => Some(e),
            Hpke(e) => Some(e),
            UnexpectedResponseSize(_) => None,
            UnexpectedStatusCode(_) => None,
        }
    }
}

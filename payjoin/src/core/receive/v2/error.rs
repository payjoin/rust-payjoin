use core::fmt;
use std::error;

use crate::hpke::HpkeError;
use crate::ohttp::{DirectoryResponseError, OhttpEncapsulationError};
use crate::receive::error::Error;
use crate::receive::ProtocolError;
use crate::time::Time;

/// Error that may occur during a v2 session typestate change
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct SessionError(pub(super) InternalSessionError);

/// A stable classification for BIP 77 v2 session errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionErrorKind {
    /// URL parsing failed.
    ParseUrl,
    /// The session expired.
    Expired,
    /// OHTTP encapsulation failed.
    OhttpEncapsulation,
    /// HPKE processing failed.
    Hpke,
    /// The directory returned a malformed or unexpected response.
    DirectoryResponse,
}

impl From<InternalSessionError> for SessionError {
    fn from(value: InternalSessionError) -> Self { SessionError(value) }
}

impl SessionError {
    /// Returns the stable classification of the session error.
    pub fn kind(&self) -> SessionErrorKind {
        match &self.0 {
            InternalSessionError::ParseUrl(_) => SessionErrorKind::ParseUrl,
            InternalSessionError::Expired(_) => SessionErrorKind::Expired,
            InternalSessionError::OhttpEncapsulation(_) => SessionErrorKind::OhttpEncapsulation,
            InternalSessionError::Hpke(_) => SessionErrorKind::Hpke,
            InternalSessionError::DirectoryResponse(_) => SessionErrorKind::DirectoryResponse,
        }
    }
}

impl From<InternalSessionError> for Error {
    fn from(e: InternalSessionError) -> Self { Error::Protocol(ProtocolError::V2(e.into())) }
}

#[derive(Debug)]
pub(crate) enum InternalSessionError {
    /// Url parsing failed
    ParseUrl(crate::into_url::Error),
    /// The session has expired
    Expired(Time),
    /// OHTTP Encapsulation failed
    OhttpEncapsulation(OhttpEncapsulationError),
    /// Hybrid Public Key Encryption failed
    Hpke(HpkeError),
    /// The directory returned a bad response
    DirectoryResponse(DirectoryResponseError),
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
            ParseUrl(e) => write!(f, "URL parsing failed: {e}"),
            Expired(expiration) => write!(f, "Session expired at {expiration:?}"),
            OhttpEncapsulation(e) => write!(f, "OHTTP Encapsulation Error: {e}"),
            Hpke(e) => write!(f, "Hpke decryption failed: {e}"),
            DirectoryResponse(e) => write!(f, "Directory response error: {e}"),
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
            DirectoryResponse(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_error_kind_accessor() {
        let expiration = Time::now();
        let error = SessionError::from(InternalSessionError::Expired(expiration));

        assert_eq!(error.kind(), SessionErrorKind::Expired);
    }
}

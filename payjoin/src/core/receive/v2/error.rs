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

impl From<InternalSessionError> for SessionError {
    fn from(value: InternalSessionError) -> Self { SessionError(value) }
}

impl SessionError {
    /// Returns `true` if the session has expired.
    pub fn is_expired(&self) -> bool { matches!(self.0, InternalSessionError::Expired(_)) }
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
    fn session_error_is_expired() {
        let expired = SessionError(InternalSessionError::Expired(Time::now()));
        assert!(expired.is_expired());

        let other = SessionError(InternalSessionError::ParseUrl(crate::into_url::Error::BadScheme));
        assert!(!other.is_expired());
    }

    #[test]
    fn top_level_error_is_expired() {
        let expired = Error::from(InternalSessionError::Expired(Time::now()));
        assert!(expired.is_expired());

        let other = Error::from(InternalSessionError::ParseUrl(crate::into_url::Error::BadScheme));
        assert!(!other.is_expired());
    }
}

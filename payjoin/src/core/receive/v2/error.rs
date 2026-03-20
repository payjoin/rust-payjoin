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

impl SessionError {
    pub fn is_retryable(&self) -> bool {
        match &self.0 {
            InternalSessionError::ParseUrl(_)
            | InternalSessionError::Expired(_)
            | InternalSessionError::OhttpEncapsulation(_)
            | InternalSessionError::Hpke(_) => false,
            InternalSessionError::DirectoryResponse(error) => error.is_retryable(),
        }
    }

    pub fn expired_at_unix_seconds(&self) -> Option<u32> {
        match &self.0 {
            InternalSessionError::Expired(expiration) => Some(expiration.to_unix_seconds()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    #[test]
    fn test_session_error_exposes_retryability_and_expiration() {
        let expiration =
            Time::try_from(SystemTime::now() - Duration::from_secs(1)).expect("valid timestamp");
        let expired: SessionError = InternalSessionError::Expired(expiration).into();
        assert!(!expired.is_retryable());
        assert_eq!(expired.expired_at_unix_seconds(), Some(expiration.to_unix_seconds()));

        let retryable: SessionError =
            InternalSessionError::DirectoryResponse(DirectoryResponseError::InvalidSize(1)).into();
        assert!(retryable.is_retryable());
        assert_eq!(retryable.expired_at_unix_seconds(), None);
    }
}

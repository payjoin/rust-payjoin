use core::fmt;
use std::error;

use crate::hpke::HpkeError;
use crate::ohttp::{DirectoryResponseError, OhttpEncapsulationError};
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

impl From<crate::into_url::Error> for SessionError {
    fn from(e: crate::into_url::Error) -> Self { SessionError(InternalSessionError::ParseUrl(e)) }
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

/// Error returned when a receiver request could not be created.
///
/// Mirrors [`crate::send::v2::CreateRequestError`]: a narrow, opaque error for
/// the `create_poll_request` and `create_post_request` constructors. It carries
/// only their real failure modes, so callers can branch on expiry without
/// matching the broad [`crate::receive::Error`] or its Display string.
#[derive(Debug)]
pub struct CreateRequestError(InternalCreateRequestError);

#[derive(Debug)]
pub(crate) enum InternalCreateRequestError {
    /// Url parsing failed
    Url(crate::into_url::Error),
    /// Hybrid Public Key Encryption failed
    Hpke(HpkeError),
    /// OHTTP Encapsulation failed
    OhttpEncapsulation(OhttpEncapsulationError),
    /// The session has expired
    Expired(Time),
}

impl fmt::Display for CreateRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalCreateRequestError::*;

        match &self.0 {
            Url(e) => write!(f, "cannot parse url: {e:#?}"),
            Hpke(e) => write!(f, "v2 error: {e}"),
            OhttpEncapsulation(e) => write!(f, "v2 error: {e}"),
            Expired(_expiration) => write!(f, "session expired"),
        }
    }
}

impl error::Error for CreateRequestError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalCreateRequestError::*;

        match &self.0 {
            Url(e) => Some(e),
            Hpke(e) => Some(e),
            OhttpEncapsulation(e) => Some(e),
            Expired(_) => None,
        }
    }
}

impl CreateRequestError {
    /// Returns `true` if the request could not be created because the session
    /// has expired.
    pub fn is_expired(&self) -> bool { matches!(self.0, InternalCreateRequestError::Expired(_)) }
}

impl From<InternalCreateRequestError> for CreateRequestError {
    fn from(value: InternalCreateRequestError) -> Self { CreateRequestError(value) }
}

impl From<crate::into_url::Error> for CreateRequestError {
    fn from(e: crate::into_url::Error) -> Self {
        CreateRequestError(InternalCreateRequestError::Url(e))
    }
}

impl From<HpkeError> for CreateRequestError {
    fn from(e: HpkeError) -> Self { CreateRequestError(InternalCreateRequestError::Hpke(e)) }
}

impl From<OhttpEncapsulationError> for CreateRequestError {
    fn from(e: OhttpEncapsulationError) -> Self {
        CreateRequestError(InternalCreateRequestError::OhttpEncapsulation(e))
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
    fn create_request_error_is_expired() {
        let expired = CreateRequestError(InternalCreateRequestError::Expired(Time::now()));
        assert!(expired.is_expired());

        let other =
            CreateRequestError(InternalCreateRequestError::Url(crate::into_url::Error::BadScheme));
        assert!(!other.is_expired());
    }
}

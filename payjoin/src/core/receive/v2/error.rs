use core::fmt;
use std::error;

use crate::hpke::HpkeError;
use crate::ohttp::{DirectoryResponseError, OhttpEncapsulationError};
use crate::receive::error::Error;
use crate::receive::ProtocolError;
use crate::time::Time;
use crate::{DirectoryResponseErrorDetails, HpkeErrorDetails, OhttpEncapsulationErrorDetails};

/// Error that may occur during a v2 session typestate change
///
/// This type keeps its internal variants private, but exposes a stable
/// classification via [`SessionError::kind`].
#[derive(Debug)]
pub struct SessionError(pub(super) InternalSessionError);

/// A stable classification for receiver v2 session failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionErrorKind {
    ParseUrl,
    Expired,
    OhttpEncapsulation,
    Hpke,
    DirectoryResponse,
}

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

impl SessionError {
    /// Returns the stable classification of the session failure.
    pub fn kind(&self) -> SessionErrorKind {
        match &self.0 {
            InternalSessionError::ParseUrl(_) => SessionErrorKind::ParseUrl,
            InternalSessionError::Expired(_) => SessionErrorKind::Expired,
            InternalSessionError::OhttpEncapsulation(_) => SessionErrorKind::OhttpEncapsulation,
            InternalSessionError::Hpke(_) => SessionErrorKind::Hpke,
            InternalSessionError::DirectoryResponse(_) => SessionErrorKind::DirectoryResponse,
        }
    }

    /// Returns nested OHTTP details when the session failed during encapsulation.
    pub fn ohttp_error(&self) -> Option<OhttpEncapsulationErrorDetails> {
        match &self.0 {
            InternalSessionError::OhttpEncapsulation(error) => Some(error.details()),
            _ => None,
        }
    }

    /// Returns nested HPKE details when the session failed during decryption or encryption.
    pub fn hpke_error(&self) -> Option<HpkeErrorDetails> {
        match &self.0 {
            InternalSessionError::Hpke(error) => Some(error.details()),
            _ => None,
        }
    }

    /// Returns nested directory-response details when the relay or directory reply was invalid.
    pub fn directory_response_error(&self) -> Option<DirectoryResponseErrorDetails> {
        match &self.0 {
            InternalSessionError::DirectoryResponse(error) => Some(error.details()),
            _ => None,
        }
    }
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
    use crate::ohttp::{DirectoryResponseErrorKind, OhttpEncapsulationErrorKind};

    #[test]
    fn session_error_exposes_directory_response_details() {
        let error = SessionError::from(InternalSessionError::DirectoryResponse(
            DirectoryResponseError::OhttpDecapsulation(OhttpEncapsulationError::ParseUrl(
                url::ParseError::EmptyHost,
            )),
        ));

        assert_eq!(error.kind(), SessionErrorKind::DirectoryResponse);
        let directory =
            error.directory_response_error().expect("directory response details should be present");
        assert_eq!(directory.kind(), DirectoryResponseErrorKind::OhttpDecapsulation);
        assert_eq!(
            directory.ohttp_error().expect("nested OHTTP details should be present").kind(),
            OhttpEncapsulationErrorKind::ParseUrl
        );
        assert!(error.hpke_error().is_none());
        assert!(error.ohttp_error().is_none());
    }
}

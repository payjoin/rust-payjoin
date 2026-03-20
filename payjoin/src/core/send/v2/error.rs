use core::fmt;

use crate::ohttp::DirectoryResponseError;
use crate::time::Time;
use crate::{DirectoryResponseErrorDetails, HpkeErrorDetails, OhttpEncapsulationErrorDetails};

/// Error returned when request could not be created.
///
/// This error can currently only happen due to programmer mistake.
/// `unwrap()`ing it is thus considered OK in Rust but you may achieve nicer message by displaying
/// it.
#[derive(Debug)]
pub struct CreateRequestError(InternalCreateRequestError);

/// A stable classification for sender request-construction failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateRequestErrorKind {
    Url,
    Hpke,
    OhttpEncapsulation,
    Expired,
}

#[derive(Debug)]
pub(crate) enum InternalCreateRequestError {
    Url(crate::into_url::Error),
    Hpke(crate::hpke::HpkeError),
    OhttpEncapsulation(crate::ohttp::OhttpEncapsulationError),
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

impl std::error::Error for CreateRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalCreateRequestError::*;

        match &self.0 {
            Url(error) => Some(error),
            Hpke(error) => Some(error),
            OhttpEncapsulation(error) => Some(error),
            Expired(_) => None,
        }
    }
}

impl From<InternalCreateRequestError> for CreateRequestError {
    fn from(value: InternalCreateRequestError) -> Self { CreateRequestError(value) }
}

impl From<crate::into_url::Error> for CreateRequestError {
    fn from(value: crate::into_url::Error) -> Self {
        CreateRequestError(InternalCreateRequestError::Url(value))
    }
}

impl CreateRequestError {
    /// Returns the stable classification of the request creation failure.
    pub fn kind(&self) -> CreateRequestErrorKind {
        match &self.0 {
            InternalCreateRequestError::Url(_) => CreateRequestErrorKind::Url,
            InternalCreateRequestError::Hpke(_) => CreateRequestErrorKind::Hpke,
            InternalCreateRequestError::OhttpEncapsulation(_) =>
                CreateRequestErrorKind::OhttpEncapsulation,
            InternalCreateRequestError::Expired(_) => CreateRequestErrorKind::Expired,
        }
    }

    /// Returns nested HPKE details when request creation failed during encryption.
    pub fn hpke_error(&self) -> Option<HpkeErrorDetails> {
        match &self.0 {
            InternalCreateRequestError::Hpke(error) => Some(error.details()),
            _ => None,
        }
    }

    /// Returns nested OHTTP details when request creation failed during encapsulation.
    pub fn ohttp_error(&self) -> Option<OhttpEncapsulationErrorDetails> {
        match &self.0 {
            InternalCreateRequestError::OhttpEncapsulation(error) => Some(error.details()),
            _ => None,
        }
    }
}

/// Error returned for v2-specific payload encapsulation errors.
#[derive(Debug)]
pub struct EncapsulationError(InternalEncapsulationError);

/// A stable classification for sender response encapsulation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncapsulationErrorKind {
    Hpke,
    DirectoryResponse,
}

#[derive(Debug)]
pub(crate) enum InternalEncapsulationError {
    /// The HPKE failed.
    Hpke(crate::hpke::HpkeError),
    /// The directory returned a bad response
    DirectoryResponse(DirectoryResponseError),
}

impl fmt::Display for EncapsulationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalEncapsulationError::*;

        match &self.0 {
            Hpke(error) => write!(f, "HPKE error: {error}"),
            DirectoryResponse(e) => write!(f, "Directory response error: {e}"),
        }
    }
}

impl std::error::Error for EncapsulationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalEncapsulationError::*;

        match &self.0 {
            Hpke(error) => Some(error),
            DirectoryResponse(e) => Some(e),
        }
    }
}

impl From<InternalEncapsulationError> for EncapsulationError {
    fn from(value: InternalEncapsulationError) -> Self { EncapsulationError(value) }
}

impl From<InternalEncapsulationError> for super::ResponseError {
    fn from(value: InternalEncapsulationError) -> Self {
        super::InternalValidationError::V2Encapsulation(value.into()).into()
    }
}

impl EncapsulationError {
    /// Returns the stable classification of the encapsulation failure.
    pub fn kind(&self) -> EncapsulationErrorKind {
        match &self.0 {
            InternalEncapsulationError::Hpke(_) => EncapsulationErrorKind::Hpke,
            InternalEncapsulationError::DirectoryResponse(_) =>
                EncapsulationErrorKind::DirectoryResponse,
        }
    }

    /// Returns nested HPKE details when response decapsulation failed cryptographically.
    pub fn hpke_error(&self) -> Option<HpkeErrorDetails> {
        match &self.0 {
            InternalEncapsulationError::Hpke(error) => Some(error.details()),
            _ => None,
        }
    }

    /// Returns nested directory-response details when the relay or directory reply was invalid.
    pub fn directory_response_error(&self) -> Option<DirectoryResponseErrorDetails> {
        match &self.0 {
            InternalEncapsulationError::DirectoryResponse(error) => Some(error.details()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ohttp::{DirectoryResponseErrorKind, OhttpEncapsulationErrorKind};

    #[test]
    fn create_request_error_exposes_nested_ohttp_details() {
        let error = CreateRequestError::from(InternalCreateRequestError::OhttpEncapsulation(
            crate::ohttp::OhttpEncapsulationError::ParseUrl(url::ParseError::EmptyHost),
        ));

        assert_eq!(error.kind(), CreateRequestErrorKind::OhttpEncapsulation);
        assert_eq!(
            error.ohttp_error().expect("OHTTP details should be present").kind(),
            OhttpEncapsulationErrorKind::ParseUrl
        );
        assert!(error.hpke_error().is_none());
    }

    #[test]
    fn encapsulation_error_exposes_directory_response_details() {
        let error = EncapsulationError::from(InternalEncapsulationError::DirectoryResponse(
            DirectoryResponseError::UnexpectedStatusCode(http::StatusCode::BAD_GATEWAY),
        ));

        assert_eq!(error.kind(), EncapsulationErrorKind::DirectoryResponse);
        let directory =
            error.directory_response_error().expect("directory response details should be present");
        assert_eq!(directory.kind(), DirectoryResponseErrorKind::UnexpectedStatusCode);
        assert_eq!(directory.unexpected_status_code(), Some(502));
        assert!(error.hpke_error().is_none());
    }
}

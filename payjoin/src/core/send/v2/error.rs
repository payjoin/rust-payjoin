use core::fmt;

use crate::ohttp::DirectoryResponseError;
use crate::time::Time;

/// Error returned when request could not be created.
///
/// This error can currently only happen due to programmer mistake.
/// `unwrap()`ing it is thus considered OK in Rust but you may achieve nicer message by displaying
/// it.
#[derive(Debug)]
pub struct CreateRequestError(InternalCreateRequestError);

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
    pub fn is_retryable(&self) -> bool {
        match &self.0 {
            InternalCreateRequestError::Url(_)
            | InternalCreateRequestError::Hpke(_)
            | InternalCreateRequestError::OhttpEncapsulation(_)
            | InternalCreateRequestError::Expired(_) => false,
        }
    }

    pub fn expired_at_unix_seconds(&self) -> Option<u32> {
        match &self.0 {
            InternalCreateRequestError::Expired(expiration) => Some(expiration.to_unix_seconds()),
            _ => None,
        }
    }
}

/// Error returned for v2-specific payload encapsulation errors.
#[derive(Debug)]
pub struct EncapsulationError(InternalEncapsulationError);

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
    pub fn is_retryable(&self) -> bool {
        match &self.0 {
            InternalEncapsulationError::Hpke(_) => false,
            InternalEncapsulationError::DirectoryResponse(error) => error.is_retryable(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    #[test]
    fn test_create_request_error_exposes_expiration_metadata() {
        let expiration =
            Time::try_from(SystemTime::now() - Duration::from_secs(1)).expect("valid timestamp");
        let error: CreateRequestError = InternalCreateRequestError::Expired(expiration).into();

        assert!(!error.is_retryable());
        assert_eq!(error.expired_at_unix_seconds(), Some(expiration.to_unix_seconds()));
    }

    #[test]
    fn test_encapsulation_error_exposes_retryability() {
        let retryable: EncapsulationError =
            InternalEncapsulationError::DirectoryResponse(DirectoryResponseError::InvalidSize(1))
                .into();
        assert!(retryable.is_retryable());

        let fatal: EncapsulationError = InternalEncapsulationError::DirectoryResponse(
            DirectoryResponseError::UnexpectedStatusCode(http::StatusCode::BAD_REQUEST),
        )
        .into();
        assert!(!fatal.is_retryable());
    }
}

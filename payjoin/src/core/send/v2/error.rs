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

impl CreateRequestError {
    /// Returns `true` if the request could not be created because the session
    /// has expired.
    pub fn is_expired(&self) -> bool { matches!(self.0, InternalCreateRequestError::Expired(_)) }
}

impl From<crate::into_url::Error> for CreateRequestError {
    fn from(value: crate::into_url::Error) -> Self {
        CreateRequestError(InternalCreateRequestError::Url(value))
    }
}

/// Error returned for v2-specific payload decapsulation errors.
#[derive(Debug)]
pub struct DecapsulationError(InternalDecapsulationError);

#[derive(Debug)]
pub(crate) enum InternalDecapsulationError {
    /// The HPKE failed.
    Hpke(crate::hpke::HpkeError),
    /// The directory returned a bad response
    DirectoryResponse(DirectoryResponseError),
}

impl fmt::Display for DecapsulationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalDecapsulationError::*;

        match &self.0 {
            Hpke(error) => write!(f, "HPKE error: {error}"),
            DirectoryResponse(e) => write!(f, "Directory response error: {e}"),
        }
    }
}

impl std::error::Error for DecapsulationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalDecapsulationError::*;

        match &self.0 {
            Hpke(error) => Some(error),
            DirectoryResponse(e) => Some(e),
        }
    }
}

impl From<InternalDecapsulationError> for DecapsulationError {
    fn from(value: InternalDecapsulationError) -> Self { DecapsulationError(value) }
}

impl From<InternalDecapsulationError> for super::ResponseError {
    fn from(value: InternalDecapsulationError) -> Self {
        super::InternalValidationError::V2Decapsulation(value.into()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_error_is_expired() {
        let expired = CreateRequestError(InternalCreateRequestError::Expired(Time::now()));
        assert!(expired.is_expired());

        let other =
            CreateRequestError(InternalCreateRequestError::Url(crate::into_url::Error::BadScheme));
        assert!(!other.is_expired());
    }
}

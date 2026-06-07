use core::{error, fmt};

#[cfg(feature = "v2-ohttp")]
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
    #[cfg(feature = "v2-ohttp")]
    Url(crate::into_url::Error),
    #[cfg(feature = "v2-ohttp")]
    Hpke(crate::hpke::HpkeError),
    #[cfg(feature = "v2-ohttp")]
    OhttpEncapsulation(crate::ohttp::OhttpEncapsulationError),
    Expired(Time),
    #[cfg(not(feature = "std"))]
    Implementation(crate::error::ImplementationError),
}

impl fmt::Display for CreateRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalCreateRequestError::*;

        match &self.0 {
            #[cfg(feature = "v2-ohttp")]
            Url(e) => write!(f, "cannot parse url: {e:#?}"),
            #[cfg(feature = "v2-ohttp")]
            Hpke(e) => write!(f, "v2 error: {e}"),
            #[cfg(feature = "v2-ohttp")]
            OhttpEncapsulation(e) => write!(f, "v2 error: {e}"),
            Expired(_expiration) => write!(f, "session expired"),
            #[cfg(not(feature = "std"))]
            Implementation(e) => write!(f, "implementation error: {e}"),
        }
    }
}

impl error::Error for CreateRequestError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalCreateRequestError::*;

        match &self.0 {
            #[cfg(feature = "v2-ohttp")]
            Url(error) => Some(error),
            #[cfg(feature = "v2-ohttp")]
            Hpke(error) => Some(error),
            #[cfg(feature = "v2-ohttp")]
            OhttpEncapsulation(error) => Some(error),
            Expired(_) => None,
            #[cfg(not(feature = "std"))]
            Implementation(e) => Some(e),
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

#[cfg(feature = "v2-ohttp")]
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
    #[cfg(feature = "v2-ohttp")]
    Hpke(crate::hpke::HpkeError),
    #[cfg(feature = "v2-ohttp")]
    DirectoryResponse(DirectoryResponseError),
    #[cfg(not(feature = "std"))]
    Implementation(crate::error::ImplementationError),
}

impl fmt::Display for DecapsulationError {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            #[cfg(feature = "v2-ohttp")]
            InternalDecapsulationError::Hpke(error) => write!(_f, "HPKE error: {error}"),
            #[cfg(feature = "v2-ohttp")]
            InternalDecapsulationError::DirectoryResponse(e) =>
                write!(_f, "Directory response error: {e}"),
            #[cfg(not(feature = "std"))]
            InternalDecapsulationError::Implementation(e) =>
                write!(_f, "implementation error: {e}"),
            #[allow(unreachable_patterns)]
            _ => unreachable!("InternalEncapsulationError is uninhabited in this configuration"),
        }
    }
}

impl error::Error for DecapsulationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            #[cfg(feature = "v2-ohttp")]
            InternalDecapsulationError::Hpke(error) => Some(error),
            #[cfg(feature = "v2-ohttp")]
            InternalDecapsulationError::DirectoryResponse(e) => Some(e),
            #[cfg(not(feature = "std"))]
            InternalDecapsulationError::Implementation(e) => Some(e),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

impl From<InternalDecapsulationError> for DecapsulationError {
    fn from(value: InternalDecapsulationError) -> Self { DecapsulationError(value) }
}

#[cfg(any(feature = "v2-ohttp", not(feature = "std")))]
impl From<InternalDecapsulationError> for super::ResponseError {
    fn from(value: InternalDecapsulationError) -> Self {
        crate::send::error::InternalValidationError::V2Decapsulation(value.into()).into()
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

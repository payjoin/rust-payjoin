#[cfg(not(feature = "std"))]
use core::error;
use core::fmt;
#[cfg(feature = "std")]
use std::error;

#[cfg(feature = "v2-std")]
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
    #[cfg(feature = "v2-std")]
    Url(crate::into_url::Error),
    #[cfg(feature = "v2-std")]
    Hpke(crate::hpke::HpkeError),
    #[cfg(feature = "v2-std")]
    OhttpEncapsulation(crate::ohttp::OhttpEncapsulationError),
    #[allow(dead_code)]
    Expired(Time),
    #[allow(dead_code)]
    Implementation(crate::error::ImplementationError),
}

impl fmt::Display for CreateRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalCreateRequestError::*;

        match &self.0 {
            #[cfg(feature = "v2-std")]
            Url(e) => write!(f, "cannot parse url: {e:#?}"),
            #[cfg(feature = "v2-std")]
            Hpke(e) => write!(f, "v2 error: {e}"),
            #[cfg(feature = "v2-std")]
            OhttpEncapsulation(e) => write!(f, "v2 error: {e}"),
            Expired(_expiration) => write!(f, "session expired"),
            Implementation(e) => write!(f, "implementation error: {e}"),
        }
    }
}

impl error::Error for CreateRequestError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalCreateRequestError::*;

        match &self.0 {
            #[cfg(feature = "v2-std")]
            Url(error) => Some(error),
            #[cfg(feature = "v2-std")]
            Hpke(error) => Some(error),
            #[cfg(feature = "v2-std")]
            OhttpEncapsulation(error) => Some(error),
            Expired(_) => None,
            Implementation(e) => Some(e),
        }
    }
}

impl From<InternalCreateRequestError> for CreateRequestError {
    fn from(value: InternalCreateRequestError) -> Self { CreateRequestError(value) }
}

#[cfg(feature = "v2-std")]
impl From<crate::into_url::Error> for CreateRequestError {
    fn from(value: crate::into_url::Error) -> Self {
        CreateRequestError(InternalCreateRequestError::Url(value))
    }
}

/// Error returned for v2-specific payload encapsulation errors.
#[derive(Debug)]
pub struct EncapsulationError(InternalEncapsulationError);

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum InternalEncapsulationError {
    /// The HPKE failed.
    #[cfg(feature = "v2-std")]
    Hpke(crate::hpke::HpkeError),
    /// The directory returned a bad response
    #[cfg(feature = "v2-std")]
    DirectoryResponse(DirectoryResponseError),
    Implementation(crate::error::ImplementationError),
}

impl fmt::Display for EncapsulationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalEncapsulationError::*;

        match &self.0 {
            #[cfg(feature = "v2-std")]
            Hpke(error) => write!(f, "HPKE error: {error}"),
            #[cfg(feature = "v2-std")]
            DirectoryResponse(e) => write!(f, "Directory response error: {e}"),
            Implementation(e) => write!(f, "implementation error: {e}"),
        }
    }
}

impl error::Error for EncapsulationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalEncapsulationError::*;

        match &self.0 {
            #[cfg(feature = "v2-std")]
            Hpke(error) => Some(error),
            #[cfg(feature = "v2-std")]
            DirectoryResponse(e) => Some(e),
            Implementation(e) => Some(e),
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

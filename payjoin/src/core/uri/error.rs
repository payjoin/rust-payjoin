use alloc::fmt;
#[cfg(not(feature = "std"))]
use core::error;
#[cfg(feature = "std")]
use std::error;
#[derive(Debug)]
pub struct PjParseError(pub(super) InternalPjParseError);

#[derive(Debug)]
#[allow(dead_code)]
pub(super) enum InternalPjParseError {
    BadPjOs,
    DuplicateParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    #[cfg(any(feature = "v1", feature = "v2-std"))]
    IntoUrl(crate::into_url::Error),
    #[cfg(feature = "v1")]
    UnsecureEndpoint,
    #[cfg(feature = "v2-std")]
    V2(super::v2::PjParseError),
}

impl From<InternalPjParseError> for PjParseError {
    fn from(value: InternalPjParseError) -> Self { PjParseError(value) }
}

impl error::Error for PjParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalPjParseError::*;
        match &self.0 {
            BadPjOs => None,
            DuplicateParams(_) => None,
            MissingEndpoint => None,
            NotUtf8 => None,
            #[cfg(any(feature = "v1", feature = "v2-std"))]
            IntoUrl(e) => Some(e),
            #[cfg(feature = "v1")]
            UnsecureEndpoint => None,
            #[cfg(feature = "v2-std")]
            V2(e) => Some(e),
        }
    }
}

impl fmt::Display for PjParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InternalPjParseError::*;
        match &self.0 {
            BadPjOs => write!(f, "Bad pjos parameter"),
            DuplicateParams(param) => {
                write!(f, "Multiple instances of parameter '{param}'")
            }
            MissingEndpoint => write!(f, "Missing payjoin endpoint"),
            NotUtf8 => write!(f, "Endpoint is not valid UTF-8"),
            #[cfg(any(feature = "v1", feature = "v2-std"))]
            IntoUrl(e) => write!(f, "Endpoint is not valid: {e:?}"),
            #[cfg(feature = "v1")]
            UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
            #[cfg(feature = "v2-std")]
            V2(e) => write!(f, "Invalid v2 parameter: {e:?}"),
        }
    }
}

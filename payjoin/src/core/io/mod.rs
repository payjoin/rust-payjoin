//! IO-related types and functions. Specifically, fetching OHTTP keys from a payjoin directory.

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
use native::InternalErrorInner;
#[cfg(not(target_arch = "wasm32"))]
pub use native::*;

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
use wasm::InternalErrorInner;
#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// When the payjoin directory returns an unexpected status code
    UnexpectedStatusCode(http::StatusCode),
    /// Internal errors that should not be pattern matched by users
    #[doc(hidden)]
    Internal(InternalError),
}

macro_rules! impl_from_error {
    ($from:ty, $to:ident) => {
        impl From<$from> for super::Error {
            fn from(value: $from) -> Self {
                Self::Internal(super::InternalError(InternalErrorInner::$to(value.into())))
            }
        }
    };
}
pub(crate) use impl_from_error;
#[derive(Debug)]
pub struct InternalError(InternalErrorInner);

impl From<InternalError> for Error {
    fn from(value: InternalError) -> Self { Self::Internal(value) }
}

impl From<InternalErrorInner> for Error {
    fn from(value: InternalErrorInner) -> Self { Self::Internal(InternalError(value)) }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnexpectedStatusCode(code) => {
                write!(f, "Unexpected status code from payjoin directory: {code}")
            }
            Self::Internal(InternalError(e)) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(InternalError(e)) => e.source(),
            Self::UnexpectedStatusCode(_) => None,
        }
    }
}

use std::error;

/// Error arising due to the specific receiver implementation
///
/// e.g. database errors, network failures, wallet errors
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct ImplementationError(#[from] payjoin::ImplementationError);

impl ImplementationError {
    pub fn new(e: impl error::Error + Send + Sync + 'static) -> Self {
        ImplementationError(payjoin::ImplementationError::new(e))
    }
}

// Removed custom FFI error types to keep FFI API aligned with core API.

/// Deprecated: Avoid converting arbitrary Strings into `ImplementationError`.
/// Prefer using `ImplementationError::new(e)` with a concrete error type.
/// Tracked in issue #737.
// Removed From<String> to prevent accidental string-to-typed error conversions.

impl From<ImplementationError> for payjoin::ImplementationError {
    fn from(value: ImplementationError) -> Self { value.0 }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("Error de/serializing JSON object: {0}")]
pub struct SerdeJsonError(#[from] serde_json::Error);

#[derive(Debug, thiserror::Error, PartialEq, Eq, uniffi::Error)]
pub enum ForeignError {
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ForeignError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::InternalError("Unexpected Uniffi callback error".to_string())
    }
}

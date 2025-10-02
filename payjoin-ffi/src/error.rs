use std::error;
use std::sync::Arc;

// UniFFI can't expose a type as both an error and an object, so we wrap the
// core error in an object (held by foreign handles) and let the outer enum act
// as the exported error type.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct ImplementationExceptionInner(#[from] payjoin::ImplementationError);

impl ImplementationExceptionInner {
    pub fn new(e: impl error::Error + Send + Sync + 'static) -> Self {
        ImplementationExceptionInner(payjoin::ImplementationError::new(e))
    }

    fn into_inner(self) -> payjoin::ImplementationError { self.0 }
}

/// Error arising due to the specific receiver implementation exposed over FFI
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ImplementationError {
    #[error(transparent)]
    Inner(Arc<ImplementationExceptionInner>),
}

impl ImplementationError {
    pub fn new(e: impl error::Error + Send + Sync + 'static) -> Self {
        ImplementationError::from(payjoin::ImplementationError::new(e))
    }

    fn into_inner(self) -> payjoin::ImplementationError {
        match self {
            ImplementationError::Inner(inner) => Arc::try_unwrap(inner)
                .expect("ImplementationError unexpectedly shared")
                .into_inner(),
        }
    }
}

impl From<payjoin::ImplementationError> for ImplementationError {
    fn from(value: payjoin::ImplementationError) -> Self {
        ImplementationError::Inner(Arc::new(ImplementationExceptionInner(value)))
    }
}

impl From<ImplementationError> for payjoin::ImplementationError {
    fn from(value: ImplementationError) -> Self { value.into_inner() }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ImplementationError {
    fn from(err: uniffi::UnexpectedUniFFICallbackError) -> Self { ImplementationError::new(err) }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("Error de/serializing JSON object: {0}")]
pub struct SerdeJsonError(#[from] serde_json::Error);

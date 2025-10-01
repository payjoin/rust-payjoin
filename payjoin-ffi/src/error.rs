use std::error;
use std::sync::Arc;

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

impl From<ImplementationError> for payjoin::ImplementationError {
    fn from(value: ImplementationError) -> Self { value.0 }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("Error de/serializing JSON object: {0}")]
pub struct SerdeJsonError(#[from] serde_json::Error);

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ForeignError {
    #[error(transparent)]
    Implementation(Arc<ImplementationError>),
}

impl From<ImplementationError> for ForeignError {
    fn from(value: ImplementationError) -> Self { Self::Implementation(Arc::new(value)) }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ForeignError {
    fn from(err: uniffi::UnexpectedUniFFICallbackError) -> Self {
        ForeignError::from(ImplementationError::new(err))
    }
}

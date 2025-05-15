#[derive(Debug, thiserror::Error)]
#[error("Error de/serializing JSON object: {0}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SerdeJsonError(#[from] serde_json::Error);

#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ForeignError {
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[cfg(feature = "uniffi")]
impl From<uniffi::UnexpectedUniFFICallbackError> for ForeignError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::InternalError("Unexpected Uniffi callback error".to_string())
    }
}

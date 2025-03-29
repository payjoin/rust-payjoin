#[derive(Debug, thiserror::Error)]
#[error("Error de/serializing JSON object: {0}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SerdeJsonError(#[from] serde_json::Error);

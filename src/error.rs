#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error de/serializing JSON object: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SerdeJsonError {
    msg: String,
}
impl From<serde_json::Error> for SerdeJsonError {
    fn from(value: serde_json::Error) -> Self {
        SerdeJsonError { msg: format!("{:?}", value) }
    }
}

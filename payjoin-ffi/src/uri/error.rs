#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error parsing the payjoin URI: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PjParseError {
    msg: String,
}

impl From<String> for PjParseError {
    fn from(msg: String) -> Self { PjParseError { msg } }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("URI doesn't support payjoin: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PjNotSupported {
    msg: String,
}

impl From<String> for PjNotSupported {
    fn from(msg: String) -> Self { PjNotSupported { msg } }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct UrlParseError(#[from] payjoin::ParseError);

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct IntoUrlError(#[from] payjoin::IntoUrlError);

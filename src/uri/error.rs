#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error parsing the payjoin URI: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PjParseError {
    msg: String,
}

impl From<String> for PjParseError {
    fn from(msg: String) -> Self {
        PjParseError { msg }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("URI doesn't support payjoin: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PjNotSupported {
    msg: String,
}

impl From<String> for PjNotSupported {
    fn from(msg: String) -> Self {
        PjNotSupported { msg }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error parsing URL: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct UrlParseError {
    msg: String,
}

impl From<payjoin::ParseError> for UrlParseError {
    fn from(value: payjoin::ParseError) -> Self {
        UrlParseError { msg: format!("{:?}", value) }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Error converting to URL: {msg}")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct IntoUrlError {
    msg: String,
}

impl From<payjoin::IntoUrlError> for IntoUrlError {
    fn from(value: payjoin::IntoUrlError) -> Self {
        IntoUrlError { msg: format!("{:?}", value) }
    }
}

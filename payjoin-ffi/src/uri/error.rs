#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
#[error("Error parsing the payjoin URI: {msg}")]
pub struct PjParseError {
    msg: String,
}

impl From<String> for PjParseError {
    fn from(msg: String) -> Self { PjParseError { msg } }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
#[error("URI doesn't support payjoin: {msg}")]
pub struct PjNotSupported {
    msg: String,
}

impl From<String> for PjNotSupported {
    fn from(msg: String) -> Self { PjNotSupported { msg } }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct UrlParseError(#[from] url::ParseError);

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct IntoUrlError(#[from] payjoin::IntoUrlError);

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct FeeRateError(#[from] bitcoin_ffi::error::FeeRateError);

#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
#[error("Error parsing the payjoin URI: {msg}")]
pub struct PjParseError {
    msg: String,
}

impl PjParseError {
    pub(crate) fn from_err(err: impl std::fmt::Display) -> Self { Self { msg: err.to_string() } }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
#[error("URI doesn't support payjoin: {msg}")]
pub struct PjNotSupported {
    msg: String,
}

impl PjNotSupported {
    pub(crate) fn from_display(uri: impl std::fmt::Display) -> Self {
        Self { msg: uri.to_string() }
    }
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

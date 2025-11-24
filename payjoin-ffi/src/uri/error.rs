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
#[error("{msg}")]
pub struct FeeRateError {
    msg: String,
}

impl FeeRateError {
    pub(crate) fn overflow(value_sat_per_vb: u64) -> Self {
        Self {
            msg: format!(
                "Fee rate {value_sat_per_vb} sat/vB exceeds the supported range for this platform"
            ),
        }
    }
}

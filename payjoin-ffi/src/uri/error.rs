#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct PjParseError(#[from] payjoin::PjParseError);

impl PjParseError {
    pub fn message(&self) -> String { self.0.to_string() }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct PjNotSupported(
    #[from] Box<payjoin::Uri<'static, payjoin::bitcoin::address::NetworkChecked>>,
);

impl PjNotSupported {
    pub fn uri(&self) -> String { self.0.to_string() }
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

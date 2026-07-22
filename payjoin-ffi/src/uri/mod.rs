use std::str::FromStr;
use std::sync::Arc;

pub use error::{PjNotSupported, UriParseError, UrlParseError};
use payjoin::bitcoin::address::NetworkChecked;

use crate::error::FfiValidationError;
use crate::validation::validate_amount_sat;

pub mod error;
#[derive(Clone, uniffi::Object)]
pub struct Uri(payjoin::Uri<NetworkChecked>);
impl From<Uri> for payjoin::Uri<NetworkChecked> {
    fn from(value: Uri) -> Self { value.0 }
}

impl From<payjoin::Uri<NetworkChecked>> for Uri {
    fn from(value: payjoin::Uri<NetworkChecked>) -> Self { Uri(value) }
}

#[uniffi::export]
impl Uri {
    #[uniffi::constructor]
    pub fn parse(uri: String) -> Result<Self, UriParseError> {
        let uri = payjoin::Uri::from_str(uri.as_str())?;
        Ok(uri.assume_checked().into())
    }
    pub fn address(&self) -> String { self.0.address().to_string() }
    /// Gets the amount in satoshis.
    pub fn amount_sats(&self) -> Option<u64> { self.0.amount().map(|x| x.to_sat()) }
    pub fn label(&self) -> Option<String> { self.0.label() }
    pub fn message(&self) -> Option<String> { self.0.message() }

    pub fn check_pj_supported(&self) -> Result<Arc<PjUri>, PjNotSupported> {
        self.0
            .clone()
            .check_pj_supported()
            .map(|uri| Arc::new(uri.into()))
            .map_err(PjNotSupported::from_display)
    }
    pub fn as_string(&self) -> String { self.0.clone().to_string() }
}

impl From<payjoin::PjUri> for PjUri {
    fn from(value: payjoin::PjUri) -> Self { Self(value) }
}

impl From<PjUri> for payjoin::PjUri {
    fn from(value: PjUri) -> Self { value.0 }
}

#[derive(Clone, uniffi::Object)]
pub struct PjUri(pub payjoin::PjUri);

#[uniffi::export]
impl PjUri {
    pub fn address(&self) -> String { self.0.address().to_string() }
    /// Number of sats requested as payment
    pub fn amount_sats(&self) -> Option<u64> { self.0.amount().map(|e| e.to_sat()) }

    /// Sets the amount in sats and returns a new PjUri
    pub fn set_amount_sats(&self, amount_sats: u64) -> Result<Self, FfiValidationError> {
        let mut uri = self.0.clone();
        let amount = validate_amount_sat(amount_sats)?;
        uri.set_amount(amount);
        Ok(uri.into())
    }

    pub fn pj_endpoint(&self) -> String { self.0.extras().endpoint().to_string() }

    pub fn as_string(&self) -> String { self.0.clone().to_string() }
}

impl From<url::Url> for Url {
    fn from(value: url::Url) -> Self { Self(value) }
}

impl From<Url> for url::Url {
    fn from(value: Url) -> Self { value.0 }
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct Url(url::Url);

#[uniffi::export]
impl Url {
    #[uniffi::constructor]
    pub fn parse(input: String) -> Result<Url, UrlParseError> {
        url::Url::parse(input.as_str()).map_err(Into::into).map(Self)
    }
    pub fn query(&self) -> Option<String> { self.0.query().map(|x| x.to_string()) }
    pub fn as_string(&self) -> String { self.0.to_string() }
}

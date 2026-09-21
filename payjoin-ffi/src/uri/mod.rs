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

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";
    const URI: &str = "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?amount=0.00000001&label=hello&message=world&pj=https://example.com/pj";

    #[test]
    fn uri_accessors_expose_parsed_fields() {
        let uri = Uri::parse(URI.to_string()).expect("valid uri");
        assert_eq!(uri.address(), ADDRESS);
        assert_eq!(uri.amount_sats(), Some(1));
        assert_eq!(uri.label(), Some("hello".to_string()));
        assert_eq!(uri.message(), Some("world".to_string()));
        assert!(uri.as_string().contains("amount=0.00000001"));
    }

    #[test]
    fn uri_without_optional_fields_returns_none() {
        let uri = Uri::parse(format!("bitcoin:{ADDRESS}")).expect("valid uri");
        assert_eq!(uri.amount_sats(), None);
        assert_eq!(uri.label(), None);
        assert_eq!(uri.message(), None);
    }

    #[test]
    fn pj_uri_accessors_expose_parsed_fields() {
        let pj_uri =
            Uri::parse(URI.to_string()).expect("valid uri").check_pj_supported().expect("pj uri");
        assert_eq!(pj_uri.address(), ADDRESS);
        assert_eq!(pj_uri.amount_sats(), Some(1));
        assert_eq!(pj_uri.pj_endpoint(), "https://example.com/pj");
        assert!(pj_uri.as_string().contains("pj="));
    }

    #[test]
    fn pj_uri_set_amount_sats_updates_amount() {
        let pj_uri =
            Uri::parse(URI.to_string()).expect("valid uri").check_pj_supported().expect("pj uri");
        let updated = pj_uri.set_amount_sats(1000).expect("valid amount");
        assert_eq!(updated.amount_sats(), Some(1000));
    }

    #[test]
    fn url_accessors_expose_parsed_fields() {
        let url = Url::parse("https://example.com/pj?a=b&c=d".to_string()).expect("valid url");
        assert_eq!(url.query(), Some("a=b&c=d".to_string()));
        assert_eq!(url.as_string(), "https://example.com/pj?a=b&c=d");
    }

    #[test]
    fn url_without_query_returns_none() {
        let url = Url::parse("https://example.com/pj".to_string()).expect("valid url");
        assert_eq!(url.query(), None);
    }
}

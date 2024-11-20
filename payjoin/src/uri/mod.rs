use std::borrow::Cow;

use bitcoin::address::NetworkChecked;
use bitcoin::{Address, Amount};
pub use error::PjParseError;
use url::Url;

#[cfg(feature = "v2")]
use crate::hpke::HpkePublicKey;
use crate::uri::error::InternalPjParseError;
#[cfg(feature = "v2")]
pub(crate) use crate::uri::url_ext::UrlExt;
#[cfg(feature = "v2")]
use crate::OhttpKeys;

pub mod error;
#[cfg(feature = "v2")]
pub(crate) mod url_ext;

#[derive(Debug, Clone)]
pub enum MaybePayjoinExtras {
    Supported(PayjoinExtras),
    Unsupported,
}

impl MaybePayjoinExtras {
    pub fn pj_is_supported(&self) -> bool {
        match self {
            MaybePayjoinExtras::Supported(_) => true,
            MaybePayjoinExtras::Unsupported => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PayjoinExtras {
    pub(crate) endpoint: Url,
    pub(crate) disable_output_substitution: bool,
}

impl PayjoinExtras {
    pub fn endpoint(&self) -> &Url { &self.endpoint }
}

pub type Uri<'a, NetworkValidation> = bip21::Uri<'a, NetworkValidation, MaybePayjoinExtras>;
pub type PjUri<'a> = bip21::Uri<'a, NetworkChecked, PayjoinExtras>;

mod sealed {
    use bitcoin::address::NetworkChecked;

    pub trait UriExt: Sized {}

    impl UriExt for super::Uri<'_, NetworkChecked> {}
    impl UriExt for super::PjUri<'_> {}
}

pub trait UriExt<'a>: sealed::UriExt {
    // Error type is boxed to reduce the size of the Result
    // (See https://rust-lang.github.io/rust-clippy/master/index.html#result_large_err)
    fn check_pj_supported(self) -> Result<PjUri<'a>, Box<bip21::Uri<'a>>>;
}

impl<'a> UriExt<'a> for Uri<'a, NetworkChecked> {
    // FIXME custom enum since error is actually a default fallback for pj unsupported
    // enumerate reasons why this might fail
    fn check_pj_supported(self) -> Result<PjUri<'a>, Box<bip21::Uri<'a>>> {
        match self.extras {
            MaybePayjoinExtras::Supported(payjoin) => {
                let mut uri = bip21::Uri::with_extras(self.address, payjoin);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Ok(uri)
            }
            MaybePayjoinExtras::Unsupported => {
                let mut uri = bip21::Uri::new(self.address);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Err(Box::new(uri))
            }
        }
    }
}

/// Build a valid `PjUri`.
///
/// Payjoin receiver can use this builder to create a payjoin
/// uri to send to the sender.
#[derive(Clone)]
pub struct PjUriBuilder {
    /// Address you want to receive funds to.
    address: Address,
    /// Amount you want to receive.
    ///
    /// If `None` the amount will be left unspecified.
    amount: Option<Amount>,
    /// Message
    message: Option<String>,
    /// Label
    label: Option<String>,
    /// Payjoin endpoint url listening for payjoin requests.
    pj: Url,
    /// Whether or not payjoin output substitution is allowed
    pjos: bool,
}

impl PjUriBuilder {
    /// Create a new `PjUriBuilder` with required parameters.
    ///
    /// ## Parameters
    /// - `address`: Represents a bitcoin address.
    /// - `origin`: Represents either the payjoin endpoint in v1 or the directory in v2.
    /// - `ohttp_keys`: Optional OHTTP keys for v2 (only available if the "v2" feature is enabled).
    /// - `expiry`: Optional non-default expiry for the payjoin session (only available if the "v2" feature is enabled).
    pub fn new(
        address: Address,
        origin: Url,
        #[cfg(feature = "v2")] receiver_pubkey: Option<HpkePublicKey>, // FIXME make Option<(pk, keys, exp)>
        #[cfg(feature = "v2")] ohttp_keys: Option<OhttpKeys>,
        #[cfg(feature = "v2")] expiry: Option<std::time::SystemTime>,
    ) -> Self {
        #[allow(unused_mut)]
        let mut pj = origin;
        #[cfg(feature = "v2")]
        pj.set_receiver_pubkey(receiver_pubkey);
        #[cfg(feature = "v2")]
        pj.set_ohttp(ohttp_keys);
        #[cfg(feature = "v2")]
        pj.set_exp(expiry);
        Self { address, amount: None, message: None, label: None, pj, pjos: false }
    }
    /// Set the amount you want to receive.
    pub fn amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set the message.
    pub fn message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }

    /// Set the label.
    pub fn label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }

    /// Set whether or not payjoin output substitution is allowed.
    #[cfg(not(feature = "v2"))] // TODO ensure v2 options are set imply pjos=true
    pub fn pjos(mut self, pjos: bool) -> Self {
        self.pjos = pjos;
        self
    }

    /// Build payjoin URI.
    ///
    /// Constructs a `bip21::Uri` with PayjoinParams from the
    /// parameters set in the builder.
    pub fn build<'a>(self) -> PjUri<'a> {
        let extras = PayjoinExtras { endpoint: self.pj, disable_output_substitution: self.pjos };
        let mut pj_uri = bip21::Uri::with_extras(self.address, extras);
        pj_uri.amount = self.amount;
        pj_uri.label = self.label.map(Into::into);
        pj_uri.message = self.message.map(Into::into);
        pj_uri
    }
}

impl PayjoinExtras {
    pub fn is_output_substitution_disabled(&self) -> bool { self.disable_output_substitution }
}

impl bip21::de::DeserializationError for MaybePayjoinExtras {
    type Error = PjParseError;
}

impl bip21::de::DeserializeParams<'_> for MaybePayjoinExtras {
    type DeserializationState = DeserializationState;
}

#[derive(Default)]
pub struct DeserializationState {
    pj: Option<Url>,
    pjos: Option<bool>,
}

impl bip21::SerializeParams for &MaybePayjoinExtras {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator {
        match self {
            MaybePayjoinExtras::Supported(extras) => extras.serialize_params(),
            MaybePayjoinExtras::Unsupported => vec![].into_iter(),
        }
    }
}

impl bip21::SerializeParams for &PayjoinExtras {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator {
        vec![
            ("pj", self.endpoint.as_str().to_string()),
            ("pjos", if self.disable_output_substitution { "1" } else { "0" }.to_string()),
        ]
        .into_iter()
    }
}

impl bip21::de::DeserializationState<'_> for DeserializationState {
    type Value = MaybePayjoinExtras;

    fn is_param_known(&self, param: &str) -> bool { matches!(param, "pj" | "pjos") }

    fn deserialize_temp(
        &mut self,
        key: &str,
        value: bip21::Param<'_>,
    ) -> std::result::Result<
        bip21::de::ParamKind,
        <Self::Value as bip21::DeserializationError>::Error,
    > {
        match key {
            "pj" if self.pj.is_none() => {
                let endpoint = Cow::try_from(value).map_err(|_| InternalPjParseError::NotUtf8)?;
                let url = Url::parse(&endpoint).map_err(|_| InternalPjParseError::BadEndpoint)?;
                self.pj = Some(url);

                Ok(bip21::de::ParamKind::Known)
            }
            "pj" => Err(InternalPjParseError::DuplicateParams("pj").into()),
            "pjos" if self.pjos.is_none() => {
                match &*Cow::try_from(value).map_err(|_| InternalPjParseError::BadPjOs)? {
                    "0" => self.pjos = Some(false),
                    "1" => self.pjos = Some(true),
                    _ => return Err(InternalPjParseError::BadPjOs.into()),
                }
                Ok(bip21::de::ParamKind::Known)
            }
            "pjos" => Err(InternalPjParseError::DuplicateParams("pjos").into()),
            _ => Ok(bip21::de::ParamKind::Unknown),
        }
    }

    fn finalize(
        self,
    ) -> std::result::Result<Self::Value, <Self::Value as bip21::DeserializationError>::Error> {
        match (self.pj, self.pjos) {
            (None, None) => Ok(MaybePayjoinExtras::Unsupported),
            (None, Some(_)) => Err(InternalPjParseError::MissingEndpoint.into()),
            (Some(endpoint), pjos) => {
                if endpoint.scheme() == "https"
                    || endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion")
                {
                    Ok(MaybePayjoinExtras::Supported(PayjoinExtras {
                        endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                    }))
                } else {
                    Err(InternalPjParseError::UnsecureEndpoint.into())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;

    #[test]
    fn test_short() {
        assert!(Uri::try_from("").is_err());
        assert!(Uri::try_from("bitcoin").is_err());
        assert!(Uri::try_from("bitcoin:").is_err());
    }

    #[ignore]
    #[test]
    fn test_todo_url_encoded() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
        assert!(Uri::try_from(uri).is_err(), "pj url should be url encoded");
    }

    #[test]
    fn test_valid_url() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=this_is_NOT_a_validURL";
        assert!(Uri::try_from(uri).is_err(), "pj is not a valid url");
    }

    #[test]
    fn test_missing_amount() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
        assert!(Uri::try_from(uri).is_ok(), "missing amount should be ok");
    }

    #[test]
    fn test_unencrypted() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=http://example.com";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");

        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=ftp://foo.onion";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");
    }

    #[test]
    fn test_valid_uris() {
        let https = "https://example.com";
        let onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion";

        let base58 = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let bech32_upper = "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4";
        let bech32_lower = "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";

        for address in [base58, bech32_upper, bech32_lower].iter() {
            for pj in [https, onion].iter() {
                let uri_with_amount = format!("{}?amount=1&pj={}", address, pj);
                assert!(Uri::try_from(uri_with_amount).is_ok());

                let uri_without_amount = format!("{}?pj={}", address, pj);
                assert!(Uri::try_from(uri_without_amount).is_ok());

                let uri_shuffled_params = format!("{}?pj={}&amount=1", address, pj);
                assert!(Uri::try_from(uri_shuffled_params).is_ok());
            }
        }
    }

    #[test]
    fn test_unsupported() {
        assert!(!Uri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX")
            .unwrap()
            .extras
            .pj_is_supported());
    }

    #[test]
    fn test_builder() {
        use std::str::FromStr;

        use url::Url;
        use PjUriBuilder;
        let https = "https://example.com/";
        let onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion/";
        let base58 = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let bech32_upper = "TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4";
        let bech32_lower = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";

        for address in [base58, bech32_upper, bech32_lower] {
            for pj in [https, onion] {
                let address = bitcoin::Address::from_str(address).unwrap().assume_checked();
                let amount = bitcoin::Amount::ONE_BTC;
                let builder = PjUriBuilder::new(
                    address.clone(),
                    Url::parse(pj).unwrap(),
                    #[cfg(feature = "v2")]
                    None,
                    #[cfg(feature = "v2")]
                    None,
                    #[cfg(feature = "v2")]
                    None,
                )
                .amount(amount)
                .message("message".to_string())
                .label("label".to_string())
                .pjos(true);
                let uri = builder.build();
                assert_eq!(uri.address, address);
                assert_eq!(uri.amount.unwrap(), bitcoin::Amount::ONE_BTC);
                let label: Cow<'_, str> = uri.label.clone().unwrap().try_into().unwrap();
                let message: Cow<'_, str> = uri.message.clone().unwrap().try_into().unwrap();
                assert_eq!(label, "label");
                assert_eq!(message, "message");
                assert!(uri.extras.disable_output_substitution);
                assert_eq!(uri.extras.endpoint.to_string(), pj.to_string());
            }
        }
    }
}

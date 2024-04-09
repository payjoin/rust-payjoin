use std::borrow::Cow;

use bitcoin::address::NetworkChecked;
use bitcoin::{Address, Amount};
use url::Url;

#[cfg(feature = "v2")]
use crate::OhttpKeys;

#[derive(Clone)]
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

#[derive(Clone)]
pub struct PayjoinExtras {
    pub(crate) endpoint: Url,
    pub(crate) disable_output_substitution: bool,
    #[cfg(feature = "v2")]
    pub(crate) ohttp_keys: Option<OhttpKeys>,
}

pub type Uri<'a, NetworkValidation> = bip21::Uri<'a, NetworkValidation, MaybePayjoinExtras>;
pub type PjUri<'a> = bip21::Uri<'a, NetworkChecked, PayjoinExtras>;

mod sealed {
    use bitcoin::address::NetworkChecked;

    pub trait UriExt: Sized {}

    impl<'a> UriExt for super::Uri<'a, NetworkChecked> {}
    impl<'a> UriExt for super::PjUri<'a> {}
}

pub trait UriExt<'a>: sealed::UriExt {
    fn check_pj_supported(self) -> Result<PjUri<'a>, bip21::Uri<'a>>;
}

impl<'a> UriExt<'a> for Uri<'a, NetworkChecked> {
    fn check_pj_supported(self) -> Result<PjUri<'a>, bip21::Uri<'a>> {
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

                Err(uri)
            }
        }
    }
}

/// Build a valid `PjUri`.
///
/// Payjoin receiver can use this builder to create a payjoin
/// uri to send to the sender.
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
    #[cfg(feature = "v2")]
    /// Config for ohttp.
    ///
    /// Required only for v2 payjoin.
    ohttp: Option<OhttpKeys>,
}

impl PjUriBuilder {
    /// Create a new `PjUriBuilder` with required parameters.
    pub fn new(
        address: Address,
        pj: Url,
        #[cfg(feature = "v2")] ohttp_keys: Option<OhttpKeys>,
    ) -> Self {
        Self {
            address,
            amount: None,
            message: None,
            label: None,
            pj,
            pjos: false,
            #[cfg(feature = "v2")]
            ohttp: ohttp_keys,
        }
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
    pub fn pjos(mut self, pjos: bool) -> Self {
        self.pjos = pjos;
        self
    }

    /// Build payjoin URI.
    ///
    /// Constructs a `bip21::Uri` with PayjoinParams from the
    /// parameters set in the builder.
    pub fn build<'a>(self) -> PjUri<'a> {
        let extras = PayjoinExtras {
            endpoint: self.pj,
            disable_output_substitution: self.pjos,
            #[cfg(feature = "v2")]
            ohttp_keys: self.ohttp,
        };
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

impl<'a> bip21::de::DeserializeParams<'a> for MaybePayjoinExtras {
    type DeserializationState = DeserializationState;
}

#[derive(Default)]
pub struct DeserializationState {
    pj: Option<Url>,
    pjos: Option<bool>,
    #[cfg(feature = "v2")]
    ohttp: Option<OhttpKeys>,
}

#[derive(Debug)]
pub struct PjParseError(InternalPjParseError);

impl From<InternalPjParseError> for PjParseError {
    fn from(value: InternalPjParseError) -> Self { PjParseError(value) }
}

impl<'a> bip21::SerializeParams for &'a MaybePayjoinExtras {
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

impl<'a> bip21::SerializeParams for &'a PayjoinExtras {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator {
        #[allow(unused_mut)]
        let mut params = vec![
            ("pj", self.endpoint.as_str().to_string()),
            ("pjos", if self.disable_output_substitution { "1" } else { "0" }.to_string()),
        ];
        #[cfg(feature = "v2")]
        if let Some(ohttp_keys) = self.ohttp_keys.clone().and_then(|c| c.encode().ok()) {
            let config =
                bitcoin::base64::Config::new(bitcoin::base64::CharacterSet::UrlSafe, false);
            let base64_ohttp_keys = bitcoin::base64::encode_config(ohttp_keys, config);
            params.push(("ohttp", base64_ohttp_keys));
        } else {
            log::warn!("Failed to encode ohttp config, ignoring");
        }
        params.into_iter()
    }
}

impl<'a> bip21::de::DeserializationState<'a> for DeserializationState {
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
            #[cfg(feature = "v2")]
            "ohttp" if self.ohttp.is_none() => {
                let base64_config =
                    Cow::try_from(value).map_err(|_| InternalPjParseError::NotUtf8)?;
                let config_bytes =
                    bitcoin::base64::decode_config(&*base64_config, bitcoin::base64::URL_SAFE)
                        .map_err(|_| InternalPjParseError::NotBase64)?;
                let config = OhttpKeys::decode(&config_bytes)
                    .map_err(|_| InternalPjParseError::DecodeOhttpKeys)?;
                self.ohttp = Some(config);
                Ok(bip21::de::ParamKind::Known)
            }
            #[cfg(feature = "v2")]
            "ohttp" => Err(PjParseError(InternalPjParseError::MultipleParams("ohttp"))),
            "pj" if self.pj.is_none() => {
                let endpoint = Cow::try_from(value).map_err(|_| InternalPjParseError::NotUtf8)?;
                let url = Url::parse(&endpoint).map_err(|_| InternalPjParseError::BadEndpoint)?;
                self.pj = Some(url);

                Ok(bip21::de::ParamKind::Known)
            }
            "pj" => Err(InternalPjParseError::MultipleParams("pj").into()),
            "pjos" if self.pjos.is_none() => {
                match &*Cow::try_from(value).map_err(|_| InternalPjParseError::BadPjOs)? {
                    "0" => self.pjos = Some(false),
                    "1" => self.pjos = Some(true),
                    _ => return Err(InternalPjParseError::BadPjOs.into()),
                }
                Ok(bip21::de::ParamKind::Known)
            }
            "pjos" => Err(InternalPjParseError::MultipleParams("pjos").into()),
            _ => Ok(bip21::de::ParamKind::Unknown),
        }
    }

    fn finalize(
        self,
    ) -> std::result::Result<Self::Value, <Self::Value as bip21::DeserializationError>::Error> {
        match (self.pj, self.pjos) {
            (None, None) => Ok(MaybePayjoinExtras::Unsupported),
            (None, Some(_)) => Err(PjParseError(InternalPjParseError::MissingEndpoint)),
            (Some(endpoint), pjos) => {
                if endpoint.scheme() == "https"
                    || endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion")
                {
                    Ok(MaybePayjoinExtras::Supported(PayjoinExtras {
                        endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                        #[cfg(feature = "v2")]
                        ohttp_keys: self.ohttp,
                    }))
                } else {
                    Err(PjParseError(InternalPjParseError::UnsecureEndpoint))
                }
            }
        }
    }
}

impl std::fmt::Display for PjParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            InternalPjParseError::BadPjOs => write!(f, "Bad pjos parameter"),
            InternalPjParseError::MultipleParams(param) => {
                write!(f, "Multiple instances of parameter '{}'", param)
            }
            InternalPjParseError::MissingEndpoint => write!(f, "Missing payjoin endpoint"),
            InternalPjParseError::NotUtf8 => write!(f, "Endpoint is not valid UTF-8"),
            #[cfg(feature = "v2")]
            InternalPjParseError::NotBase64 => write!(f, "ohttp config is not valid base64"),
            InternalPjParseError::BadEndpoint => write!(f, "Endpoint is not valid"),
            #[cfg(feature = "v2")]
            InternalPjParseError::DecodeOhttpKeys => write!(f, "ohttp config is not valid"),
            InternalPjParseError::UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
        }
    }
}

#[derive(Debug)]
enum InternalPjParseError {
    BadPjOs,
    MultipleParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    #[cfg(feature = "v2")]
    NotBase64,
    BadEndpoint,
    #[cfg(feature = "v2")]
    DecodeOhttpKeys,
    UnsecureEndpoint,
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
                // TODO add with and without amount
                // TODO shuffle params
                let uri = format!("{}?amount=1&pj={}", address, pj);
                assert!(Uri::try_from(&*uri).is_ok());
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

        for address in vec![base58, bech32_upper, bech32_lower] {
            for pj in vec![https, onion] {
                let address = bitcoin::Address::from_str(address).unwrap().assume_checked();
                let amount = bitcoin::Amount::ONE_BTC;
                let builder = PjUriBuilder::new(
                    address.clone(),
                    Url::parse(pj).unwrap(),
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
                assert_eq!(uri.extras.disable_output_substitution, true);
                assert_eq!(uri.extras.endpoint.to_string(), pj.to_string());
            }
        }
    }
}

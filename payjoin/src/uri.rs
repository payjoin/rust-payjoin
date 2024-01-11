use std::borrow::Cow;
use std::convert::TryFrom;

use bip21::de::UriError;
use bitcoin::address::{Error, NetworkChecked, NetworkUnchecked, NetworkValidation};
use bitcoin::{Address, Amount, Network};
use url::Url;

/// Payjoin Uri represents a bip21 uri with additional
/// payjoin parameters.
#[derive(Clone)]
pub struct PayjoinUri<'a, N: NetworkValidation> {
    pub inner: bip21::Uri<'a, N, PayjoinParams>,
}

impl<'a, N: NetworkValidation> From<bip21::Uri<'a, N, PayjoinParams>> for PayjoinUri<'a, N> {
    fn from(value: bip21::Uri<'a, N, PayjoinParams>) -> Self { Self { inner: value } }
}

impl<'a> PayjoinUri<'a, NetworkUnchecked> {
    /// Marks network of this address as checked.
    pub fn assume_checked(self) -> PayjoinUri<'a, NetworkChecked> {
        PayjoinUri::new(
            self.inner.address.assume_checked(),
            self.inner.extras,
            self.inner.amount,
            self.inner.label,
            self.inner.message,
        )
        .into()
    }
    /// Checks whether network of this address is as required.
    pub fn require_network(
        self,
        network: Network,
    ) -> Result<PayjoinUri<'a, NetworkChecked>, Error> {
        Ok(PayjoinUri::new(
            self.inner.address.require_network(network)?,
            self.inner.extras,
            self.inner.amount,
            self.inner.label,
            self.inner.message,
        )
        .into())
    }
}

impl<'a, N: NetworkValidation> PayjoinUri<'a, N> {
    fn new(
        address: Address<N>,
        extras: PayjoinParams,
        amount: Option<Amount>,
        label: Option<bip21::Param<'a>>,
        message: Option<bip21::Param<'a>>,
    ) -> Self {
        let mut uri = bip21::Uri::with_extras(address, extras);
        uri.amount = amount;
        uri.label = label;
        uri.message = message;
        Self { inner: uri }
    }
}

impl From<bip21::de::Error<PjParseError>> for PjParseError {
    fn from(e: bip21::de::Error<PjParseError>) -> Self {
        match e {
            bip21::de::Error::Uri(e) => InternalPjParseError::UriParseError(e).into(),
            bip21::de::Error::Extras(e) => e.into(),
        }
    }
}

impl<'a> TryFrom<&'a str> for PayjoinUri<'a, NetworkUnchecked> {
    type Error = PjParseError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let uri = bip21::Uri::try_from(s).map_err(|e| Into::<PjParseError>::into(e))?;
        Ok(uri.into())
    }
}

impl ToString for PayjoinUri<'_, NetworkChecked> {
    fn to_string(&self) -> String { self.inner.to_string() }
}

#[derive(Clone)]
pub struct PayjoinParams {
    endpoint: Url,
    disable_output_substitution: bool,
    #[cfg(feature = "v2")]
    ohttp_config: Option<ohttp::KeyConfig>,
}

impl PayjoinParams {
    pub fn disable_output_substitution(&self) -> bool { self.disable_output_substitution }
    pub fn endpoint(&self) -> &Url { &self.endpoint }
    #[cfg(feature = "v2")]
    pub fn ohttp_config(&self) -> Option<&ohttp::KeyConfig> { self.ohttp_config.as_ref() }
}

impl bip21::de::DeserializationError for PayjoinParams {
    type Error = PjParseError;
}

impl<'a> bip21::de::DeserializeParams<'a> for PayjoinParams {
    type DeserializationState = DeserializationState;
}

#[derive(Default)]
pub struct DeserializationState {
    pj: Option<Url>,
    pjos: Option<bool>,
    #[cfg(feature = "v2")]
    ohttp: Option<ohttp::KeyConfig>,
}

#[derive(Debug)]
pub struct PjParseError(InternalPjParseError);

impl From<InternalPjParseError> for PjParseError {
    fn from(value: InternalPjParseError) -> Self { PjParseError(value) }
}

impl<'a> bip21::de::DeserializationState<'a> for DeserializationState {
    type Value = PayjoinParams;

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
                let base64_config = Cow::try_from(value).map_err(InternalPjParseError::NotUtf8)?;
                let config_bytes =
                    bitcoin::base64::decode_config(&*base64_config, bitcoin::base64::URL_SAFE)
                        .map_err(InternalPjParseError::NotBase64)?;
                let config = ohttp::KeyConfig::decode(&config_bytes)
                    .map_err(InternalPjParseError::BadOhttp)?;
                self.ohttp = Some(config);
                Ok(bip21::de::ParamKind::Known)
            }
            #[cfg(feature = "v2")]
            "ohttp" => Err(PjParseError(InternalPjParseError::MultipleParams("ohttp"))),
            "pj" if self.pj.is_none() => {
                let endpoint = Cow::try_from(value).map_err(InternalPjParseError::NotUtf8)?;
                let url = Url::parse(&endpoint).map_err(InternalPjParseError::BadEndpoint)?;
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

    #[cfg(feature = "v2")]
    fn finalize(
        self,
    ) -> std::result::Result<Self::Value, <Self::Value as bip21::DeserializationError>::Error> {
        match (self.pj, self.pjos, self.ohttp) {
            (None, None, _) => Err(PjParseError(InternalPjParseError::Unsupported)),
            (None, Some(_), _) => Err(PjParseError(InternalPjParseError::MissingEndpoint)),
            (Some(endpoint), pjos, None) => {
                if endpoint.scheme() == "https"
                    || endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion")
                {
                    Ok(PayjoinParams {
                        endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                        ohttp_config: None,
                    })
                } else {
                    Err(PjParseError(InternalPjParseError::UnsecureEndpoint))
                }
            }
            (Some(endpoint), pjos, Some(ohttp)) => {
                if endpoint.scheme() == "https"
                    || endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion")
                {
                    Ok(PayjoinParams {
                        endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                        ohttp_config: Some(ohttp),
                    })
                } else if endpoint.scheme() == "http" {
                    Ok(PayjoinParams {
                        endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                        ohttp_config: Some(ohttp),
                    })
                } else {
                    Err(PjParseError(InternalPjParseError::UnsecureEndpoint))
                }
            }
        }
    }

    #[cfg(not(feature = "v2"))]
    fn finalize(
        self,
    ) -> std::result::Result<Self::Value, <Self::Value as bip21::DeserializationError>::Error> {
        match (self.pj, self.pjos) {
            (None, None) => Err(PjParseError(InternalPjParseError::Unsupported)),
            (None, Some(_)) => Err(PjParseError(InternalPjParseError::MissingEndpoint)),
            (Some(endpoint), pjos) => {
                if endpoint.scheme() == "https"
                    || endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion")
                {
                    Ok(PayjoinParams {
                        endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                    })
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
            InternalPjParseError::UriParseError(e) => write!(f, "Uri parse error: {}", e),
            InternalPjParseError::Unsupported => write!(f, "Payjoin is not supported"),
            InternalPjParseError::BadPjOs => write!(f, "Bad pjos parameter"),
            InternalPjParseError::MultipleParams(param) => {
                write!(f, "Multiple instances of parameter '{}'", param)
            }
            InternalPjParseError::MissingEndpoint => write!(f, "Missing payjoin endpoint"),
            InternalPjParseError::NotUtf8(_) => write!(f, "Endpoint is not valid UTF-8"),
            #[cfg(feature = "v2")]
            InternalPjParseError::NotBase64(_) => write!(f, "ohttp config is not valid base64"),
            InternalPjParseError::BadEndpoint(_) => write!(f, "Endpoint is not valid"),
            #[cfg(feature = "v2")]
            InternalPjParseError::BadOhttp(_) => write!(f, "ohttp config is not valid"),
            InternalPjParseError::UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
        }
    }
}

#[derive(Debug)]
enum InternalPjParseError {
    UriParseError(UriError),
    Unsupported,
    BadPjOs,
    MultipleParams(&'static str),
    MissingEndpoint,
    NotUtf8(core::str::Utf8Error),
    #[cfg(feature = "v2")]
    NotBase64(bitcoin::base64::DecodeError),
    BadEndpoint(url::ParseError),
    #[cfg(feature = "v2")]
    BadOhttp(ohttp::Error),
    UnsecureEndpoint,
}

impl<'a> bip21::SerializeParams for &'a PayjoinParams {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator {
        let mut params = vec![
            ("pj", self.endpoint.as_str().to_string()),
            ("pjos", if self.disable_output_substitution { "1" } else { "0" }.to_string()),
        ];
        #[cfg(feature = "v2")]
        if let Some(config) = &self.ohttp_config {
            if let Ok(config) = config.encode() {
                let encoded_config =
                    bitcoin::base64::encode_config(config, bitcoin::base64::URL_SAFE);
                params.push(("ohttp", encoded_config));
            } else {
                log::warn!("Failed to encode ohttp config, ignoring");
            }
            log::warn!("Ohttp config is not set, ignoring");
        }
        params.into_iter()
    }
}

/// Builder for `bip21::Uri` with PayjoinParams.
///
/// Payjoin receiver can use this builder to create a payjoin
/// uri to send to the sender.
pub struct PayjoinUriBuilder {
    /// Address you want to receive funds to.
    ///
    /// Must be a valid bitcoin address.
    address: Address,
    /// Payjoing endpoint url listening for payjoin requests.
    ///
    /// Must be a valid url that can be parsed
    /// with `[Payjoin::Url::parse]`.
    pj_endpoint: Url,
    /// Amount you want to receive.
    ///
    /// If `None` the amount will be left unspecified.
    amount: Option<Amount>,
    /// Message
    message: Option<String>,
    /// Label
    label: Option<String>,
    #[cfg(feature = "v2")]
    /// Config for ohttp.
    ///
    /// Required only for v2 payjoin.
    ohttp_config: Option<ohttp::KeyConfig>,
}

impl PayjoinUriBuilder {
    /// Create a new `PayjoinUriBuilder` with required parameters.
    pub fn new(
        address: Address,
        pj_endpoint: Url,
        #[cfg(feature = "v2")] ohttp_config: Option<ohttp::KeyConfig>,
    ) -> Self {
        Self {
            address,
            pj_endpoint,
            amount: None,
            message: None,
            label: None,
            #[cfg(feature = "v2")]
            ohttp_config,
        }
    }
    /// Set the amount you want to receive.
    pub fn amount(&mut self, amount: Amount) { self.amount = Some(amount); }
    /// Set the message.
    pub fn message(&mut self, message: String) { self.message = Some(message); }
    /// Set the label.
    pub fn label(&mut self, label: String) { self.label = Some(label); }
    /// Build payjoin URI.
    ///
    /// Constructs a `bip21::Uri` with PayjoinParams from the
    /// parameters set in the builder.
    pub fn build<'a>(self) -> PayjoinUri<'a, NetworkChecked> {
        let pj_params = PayjoinParams {
            endpoint: self.pj_endpoint,
            disable_output_substitution: false,
            #[cfg(feature = "v2")]
            ohttp_config: self.ohttp_config,
        };
        PayjoinUri::new(
            self.address,
            pj_params,
            self.amount,
            self.label.map(bip21::Param::from),
            self.message.map(bip21::Param::from),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::convert::TryFrom;

    use crate::PayjoinUri;

    #[test]
    fn test_short() {
        assert!(PayjoinUri::try_from("").is_err());
        assert!(PayjoinUri::try_from("bitcoin").is_err());
        assert!(PayjoinUri::try_from("bitcoin:").is_err());
    }

    #[ignore]
    #[test]
    fn test_todo_url_encoded() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
        assert!(PayjoinUri::try_from(uri).is_err(), "pj url should be url encoded");
    }

    #[test]
    fn test_valid_url() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=this_is_NOT_a_validURL";
        assert!(PayjoinUri::try_from(uri).is_err(), "pj is not a valid url");
    }

    #[test]
    fn test_missing_amount() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
        assert!(PayjoinUri::try_from(uri).is_ok(), "missing amount should be ok");
    }

    #[test]
    fn test_unencrypted() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=http://example.com";
        assert!(PayjoinUri::try_from(uri).is_err(), "unencrypted connection");

        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=ftp://foo.onion";
        assert!(PayjoinUri::try_from(uri).is_err(), "unencrypted connection");
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
                assert!(PayjoinUri::try_from(&*uri).is_ok());
            }
        }
    }

    #[test]
    fn test_payjoin_uri_builder() {
        use std::str::FromStr;

        use url::Url;

        use crate::PayjoinUriBuilder;
        let https = "https://example.com/";
        let onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion/";
        let base58 = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let bech32_upper = "TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4";
        let bech32_lower = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";

        for address in vec![base58, bech32_upper, bech32_lower] {
            for pj in [https, onion].iter() {
                let address = bitcoin::Address::from_str(address).unwrap().assume_checked();
                let amount = bitcoin::Amount::ONE_BTC;
                let mut uri = PayjoinUriBuilder::new(
                    address.clone(),
                    Url::parse(pj).unwrap(),
                    #[cfg(feature = "v2")]
                    None,
                );
                uri.amount(amount);
                uri.message("message".to_string());
                uri.label("label".to_string());
                let uri = uri.build();
                assert_eq!(uri.inner.address, address);
                assert_eq!(uri.inner.amount.unwrap(), bitcoin::Amount::ONE_BTC);
                let label: Cow<'_, str> = uri.inner.label.clone().unwrap().try_into().unwrap();
                let message: Cow<'_, str> = uri.inner.message.clone().unwrap().try_into().unwrap();
                assert_eq!(label, "label");
                assert_eq!(message, "message");
                assert_eq!(uri.inner.extras.endpoint().to_string(), pj.to_string());
            }
        }
    }

    #[test]
    fn test_unsupported() {
        assert!(PayjoinUri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX").is_err());
    }
}

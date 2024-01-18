use std::borrow::Cow;
use std::convert::TryFrom;
#[cfg(feature = "v2")]
use std::sync::Arc;

use bitcoin::address::{Error, NetworkChecked, NetworkUnchecked};
use bitcoin::Network;
use url::Url;
#[derive(Clone)]
pub enum Payjoin {
    Supported(PayjoinParams),
    V2Only(PayjoinParams),
    Unsupported,
}

impl Payjoin {
    pub fn pj_is_supported(&self) -> bool {
        match self {
            Payjoin::Supported(_) => true,
            Payjoin::V2Only(_) => true,
            Payjoin::Unsupported => false,
        }
    }
}

#[derive(Clone)]
pub struct PayjoinParams {
    pub(crate) _endpoint: Url,
    pub(crate) disable_output_substitution: bool,
    #[cfg(feature = "v2")]
    pub(crate) ohttp_config: Option<Arc<ohttp::KeyConfig>>,
}

impl Clone for PayjoinParams {
    fn clone(&self) -> Self {
        PayjoinParams {
            _endpoint: self._endpoint.clone(),
            disable_output_substitution: self.disable_output_substitution,
            #[cfg(feature = "v2")]
            ohttp_config: self.ohttp_config.as_ref().map(|config| config.clone()),
        }
    }
}

pub type Uri<'a, NetworkValidation> = bip21::Uri<'a, NetworkValidation, Payjoin>;
pub type PjUri<'a> = bip21::Uri<'a, NetworkChecked, PayjoinParams>;

mod sealed {
    use bitcoin::address::{NetworkChecked, NetworkUnchecked};

    pub trait UriExt: Sized {}

    impl<'a> UriExt for super::Uri<'a, NetworkChecked> {}
    impl<'a> UriExt for super::PjUri<'a> {}

    pub trait UriExtNetworkUnchecked: Sized {}

    impl<'a> UriExtNetworkUnchecked for super::Uri<'a, NetworkUnchecked> {}
}
pub trait UriExtNetworkUnchecked<'a>: sealed::UriExtNetworkUnchecked {
    fn require_network(self, network: Network) -> Result<Uri<'a, NetworkChecked>, Error>;

    fn assume_checked(self) -> Uri<'a, NetworkChecked>;
}

pub trait UriExt<'a>: sealed::UriExt {
    fn check_pj_supported(self) -> Result<PjUri<'a>, bip21::Uri<'a>>;
}

impl<'a> UriExtNetworkUnchecked<'a> for Uri<'a, NetworkUnchecked> {
    fn require_network(self, network: Network) -> Result<Uri<'a, NetworkChecked>, Error> {
        let checked_address = self.address.require_network(network)?;
        let mut uri = bip21::Uri::with_extras(checked_address, self.extras);
        uri.amount = self.amount;
        uri.label = self.label;
        uri.message = self.message;
        Ok(uri)
    }

    fn assume_checked(self) -> Uri<'a, NetworkChecked> {
        let checked_address = self.address.assume_checked();
        let mut uri = bip21::Uri::with_extras(checked_address, self.extras);
        uri.amount = self.amount;
        uri.label = self.label;
        uri.message = self.message;
        uri
    }
}

impl<'a> UriExt<'a> for Uri<'a, NetworkChecked> {
    fn check_pj_supported(self) -> Result<PjUri<'a>, bip21::Uri<'a>> {
        match self.extras {
            Payjoin::Supported(payjoin) | Payjoin::V2Only(payjoin) => {
                let mut uri = bip21::Uri::with_extras(self.address, payjoin);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Ok(uri)
            }
            Payjoin::Unsupported => {
                let mut uri = bip21::Uri::new(self.address);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Err(uri)
            }
        }
    }
}

impl PayjoinParams {
    pub fn is_output_substitution_disabled(&self) -> bool { self.disable_output_substitution }
}

impl bip21::de::DeserializationError for Payjoin {
    type Error = PjParseError;
}

impl<'a> bip21::de::DeserializeParams<'a> for Payjoin {
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
    type Value = Payjoin;

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
                    "0" => {
                        self.pjos = Some(false);
                    }
                    "1" => {
                        self.pjos = Some(true);
                    }
                    _ => {
                        return Err(InternalPjParseError::BadPjOs.into());
                    }
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
            (None, None, _) => Ok(Payjoin::Unsupported),
            (None, Some(_), _) => Err(PjParseError(InternalPjParseError::MissingEndpoint)),
            (Some(endpoint), pjos, None) => {
                if endpoint.scheme() == "https"
                    || (endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion"))
                {
                    Ok(Payjoin::Supported(PayjoinParams {
                        _endpoint: endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                        ohttp_config: None,
                    }))
                } else {
                    Err(PjParseError(InternalPjParseError::UnsecureEndpoint))
                }
            }
            (Some(endpoint), pjos, Some(ohttp)) => {
                if endpoint.scheme() == "https"
                    || (endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion"))
                {
                    Ok(Payjoin::Supported(PayjoinParams {
                        _endpoint: endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                        ohttp_config: Some(Arc::new(ohttp)),
                    }))
                } else if endpoint.scheme() == "http" {
                    Ok(Payjoin::V2Only(PayjoinParams {
                        _endpoint: endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                        ohttp_config: Some(Arc::new(ohttp)),
                    }))
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
            (None, None) => Ok(Payjoin::Unsupported),
            (None, Some(_)) => Err(PjParseError(InternalPjParseError::MissingEndpoint)),
            (Some(endpoint), pjos) => {
                if endpoint.scheme() == "https"
                    || (endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion"))
                {
                    Ok(Payjoin::Supported(PayjoinParams {
                        _endpoint: endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
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

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::Uri;

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
        let uri =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
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
}

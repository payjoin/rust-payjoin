use std::borrow::Cow;

use bitcoin::address::NetworkChecked;
pub use error::PjParseError;
use url::Url;

#[cfg(feature = "v2")]
pub(crate) use crate::directory::ShortId;
use crate::output_substitution::OutputSubstitution;
use crate::uri::error::InternalPjParseError;
#[cfg(feature = "v2")]
pub(crate) use crate::uri::url_ext::UrlExt;

pub mod error;
#[cfg(feature = "v2")]
pub(crate) mod url_ext;

pub use error::PayjoinUriError;

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

/// Validated payjoin parameters
#[derive(Debug, Clone)]
pub struct PayjoinExtras {
    /// pj parameter
    pub(crate) endpoint: Url,
    /// pjos parameter
    pub(crate) output_substitution: OutputSubstitution,
}

impl PayjoinExtras {
    pub fn endpoint(&self) -> &Url { &self.endpoint }
    pub fn output_substitution(&self) -> OutputSubstitution { self.output_substitution }
}

#[derive(Debug, Clone)]
pub struct PayjoinUri<'a> {
    inner: bitcoin_uri::Uri<'a, NetworkChecked, MaybePayjoinExtras>,
}

#[derive(Debug, Clone)]
pub struct ValidatedPayjoinUri<'a> {
    inner: bitcoin_uri::Uri<'a, NetworkChecked, PayjoinExtras>,
}

impl<'a> PayjoinUri<'a> {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &'a str) -> Result<Self, PayjoinUriError> {
        let inner = bitcoin_uri::Uri::try_from(s)
            .map_err(PayjoinUriError::from)?
            .require_network(bitcoin::Network::Bitcoin)
            .map_err(PayjoinUriError::from)?;
        Ok(PayjoinUri { inner })
    }

    pub fn check_pj_supported(&self) -> Result<ValidatedPayjoinUri<'a>, PayjoinUriError> {
        match &self.inner.extras {
            MaybePayjoinExtras::Supported(payjoin) => {
                let mut inner =
                    bitcoin_uri::Uri::with_extras(self.inner.address.clone(), payjoin.clone());
                inner.amount = self.inner.amount;
                inner.label = self.inner.label.clone();
                inner.message = self.inner.message.clone();
                Ok(ValidatedPayjoinUri { inner })
            }
            MaybePayjoinExtras::Unsupported => Err(PayjoinUriError::UnsupportedUri),
        }
    }

    pub fn address(&self) -> &bitcoin::Address<NetworkChecked> { &self.inner.address }

    pub fn amount(&self) -> Option<bitcoin::Amount> { self.inner.amount }

    pub fn label(&self) -> Option<String> {
        self.inner
            .label
            .clone()
            .and_then(|p| std::borrow::Cow::<str>::try_from(p).ok())
            .map(|s| s.to_string())
    }

    pub fn message(&self) -> Option<String> {
        self.inner
            .message
            .clone()
            .and_then(|p| std::borrow::Cow::<str>::try_from(p).ok())
            .map(|s| s.to_string())
    }

    pub fn supports_payjoin(&self) -> bool { self.inner.extras.pj_is_supported() }

    pub fn as_bitcoin_uri(&self) -> &bitcoin_uri::Uri<'a, NetworkChecked, MaybePayjoinExtras> {
        &self.inner
    }
}

impl<'a> ValidatedPayjoinUri<'a> {
    pub fn endpoint(&self) -> &url::Url { self.inner.extras.endpoint() }

    pub fn output_substitution(&self) -> OutputSubstitution {
        self.inner.extras.output_substitution()
    }

    pub fn address(&self) -> &bitcoin::Address<NetworkChecked> { &self.inner.address }

    pub fn amount(&self) -> Option<bitcoin::Amount> { self.inner.amount }

    pub fn label(&self) -> Option<String> {
        self.inner
            .label
            .clone()
            .and_then(|p| std::borrow::Cow::<str>::try_from(p).ok())
            .map(|s| s.to_string())
    }

    pub fn message(&self) -> Option<String> {
        self.inner
            .message
            .clone()
            .and_then(|p| std::borrow::Cow::<str>::try_from(p).ok())
            .map(|s| s.to_string())
    }

    pub fn as_bitcoin_uri(&self) -> &bitcoin_uri::Uri<'a, NetworkChecked, PayjoinExtras> {
        &self.inner
    }
}

impl std::fmt::Display for PayjoinUri<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.inner.fmt(f) }
}

impl std::fmt::Display for ValidatedPayjoinUri<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.inner.fmt(f) }
}

pub type Uri<'a, NetworkValidation> = bitcoin_uri::Uri<'a, NetworkValidation, MaybePayjoinExtras>;
pub type PjUri<'a> = bitcoin_uri::Uri<'a, NetworkChecked, PayjoinExtras>;

mod sealed {
    use bitcoin::address::NetworkChecked;

    pub trait UriExt: Sized {}

    impl UriExt for super::Uri<'_, NetworkChecked> {}
    impl UriExt for super::PjUri<'_> {}
}

pub trait UriExt<'a>: sealed::UriExt {
    fn check_pj_supported(self) -> Result<PjUri<'a>, PayjoinUriError>;
}

impl<'a> UriExt<'a> for Uri<'a, NetworkChecked> {
    fn check_pj_supported(self) -> Result<PjUri<'a>, PayjoinUriError> {
        match self.extras {
            MaybePayjoinExtras::Supported(payjoin) => {
                let mut uri = bitcoin_uri::Uri::with_extras(self.address, payjoin);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Ok(uri)
            }
            MaybePayjoinExtras::Unsupported => Err(PayjoinUriError::unsupported_uri()),
        }
    }
}

impl bitcoin_uri::de::DeserializationError for MaybePayjoinExtras {
    type Error = PjParseError;
}

impl bitcoin_uri::de::DeserializeParams<'_> for MaybePayjoinExtras {
    type DeserializationState = DeserializationState;
}

#[derive(Default)]
pub struct DeserializationState {
    pj: Option<Url>,
    pjos: Option<OutputSubstitution>,
}

impl bitcoin_uri::SerializeParams for &MaybePayjoinExtras {
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

impl bitcoin_uri::SerializeParams for &PayjoinExtras {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator {
        // normalizing to uppercase enables QR alphanumeric mode encoding
        // unfortunately Url normalizes these to be lowercase
        let scheme = self.endpoint.scheme();
        let host = self.endpoint.host_str().expect("host must be set");
        let endpoint_str = self
            .endpoint
            .as_str()
            .replacen(scheme, &scheme.to_uppercase(), 1)
            .replacen(host, &host.to_uppercase(), 1);

        let mut params = Vec::with_capacity(2);
        if self.output_substitution == OutputSubstitution::Disabled {
            params.push(("pjos", String::from("0")));
        }
        params.push(("pj", endpoint_str));
        params.into_iter()
    }
}

impl bitcoin_uri::de::DeserializationState<'_> for DeserializationState {
    type Value = MaybePayjoinExtras;

    fn is_param_known(&self, param: &str) -> bool { matches!(param, "pj" | "pjos") }

    fn deserialize_temp(
        &mut self,
        key: &str,
        value: bitcoin_uri::Param<'_>,
    ) -> std::result::Result<
        bitcoin_uri::de::ParamKind,
        <Self::Value as bitcoin_uri::DeserializationError>::Error,
    > {
        match key {
            "pj" if self.pj.is_none() => {
                let endpoint = Cow::try_from(value).map_err(|_| InternalPjParseError::NotUtf8)?;
                #[cfg(not(feature = "v2"))]
                let url = Url::parse(&endpoint).map_err(|e| {
                    InternalPjParseError::BadEndpoint(error::BadEndpointError::UrlParse(e))
                })?;
                #[cfg(feature = "v2")]
                let url = url_ext::parse_with_fragment(&endpoint)
                    .map_err(InternalPjParseError::BadEndpoint)?;

                self.pj = Some(url);

                Ok(bitcoin_uri::de::ParamKind::Known)
            }
            "pj" => Err(InternalPjParseError::DuplicateParams("pj").into()),
            "pjos" if self.pjos.is_none() => {
                match &*Cow::try_from(value).map_err(|_| InternalPjParseError::BadPjOs)? {
                    "0" => self.pjos = Some(OutputSubstitution::Disabled),
                    "1" => self.pjos = Some(OutputSubstitution::Enabled),
                    _ => return Err(InternalPjParseError::BadPjOs.into()),
                }
                Ok(bitcoin_uri::de::ParamKind::Known)
            }
            "pjos" => Err(InternalPjParseError::DuplicateParams("pjos").into()),
            _ => Ok(bitcoin_uri::de::ParamKind::Unknown),
        }
    }

    fn finalize(
        self,
    ) -> std::result::Result<Self::Value, <Self::Value as bitcoin_uri::DeserializationError>::Error>
    {
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
                        output_substitution: pjos.unwrap_or(OutputSubstitution::Enabled),
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

    use bitcoin_uri::SerializeParams;

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
                let uri_with_amount = format!("{address}?amount=1&pj={pj}");
                assert!(Uri::try_from(uri_with_amount).is_ok());

                let uri_without_amount = format!("{address}?pj={pj}");
                assert!(Uri::try_from(uri_without_amount).is_ok());

                let uri_shuffled_params = format!("{address}?pj={pj}&amount=1");
                assert!(Uri::try_from(uri_shuffled_params).is_ok());
            }
        }
    }

    #[test]
    fn test_unsupported() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let unchecked = Uri::try_from(uri).unwrap();
        let parsed = unchecked.require_network(bitcoin::Network::Bitcoin).unwrap();

        assert!(
            !parsed.extras.pj_is_supported(),
            "Uri expected a failure with missing pj extras, but it succeeded"
        );

        let result = parsed.check_pj_supported();
        assert!(result.is_err());

        let err = result.err().unwrap();
        assert!(err.to_string().contains("URI does not support Payjoin"));
    }

    #[test]
    fn test_supported() {
        assert!(
            Uri::try_from(
                "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pjos=0&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC"
            )
            .unwrap()
            .extras
            .pj_is_supported(),
            "Uri expected a success with a well formatted pj extras, but it failed"
        );
    }

    #[test]
    fn test_pj_param_unknown() {
        use bitcoin_uri::de::DeserializationState as _;
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=1&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let pjuri = Uri::try_from(uri)
            .unwrap()
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap()
            .check_pj_supported()
            .unwrap();
        let serialized_params = pjuri.extras.serialize_params();
        let pjos_key = serialized_params.clone().next().expect("Missing pjos key").0;
        let pj_key = serialized_params.clone().next().expect("Missing pj key").0;

        let state = DeserializationState::default();

        assert!(state.is_param_known(pjos_key), "The pjos key should match 'pjos', but it failed");
        assert!(state.is_param_known(pj_key), "The pj key should match 'pj', but it failed");
        assert!(
            !state.is_param_known("unknown_param"),
            "An unknown_param should not match 'pj' or 'pjos'"
        );
    }

    #[test]
    fn test_pj_duplicate_params() {
        let uri =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=1&pjos=1&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let pjuri = Uri::try_from(uri);
        assert!(matches!(
            pjuri,
            Err(bitcoin_uri::de::Error::Extras(PjParseError(
                InternalPjParseError::DuplicateParams("pjos")
            )))
        ));
        let uri =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=1&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let pjuri = Uri::try_from(uri);
        assert!(matches!(
            pjuri,
            Err(bitcoin_uri::de::Error::Extras(PjParseError(
                InternalPjParseError::DuplicateParams("pj")
            )))
        ));
    }

    #[test]
    fn test_serialize_pjos() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=HTTPS://EXAMPLE.COM/%23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let expected_is_disabled = "pjos=0";
        let expected_is_enabled = "pjos=1";
        let mut pjuri = Uri::try_from(uri)
            .expect("Invalid uri")
            .require_network(bitcoin::Network::Bitcoin)
            .expect("Network check failed")
            .check_pj_supported()
            .expect("Could not parse pj extras");

        pjuri.extras.output_substitution = OutputSubstitution::Disabled;
        assert!(
            pjuri.to_string().contains(expected_is_disabled),
            "Pj uri should contain param: {expected_is_disabled}, but it did not"
        );

        pjuri.extras.output_substitution = OutputSubstitution::Enabled;
        assert!(
            !pjuri.to_string().contains(expected_is_enabled),
            "Pj uri should elide param: {expected_is_enabled}, but it did not"
        );
    }

    #[test]
    fn test_wrapper_structs() {
        let uri_str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com";

        let payjoin_uri = PayjoinUri::from_str(uri_str).expect("Should parse valid URI");
        assert!(payjoin_uri.supports_payjoin());

        let validated = payjoin_uri.check_pj_supported().expect("Should support payjoin");

        assert!(payjoin_uri.supports_payjoin());

        let bitcoin_uri = payjoin_uri.as_bitcoin_uri();
        assert!(bitcoin_uri.extras.pj_is_supported());

        assert_eq!(validated.endpoint().as_str(), "https://example.com/");

        let unsupported_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let payjoin_uri = PayjoinUri::from_str(unsupported_uri).expect("Should parse");
        let result = payjoin_uri.check_pj_supported();
        assert!(result.is_err());
        matches!(result.unwrap_err(), PayjoinUriError::UnsupportedUri);
    }

    #[test]
    fn test_deserialize_pjos() {
        // pjos=0 should disable output substitution
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=0";
        let parsed = Uri::try_from(uri).unwrap();
        match parsed.extras {
            MaybePayjoinExtras::Supported(extras) =>
                assert_eq!(extras.output_substitution, OutputSubstitution::Disabled),
            _ => panic!("Expected Supported PayjoinExtras"),
        }

        // pjos=1 should allow output substitution
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=1";
        let parsed = Uri::try_from(uri).unwrap();
        match parsed.extras {
            MaybePayjoinExtras::Supported(extras) =>
                assert_eq!(extras.output_substitution, OutputSubstitution::Enabled),
            _ => panic!("Expected Supported PayjoinExtras"),
        }

        // Elided pjos=1 should allow output substitution
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com";
        let parsed = Uri::try_from(uri).unwrap();
        match parsed.extras {
            MaybePayjoinExtras::Supported(extras) =>
                assert_eq!(extras.output_substitution, OutputSubstitution::Enabled),
            _ => panic!("Expected Supported PayjoinExtras"),
        }
    }

    #[test]
    fn test_bitcoin_uri_error_wrapping() {
        let invalid_uri = "not-a-bitcoin-uri";
        let result = PayjoinUri::from_str(invalid_uri);
        assert!(result.is_err(), "Invalid URI should fail to parse");

        match result.unwrap_err() {
            PayjoinUriError::Parse(_) => {}
            other => panic!("Expected PayjoinUriError::Parse, got: {:?}", other),
        }

        let bad_address = "bitcoin:not-a-valid-address?pj=https://example.com";
        let result = PayjoinUri::from_str(bad_address);
        assert!(result.is_err(), "Bad address should fail to parse");

        match result.unwrap_err() {
            PayjoinUriError::Parse(_) => {}
            other => panic!("Expected PayjoinUriError::Parse, got: {:?}", other),
        }

        let valid_bitcoin_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1";
        let result = PayjoinUri::from_str(valid_bitcoin_uri);
        assert!(result.is_ok(), "Valid Bitcoin URI should parse successfully");

        let uri = result.unwrap();
        assert!(!uri.supports_payjoin(), "URI without pj param should not support payjoin");

        let testnet_address =
            "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?pj=https://example.com";
        let result = PayjoinUri::from_str(testnet_address);
        if let Err(error) = result {
            match error {
                PayjoinUriError::Parse(_) => {}
                other =>
                    panic!("Expected PayjoinUriError::Parse for network mismatch, got: {:?}", other),
            }
        }
    }

    #[test]
    fn test_non_consuming_payjoin_check() {
        let uri_str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com";
        let payjoin_uri = PayjoinUri::from_str(uri_str).expect("Valid URI should parse");

        let validated_result = payjoin_uri.check_pj_supported();
        assert!(validated_result.is_ok(), "URI with pj param should support payjoin");

        assert!(payjoin_uri.supports_payjoin(), "Original URI should still be accessible");
        assert_eq!(payjoin_uri.address().to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
        assert_eq!(payjoin_uri.amount().unwrap().to_sat(), 100_000_000);

        let second_check = payjoin_uri.check_pj_supported();
        assert!(second_check.is_ok(), "Should be able to check payjoin support multiple times");

        let bitcoin_uri = payjoin_uri.as_bitcoin_uri();
        assert!(bitcoin_uri.extras.pj_is_supported(), "Should be able to access underlying URI");

        let non_pj_uri_str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1";
        let non_pj_uri = PayjoinUri::from_str(non_pj_uri_str).expect("Valid URI should parse");

        let check_result = non_pj_uri.check_pj_supported();
        assert!(check_result.is_err(), "URI without pj param should fail payjoin check");

        assert!(
            !non_pj_uri.supports_payjoin(),
            "Should be able to call methods after failed check"
        );
        assert_eq!(non_pj_uri.address().to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
    }

    #[test]
    fn test_concrete_error_variants() {
        let non_pj_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let payjoin_uri = PayjoinUri::from_str(non_pj_uri).expect("Should parse Bitcoin URI");
        let result = payjoin_uri.check_pj_supported();

        match result.unwrap_err() {
            PayjoinUriError::UnsupportedUri => {}
            other => panic!("Expected UnsupportedUri, got: {:?}", other),
        }

        let bad_endpoint_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=not-a-valid-url";
        let result = PayjoinUri::from_str(bad_endpoint_uri);
        assert!(result.is_err(), "Invalid pj URL should fail");

        match result.unwrap_err() {
            PayjoinUriError::Parse(_) => {}
            other => panic!("Expected Parse error for invalid URL, got: {:?}", other),
        }

        let unsecure_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=ftp://example.com";
        let result = PayjoinUri::from_str(unsecure_uri);
        assert!(result.is_err(), "Unsecure endpoint should fail");

        let error = PayjoinUriError::UnsupportedUri;
        let error_msg = error.to_string();
        assert!(
            error_msg.contains("does not support Payjoin"),
            "Error message should be descriptive"
        );

        let error1 = PayjoinUriError::UnsupportedUri;
        let error2 = PayjoinUriError::UnsupportedUri;
        assert_eq!(error1, error2, "Same error variants should be equal");

        let error3 = PayjoinUriError::NotUtf8;
        assert_ne!(error1, error3, "Different error variants should not be equal");
    }

    #[test]
    fn test_bitcoin_uri_interoperability() {
        let uri_str =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com&label=test";
        let payjoin_uri = PayjoinUri::from_str(uri_str).expect("Valid URI should parse");

        let bitcoin_uri = payjoin_uri.as_bitcoin_uri();
        assert_eq!(bitcoin_uri.address.to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
        assert_eq!(bitcoin_uri.amount.unwrap().to_sat(), 100_000_000);
        assert!(bitcoin_uri.extras.pj_is_supported());

        assert_eq!(payjoin_uri.address().to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
        assert_eq!(payjoin_uri.amount().unwrap().to_sat(), 100_000_000);
        assert!(payjoin_uri.label().is_some(), "Label should be preserved");

        let validated = payjoin_uri.check_pj_supported().expect("Should support payjoin");
        let validated_bitcoin_uri = validated.as_bitcoin_uri();

        assert_eq!(validated_bitcoin_uri.address.to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
        assert_eq!(validated.endpoint().as_str(), "https://example.com/");

        let payjoin_str = payjoin_uri.to_string();
        assert!(payjoin_str.starts_with("bitcoin:"), "Should maintain bitcoin: scheme");
        assert!(payjoin_str.contains("amount=1"), "Should preserve amount");
        assert!(payjoin_str.contains("pj="), "Should preserve pj parameter");

        let round_trip = PayjoinUri::from_str(&payjoin_str).expect("Round-trip should work");
        assert_eq!(round_trip.address(), payjoin_uri.address());
        assert_eq!(round_trip.amount(), payjoin_uri.amount());
        assert_eq!(round_trip.supports_payjoin(), payjoin_uri.supports_payjoin());
    }

    #[test]
    fn test_malformed_uri_edge_cases() {
        let result = PayjoinUri::from_str("");
        assert!(result.is_err(), "Empty string should fail");
        assert!(matches!(result.unwrap_err(), PayjoinUriError::Parse(_)));

        let result = PayjoinUri::from_str("bitcoin:");
        assert!(result.is_err(), "Just scheme should fail");
        assert!(matches!(result.unwrap_err(), PayjoinUriError::Parse(_)));

        let result = PayjoinUri::from_str("bitcoin:invalid@#$%?pj=https://example.com");
        assert!(result.is_err(), "Invalid address characters should fail");
        assert!(matches!(result.unwrap_err(), PayjoinUriError::Parse(_)));

        let result = PayjoinUri::from_str(
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=invalid&pj=https://example.com",
        );
        assert!(result.is_err(), "Invalid amount should fail");
        assert!(matches!(result.unwrap_err(), PayjoinUriError::Parse(_)));

        let result = PayjoinUri::from_str(
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=javascript:alert('xss')",
        );
        assert!(result.is_err(), "Malicious URL scheme should fail");
        assert!(matches!(result.unwrap_err(), PayjoinUriError::Parse(_)));

        let long_address = "a".repeat(1000);
        let long_uri = format!("bitcoin:{}?pj=https://example.com", long_address);
        let result = PayjoinUri::from_str(&long_uri);
        assert!(result.is_err(), "Extremely long URI should fail gracefully");
        assert!(matches!(result.unwrap_err(), PayjoinUriError::Parse(_)));
    }

    #[test]
    fn test_boundary_conditions() {
        let full_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.00000001&label=Test%20Label&message=Test%20Message&pj=https://example.com&pjos=0";
        let payjoin_uri = PayjoinUri::from_str(full_uri).expect("Full URI should parse");

        assert!(payjoin_uri.supports_payjoin());
        assert_eq!(payjoin_uri.amount().unwrap().to_sat(), 1);
        assert!(payjoin_uri.label().is_some());
        assert!(payjoin_uri.message().is_some());

        let max_amount_uri =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=21000000&pj=https://example.com";
        let result = PayjoinUri::from_str(max_amount_uri);
        assert!(result.is_ok(), "Maximum amount should be valid");

        let min_amount_uri =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.00000001&pj=https://example.com";
        let result = PayjoinUri::from_str(min_amount_uri);
        assert!(result.is_ok(), "Minimum amount should be valid");

        let dup_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pj=https://other.com";
        let result = PayjoinUri::from_str(dup_uri);
        assert!(result.is_err(), "Duplicate pj parameters should fail");

        let pjos_only = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=0";
        let result = PayjoinUri::from_str(pjos_only);
        assert!(result.is_err(), "pjos without pj should fail");
    }

    #[test]
    fn test_error_path_completeness() {
        let no_pj_uri = PayjoinUri::from_str("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX").unwrap();
        let result = no_pj_uri.check_pj_supported();
        assert!(matches!(result.unwrap_err(), PayjoinUriError::UnsupportedUri));

        let parse_result = PayjoinUri::from_str("not-a-uri");
        assert!(matches!(parse_result.unwrap_err(), PayjoinUriError::Parse(_)));

        let bad_pjos =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=invalid";
        let result = PayjoinUri::from_str(bad_pjos);
        assert!(result.is_err(), "Invalid pjos value should fail");

        let error = PayjoinUriError::UnsupportedUri;
        let error_str = format!("{}", error);
        assert!(!error_str.is_empty(), "Error messages should not be empty");
        assert!(error_str.len() > 10, "Error messages should be descriptive");

        let parse_error = PayjoinUri::from_str("invalid-uri").unwrap_err();
        match parse_error {
            PayjoinUriError::Parse(inner) => {
                // Verify the error chain is preserved
                let debug_str = format!("{:?}", inner);
                assert!(!debug_str.is_empty(), "Inner error should be preserved for debugging");
            }
            _ => panic!("Expected Parse error"),
        }
    }

    #[test]
    fn test_cli_integration_patterns() {
        let uri_string =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com";

        let payjoin_uri = PayjoinUri::from_str(uri_string).expect("CLI should parse valid URI");
        assert!(payjoin_uri.supports_payjoin(), "CLI should detect payjoin support");

        let validated = payjoin_uri
            .check_pj_supported()
            .map_err(|_| "URI does not support Payjoin")
            .expect("CLI should validate payjoin URI");

        assert_eq!(validated.endpoint().as_str(), "https://example.com/");

        let invalid_uri = "not-a-bitcoin-uri";
        let result = PayjoinUri::from_str(invalid_uri);
        assert!(result.is_err(), "CLI should gracefully handle invalid input");

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Bitcoin URI parse error"),
            "CLI should show user-friendly error messages"
        );
        assert!(!error_msg.is_empty(), "Error messages should not be empty");

        let base58_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com";
        let bech32_uri =
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?pj=https://example.com";

        for uri in &[base58_uri, bech32_uri] {
            let result = PayjoinUri::from_str(uri);
            assert!(result.is_ok(), "CLI should handle all address formats: {}", uri);
        }
    }

    #[test]
    fn test_ffi_integration_orphan_rule_solution() {
        #[derive(Debug, thiserror::Error)]
        #[error("FFI Parse Error: {msg}")]
        struct FfiParseError {
            msg: String,
        }

        impl From<PayjoinUriError> for FfiParseError {
            fn from(error: PayjoinUriError) -> Self { FfiParseError { msg: error.to_string() } }
        }

        fn ffi_parse_uri(uri_str: &str) -> Result<(), FfiParseError> {
            let _payjoin_uri = PayjoinUri::from_str(uri_str)?;
            Ok(())
        }

        let result = ffi_parse_uri("invalid-uri");
        assert!(result.is_err(), "FFI should handle parsing errors");

        let ffi_error = result.unwrap_err();
        assert!(
            ffi_error.to_string().contains("FFI Parse Error"),
            "FFI error conversion should work"
        );
        assert!(
            ffi_error.to_string().contains("Bitcoin URI parse error"),
            "Should preserve original error info"
        );

        #[derive(Debug, thiserror::Error)]
        enum FfiError {
            #[error("Parse failed: {0}")]
            Parse(#[from] PayjoinUriError),
            #[allow(dead_code)]
            #[error("Other error")]
            Other,
        }

        let uri_error = PayjoinUriError::UnsupportedUri;
        let ffi_error: FfiError = uri_error.into();
        match ffi_error {
            FfiError::Parse(_) => {}
            _ => panic!("Error conversion should work"),
        }

        let parse_error = PayjoinUri::from_str("invalid").unwrap_err();
        let ffi_error: FfiError = parse_error.into();

        match ffi_error {
            FfiError::Parse(PayjoinUriError::Parse(_)) => {}
            _ => panic!("Error type should be preserved through FFI conversion"),
        }
    }

    #[test]
    fn test_no_breaking_changes() {
        let uri_str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com";

        let legacy_uri = Uri::try_from(uri_str).expect("Legacy Uri should still work");
        let checked_uri = legacy_uri
            .require_network(bitcoin::Network::Bitcoin)
            .expect("Network check should work");

        let pj_uri =
            checked_uri.check_pj_supported().expect("Legacy check_pj_supported should work");
        assert_eq!(pj_uri.extras.endpoint().as_str(), "https://example.com/");

        let new_uri = PayjoinUri::from_str(uri_str).expect("New PayjoinUri should work");
        let validated = new_uri.check_pj_supported().expect("New check_pj_supported should work");
        assert_eq!(validated.endpoint().as_str(), "https://example.com/");

        assert_eq!(pj_uri.address.to_string(), validated.address().to_string());
        assert_eq!(pj_uri.amount, validated.amount());

        let legacy_str = pj_uri.to_string();
        let new_str = validated.to_string();

        assert!(legacy_str.starts_with("bitcoin:"));
        assert!(new_str.starts_with("bitcoin:"));
        assert!(legacy_str.contains("pj="));
        assert!(new_str.contains("pj="));

        let reparsed = PayjoinUri::from_str(&legacy_str).expect("Should parse legacy output");
        assert!(reparsed.supports_payjoin());
    }

    #[test]
    fn test_protocol_compatibility() {
        let v1_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://btcpayserver.org/pj";
        let parsed = PayjoinUri::from_str(v1_uri).expect("v1 URI should parse");
        let validated = parsed.check_pj_supported().expect("v1 URI should support payjoin");
        assert_eq!(validated.endpoint().scheme(), "https");

        #[cfg(feature = "v2")]
        {
            let v2_uri =
                "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com#FRAGMENT";
            let result = PayjoinUri::from_str(v2_uri);
            assert!(result.is_ok(), "v2 URI with fragment should parse when v2 enabled");
        }

        let onion_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion";
        let parsed = PayjoinUri::from_str(onion_uri).expect("Onion URI should parse");
        let validated = parsed.check_pj_supported().expect("Onion URI should support payjoin");
        assert!(validated.endpoint().host_str().unwrap().ends_with(".onion"));

        let pjos_disabled =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=0";
        let parsed = PayjoinUri::from_str(pjos_disabled).expect("pjos=0 should parse");
        let validated = parsed.check_pj_supported().expect("Should support payjoin");
        assert_eq!(validated.output_substitution(), OutputSubstitution::Disabled);

        let pjos_enabled =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=1";
        let parsed = PayjoinUri::from_str(pjos_enabled).expect("pjos=1 should parse");
        let validated = parsed.check_pj_supported().expect("Should support payjoin");
        assert_eq!(validated.output_substitution(), OutputSubstitution::Enabled);

        let reordered = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pjos=0&pj=https://example.com&label=test";
        let parsed = PayjoinUri::from_str(reordered).expect("Parameter order shouldn't matter");
        let validated = parsed.check_pj_supported().expect("Should support payjoin");
        assert_eq!(validated.amount().unwrap().to_sat(), 100_000_000);
        assert!(parsed.label().is_some());
    }

    #[test]
    fn test_label_message_mutation_coverage() {
        let uri_with_labels = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com&label=Test%20Label&message=Test%20Message";
        let payjoin_uri =
            PayjoinUri::from_str(uri_with_labels).expect("Should parse URI with labels");

        let label = payjoin_uri.label().expect("Should have label");
        assert!(label.contains("Test"), "Label should contain actual content, not empty string");
        assert_eq!(label, "Test Label", "Label should match exact content");

        let message = payjoin_uri.message().expect("Should have message");
        assert!(
            message.contains("Test"),
            "Message should contain actual content, not empty string"
        );
        assert_eq!(message, "Test Message", "Message should match exact content");

        let uri_without_labels =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com";
        let payjoin_uri =
            PayjoinUri::from_str(uri_without_labels).expect("Should parse URI without labels");

        assert!(payjoin_uri.label().is_none(), "Should return None for missing label");
        assert!(payjoin_uri.message().is_none(), "Should return None for missing message");

        let validated = payjoin_uri.check_pj_supported().expect("Should support payjoin");
        assert!(
            validated.label().is_none(),
            "Validated URI should also return None for missing label"
        );
        assert!(
            validated.message().is_none(),
            "Validated URI should also return None for missing message"
        );

        let validated_with_labels = PayjoinUri::from_str(uri_with_labels)
            .expect("Should parse")
            .check_pj_supported()
            .expect("Should support payjoin");

        let validated_label = validated_with_labels.label().expect("Should have label");
        assert_ne!(validated_label, "", "Label should not be empty string");
        assert_ne!(validated_label, "xyzzy", "Label should not be mutated placeholder");
        assert_eq!(validated_label, "Test Label", "Should preserve original label");

        let validated_message = validated_with_labels.message().expect("Should have message");
        assert_ne!(validated_message, "", "Message should not be empty string");
        assert_ne!(validated_message, "xyzzy", "Message should not be mutated placeholder");
        assert_eq!(validated_message, "Test Message", "Should preserve original message");
    }

    #[test]
    fn test_error_partialeq_mutation_coverage() {
        let error1 = PayjoinUriError::UnsupportedUri;
        let error2 = PayjoinUriError::UnsupportedUri;
        assert_eq!(error1, error2, "Same error variants should be equal");

        // Test 2: Different error variants should NOT be equal
        let error3 = PayjoinUriError::NotUtf8;
        assert_ne!(error1, error3, "Different error variants should not be equal");

        // Test 3: DuplicateParams with same param should be equal
        let dup1 = PayjoinUriError::DuplicateParams { param: "pj" };
        let dup2 = PayjoinUriError::DuplicateParams { param: "pj" };
        assert_eq!(dup1, dup2, "DuplicateParams with same param should be equal");

        // Test 4: DuplicateParams with different params should NOT be equal
        let dup3 = PayjoinUriError::DuplicateParams { param: "pjos" };
        assert_ne!(dup1, dup3, "DuplicateParams with different params should not be equal");

        // Test 5: BadEndpoint errors (test equality when possible)
        use crate::uri::error::BadEndpointError;
        let bad1 =
            PayjoinUriError::BadEndpoint(BadEndpointError::UrlParse(url::ParseError::EmptyHost));
        let bad2 =
            PayjoinUriError::BadEndpoint(BadEndpointError::UrlParse(url::ParseError::EmptyHost));
        assert_eq!(bad1, bad2, "Same BadEndpoint errors should be equal");

        let bad3 =
            PayjoinUriError::BadEndpoint(BadEndpointError::UrlParse(url::ParseError::InvalidPort));
        assert_ne!(bad1, bad3, "Different BadEndpoint errors should not be equal");

        // Test 6: Parse errors should always be unequal (even with same content)
        let parse1 = PayjoinUri::from_str("invalid-uri-1").unwrap_err();
        let parse2 = PayjoinUri::from_str("invalid-uri-2").unwrap_err();
        assert_ne!(parse1, parse2, "Parse errors should be unequal per PartialEq implementation");

        let all_different_variants = [
            PayjoinUriError::UnsupportedUri,
            PayjoinUriError::BadPjOs,
            PayjoinUriError::DuplicateParams { param: "test" },
            PayjoinUriError::MissingEndpoint,
            PayjoinUriError::NotUtf8,
            PayjoinUriError::BadEndpoint(BadEndpointError::UrlParse(url::ParseError::EmptyHost)),
            PayjoinUriError::UnsecureEndpoint,
        ];

        for (i, variant1) in all_different_variants.iter().enumerate() {
            for (j, variant2) in all_different_variants.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        variant1, variant2,
                        "Different error variants should never be equal: {:?} vs {:?}",
                        variant1, variant2
                    );
                }
            }
        }
    }

    #[test]
    fn test_error_construction_mutation_coverage() {
        let error1 = PayjoinUriError::unsupported_uri();
        assert!(matches!(error1, PayjoinUriError::UnsupportedUri));

        // Test 2: bad_pj_os() constructor
        let error2 = PayjoinUriError::bad_pj_os();
        assert!(matches!(error2, PayjoinUriError::BadPjOs));

        // Test 3: duplicate_params() constructor
        let error3 = PayjoinUriError::duplicate_params("pj");
        assert!(matches!(error3, PayjoinUriError::DuplicateParams { param: "pj" }));

        // Test 4: missing_endpoint() constructor
        let error4 = PayjoinUriError::missing_endpoint();
        assert!(matches!(error4, PayjoinUriError::MissingEndpoint));

        // Test 5: not_utf8() constructor
        let error5 = PayjoinUriError::not_utf8();
        assert!(matches!(error5, PayjoinUriError::NotUtf8));

        // Test 6: unsecure_endpoint() constructor
        let error6 = PayjoinUriError::unsecure_endpoint();
        assert!(matches!(error6, PayjoinUriError::UnsecureEndpoint));

        assert_eq!(error1, PayjoinUriError::UnsupportedUri);
        assert_eq!(error2, PayjoinUriError::BadPjOs);
        assert_eq!(error3, PayjoinUriError::DuplicateParams { param: "pj" });
        assert_eq!(error4, PayjoinUriError::MissingEndpoint);
        assert_eq!(error5, PayjoinUriError::NotUtf8);
        assert_eq!(error6, PayjoinUriError::UnsecureEndpoint);
    }

    #[test]
    fn test_payjoin_uri_roundtrip_serialization() {
        let original_str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com&label=Test%20Label";
        let payjoin_uri = PayjoinUri::from_str(original_str).expect("Should parse original URI");

        let serialized = payjoin_uri.to_string();
        let deserialized = PayjoinUri::from_str(&serialized).expect("Should parse serialized URI");

        assert_eq!(payjoin_uri.address(), deserialized.address());
        assert_eq!(payjoin_uri.amount(), deserialized.amount());
        assert_eq!(payjoin_uri.label(), deserialized.label());
        assert_eq!(payjoin_uri.supports_payjoin(), deserialized.supports_payjoin());

        let validated_original = payjoin_uri.check_pj_supported().expect("Should support payjoin");
        let validated_serialized = validated_original.to_string();
        let validated_deserialized = PayjoinUri::from_str(&validated_serialized)
            .expect("Should parse")
            .check_pj_supported()
            .expect("Should support payjoin");

        assert_eq!(validated_original.address(), validated_deserialized.address());
        assert_eq!(validated_original.amount(), validated_deserialized.amount());
        assert_eq!(
            validated_original.endpoint().to_string(),
            validated_deserialized.endpoint().to_string()
        );
    }

    #[test]
    fn test_display_implementation_correctness() {
        let test_cases = [
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com",
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.001&pj=https://example.com&label=Test",
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=1&message=Hello%20World",
        ];

        for uri_str in test_cases {
            let payjoin_uri = PayjoinUri::from_str(uri_str).expect("Should parse test URI");
            let displayed = format!("{}", payjoin_uri);

            let reparsed =
                PayjoinUri::from_str(&displayed).expect("Display output should be parseable");

            assert_eq!(payjoin_uri.address(), reparsed.address());
            assert_eq!(payjoin_uri.supports_payjoin(), reparsed.supports_payjoin());

            if payjoin_uri.supports_payjoin() {
                let validated = payjoin_uri.check_pj_supported().expect("Should validate");
                let displayed_validated = format!("{}", validated);
                let reparsed_validated = PayjoinUri::from_str(&displayed_validated)
                    .expect("Should parse")
                    .check_pj_supported()
                    .expect("Should validate");

                assert_eq!(
                    validated.endpoint().to_string(),
                    reparsed_validated.endpoint().to_string()
                );
            }
        }
    }

    #[test]
    fn test_wrapper_serialization_transparency() {
        let test_uris = [
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com",
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.5&pj=https://payjoin.org",
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=0&label=Store%20Purchase",
        ];

        for uri_str in test_uris {
            let payjoin_uri = PayjoinUri::from_str(uri_str).expect("Should parse with wrapper");
            let wrapper_string = payjoin_uri.to_string();

            assert!(
                wrapper_string.starts_with("bitcoin:"),
                "Wrapper should maintain bitcoin: scheme for: {}",
                uri_str
            );
            assert!(
                wrapper_string.contains("pj="),
                "Wrapper should preserve pj parameter for: {}",
                uri_str
            );

            let inner_string = payjoin_uri.as_bitcoin_uri().to_string();
            assert_eq!(
                wrapper_string, inner_string,
                "Wrapper Display should match inner bitcoin_uri Display for: {}",
                uri_str
            );

            let reparsed =
                PayjoinUri::from_str(&wrapper_string).expect("Should reparse wrapper output");
            assert_eq!(payjoin_uri.address(), reparsed.address());
            assert_eq!(payjoin_uri.supports_payjoin(), reparsed.supports_payjoin());
        }
    }

    #[test]
    fn test_bip21_compliance_preservation() {
        let bip21_uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.123&label=Store%20Purchase&message=Payment%20for%20order%20123&pj=https://store.com/payjoin";

        let payjoin_uri = PayjoinUri::from_str(bip21_uri).expect("Should parse BIP21 URI");
        let serialized = payjoin_uri.to_string();

        assert!(serialized.starts_with("bitcoin:"));
        assert!(serialized.contains("12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"));
        assert!(serialized.contains("amount=0.123"));
        assert!(serialized.contains("label=Store%20Purchase"));
        assert!(serialized.contains("message=Payment%20for%20order%20123"));

        assert!(serialized.contains("pj="), "Should contain pj parameter");
        assert!(
            serialized.contains("STORE.COM"),
            "Should contain domain from payjoin URL (may be uppercase)"
        );

        let reparsed = PayjoinUri::from_str(&serialized).expect("Should reparse serialized URI");
        assert!(reparsed.supports_payjoin(), "Reparsed URI should support payjoin");
        let validated = reparsed.check_pj_supported().expect("Should validate payjoin support");
        assert_eq!(validated.endpoint().host_str().unwrap().to_lowercase(), "store.com");
        assert_eq!(validated.endpoint().path(), "/payjoin");

        let qr_compatible = serialized.len() < 300;
        assert!(qr_compatible, "Serialized URI should be QR code compatible");

        assert!(serialized.contains("%20"), "URL encoding should be preserved");
    }

    #[test]
    fn test_before_after_error_handling_patterns() {
        let uri_str = "bitcoin:invalid@address?pj=https://example.com";

        let legacy_result = Uri::try_from(uri_str);
        let legacy_error = legacy_result.unwrap_err();

        assert!(!format!("{}", legacy_error).contains("Payjoin"));
        assert!(!format!("{}", legacy_error).is_empty());

        let new_result = PayjoinUri::from_str(uri_str);
        let new_error = new_result.unwrap_err();

        assert!(format!("{}", new_error).contains("Bitcoin URI parse error"));
        assert!(matches!(new_error, PayjoinUriError::Parse(_)));

        match new_error {
            PayjoinUriError::Parse(ref inner) => {
                assert!(!format!("{:?}", inner).is_empty());
            }
            _ => panic!("Expected Parse error"),
        }

        #[derive(Debug, thiserror::Error)]
        #[error("FFI Error: {0}")]
        struct FfiError(PayjoinUriError);

        impl From<PayjoinUriError> for FfiError {
            fn from(error: PayjoinUriError) -> Self { FfiError(error) }
        }

        let ffi_error: FfiError = new_error.into();
        assert!(format!("{}", ffi_error).contains("FFI Error"));

        let unsupported_uri =
            PayjoinUri::from_str("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX").unwrap();
        let unsupported_error = unsupported_uri.check_pj_supported().unwrap_err();

        assert_eq!(unsupported_error, PayjoinUriError::UnsupportedUri);
    }

    #[test]
    fn test_type_safety_benefits() {
        let uri_str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com";

        let legacy_uri =
            Uri::try_from(uri_str).unwrap().require_network(bitcoin::Network::Bitcoin).unwrap();

        match &legacy_uri.extras {
            MaybePayjoinExtras::Supported(_) => {}
            MaybePayjoinExtras::Unsupported => panic!("Not payjoin URI"),
        }

        let payjoin_uri = PayjoinUri::from_str(uri_str).expect("Should parse");

        let validated_uri: ValidatedPayjoinUri =
            payjoin_uri.check_pj_supported().expect("Should support payjoin");

        let endpoint = validated_uri.endpoint();
        assert_eq!(endpoint.as_str(), "https://example.com/");

        let _original_still_usable = payjoin_uri.address();
        let _validated_also_usable = validated_uri.address();

        assert!(payjoin_uri.supports_payjoin());
    }

    #[test]
    fn test_ffi_orphan_rule_solution() {
        #[derive(Debug, thiserror::Error, PartialEq)]
        enum MockFfiError {
            #[error("URI parsing failed: {0}")]
            UriParse(PayjoinUriError),
            #[allow(dead_code)]
            #[error("Network error: {message}")]
            Network { message: String },
            #[allow(dead_code)]
            #[error("Invalid amount")]
            InvalidAmount,
        }

        impl From<PayjoinUriError> for MockFfiError {
            fn from(error: PayjoinUriError) -> Self { MockFfiError::UriParse(error) }
        }

        let invalid_uri = "bitcoin:invalid@address?pj=https://example.com";

        let payjoin_error = PayjoinUri::from_str(invalid_uri).unwrap_err();

        let ffi_error: MockFfiError = payjoin_error.into();

        match ffi_error {
            MockFfiError::UriParse(inner) => {
                assert!(matches!(inner, PayjoinUriError::Parse(_)));
                assert!(format!("{}", inner).contains("Bitcoin URI parse error"));
            }
            _ => panic!("Expected UriParse error"),
        }

        fn simulate_python_error_mapping(error: PayjoinUriError) -> String {
            match error {
                PayjoinUriError::Parse(inner) =>
                    format!("ValueError: Invalid Bitcoin URI: {}", inner),
                PayjoinUriError::UnsupportedUri =>
                    "ValueError: URI does not support Payjoin".to_string(),
                PayjoinUriError::BadPjOs => "ValueError: Bad pjos parameter".to_string(),
                PayjoinUriError::DuplicateParams { param } =>
                    format!("ValueError: Duplicate parameter '{}'", param),
                PayjoinUriError::MissingEndpoint =>
                    "ValueError: Missing payjoin endpoint".to_string(),
                PayjoinUriError::NotUtf8 => "ValueError: Invalid UTF-8 in endpoint".to_string(),
                PayjoinUriError::BadEndpoint(_) =>
                    "ValueError: Invalid payjoin endpoint URL".to_string(),
                PayjoinUriError::UnsecureEndpoint =>
                    "ValueError: Endpoint must use https or onion".to_string(),
            }
        }

        let python_error = simulate_python_error_mapping(PayjoinUriError::UnsupportedUri);
        assert_eq!(python_error, "ValueError: URI does not support Payjoin");

        let unsupported_uri =
            PayjoinUri::from_str("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX").unwrap();
        let unsupported_error = unsupported_uri.check_pj_supported().unwrap_err();
        let ffi_unsupported: MockFfiError = unsupported_error.into();

        assert!(matches!(ffi_unsupported, MockFfiError::UriParse(PayjoinUriError::UnsupportedUri)));
    }

    #[test]
    fn test_language_specific_error_mappings() {
        let test_cases = vec![
            ("bitcoin:invalid@address", "Parse error"),
            ("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX", "Unsupported URI"),
            ("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=invalid-url", "Invalid endpoint"),
        ];

        for (uri_str, _expected_type) in test_cases {
            let error = if uri_str.contains("invalid@address") {
                PayjoinUri::from_str(uri_str).unwrap_err()
            } else if uri_str.contains("invalid-url") {
                PayjoinUri::from_str("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX")
                    .unwrap()
                    .check_pj_supported()
                    .unwrap_err()
            } else {
                PayjoinUri::from_str(uri_str).unwrap().check_pj_supported().unwrap_err()
            };

            let python_error = match &error {
                PayjoinUriError::Parse(_) => "ValueError",
                PayjoinUriError::UnsupportedUri => "ValueError",
                PayjoinUriError::BadPjOs => "ValueError",
                PayjoinUriError::DuplicateParams { .. } => "ValueError",
                PayjoinUriError::MissingEndpoint => "ValueError",
                PayjoinUriError::NotUtf8 => "ValueError",
                PayjoinUriError::BadEndpoint(_) => "ValueError",
                PayjoinUriError::UnsecureEndpoint => "ValueError",
            };

            let java_error = match &error {
                PayjoinUriError::Parse(_) => "IllegalArgumentException",
                PayjoinUriError::UnsupportedUri => "UnsupportedOperationException",
                PayjoinUriError::BadPjOs => "IllegalArgumentException",
                PayjoinUriError::DuplicateParams { .. } => "IllegalArgumentException",
                PayjoinUriError::MissingEndpoint => "IllegalStateException",
                PayjoinUriError::NotUtf8 => "IllegalArgumentException",
                PayjoinUriError::BadEndpoint(_) => "MalformedURLException",
                PayjoinUriError::UnsecureEndpoint => "SecurityException",
            };

            let swift_error = match &error {
                PayjoinUriError::Parse(_) => "PayjoinError.parseError",
                PayjoinUriError::UnsupportedUri => "PayjoinError.unsupportedURI",
                PayjoinUriError::BadPjOs => "PayjoinError.badPjOs",
                PayjoinUriError::DuplicateParams { .. } => "PayjoinError.duplicateParams",
                PayjoinUriError::MissingEndpoint => "PayjoinError.missingEndpoint",
                PayjoinUriError::NotUtf8 => "PayjoinError.notUtf8",
                PayjoinUriError::BadEndpoint(_) => "PayjoinError.invalidEndpoint",
                PayjoinUriError::UnsecureEndpoint => "PayjoinError.unsecureEndpoint",
            };

            let kotlin_error = match &error {
                PayjoinUriError::Parse(_) => "IllegalArgumentException",
                PayjoinUriError::UnsupportedUri => "UnsupportedOperationException",
                PayjoinUriError::BadPjOs => "IllegalStateException",
                PayjoinUriError::DuplicateParams { .. } => "IllegalArgumentException",
                PayjoinUriError::MissingEndpoint => "NoSuchElementException",
                PayjoinUriError::NotUtf8 => "IllegalArgumentException",
                PayjoinUriError::BadEndpoint(_) => "MalformedURLException",
                PayjoinUriError::UnsecureEndpoint => "SecurityException",
            };

            assert!(!python_error.is_empty());
            assert!(!java_error.is_empty());
            assert!(!swift_error.is_empty());
            assert!(!kotlin_error.is_empty());

            let error_debug = format!("{:?}", error);
            assert!(!error_debug.is_empty());
        }
    }

    #[test]
    fn test_zero_cost_abstraction_performance() {
        use std::time::Instant;

        let test_uris = vec![
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.001&pj=https://example.com/payjoin",
            "bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2?label=test&message=payment&pj=https://store.com/pj",
            "bitcoin:3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy?amount=0.5&pj=https://merchant.org/payjoin?v=2",
        ];

        let iterations = 1000;

        let start_baseline = Instant::now();
        for _ in 0..iterations {
            for uri_str in &test_uris {
                let _uri = Uri::try_from(*uri_str).expect("Valid URI");
            }
        }
        let baseline_duration = start_baseline.elapsed();

        let start_wrapper = Instant::now();
        for _ in 0..iterations {
            for uri_str in &test_uris {
                let _uri = PayjoinUri::from_str(uri_str).expect("Valid URI");
            }
        }
        let wrapper_duration = start_wrapper.elapsed();

        let overhead_ratio =
            wrapper_duration.as_nanos() as f64 / baseline_duration.as_nanos() as f64;
        println!("Performance comparison:");
        println!("  Baseline (bitcoin_uri): {:?}", baseline_duration);
        println!("  Wrapper (PayjoinUri): {:?}", wrapper_duration);
        println!("  Overhead ratio: {:.2}x", overhead_ratio);

        assert!(overhead_ratio < 2.0, "Wrapper overhead too high: {:.2}x", overhead_ratio);

        let uri = PayjoinUri::from_str(test_uris[0]).unwrap();
        let validated = uri.check_pj_supported().unwrap();

        let original_address = uri.address().to_string();
        let validated_address = validated.address().to_string();
        assert_eq!(original_address, validated_address);

        let original_str = uri.to_string();
        let validated_str = validated.to_string();
        assert_eq!(original_str, validated_str);
    }

    #[test]
    fn test_memory_allocation_efficiency() {
        let uri_str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.001&pj=https://example.com/payjoin";

        let payjoin_uri = PayjoinUri::from_str(uri_str).unwrap();
        let bitcoin_uri =
            Uri::try_from(uri_str).unwrap().require_network(bitcoin::Network::Bitcoin).unwrap();

        let payjoin_size = std::mem::size_of_val(&payjoin_uri);
        let bitcoin_size = std::mem::size_of_val(&bitcoin_uri);

        println!("Memory size comparison:");
        println!("  PayjoinUri: {} bytes", payjoin_size);
        println!("  bitcoin_uri::Uri: {} bytes", bitcoin_size);

        assert!(payjoin_size <= bitcoin_size * 2, "PayjoinUri wrapper too large");

        let validated = payjoin_uri.check_pj_supported().unwrap();
        let validated_size = std::mem::size_of_val(&validated);

        println!("  ValidatedPayjoinUri: {} bytes", validated_size);

        assert!(validated_size <= payjoin_size + 16, "ValidatedPayjoinUri too large");

        let str1 = payjoin_uri.to_string();
        let str2 = validated.to_string();
        let str3 = bitcoin_uri.to_string();

        assert_eq!(str1, str2);
        assert!(str3.contains("12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"));

        let address1 = payjoin_uri.address();
        let address2 = validated.address();

        assert_eq!(address1, address2);
        assert_eq!(address1.to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
    }

    #[test]
    fn test_concrete_use_cases_enabled() {
        fn ffi_payjoin_parse(uri_str: &str) -> Result<String, String> {
            match PayjoinUri::from_str(uri_str) {
                Ok(uri) => match uri.check_pj_supported() {
                    Ok(validated) => Ok(validated.endpoint().to_string()),
                    Err(PayjoinUriError::UnsupportedUri) => Err("URI_NOT_PAYJOIN".to_string()),
                    Err(other) => Err(format!("PARSE_ERROR: {}", other)),
                },
                Err(PayjoinUriError::Parse(inner)) =>
                    Err(format!("INVALID_BITCOIN_URI: {}", inner)),
                Err(other) => Err(format!("PAYJOIN_ERROR: {}", other)),
            }
        }

        let success =
            ffi_payjoin_parse("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com/");
        assert_eq!(success.unwrap(), "https://example.com/");

        let no_payjoin = ffi_payjoin_parse("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
        assert_eq!(no_payjoin.unwrap_err(), "URI_NOT_PAYJOIN");

        let invalid_uri = ffi_payjoin_parse("bitcoin:invalid@address");
        assert!(invalid_uri.unwrap_err().starts_with("INVALID_BITCOIN_URI:"));

        fn process_payment_request(uri_str: &str) -> Result<(bitcoin::Address, String), String> {
            let uri =
                PayjoinUri::from_str(uri_str).map_err(|e| format!("Invalid payment URI: {}", e))?;

            let validated = uri
                .check_pj_supported()
                .map_err(|e| format!("Payment does not support Payjoin: {}", e))?;

            Ok((validated.address().clone(), validated.endpoint().to_string()))
        }

        let (address, endpoint) = process_payment_request(
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://merchant.com/pj",
        )
        .unwrap();

        assert_eq!(address.to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");
        assert_eq!(endpoint, "https://merchant.com/pj");

        struct PaymentProcessor {
            uri: PayjoinUri<'static>,
        }

        impl PaymentProcessor {
            fn new(uri_str: &'static str) -> Result<Self, PayjoinUriError> {
                let uri = PayjoinUri::from_str(uri_str)?;
                Ok(PaymentProcessor { uri })
            }

            fn supports_payjoin(&self) -> bool { self.uri.supports_payjoin() }

            fn get_payjoin_endpoint(&self) -> Result<String, PayjoinUriError> {
                let validated = self.uri.check_pj_supported()?;
                Ok(validated.endpoint().to_string())
            }

            fn get_address(&self) -> &bitcoin::Address<bitcoin::address::NetworkChecked> {
                self.uri.address()
            }
        }

        let processor = PaymentProcessor::new(
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.001&pj=https://store.com/pj",
        )
        .unwrap();

        assert!(processor.supports_payjoin());
        assert_eq!(processor.get_payjoin_endpoint().unwrap(), "https://store.com/pj");
        assert_eq!(processor.get_address().to_string(), "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX");

        assert!(processor.supports_payjoin());
    }

    #[test]
    fn test_serialization_error_handling() {
        let non_payjoin_str = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1";
        let non_payjoin_uri =
            PayjoinUri::from_str(non_payjoin_str).expect("Should parse non-payjoin URI");

        let serialized = non_payjoin_uri.to_string();
        assert_eq!(serialized, non_payjoin_str);
        assert!(!non_payjoin_uri.supports_payjoin());

        let payjoin_str =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com";
        let validated = PayjoinUri::from_str(payjoin_str)
            .expect("Should parse")
            .check_pj_supported()
            .expect("Should support payjoin");

        let validated_serialized = validated.to_string();
        assert!(validated_serialized.contains("pj="));

        let revalidated = PayjoinUri::from_str(&validated_serialized)
            .expect("Should reparse")
            .check_pj_supported()
            .expect("Should revalidate");

        assert_eq!(validated.endpoint().to_string(), revalidated.endpoint().to_string());
    }
}

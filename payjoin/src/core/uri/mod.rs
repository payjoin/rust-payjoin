//! Payjoin URI parsing and validation
use alloc::borrow::Cow;
use alloc::boxed::Box;
#[cfg(any(feature = "v1", feature = "v2-ohttp"))]
use alloc::fmt;
#[cfg(any(feature = "v1", feature = "v2-ohttp"))]
use alloc::string::{String, ToString};
#[cfg(all(feature = "std", any(feature = "v1", feature = "v2-ohttp")))]
use alloc::vec;
#[cfg(all(feature = "std", any(feature = "v1", feature = "v2-ohttp")))]
use alloc::vec::Vec;
use core::str::FromStr;

use bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bitcoin::{Address, Amount};
pub use error::{PjParseError, UriParseError};

#[cfg(feature = "v2-ohttp")]
pub(crate) use crate::directory::ShortId;
use crate::output_substitution::OutputSubstitution;
#[cfg(feature = "std")]
#[cfg(any(feature = "v1", feature = "v2-ohttp"))]
use crate::uri::error::InternalPjParseError;

mod error;
#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2-ohttp")]
pub mod v2;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
#[cfg_attr(feature = "v2", allow(clippy::large_enum_variant))]
pub enum PjParam {
    #[cfg(feature = "v1")]
    V1(v1::PjParam),
    #[cfg(feature = "v2-ohttp")]
    V2(v2::PjParam),
}

impl PjParam {
    #[cfg(any(feature = "v1", feature = "v2-ohttp"))]
    pub fn parse(endpoint: impl super::IntoUrl) -> Result<Self, PjParseError> {
        let endpoint = endpoint.into_url().map_err(InternalPjParseError::IntoUrl)?;

        #[cfg(feature = "v2-ohttp")]
        {
            match v2::PjParam::parse(endpoint.clone()) {
                Ok(v2) => return Ok(PjParam::V2(v2)),

                Err(v2::PjParseError::NotV2) => {}

                Err(v2::PjParseError::LowercaseFragment) => {
                    return Err(
                        InternalPjParseError::V2(v2::PjParseError::LowercaseFragment).into()
                    );
                }

                Err(e) => {
                    return Err(InternalPjParseError::V2(e).into());
                }
            }
        }

        #[cfg(feature = "v1")]
        return Ok(PjParam::V1(v1::PjParam::parse(endpoint)?));

        #[cfg(all(feature = "v2-ohttp", not(feature = "v1")))]
        return Err(InternalPjParseError::V2(v2::PjParseError::NotV2).into());

        #[cfg(all(not(feature = "v1"), not(feature = "v2")))]
        compile_error!("Either v1 or v2 feature must be enabled");
    }

    #[cfg(any(feature = "v1", feature = "v2-ohttp"))]
    pub fn endpoint(&self) -> String { self.endpoint_url().to_string() }

    #[cfg(any(feature = "v1", feature = "v2-ohttp"))]
    pub(crate) fn endpoint_url(&self) -> crate::core::Url {
        match self {
            #[cfg(feature = "v1")]
            PjParam::V1(url) => url.endpoint(),
            #[cfg(feature = "v2-ohttp")]
            PjParam::V2(url) => url.endpoint(),
        }
    }
}

#[cfg(any(feature = "v1", feature = "v2-ohttp"))]
impl fmt::Display for PjParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // normalizing to uppercase enables QR alphanumeric mode encoding
        // unfortunately Url normalizes these to be lowercase
        let endpoint = &self.endpoint_url();
        let scheme = endpoint.scheme();
        let host = endpoint.host_str();
        let endpoint_str = self
            .endpoint()
            .as_str()
            .replacen(scheme, &scheme.to_uppercase(), 1)
            .replacen(&host, &host.to_uppercase(), 1);
        write!(f, "{endpoint_str}")
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
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
    pub(crate) pj_param: PjParam,
    /// pjos parameter
    pub(crate) output_substitution: OutputSubstitution,
}

impl PayjoinExtras {
    pub fn pj_param(&self) -> &PjParam { &self.pj_param }

    #[cfg(any(feature = "v1", feature = "v2-ohttp"))]
    pub fn endpoint(&self) -> String { self.pj_param.endpoint() }

    pub fn output_substitution(&self) -> OutputSubstitution { self.output_substitution }
}

/// A BIP21 URI that may or may not request payjoin.
///
/// This newtype wraps [`bitcoin_uri::Uri`] so that a breaking change in that
/// crate does not force a breaking change in this crate's public API. Parse one
/// with [`Uri::try_from`] or [`str::parse`], validate the address network with
/// [`assume_checked`](Self::assume_checked) or
/// [`require_network`](Self::require_network), then check for payjoin support
/// with [`check_pj_supported`](Self::check_pj_supported).
///
/// The URI is always owned, so it carries no lifetime parameter.
#[derive(Clone, Debug)]
pub struct Uri<NetVal: NetworkValidation>(
    bitcoin_uri::Uri<'static, NetVal, MaybePayjoinExtrasAdapter>,
);

impl<NetVal: NetworkValidation> Uri<NetVal> {
    /// The address the URI pays to.
    pub fn address(&self) -> &Address<NetVal> { &self.0.address }

    /// The amount the URI requests, if any.
    pub fn amount(&self) -> Option<Amount> { self.0.amount }

    /// The label describing the URI, if present and valid UTF-8.
    pub fn label(&self) -> Option<String> {
        self.0.label.clone().and_then(|label| String::try_from(label).ok())
    }

    /// The message describing the URI, if present and valid UTF-8.
    pub fn message(&self) -> Option<String> {
        self.0.message.clone().and_then(|message| String::try_from(message).ok())
    }

    /// The payjoin parameters carried by the URI.
    pub fn extras(&self) -> &MaybePayjoinExtras { &self.0.extras.0 }
}

impl Uri<NetworkUnchecked> {
    /// Marks the URI's address as validated without checking the network.
    pub fn assume_checked(self) -> Uri<NetworkChecked> { Uri(self.0.assume_checked()) }

    /// Validates that the URI's address is valid for the given network.
    pub fn require_network(
        self,
        network: bitcoin::Network,
    ) -> Result<Uri<NetworkChecked>, UriParseError> {
        self.0.require_network(network).map(Uri).map_err(UriParseError::from_bip21_error)
    }
}

impl Uri<NetworkChecked> {
    /// Converts this URI into a [`PjUri`] if it supports payjoin.
    ///
    /// If payjoin is unsupported the URI is handed back unchanged in the error
    /// variant. It is boxed to reduce the size of the `Result` (see
    /// <https://rust-lang.github.io/rust-clippy/master/index.html#result_large_err>).
    #[cfg(feature = "std")]
    pub fn check_pj_supported(self) -> Result<PjUri, Box<Self>> {
        match self.0.extras.0 {
            MaybePayjoinExtras::Supported(payjoin) => {
                let mut uri =
                    bitcoin_uri::Uri::with_extras(self.0.address, PayjoinExtrasAdapter(payjoin));
                uri.amount = self.0.amount;
                uri.label = self.0.label;
                uri.message = self.0.message;
                Ok(PjUri(uri))
            }
            MaybePayjoinExtras::Unsupported => {
                let mut uri = bitcoin_uri::Uri::with_extras(
                    self.0.address,
                    MaybePayjoinExtrasAdapter(MaybePayjoinExtras::Unsupported),
                );
                uri.amount = self.0.amount;
                uri.label = self.0.label;
                uri.message = self.0.message;
                Err(Box::new(Uri(uri)))
            }
        }
    }
}

impl FromStr for Uri<NetworkUnchecked> {
    type Err = UriParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri: bitcoin_uri::Uri<'static, NetworkUnchecked, MaybePayjoinExtrasAdapter> =
            s.parse().map_err(UriParseError::from_bip21_error)?;
        Ok(Uri(uri))
    }
}

impl TryFrom<&str> for Uri<NetworkUnchecked> {
    type Error = UriParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> { s.parse() }
}

impl TryFrom<String> for Uri<NetworkUnchecked> {
    type Error = UriParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> { s.parse() }
}

impl fmt::Display for Uri<NetworkChecked> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}

/// A BIP21 URI that is known to request payjoin, with validated payjoin parameters.
///
/// Obtained from [`Uri::check_pj_supported`]. Like [`Uri`], this newtype
/// insulates the public API from [`bitcoin_uri`] and is always owned.
#[derive(Clone, Debug)]
pub struct PjUri(bitcoin_uri::Uri<'static, NetworkChecked, PayjoinExtrasAdapter>);

impl PjUri {
    /// Builds a payjoin URI from a checked address and validated payjoin parameters.
    pub(crate) fn from_extras(address: Address<NetworkChecked>, extras: PayjoinExtras) -> Self {
        PjUri(bitcoin_uri::Uri::with_extras(address, PayjoinExtrasAdapter(extras)))
    }

    /// The address the URI pays to.
    pub fn address(&self) -> &Address<NetworkChecked> { &self.0.address }

    /// The amount the URI requests, if any.
    pub fn amount(&self) -> Option<Amount> { self.0.amount }

    /// Sets the amount the URI requests.
    pub fn set_amount(&mut self, amount: Amount) { self.0.amount = Some(amount); }

    /// The label describing the URI, if present and valid UTF-8.
    pub fn label(&self) -> Option<String> {
        self.0.label.clone().and_then(|label| String::try_from(label).ok())
    }

    /// The message describing the URI, if present and valid UTF-8.
    pub fn message(&self) -> Option<String> {
        self.0.message.clone().and_then(|message| String::try_from(message).ok())
    }

    /// The validated payjoin parameters carried by the URI.
    pub fn extras(&self) -> &PayjoinExtras { &self.0.extras.0 }
}

impl fmt::Display for PjUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}

/// Private adapter that carries the `bitcoin_uri` parsing and serialization
/// trait impls, keeping them off the public [`MaybePayjoinExtras`] type so that
/// `bitcoin_uri` stays out of this crate's semver surface.
#[derive(Clone, Debug)]
pub(crate) struct MaybePayjoinExtrasAdapter(pub(crate) MaybePayjoinExtras);

/// Private adapter that carries the `bitcoin_uri` serialization trait impl for
/// [`PayjoinExtras`], keeping it off the public type.
#[derive(Clone, Debug)]
pub(crate) struct PayjoinExtrasAdapter(pub(crate) PayjoinExtras);

/// Serializes the payjoin BIP21 query parameters (`pj` and optional `pjos`).
fn serialize_payjoin_params(extras: &PayjoinExtras) -> Vec<(&'static str, String)> {
    let mut params = Vec::with_capacity(2);
    if extras.output_substitution == OutputSubstitution::Disabled {
        params.push(("pjos", String::from("0")));
    }
    params.push(("pj", extras.pj_param.to_string()));
    params
}

#[cfg(any(feature = "v1", feature = "v2-ohttp"))]
impl bitcoin_uri::de::DeserializationError for MaybePayjoinExtrasAdapter {
    type Error = PjParseError;
}

#[cfg(any(feature = "v1", feature = "v2-ohttp"))]
impl bitcoin_uri::de::DeserializeParams<'_> for MaybePayjoinExtrasAdapter {
    type DeserializationState = DeserializationState;
}

#[derive(Default)]
#[allow(dead_code)]
pub(crate) struct DeserializationState {
    pj: Option<PjParam>,
    pjos: Option<OutputSubstitution>,
}

#[cfg(feature = "v2-ohttp")]
impl bitcoin_uri::SerializeParams for &MaybePayjoinExtrasAdapter {
    type Key = &'static str;
    type Value = String;
    type Iterator = alloc::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator {
        match &self.0 {
            MaybePayjoinExtras::Supported(extras) => serialize_payjoin_params(extras).into_iter(),
            MaybePayjoinExtras::Unsupported => Vec::new().into_iter(),
        }
    }
}

#[cfg(any(feature = "v1", feature = "v2-ohttp"))]
impl bitcoin_uri::SerializeParams for &PayjoinExtrasAdapter {
    type Key = &'static str;
    type Value = String;
    type Iterator = vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator { serialize_payjoin_params(&self.0).into_iter() }
}

#[cfg(all(feature = "std", any(feature = "v1", feature = "v2-ohttp")))]
impl bitcoin_uri::de::DeserializationState<'_> for DeserializationState {
    type Value = MaybePayjoinExtrasAdapter;

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
                let pj_param = PjParam::parse(endpoint.as_ref())?;
                self.pj = Some(pj_param);

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
        let extras = match (self.pj, self.pjos) {
            (None, None) => MaybePayjoinExtras::Unsupported,
            (None, Some(_)) => return Err(InternalPjParseError::MissingEndpoint.into()),
            (Some(pj_param), pjos) => MaybePayjoinExtras::Supported(PayjoinExtras {
                pj_param,
                output_substitution: pjos.unwrap_or(OutputSubstitution::Enabled),
            }),
        };
        Ok(MaybePayjoinExtrasAdapter(extras))
    }
}

#[cfg(all(test, feature = "v1"))]
pub(crate) fn pj_uri(uri: &str) -> PjUri {
    Uri::try_from(uri)
        .expect("uri should parse")
        .assume_checked()
        .check_pj_supported()
        .expect("uri should support payjoin")
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    #[cfg(all(feature = "std", feature = "v1"))]
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
    #[cfg(feature = "v1")]
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
    #[cfg(feature = "v1")]
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
        assert!(
            !Uri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX")
                .unwrap()
                .extras()
                .pj_is_supported(),
            "Uri expected a failure with missing pj extras, but it succeeded"
        );
    }

    #[test]
    #[cfg(feature = "v1")]
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
    #[cfg(feature = "v1")]
    fn test_pj_param_unknown() {
        use bitcoin_uri::de::DeserializationState as _;
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=1&pj=HTTPS://EXAMPLE.COM/TXJCGKTKXLUUZ%23EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";
        let pjuri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        let serialized_params = serialize_payjoin_params(pjuri.extras());
        let pj_key = serialized_params.first().expect("Missing pj key").0;

        let state = DeserializationState::default();

        assert!(state.is_param_known("pjos"), "The pjos key should match 'pjos', but it failed");
        assert!(state.is_param_known(pj_key), "The pj key should match 'pj', but it failed");
        assert!(
            !state.is_param_known("unknown_param"),
            "An unknown_param should not match 'pj' or 'pjos'"
        );
    }

    #[test]
    #[cfg(feature = "v1")]
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
    #[cfg(feature = "v1")]
    fn test_serialize_pjos() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=HTTPS://EXAMPLE.COM/%23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let expected_is_disabled = "pjos=0";
        let expected_is_enabled = "pjos=1";
        let mut pjuri = Uri::try_from(uri)
            .expect("Invalid uri")
            .assume_checked()
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
    #[cfg(feature = "v1")]
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

    /// Test that rejects HTTP URLs that are not onion addresses
    #[cfg(feature = "v1")]
    #[test]
    fn test_http_non_onion_rejected() {
        // HTTP to regular domain should be rejected
        let url = "http://example.com";
        let result = PjParam::parse(url);
        assert!(matches!(result, Err(PjParseError(_))));

        // HTTPS to subdomain should be accepted
        let url = "https://example.com";
        let result = PjParam::parse(url);
        assert!(
            matches!(result, Ok(PjParam::V1(_))),
            "Expected PjParam::V1 for HTTPS to non-onion domain without fragment"
        );

        // HTTP to domain ending in .onion should be accepted
        let url = "http://example.onion";
        let result = PjParam::parse(url);
        assert!(
            matches!(result, Ok(PjParam::V1(_))),
            "Expected PjParam::V1 for HTTP to onion domain without fragment"
        );
    }
}

//! Payjoin URI parsing and validation

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use bitcoin::address::{NetworkChecked, NetworkUnchecked, NetworkValidation};
use bitcoin::{Address, Amount};
pub use error::{PjParseError, UriParseError};

#[cfg(feature = "v2")]
pub(crate) use crate::directory::ShortId;
use crate::output_substitution::OutputSubstitution;
use crate::uri::error::InternalPjParseError;

mod error;
#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
#[cfg_attr(feature = "v2", allow(clippy::large_enum_variant))]
pub enum PjParam {
    #[cfg(feature = "v1")]
    V1(v1::PjParam),
    #[cfg(feature = "v2")]
    V2(v2::PjParam),
}

impl PjParam {
    pub fn parse(endpoint: impl super::IntoUrl) -> Result<Self, PjParseError> {
        let endpoint = endpoint.into_url().map_err(InternalPjParseError::IntoUrl)?;

        #[cfg(feature = "v2")]
        match v2::PjParam::parse(endpoint.clone()) {
            Err(v2::PjParseError::NotV2) => (), // continue
            Ok(v2) => return Ok(PjParam::V2(v2)),
            Err(e) => return Err(InternalPjParseError::V2(e).into()),
        }

        #[cfg(feature = "v1")]
        return Ok(PjParam::V1(v1::PjParam::parse(endpoint)?));

        #[cfg(all(not(feature = "v1"), feature = "v2"))]
        return Err(InternalPjParseError::V2(v2::PjParseError::NotV2).into());

        #[cfg(all(not(feature = "v1"), not(feature = "v2")))]
        compile_error!("Either v1 or v2 feature must be enabled");
    }

    pub fn endpoint(&self) -> String { self.endpoint_url().to_string() }

    pub(crate) fn endpoint_url(&self) -> crate::core::Url {
        match self {
            #[cfg(feature = "v1")]
            PjParam::V1(url) => url.endpoint(),
            #[cfg(feature = "v2")]
            PjParam::V2(url) => url.endpoint(),
        }
    }
}

impl std::fmt::Display for PjParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

    /// Overrides the output substitution preference carried by the URI.
    #[cfg(test)]
    pub(crate) fn set_output_substitution(&mut self, output_substitution: OutputSubstitution) {
        self.0.extras.0.output_substitution = output_substitution;
    }
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

impl bitcoin_uri::de::DeserializationError for MaybePayjoinExtrasAdapter {
    type Error = PjParseError;
}

impl bitcoin_uri::de::DeserializeParams<'_> for MaybePayjoinExtrasAdapter {
    type DeserializationState = DeserializationState;
}

#[derive(Default)]
pub(crate) struct DeserializationState {
    pj: Option<PjParam>,
    pjos: Option<OutputSubstitution>,
}

impl bitcoin_uri::SerializeParams for &MaybePayjoinExtrasAdapter {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator {
        match &self.0 {
            MaybePayjoinExtras::Supported(extras) => serialize_payjoin_params(extras).into_iter(),
            MaybePayjoinExtras::Unsupported => Vec::new().into_iter(),
        }
    }
}

impl bitcoin_uri::SerializeParams for &PayjoinExtrasAdapter {
    type Key = &'static str;
    type Value = String;
    type Iterator = std::vec::IntoIter<(Self::Key, Self::Value)>;

    fn serialize_params(self) -> Self::Iterator { serialize_payjoin_params(&self.0).into_iter() }
}

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
    fn test_unencrypted() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=http://example.com";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");

        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=ftp://foo.onion";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");
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
}

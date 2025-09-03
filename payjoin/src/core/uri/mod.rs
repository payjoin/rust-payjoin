//! Payjoin URI parsing and validation

use std::borrow::Cow;

use bitcoin::address::NetworkChecked;
pub use error::PjParseError;

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

    pub(crate) fn endpoint_url(&self) -> url::Url {
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
        let host = endpoint.host_str().expect("host must be set");
        let endpoint_str = self
            .endpoint()
            .as_str()
            .replacen(scheme, &scheme.to_uppercase(), 1)
            .replacen(host, &host.to_uppercase(), 1);
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

pub type Uri<'a, NetworkValidation> = bitcoin_uri::Uri<'a, NetworkValidation, MaybePayjoinExtras>;
pub type PjUri<'a> = bitcoin_uri::Uri<'a, NetworkChecked, PayjoinExtras>;

mod sealed {
    use bitcoin::address::NetworkChecked;

    pub trait UriExt: Sized {}

    impl UriExt for super::Uri<'_, NetworkChecked> {}
    impl UriExt for super::PjUri<'_> {}
}

pub trait UriExt<'a>: sealed::UriExt {
    // Error type is boxed to reduce the size of the Result
    // (See https://rust-lang.github.io/rust-clippy/master/index.html#result_large_err)
    fn check_pj_supported(self) -> Result<PjUri<'a>, Box<bitcoin_uri::Uri<'a>>>;
}

impl<'a> UriExt<'a> for Uri<'a, NetworkChecked> {
    fn check_pj_supported(self) -> Result<PjUri<'a>, Box<bitcoin_uri::Uri<'a>>> {
        match self.extras {
            MaybePayjoinExtras::Supported(payjoin) => {
                let mut uri = bitcoin_uri::Uri::with_extras(self.address, payjoin);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Ok(uri)
            }
            MaybePayjoinExtras::Unsupported => {
                let mut uri = bitcoin_uri::Uri::new(self.address);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Err(Box::new(uri))
            }
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
    pj: Option<PjParam>,
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
        let mut params = Vec::with_capacity(2);
        if self.output_substitution == OutputSubstitution::Disabled {
            params.push(("pjos", String::from("0")));
        }
        params.push(("pj", self.pj_param.to_string()));
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
        match (self.pj, self.pjos) {
            (None, None) => Ok(MaybePayjoinExtras::Unsupported),
            (None, Some(_)) => Err(InternalPjParseError::MissingEndpoint.into()),
            (Some(pj_param), pjos) => Ok(MaybePayjoinExtras::Supported(PayjoinExtras {
                pj_param,
                output_substitution: pjos.unwrap_or(OutputSubstitution::Enabled),
            })),
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
                .extras
                .pj_is_supported(),
            "Uri expected a failure with missing pj extras, but it succeeded"
        );
    }

    #[test]
    fn test_pj_param_unknown() {
        use bitcoin_uri::de::DeserializationState as _;
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=1&pj=HTTPS://EXAMPLE.COM/TXJCGKTKXLUUZ%23EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";
        let pjuri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
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
}

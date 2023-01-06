use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};

use url::Url;

#[cfg(feature = "sender")]
use crate::sender;

#[derive(Debug, Clone)]
pub enum PayJoin {
    Supported(PayJoinParams),
    Unsupported,
}

impl PayJoin {
    pub fn pj_is_supported(&self) -> bool {
        match self {
            PayJoin::Supported(_) => true,
            PayJoin::Unsupported => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PayJoinParams {
    pub(crate) endpoint: Url,
    pub(crate) disable_output_substitution: bool,
}

pub type Uri<'a> = bip21::Uri<'a, PayJoin>;
pub type PjUri<'a> = bip21::Uri<'a, PayJoinParams>;

mod sealed {
    pub trait UriExt: Sized {}

    impl<'a> UriExt for super::Uri<'a> {}
    impl<'a> UriExt for super::PjUri<'a> {}
}

pub trait PjUriExt: sealed::UriExt {
    #[cfg(feature = "sender")]
    fn create_pj_request(
        self,
        psbt: bitcoin::util::psbt::PartiallySignedTransaction,
        params: sender::Params,
    ) -> Result<(sender::Request, sender::Context), sender::CreateRequestError>;
}

pub trait UriExt<'a>: sealed::UriExt {
    fn check_pj_supported(self) -> Result<PjUri<'a>, bip21::Uri<'a>>;
}

impl<'a> PjUriExt for PjUri<'a> {
    #[cfg(feature = "sender")]
    fn create_pj_request(
        self,
        psbt: bitcoin::util::psbt::PartiallySignedTransaction,
        params: sender::Params,
    ) -> Result<(sender::Request, sender::Context), sender::CreateRequestError> {
        sender::from_psbt_and_uri(
            psbt.try_into()
                .map_err(sender::InternalCreateRequestError::InconsistentOriginalPsbt)?,
            self,
            params,
        )
    }
}

impl<'a> UriExt<'a> for Uri<'a> {
    fn check_pj_supported(self) -> Result<PjUri<'a>, bip21::Uri<'a>> {
        match self.extras {
            PayJoin::Supported(payjoin) => {
                let mut uri = bip21::Uri::with_extras(self.address, payjoin);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Ok(uri)
            }
            PayJoin::Unsupported => {
                let mut uri = bip21::Uri::new(self.address);
                uri.amount = self.amount;
                uri.label = self.label;
                uri.message = self.message;

                Err(uri)
            }
        }
    }
}

impl PayJoinParams {
    pub fn is_output_substitution_disabled(&self) -> bool { self.disable_output_substitution }
}

impl bip21::de::DeserializationError for PayJoin {
    type Error = PjParseError;
}

impl<'a> bip21::de::DeserializeParams<'a> for PayJoin {
    type DeserializationState = DeserializationState;
}

#[derive(Default)]
pub struct DeserializationState {
    pj: Option<Url>,
    pjos: Option<bool>,
}

#[derive(Debug)]
pub struct PjParseError(InternalPjParseError);

impl From<InternalPjParseError> for PjParseError {
    fn from(value: InternalPjParseError) -> Self { PjParseError(value) }
}

impl<'a> bip21::de::DeserializationState<'a> for DeserializationState {
    type Value = PayJoin;

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

    fn finalize(
        self,
    ) -> std::result::Result<Self::Value, <Self::Value as bip21::DeserializationError>::Error> {
        match (self.pj, self.pjos) {
            (None, None) => Ok(PayJoin::Unsupported),
            (None, Some(_)) => Err(PjParseError(InternalPjParseError::MissingEndpoint)),
            (Some(endpoint), pjos) => {
                if endpoint.scheme() == "https"
                    || endpoint.scheme() == "http"
                        && endpoint.domain().unwrap_or_default().ends_with(".onion")
                {
                    Ok(PayJoin::Supported(PayJoinParams {
                        endpoint,
                        disable_output_substitution: pjos.unwrap_or(false),
                    }))
                } else {
                    Err(PjParseError(InternalPjParseError::UnsecureEndpoint))
                }
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
    BadEndpoint(url::ParseError),
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
}

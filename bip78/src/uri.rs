use std::borrow::Cow;
use std::convert::TryFrom;
#[cfg(feature = "sender")]
use crate::sender;
#[cfg(feature = "sender")]
use std::convert::TryInto;

#[derive(Debug, Eq, PartialEq)]
pub struct Uri<'a> {
    pub(crate) address: bitcoin::Address,
    pub(crate) amount: Option<bitcoin::Amount>,
    pub(crate) endpoint: Cow<'a, str>,
    pub(crate) disable_output_substitution: bool,
}

impl<'a> Uri<'a> {
    pub fn address(&self) -> &bitcoin::Address {
        &self.address
    }

    pub fn amount(&self) -> Option<bitcoin::Amount> {
        self.amount
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.disable_output_substitution
    }

    #[cfg(feature = "sender")]
    pub fn create_request(
        self,
        psbt: bitcoin::util::psbt::PartiallySignedTransaction,
        params: sender::Params,
    ) -> Result<(sender::Request, sender::Context), sender::CreateRequestError> {
        sender::from_psbt_and_uri(psbt.try_into().map_err(sender::InternalCreateRequestError::InconsistentOriginalPsbt)?, self, params)
    }

    pub fn into_static(self) -> Uri<'static> {
        Uri {
            address: self.address,
            amount: self.amount,
            endpoint: Cow::Owned(self.endpoint.into()),
            disable_output_substitution: self.disable_output_substitution,
        }
    }
}

impl<'a> TryFrom<&'a str> for Uri<'a> {
    type Error = ParseUriError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        fn match_kv<'a, T, E: Into<ParseUriError>, F: FnOnce(&'a str) -> Result<T, E>>(kv: &'a str, prefix: &'static str, out: &mut Option<T>, fun: F) -> Result<(), ParseUriError> where ParseUriError: From<E> {
            if kv.starts_with(prefix) {
                let value = fun(&kv[prefix.len()..])?;
                if out.is_some() {
                    return Err(InternalBip21Error::DuplicateKey(prefix).into());
                }
                *out = Some(value);
            }
            Ok(())
        }

        let prefix = "bitcoin:";
        if !s.chars().zip(prefix.chars()).all(|(left, right)| left.to_ascii_lowercase() == right) || s.len() < 8 {
            return Err(InternalBip21Error::BadSchema(s.into()).into())
        }
        let uri_without_prefix = &s[prefix.len()..];
        let question_mark_pos = uri_without_prefix.find('?').ok_or(ParseUriError::PjNotPresent)?;
        let address = uri_without_prefix[..question_mark_pos].parse().map_err(InternalBip21Error::Address)?;
        let mut amount = None;
        let mut endpoint = None;
        let mut disable_pjos = None;

        for kv in uri_without_prefix[(question_mark_pos + 1)..].split('&') {
            match_kv(kv, "amount=", &mut amount, |s| bitcoin::Amount::from_str_in(s, bitcoin::Denomination::Bitcoin).map_err(InternalBip21Error::Amount))?;
            match_kv(kv, "pjos=", &mut disable_pjos, |s| if s == "0" { Ok(true) } else if s == "1" { Ok(false) } else { Err(InternalPjParseError::BadPjos(s.into())) })?;
            match_kv(kv, "pj=", &mut endpoint, |s| if s.starts_with("https://") || s.starts_with("http://") { Ok(s) } else { Err(InternalPjParseError::BadSchema(s.into())) })?;
        }

        match (amount, endpoint, disable_pjos) {
            (_, None, None) => Err(ParseUriError::PjNotPresent),
            (amount @ _, Some(endpoint), disable_pjos) => Ok(Uri { address, amount, endpoint: endpoint.into(), disable_output_substitution: disable_pjos.unwrap_or(false), }),
            (None, None, Some(_)) => Err(ParseUriError::PayJoin(PjParseError(InternalPjParseError::MissingAmountAndEndpoint))),
            (Some(_), None, Some(_)) => Err(ParseUriError::PayJoin(PjParseError(InternalPjParseError::MissingEndpoint))),
        }
    }
}

impl std::str::FromStr for Uri<'static> {
    type Err = ParseUriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uri::try_from(s).map(Uri::into_static)
    }
}

#[derive(Debug)]
pub enum ParseUriError {
    PjNotPresent,
    Bip21(Bip21Error),
    PayJoin(PjParseError),
}

#[derive(Debug)]
pub struct Bip21Error(InternalBip21Error);

#[derive(Debug)]
pub struct PjParseError(InternalPjParseError);

#[derive(Debug)]
enum InternalBip21Error {
    Amount(bitcoin::util::amount::ParseAmountError),
    DuplicateKey(&'static str),
    BadSchema(String),
    Address(bitcoin::util::address::Error),
}

#[derive(Debug)]
enum InternalPjParseError {
    BadPjos(String),
    BadSchema(String),
    MissingAmount,
    MissingAmountAndEndpoint,
    MissingEndpoint,
}

impl From<Bip21Error> for ParseUriError {
    fn from(value: Bip21Error) -> Self {
        ParseUriError::Bip21(value)
    }
}

impl From<PjParseError> for ParseUriError {
    fn from(value: PjParseError) -> Self {
        ParseUriError::PayJoin(value)
    }
}

impl From<InternalBip21Error> for ParseUriError {
    fn from(value: InternalBip21Error) -> Self {
        Bip21Error(value).into()
    }
}

impl From<InternalPjParseError> for ParseUriError {
    fn from(value: InternalPjParseError) -> Self {
        PjParseError(value).into()
    }
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::util;
    use crate::bitcoin::util::amount::ParseAmountError;
    use crate::uri::{InternalBip21Error, InternalPjParseError, Bip21Error};
    use crate::{ParseUriError, Uri};
    use assert_matches::assert_matches;
    use std::str::FromStr;

    #[test]
    fn test_short() {
        assert!(Uri::from_str("").is_err());
        assert!(Uri::from_str("bitcoin").is_err());
        assert!(Uri::from_str("bitcoin:").is_err());
    }

    #[ignore]
    #[test]
    fn test_todo_url_encoded() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
        assert!(Uri::from_str(uri).is_err(), "pj url should be url encoded");
    }

    #[ignore]
    #[test]
    fn test_todo_valid_url() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=http://a";
        assert!(Uri::from_str(uri).is_err(), "pj is not a valid url");
    }

    #[test]
    fn test_missing_amount() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
        assert!(Uri::from_str(uri).is_ok(), "missing amount should be ok");
    }

    #[ignore]
    #[test]
    fn test_todo_unencrypted() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=http://example.com";
        assert!(Uri::from_str(uri).is_err(), "unencrypted connection");
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
                assert!(Uri::from_str(&uri).is_ok());
            }
        }
    }

    #[test]
    fn test_errors() {
        assert_matches!(
            Uri::from_str("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX").unwrap_err(),
            ParseUriError::PjNotPresent
        );

        let bitcoinz = "bitcoinz:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let bitcoi = "bitcoi:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        for schema in [bitcoinz, bitcoi].iter() {
            let uri = Uri::from_str(schema).unwrap_err();
            let bad_schema = ParseUriError::from(InternalBip21Error::BadSchema(schema.to_string()));
            assert_matches!(uri, bad_schema);
        }

        let uri = "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=20.3&label=Luke-Jr";
        assert_matches!(Uri::from_str(uri).unwrap_err(), ParseUriError::Bip21(Bip21Error(InternalBip21Error::Address(_))));

        let err = ParseUriError::from(InternalBip21Error::Amount(ParseAmountError::InvalidFormat));
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&amount=";
        assert_matches!(Uri::from_str(uri).unwrap_err(), err);

        let invalid_char = ParseAmountError::InvalidCharacter('B');
        let err = ParseUriError::from(InternalBip21Error::Amount(invalid_char));
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&amount=1BTC";
        assert_matches!(Uri::from_str(uri).unwrap_err(), err);

        let err = ParseUriError::from(InternalBip21Error::Amount(ParseAmountError::TooBig));
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&amount=9999999999999999999";
        assert_matches!(Uri::from_str(uri).unwrap_err(), err);
    }

}

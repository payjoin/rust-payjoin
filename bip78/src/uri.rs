use std::borrow::Cow;
use std::convert::TryFrom;
#[cfg(feature = "sender")]
use crate::sender;

pub struct Uri<'a> {
    pub(crate) address: bitcoin::Address,
    pub(crate) amount: bitcoin::Amount,
    pub(crate) endpoint: Cow<'a, str>,
    pub(crate) disable_output_substitution: bool,
}

impl<'a> Uri<'a> {
    pub fn address(&self) -> &bitcoin::Address {
        &self.address
    }

    pub fn amount(&self) -> bitcoin::Amount {
        self.amount
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.disable_output_substitution
    }

    #[cfg(feature = "sender")]
    pub fn create_request(self, psbt: bitcoin::util::psbt::PartiallySignedTransaction, params: sender::Params) -> Result<(sender::Request, sender::Context), sender::CreateRequestError> {
        sender::from_psbt_and_uri(psbt, self, params)
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
        if !s.chars().zip(prefix.chars()).all(|(left, right)| left.to_ascii_lowercase() == right) {
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
            (Some(amount), Some(endpoint), disable_pjos) => Ok(Uri { address, amount, endpoint: endpoint.into(), disable_output_substitution: disable_pjos.unwrap_or(false), }),
            (None, Some(_), _) => Err(ParseUriError::PayJoin(PjParseError(InternalPjParseError::MissingAmount))),
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

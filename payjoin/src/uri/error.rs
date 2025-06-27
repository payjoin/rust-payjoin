use std::error::Error;

use thiserror::Error;
use url::ParseError;

#[derive(Debug, Clone)]
pub struct PjParseError(pub(crate) InternalPjParseError);

#[derive(Debug, Clone)]
pub(crate) enum InternalPjParseError {
    BadPjOs,
    DuplicateParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    BadEndpoint(BadEndpointError),
    UnsecureEndpoint,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BadEndpointError {
    #[error("Invalid URL: {0}")]
    UrlParse(#[from] ParseError),
    #[cfg(feature = "v2")]
    #[error("URL fragment contains lowercase characters")]
    LowercaseFragment,
}

impl From<InternalPjParseError> for PjParseError {
    fn from(value: InternalPjParseError) -> Self { PjParseError(value) }
}

impl std::fmt::Display for PjParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InternalPjParseError::*;
        match &self.0 {
            BadPjOs => write!(f, "Bad pjos parameter"),
            DuplicateParams(param) => {
                write!(f, "Multiple instances of parameter '{param}'")
            }
            MissingEndpoint => write!(f, "Missing payjoin endpoint"),
            NotUtf8 => write!(f, "Endpoint is not valid UTF-8"),
            BadEndpoint(e) => write!(f, "Endpoint is not valid: {e:?}"),
            UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
        }
    }
}

impl Error for PjParseError {}

#[derive(Debug, Error)]
pub enum PayjoinUriError {
    #[error("Bitcoin URI parse error: {0}")]
    Parse(bitcoin_uri::de::Error<PjParseError>),

    #[error("URI does not support Payjoin (missing 'pj' parameter)")]
    UnsupportedUri,

    #[error("Invalid pjos parameter")]
    BadPjOs,

    #[error("Duplicate parameter '{param}' in URI")]
    DuplicateParams { param: &'static str },

    #[error("Missing payjoin endpoint")]
    MissingEndpoint,

    #[error("Parameter contains invalid UTF-8")]
    NotUtf8,

    #[error("Invalid payjoin endpoint: {0}")]
    BadEndpoint(BadEndpointError),

    #[error("Endpoint scheme is not secure (must be https or onion)")]
    UnsecureEndpoint,
}

impl PartialEq for PayjoinUriError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PayjoinUriError::Parse(_), PayjoinUriError::Parse(_)) => false,
            (PayjoinUriError::UnsupportedUri, PayjoinUriError::UnsupportedUri) => true,
            (PayjoinUriError::BadPjOs, PayjoinUriError::BadPjOs) => true,
            (
                PayjoinUriError::DuplicateParams { param: a },
                PayjoinUriError::DuplicateParams { param: b },
            ) => a == b,
            (PayjoinUriError::MissingEndpoint, PayjoinUriError::MissingEndpoint) => true,
            (PayjoinUriError::NotUtf8, PayjoinUriError::NotUtf8) => true,
            (PayjoinUriError::BadEndpoint(a), PayjoinUriError::BadEndpoint(b)) => a == b,
            (PayjoinUriError::UnsecureEndpoint, PayjoinUriError::UnsecureEndpoint) => true,
            _ => false,
        }
    }
}

impl Eq for PayjoinUriError {}

impl PayjoinUriError {
    pub fn unsupported_uri() -> Self { PayjoinUriError::UnsupportedUri }

    pub fn bad_pj_os() -> Self { PayjoinUriError::BadPjOs }

    pub fn duplicate_params(param: &'static str) -> Self {
        PayjoinUriError::DuplicateParams { param }
    }

    pub fn missing_endpoint() -> Self { PayjoinUriError::MissingEndpoint }

    pub fn not_utf8() -> Self { PayjoinUriError::NotUtf8 }

    pub fn unsecure_endpoint() -> Self { PayjoinUriError::UnsecureEndpoint }
}

impl From<bitcoin_uri::de::Error<PjParseError>> for PayjoinUriError {
    fn from(error: bitcoin_uri::de::Error<PjParseError>) -> Self { PayjoinUriError::Parse(error) }
}

impl From<InternalPjParseError> for PayjoinUriError {
    fn from(error: InternalPjParseError) -> Self {
        match error {
            InternalPjParseError::BadPjOs => PayjoinUriError::BadPjOs,
            InternalPjParseError::DuplicateParams(param) =>
                PayjoinUriError::DuplicateParams { param },
            InternalPjParseError::MissingEndpoint => PayjoinUriError::MissingEndpoint,
            InternalPjParseError::NotUtf8 => PayjoinUriError::NotUtf8,
            InternalPjParseError::BadEndpoint(e) => PayjoinUriError::BadEndpoint(e),
            InternalPjParseError::UnsecureEndpoint => PayjoinUriError::UnsecureEndpoint,
        }
    }
}

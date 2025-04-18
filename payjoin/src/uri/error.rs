use std::error::Error;
use std::fmt;
use url::ParseError;

#[derive(Debug)]
pub struct PjParseError(InternalPjParseError);

#[derive(Debug)]
pub(crate) enum InternalPjParseError {
    BadPjOs,
    DuplicateParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    BadEndpoint(BadEndpointError),
    UnsecureEndpoint,
}

#[derive(Debug)]
pub enum BadEndpointError {
    UrlParse(ParseError),
    #[cfg(feature = "v2")]
    LowercaseFragment,
}

impl std::fmt::Display for BadEndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BadEndpointError::UrlParse(e) => write!(f, "Invalid URL: {:?}", e),
            #[cfg(feature = "v2")]
            BadEndpointError::LowercaseFragment => {
                write!(f, "Some or all of the fragment is lowercase")
            }
        }
    }
}

impl From<InternalPjParseError> for PjParseError {
    fn from(value: InternalPjParseError) -> Self {
        PjParseError(value)
    }
}

impl std::fmt::Display for PjParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InternalPjParseError::*;
        match &self.0 {
            BadPjOs => write!(f, "Bad pjos parameter"),
            DuplicateParams(param) => {
                write!(f, "Multiple instances of parameter '{}'", param)
            }
            MissingEndpoint => write!(f, "Missing payjoin endpoint"),
            NotUtf8 => write!(f, "Endpoint is not valid UTF-8"),
            BadEndpoint(e) => write!(f, "Endpoint is not valid: {:?}", e),
            UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
        }
    }
}

impl Error for PjParseError {}

#[derive(Debug)]
pub struct PayjoinUriError {
    message: String,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl PayjoinUriError {
    pub fn new<S: Into<String>>(message: S) -> Self {
        Self { message: message.into(), source: None }
    }

    pub fn from_uri_error(error: bitcoin_uri::de::Error<PjParseError>) -> Self {
        Self { message: format!("Bitcoin URI error: {}", error), source: None }
    }

    pub fn unsupported_uri() -> Self {
        Self::new("URI does not support Payjoin (missing 'pj' parameter)")
    }
}

impl fmt::Display for PayjoinUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Payjoin URI error: {}", self.message)
    }
}

impl Error for PayjoinUriError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn Error + 'static))
    }
}

impl From<bitcoin_uri::de::Error<PjParseError>> for PayjoinUriError {
    fn from(error: bitcoin_uri::de::Error<PjParseError>) -> Self {
        Self::from_uri_error(error)
    }
}

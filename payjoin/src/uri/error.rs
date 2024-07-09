#[cfg(feature = "v2")]
use crate::v2::ParseOhttpKeysError;

#[derive(Debug)]
pub struct PjParseError(InternalPjParseError);

#[derive(Debug)]
pub(crate) enum InternalPjParseError {
    BadPjOs,
    DuplicateParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    BadEndpoint,
    #[cfg(feature = "v2")]
    BadOhttpKeys(ParseOhttpKeysError),
    UnsecureEndpoint,
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
                write!(f, "Multiple instances of parameter '{}'", param)
            }
            MissingEndpoint => write!(f, "Missing payjoin endpoint"),
            NotUtf8 => write!(f, "Endpoint is not valid UTF-8"),
            BadEndpoint => write!(f, "Endpoint is not valid"),
            #[cfg(feature = "v2")]
            BadOhttpKeys(e) => write!(f, "OHTTP keys are not valid: {}", e),
            UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
        }
    }
}

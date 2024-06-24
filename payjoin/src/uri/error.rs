#[cfg(feature = "v2")]
use crate::uri::OhttpKeysParseError;

#[derive(Debug)]
pub struct PjParseError(InternalPjParseError);

#[derive(Debug)]
pub(crate) enum InternalPjParseError {
    BadPjOs,
    MultipleParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    BadEndpoint,
    #[cfg(feature = "v2")]
    ParseOhttpKeys(OhttpKeysParseError),
    UnsecureEndpoint,
}

impl From<InternalPjParseError> for PjParseError {
    fn from(value: InternalPjParseError) -> Self { PjParseError(value) }
}

impl std::fmt::Display for PjParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            InternalPjParseError::BadPjOs => write!(f, "Bad pjos parameter"),
            InternalPjParseError::MultipleParams(param) => {
                write!(f, "Multiple instances of parameter '{}'", param)
            }
            InternalPjParseError::MissingEndpoint => write!(f, "Missing payjoin endpoint"),
            InternalPjParseError::NotUtf8 => write!(f, "Endpoint is not valid UTF-8"),
            InternalPjParseError::BadEndpoint => write!(f, "Endpoint is not valid"),
            #[cfg(feature = "v2")]
            InternalPjParseError::ParseOhttpKeys(e) => write!(f, "OHTTP Keys are not valid: {}", e),
            InternalPjParseError::UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
        }
    }
}

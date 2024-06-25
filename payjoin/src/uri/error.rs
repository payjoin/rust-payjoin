#[derive(Debug)]
pub struct PjParseError(InternalPjParseError);

#[derive(Debug)]
pub(crate) enum InternalPjParseError {
    BadPjOs,
    MultipleParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    BadEndpoint,
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
            InternalPjParseError::UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
        }
    }
}

#[cfg(feature = "v2")]
#[derive(Debug)]
pub(crate) enum SubdirParseError {
    MissingSubdirectory,
    SubdirectoryNotBase64(bitcoin::base64::DecodeError),
    SubdirectoryInvalidPubkey(bitcoin::secp256k1::Error),
}

#[cfg(feature = "v2")]
impl std::fmt::Display for SubdirParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use SubdirParseError::*;

        match &self {
            MissingSubdirectory => write!(f, "subdirectory is missing"),
            SubdirectoryNotBase64(e) => write!(f, "subdirectory is not valid base64 error: {}", e),
            SubdirectoryInvalidPubkey(e) =>
                write!(f, "subdirectory does not represent a valid pubkey: {}", e),
        }
    }
}

#[cfg(feature = "v2")]
impl std::error::Error for SubdirParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SubdirParseError::*;

        match &self {
            MissingSubdirectory => None,
            SubdirectoryNotBase64(error) => Some(error),
            SubdirectoryInvalidPubkey(error) => Some(error),
        }
    }
}

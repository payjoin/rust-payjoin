#[derive(Debug)]
pub struct PjParseError(InternalPjParseError);

#[derive(Debug)]
pub(crate) enum InternalPjParseError {
    BadPjOs,
    DuplicateParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    BadEndpoint,
    UnsecureEndpoint,
}

#[cfg(feature = "v2")]
#[derive(Debug)]
pub(crate) enum ParseReceiverPubkeyError {
    MissingPubkey,
    PubkeyNotBase64(bitcoin::base64::DecodeError),
    InvalidPubkey(crate::hpke::HpkeError),
}

#[cfg(feature = "v2")]
impl std::fmt::Display for ParseReceiverPubkeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ParseReceiverPubkeyError::*;

        match &self {
            MissingPubkey => write!(f, "receiver public key is missing"),
            PubkeyNotBase64(e) => write!(f, "receiver public is not valid base64: {}", e),
            InvalidPubkey(e) =>
                write!(f, "receiver public key does not represent a valid pubkey: {}", e),
        }
    }
}

#[cfg(feature = "v2")]
impl std::error::Error for ParseReceiverPubkeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseReceiverPubkeyError::*;

        match &self {
            MissingPubkey => None,
            PubkeyNotBase64(error) => Some(error),
            InvalidPubkey(error) => Some(error),
        }
    }
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
            UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
        }
    }
}

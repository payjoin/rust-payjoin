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
pub(crate) enum ParseOhttpKeysParamError {
    MissingOhttpKeys,
    InvalidOhttpKeys(crate::ohttp::ParseOhttpKeysError),
}

#[cfg(feature = "v2")]
impl std::fmt::Display for ParseOhttpKeysParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseOhttpKeysParamError::*;

        match &self {
            MissingOhttpKeys => write!(f, "ohttp keys are missing"),
            InvalidOhttpKeys(o) => write!(f, "invalid ohttp keys: {}", o),
        }
    }
}

#[cfg(feature = "v2")]
#[derive(Debug)]
pub(crate) enum ParseReceiverPubkeyParamError {
    MissingPubkey,
    InvalidHrp(bitcoin::bech32::Hrp),
    DecodeBech32(bitcoin::bech32::primitives::decode::CheckedHrpstringError),
    InvalidPubkey(crate::hpke::HpkeError),
}

#[cfg(feature = "v2")]
impl std::fmt::Display for ParseReceiverPubkeyParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ParseReceiverPubkeyParamError::*;

        match &self {
            MissingPubkey => write!(f, "receiver public key is missing"),
            InvalidHrp(h) => write!(f, "incorrect hrp for receiver key: {}", h),
            DecodeBech32(e) => write!(f, "receiver public is not valid base64: {}", e),
            InvalidPubkey(e) =>
                write!(f, "receiver public key does not represent a valid pubkey: {}", e),
        }
    }
}

#[cfg(feature = "v2")]
impl std::error::Error for ParseReceiverPubkeyParamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseReceiverPubkeyParamError::*;

        match &self {
            MissingPubkey => None,
            InvalidHrp(_) => None,
            DecodeBech32(error) => Some(error),
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

use core::fmt;

use crate::uri::url_ext::ParseReceiverPubkeyParamError;

/// Error returned when request could not be created.
///
/// This error can currently only happen due to programmer mistake.
/// `unwrap()`ing it is thus considered OK in Rust but you may achieve nicer message by displaying
/// it.
#[derive(Debug)]
pub struct CreateRequestError(InternalCreateRequestError);

#[derive(Debug)]
pub(crate) enum InternalCreateRequestError {
    Url(url::ParseError),
    Hpke(crate::hpke::HpkeError),
    OhttpEncapsulation(crate::ohttp::OhttpEncapsulationError),
    ParseReceiverPubkey(ParseReceiverPubkeyParamError),
    MissingOhttpConfig,
    Expired(std::time::SystemTime),
}

impl fmt::Display for CreateRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalCreateRequestError::*;

        match &self.0 {
            Url(e) => write!(f, "cannot parse url: {:#?}", e),
            Hpke(e) => write!(f, "v2 error: {}", e),
            OhttpEncapsulation(e) => write!(f, "v2 error: {}", e),
            ParseReceiverPubkey(e) => write!(f, "cannot parse receiver public key: {}", e),
            MissingOhttpConfig =>
                write!(f, "no ohttp configuration with which to make a v2 request available"),
            Expired(expiry) => write!(f, "session expired at {:?}", expiry),
        }
    }
}

impl std::error::Error for CreateRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalCreateRequestError::*;

        match &self.0 {
            Url(error) => Some(error),
            Hpke(error) => Some(error),
            OhttpEncapsulation(error) => Some(error),
            ParseReceiverPubkey(error) => Some(error),
            MissingOhttpConfig => None,
            Expired(_) => None,
        }
    }
}

impl From<InternalCreateRequestError> for CreateRequestError {
    fn from(value: InternalCreateRequestError) -> Self { CreateRequestError(value) }
}

impl From<ParseReceiverPubkeyParamError> for CreateRequestError {
    fn from(value: ParseReceiverPubkeyParamError) -> Self {
        CreateRequestError(InternalCreateRequestError::ParseReceiverPubkey(value))
    }
}

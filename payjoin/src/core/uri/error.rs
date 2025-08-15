#[derive(Debug)]
pub struct PjParseError(pub(crate) InternalPjParseError);

#[derive(Debug)]
pub(crate) enum InternalPjParseError {
    BadPjOs,
    DuplicateParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    IntoUrl(crate::into_url::Error),
    #[cfg(feature = "v1")]
    UnsecureEndpoint,
    #[cfg(feature = "v2")]
    V2(super::v2::PjParseError),
}

impl From<InternalPjParseError> for PjParseError {
    fn from(value: InternalPjParseError) -> Self { PjParseError(value) }
}

impl std::error::Error for PjParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalPjParseError::*;
        match &self.0 {
            BadPjOs => None,
            DuplicateParams(_) => None,
            MissingEndpoint => None,
            NotUtf8 => None,
            IntoUrl(e) => Some(e),
            #[cfg(feature = "v1")]
            UnsecureEndpoint => None,
            #[cfg(feature = "v2")]
            V2(e) => Some(e),
        }
    }
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
            IntoUrl(e) => write!(f, "Endpoint is not valid: {e:?}"),
            #[cfg(feature = "v1")]
            UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
            #[cfg(feature = "v2")]
            V2(e) => write!(f, "Invalid v2 parameter: {e:?}"),
        }
    }
}

#[derive(Debug)]
pub struct PjParseError(pub(crate) InternalPjParseError);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InternalPjParseError {
    BadPjOs,
    DuplicateParams(&'static str),
    MissingEndpoint,
    NotUtf8,
    BadEndpoint(BadEndpointError),
    UnsecureEndpoint,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BadEndpointError {
    IntoUrl(crate::into_url::Error),
    #[cfg(feature = "v2")]
    LowercaseFragment,
}

impl std::error::Error for BadEndpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BadEndpointError::IntoUrl(e) => Some(e),
            #[cfg(feature = "v2")]
            BadEndpointError::LowercaseFragment => None,
        }
    }
}

impl std::fmt::Display for BadEndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BadEndpointError::IntoUrl(e) => write!(f, "Invalid URL: {e:?}"),
            #[cfg(feature = "v2")]
            BadEndpointError::LowercaseFragment =>
                write!(f, "Some or all of the fragment is lowercase"),
        }
    }
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
            BadEndpoint(e) => Some(e),
            UnsecureEndpoint => None,
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
            BadEndpoint(e) => write!(f, "Endpoint is not valid: {e:?}"),
            UnsecureEndpoint => {
                write!(f, "Endpoint scheme is not secure (https or onion)")
            }
        }
    }
}

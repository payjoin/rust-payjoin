#[derive(Debug)]
pub struct PjParseError(pub(super) InternalPjParseError);

/// Error parsing a BIP21 URI into a payjoin [`Uri`](super::Uri).
///
/// This wraps the underlying `bitcoin_uri` errors so that a breaking change in
/// that crate does not force a breaking change in this crate's public API.
#[derive(Debug)]
pub struct UriParseError(InternalUriParseError);

#[derive(Debug)]
enum InternalUriParseError {
    /// The BIP21 URI itself (address, amount, or standard parameters) is invalid.
    ///
    /// The foreign error is held in a private variant so that it does not appear
    /// in the public API, while preserving the `source()` chain.
    Bip21(bitcoin_uri::Error),
    /// The address does not belong to the requested network.
    Network(bitcoin_uri::NetworkError),
    /// The URI carries no on-chain address, which payjoin requires.
    MissingAddress,
    /// The URI has a `req-` parameter this crate does not understand, so
    /// BIP 321 requires rejecting it. Holds the full key, prefix included.
    UnsatisfiedRequirement(String),
    /// The payjoin parameters are invalid.
    PayjoinParams(PjParseError),
}

impl UriParseError {
    /// Erases a `bitcoin_uri` parse error into this opaque type.
    ///
    /// These are inherent constructors rather than `From` impls so that
    /// `bitcoin_uri` types stay out of the public API.
    pub(super) fn from_bip21(e: bitcoin_uri::Error) -> Self {
        UriParseError(InternalUriParseError::Bip21(e))
    }

    pub(super) fn from_network(e: bitcoin_uri::NetworkError) -> Self {
        UriParseError(InternalUriParseError::Network(e))
    }

    pub(super) fn missing_address() -> Self { UriParseError(InternalUriParseError::MissingAddress) }

    pub(super) fn unsatisfied_requirement(key: String) -> Self {
        UriParseError(InternalUriParseError::UnsatisfiedRequirement(key))
    }

    /// The payjoin parameter parse error, if parsing failed because the payjoin
    /// parameters were invalid.
    #[cfg(test)]
    pub(crate) fn payjoin_params(&self) -> Option<&PjParseError> {
        match &self.0 {
            InternalUriParseError::PayjoinParams(e) => Some(e),
            _ => None,
        }
    }
}

impl From<PjParseError> for UriParseError {
    fn from(e: PjParseError) -> Self { UriParseError(InternalUriParseError::PayjoinParams(e)) }
}

impl std::fmt::Display for UriParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            InternalUriParseError::Bip21(e) => write!(f, "Invalid BIP21 URI: {e}"),
            InternalUriParseError::Network(e) => write!(f, "Invalid network: {e}"),
            InternalUriParseError::MissingAddress => write!(f, "BIP21 URI has no on-chain address"),
            InternalUriParseError::UnsatisfiedRequirement(key) => {
                write!(f, "BIP21 URI requires unsupported parameter '{key}'")
            }
            InternalUriParseError::PayjoinParams(e) => write!(f, "Invalid payjoin parameters: {e}"),
        }
    }
}

impl std::error::Error for UriParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalUriParseError::Bip21(e) => Some(e),
            InternalUriParseError::Network(e) => Some(e),
            InternalUriParseError::MissingAddress => None,
            InternalUriParseError::UnsatisfiedRequirement(_) => None,
            InternalUriParseError::PayjoinParams(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub(super) enum InternalPjParseError {
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

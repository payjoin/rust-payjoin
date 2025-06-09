use std::fmt;

#[cfg(feature = "v2")]
use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::ImplementationError;
use sled::Error as SledError;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub(crate) enum Error {
    Sled(SledError),
    #[cfg(feature = "v2")]
    Serialize(serde_json::Error),
    #[cfg(feature = "v2")]
    Deserialize(serde_json::Error),
    #[cfg(feature = "v2")]
    NotFound(String),
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::Sled(_), Error::Sled(_)) => true,
            #[cfg(feature = "v2")]
            (Error::Serialize(_), Error::Serialize(_)) => true,
            #[cfg(feature = "v2")]
            (Error::Deserialize(_), Error::Deserialize(_)) => true,
            #[cfg(feature = "v2")]
            (Error::NotFound(s1), Error::NotFound(s2)) => s1 == s2,
            _ => false,
        }
    }
}

impl Eq for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Sled(e) => write!(f, "Database operation failed: {e}"),
            #[cfg(feature = "v2")]
            Error::Serialize(e) => write!(f, "Serialization failed: {e}"),
            #[cfg(feature = "v2")]
            Error::Deserialize(e) => write!(f, "Deserialization failed: {e}"),
            #[cfg(feature = "v2")]
            Error::NotFound(key) => write!(f, "Key not found: {key}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<SledError> for Error {
    fn from(error: SledError) -> Self { Error::Sled(error) }
}

impl From<Error> for ImplementationError {
    fn from(error: Error) -> Self { ImplementationError::new(error) }
}

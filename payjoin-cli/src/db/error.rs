use std::fmt;

#[cfg(feature = "v2")]
use bitcoincore_rpc::jsonrpc::serde_json;
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
    #[cfg(feature = "v2")]
    TryFromSlice(std::array::TryFromSliceError),
}

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
            #[cfg(feature = "v2")]
            Error::TryFromSlice(e) => write!(f, "TryFromSlice failed: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<SledError> for Error {
    fn from(error: SledError) -> Self { Error::Sled(error) }
}

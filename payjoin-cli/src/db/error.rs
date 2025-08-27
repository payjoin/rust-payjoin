use std::fmt;

use payjoin::ImplementationError;
use r2d2::Error as R2d2Error;
use rusqlite::Error as RusqliteError;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub(crate) enum Error {
    Rusqlite(RusqliteError),
    R2d2(R2d2Error),
    #[cfg(feature = "v2")]
    Serialize(serde_json::Error),
    #[cfg(feature = "v2")]
    Deserialize(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rusqlite(e) => write!(f, "Database operation failed: {e}"),
            Error::R2d2(e) => write!(f, "Connection pool error: {e}"),
            #[cfg(feature = "v2")]
            Error::Serialize(e) => write!(f, "Serialization failed: {e}"),
            #[cfg(feature = "v2")]
            Error::Deserialize(e) => write!(f, "Deserialization failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Rusqlite(e) => Some(e),
            Error::R2d2(e) => Some(e),
            #[cfg(feature = "v2")]
            Error::Serialize(e) => Some(e),
            #[cfg(feature = "v2")]
            Error::Deserialize(e) => Some(e),
        }
    }
}

impl From<RusqliteError> for Error {
    fn from(error: RusqliteError) -> Self { Error::Rusqlite(error) }
}

impl From<R2d2Error> for Error {
    fn from(error: R2d2Error) -> Self { Error::R2d2(error) }
}

#[cfg(feature = "v2")]
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        match error.classify() {
            serde_json::error::Category::Io => Error::Serialize(error), // I/O errors during writing/serialization
            serde_json::error::Category::Syntax
            | serde_json::error::Category::Data
            | serde_json::error::Category::Eof => Error::Deserialize(error), // All parsing/reading errors
        }
    }
}

impl From<Error> for ImplementationError {
    fn from(error: Error) -> Self { ImplementationError::new(error) }
}

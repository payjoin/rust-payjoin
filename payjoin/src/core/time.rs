use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::absolute::Time as BitcoinTime;
use bitcoin::consensus::encode::{Decodable, Error as EncodeError};
use bitcoin::consensus::Encodable;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub(crate) struct Time(BitcoinTime);

impl Time {
    /// Specify a time some duration from now (e.g. an expiration time).
    pub(crate) fn from_now(duration: Duration) -> Result<Self, ConversionError> {
        SystemTime::now().checked_add(duration).unwrap_or(UNIX_EPOCH).try_into()
    }

    /// Get the current time.
    pub(crate) fn now() -> Self {
        Time::try_from(SystemTime::now()).expect("Current time should always be a valid timestamp")
    }

    /// Create a time value from a u32 UNIX timestamp representation.
    pub(crate) fn from_unix_seconds(seconds: u32) -> Result<Self, ConversionError> {
        Ok(Time(BitcoinTime::from_consensus(seconds)?))
    }

    /// Parse from the Bitcoin consensus encoding of a u32 UNIX timestamp representation.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, ParseTimeError> {
        use ParseTimeError::*;
        if bytes.len() != core::mem::size_of::<u32>() {
            return Err(IncorrectLength(bytes.len()));
        }
        let mut cursor = bytes;
        let seconds = u32::consensus_decode(&mut cursor).map_err(Decode)?;
        debug_assert!(cursor.is_empty());
        Time::from_unix_seconds(seconds).map_err(Convert)
    }

    /// Encode as a Bitcoin consensus encoding of u32 UNIX timestamp.
    pub(crate) fn to_bytes(self) -> [u8; 4] {
        let t = self.0.to_consensus_u32();

        let mut buf = [0u8; 4];
        t.consensus_encode(&mut &mut buf[..]).expect("encoding should never fail because all valid Time values are encodable and u32 has a known width");
        buf
    }

    /// Check if the time is in the past.
    pub(crate) fn elapsed(self) -> bool { self <= Self::now() }
}

#[derive(Debug)]
pub struct ConversionError(bitcoin::absolute::ConversionError);

impl std::error::Error for ConversionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl std::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.0.fmt(f) }
}

impl From<bitcoin::absolute::ConversionError> for ConversionError {
    fn from(val: bitcoin::absolute::ConversionError) -> Self { Self(val) }
}

#[derive(Debug)]
pub(crate) enum ParseTimeError {
    IncorrectLength(usize),
    Decode(EncodeError),
    Convert(ConversionError),
}

impl std::error::Error for ParseTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl std::fmt::Display for ParseTimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseTimeError::*;

        match &self {
            Decode(e) => write!(f, "invalid bytes: {e}"),
            Convert(e) => write!(f, "invalid date: {e}"),
            IncorrectLength(l) => write!(f, "incorrect length: expected 4 bytes, got {l}"),
        }
    }
}

impl TryFrom<SystemTime> for Time {
    type Error = ConversionError;
    fn try_from(val: SystemTime) -> Result<Self, ConversionError> {
        Time::from_unix_seconds(val.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as u32)
    }
}

impl TryFrom<Duration> for Time {
    type Error = ConversionError;
    fn try_from(val: Duration) -> Result<Self, ConversionError> { Time::from_now(val) }
}

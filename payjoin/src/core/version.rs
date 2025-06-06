use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The Payjoin version
///
/// From [BIP 78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#optional-parameters),
/// the supported versions should be output as numbers:
///
/// ```json
/// {
///     "errorCode": "version-unsupported",
///     "supported" : [ 2, 3, 4 ],
///     "message": "The version is not supported anymore"
/// }
/// ```
///
/// # Note
/// - Both [`Serialize`] and [`Deserialize`] are implemented for json array serialization in the `unsupported-version` error message,
/// - [`fmt::Display`] and [`fmt::Debug`] output the `u8` representation for compatibility with BIP 78/77
///   and to match the expected wire format.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// BIP 78 Payjoin
    One = 1,
    /// BIP 77 Async Payjoin
    Two = 2,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { (*self as u8).fmt(f) }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(self, f) }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (*self as u8).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        match v {
            1 => Ok(Version::One),
            2 => Ok(Version::Two),
            _ => Err(serde::de::Error::custom("Invalid version")),
        }
    }
}

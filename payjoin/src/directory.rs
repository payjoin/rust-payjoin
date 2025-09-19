//! Types relevant to the Payjoin Directory as defined in BIP 77.

pub const ENCAPSULATED_MESSAGE_BYTES: usize = 8192;

/// A 64-bit identifier used to identify Payjoin Directory entries.
///
/// ShortId is derived from a truncated SHA256 hash of a compressed public key. While SHA256 is used
/// internally, ShortIds should be treated only as unique identifiers, not cryptographic hashes.
/// The truncation to 64 bits means they are not cryptographically binding.
///
/// ## Security Characteristics
///
/// - Provides sufficient entropy for practical uniqueness in the Payjoin Directory context
/// - With ~2^21 concurrent entries (24h tx limit), collision probability is < 1e-6
/// - Individual entry collision probability is << 1e-10
/// - Collisions only affect liveness (ability to complete the payjoin), not security
/// - For v2 entries, collisions result in HPKE failure
/// - For v1 entries, collisions may leak PSBT proposals to interceptors
///
/// Note: This implementation assumes ephemeral public keys with sufficient entropy. The short length
/// is an intentional tradeoff that provides adequate practical uniqueness while reducing DoS surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "_core", derive(serde::Serialize, serde::Deserialize))]
pub struct ShortId(pub [u8; 8]);

impl ShortId {
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    pub fn as_slice(&self) -> &[u8] { &self.0 }
}

impl std::fmt::Display for ShortId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let id_hrp = bitcoin::bech32::Hrp::parse("ID")
            .expect("parsing a valid HRP constant should never fail");
        f.write_str(
            crate::bech32::nochecksum::encode(id_hrp, &self.0)
                .expect("bech32 encoding of short ID must succeed")
                .strip_prefix("ID1")
                .expect("human readable part must be ID1"),
        )
    }
}

#[derive(Debug)]
pub enum ShortIdError {
    DecodeBech32(bitcoin::bech32::primitives::decode::CheckedHrpstringError),
    IncorrectLength(std::array::TryFromSliceError),
}

impl std::convert::From<bitcoin::hashes::sha256::Hash> for ShortId {
    fn from(h: bitcoin::hashes::sha256::Hash) -> Self {
        bitcoin::hashes::Hash::as_byte_array(&h)[..8]
            .try_into()
            .expect("truncating SHA256 to 8 bytes should always succeed")
    }
}

impl std::convert::TryFrom<&[u8]> for ShortId {
    type Error = ShortIdError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 8] = bytes.try_into().map_err(ShortIdError::IncorrectLength)?;
        Ok(Self(bytes))
    }
}

impl std::str::FromStr for ShortId {
    type Err = ShortIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, bytes) = crate::bech32::nochecksum::decode(&("ID1".to_string() + s))
            .map_err(ShortIdError::DecodeBech32)?;
        (&bytes[..]).try_into()
    }
}

#[cfg(test)]
mod tests {
    use crate::uri::ShortId;

    #[test]
    fn short_id_conversion() {
        let short_id = ShortId([0; 8]);
        assert_eq!(short_id.as_bytes(), short_id.0);
        assert_eq!(short_id.as_slice(), short_id.0);
    }
}

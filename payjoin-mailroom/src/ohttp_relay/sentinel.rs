use hex::DisplayHex;

/// HTTP header name for the sentinel tag.
pub const HEADER_NAME: &str = "x-ohttp-self-loop-tag";

/// A random 32-byte tag shared between relay and gateway for same-instance detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentinelTag([u8; 32]);

impl SentinelTag {
    /// Creates a new sentinel tag from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self { Self(bytes) }

    /// Returns the tag as a hex string for use in HTTP headers.
    pub fn to_header_value(&self) -> String { self.0.to_lower_hex_string() }
}

/// Checks if a request originated from the same instance by comparing sentinel tags.
///
/// Returns `true` if the header value matches this instance's tag, indicating a self-loop
/// that should be rejected.
pub fn is_self_loop(tag: &SentinelTag, header_value: &str) -> bool {
    tag.to_header_value() == header_value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_tag_matches() {
        let tag = SentinelTag::new([0u8; 32]);
        let header = tag.to_header_value();
        assert!(is_self_loop(&tag, &header), "same tag should match");
    }

    #[test]
    fn different_tag_does_not_match() {
        let tag1 = SentinelTag::new([0u8; 32]);
        let tag2 = SentinelTag::new([1u8; 32]);
        let header = tag1.to_header_value();
        assert!(!is_self_loop(&tag2, &header), "different tag should not match");
    }

    #[test]
    fn header_format() {
        let tag = SentinelTag::new([0xab; 32]);
        let header = tag.to_header_value();

        // Should be 64 hex characters (32 bytes)
        assert_eq!(header.len(), 64, "header should be 64 hex characters");
        assert!(header.chars().all(|c| c.is_ascii_hexdigit()), "header should be valid hex");
        assert_eq!(header, "ab".repeat(32), "header should match expected hex");
    }
}

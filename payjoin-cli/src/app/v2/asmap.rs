use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use payjoin::bitcoin::hashes::{sha256, Hash, HashEngine};

/// Domain separation tag for tagged hashing (BIP340) to derive ASMAP seeds.
const ASMAP_TAG: &[u8] = b"payjoin/asmap/relay-selection";

#[derive(Debug, Clone)]
pub struct AsmapSeed([u8; 32]);

impl AsmapSeed {
    /// A shared seed that allows the sender and receiver to arrive
    /// at the same relay order independently, without additional communication.
    pub fn from_receiver_pubkey(pubkey_bytes: &[u8]) -> Self {
        // BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || pubkey_bytes)
        // Ensures hashes in this context cannot be reinterpreted in another context.
        let tag_hash = sha256::Hash::hash(ASMAP_TAG);
        let mut engine = sha256::HashEngine::default();
        engine.input(tag_hash.as_byte_array());
        engine.input(tag_hash.as_byte_array());
        engine.input(pubkey_bytes);
        AsmapSeed(*sha256::Hash::from_engine(engine).as_byte_array())
    }

    // SHA256(seed || asn_be)
    pub fn hash_asn(&self, asn: u32) -> [u8; 32] {
        let mut engine = sha256::HashEngine::default();
        engine.input(&self.0);
        engine.input(&asn.to_be_bytes());
        *sha256::Hash::from_engine(engine).as_byte_array()
    }

    // SHA256(seed || relay_uri_utf8)
    pub fn hash_relay(&self, relay_uri: &str) -> [u8; 32] {
        let mut engine = sha256::HashEngine::default();
        engine.input(&self.0);
        engine.input(relay_uri.as_bytes());
        *sha256::Hash::from_engine(engine).as_byte_array()
    }

    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Debug)]
pub enum AsmapError {
    Io(std::io::Error),
    Parse(String),
    InvalidPrefix(String),
}

impl fmt::Display for AsmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsmapError::Io(e) => write!(f, "Failed to read asmap file: {e}"),
            AsmapError::Parse(s) => write!(f, "Failed to parse line: {s}"),
            AsmapError::InvalidPrefix(s) => write!(f, "Invalid IP prefix: {s}"),
        }
    }
}

impl std::error::Error for AsmapError {}

impl From<std::io::Error> for AsmapError {
    fn from(e: std::io::Error) -> Self { AsmapError::Io(e) }
}

#[derive(Debug, Clone)]
pub(crate) struct AsmapEntry {
    prefix: IpAddr,
    prefix_len: u8,
    asn: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Asmap {
    entries: Vec<AsmapEntry>,
}

impl Asmap {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, AsmapError> {
        let content = std::fs::read_to_string(path)?;
        content.parse()
    }

    // O(n) linear scan. Bitcoin Core uses a pre-compiled binary trie (.dat,
    // bitcoin-core/asmap-data) with O(32) lookup and better UX. users could
    // download a pre-audited file instead of running Kartograf.
    pub fn lookup(&self, ip: IpAddr) -> Option<u32> {
        let mut best_match: Option<(u8, u32)> = None;
        for entry in &self.entries {
            if ip_version_match(&ip, &entry.prefix)
                && ip_in_prefix(ip, entry.prefix, entry.prefix_len)
                && (best_match.is_none() || entry.prefix_len > best_match.as_ref().unwrap().0)
            {
                best_match = Some((entry.prefix_len, entry.asn));
            }
        }
        best_match.map(|(_, asn)| asn)
    }
}

impl std::str::FromStr for Asmap {
    type Err = AsmapError;
    fn from_str(s: &str) -> Result<Self, AsmapError> {
        let mut entries = Vec::new();
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            entries.push(parse_line(line)?);
        }
        Ok(Self { entries })
    }
}

// should we use a dep like ipnet?
fn ip_version_match(a: &IpAddr, b: &IpAddr) -> bool {
    matches!((a, b), (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)))
}

fn ip_in_prefix(ip: IpAddr, prefix: IpAddr, prefix_len: u8) -> bool {
    match (ip, prefix) {
        (IpAddr::V4(ip), IpAddr::V4(prefix)) => ipv4_in_prefix(ip, prefix, prefix_len),
        (IpAddr::V6(ip), IpAddr::V6(prefix)) => ipv6_in_prefix(ip, prefix, prefix_len),
        _ => false,
    }
}

fn ipv4_in_prefix(ip: Ipv4Addr, prefix: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = !0u32 << (32 - prefix_len);
    let ip_bits = u32::from_be_bytes(ip.octets());
    let prefix_bits = u32::from_be_bytes(prefix.octets());
    (ip_bits & mask) == (prefix_bits & mask)
}

fn ipv6_in_prefix(ip: Ipv6Addr, prefix: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let octets = ip.octets();
    let prefix_octets = prefix.octets();
    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;

    if full_bytes > 0 && octets[..full_bytes] != prefix_octets[..full_bytes] {
        return false;
    }
    if remaining_bits > 0 && full_bytes < 16 {
        let mask = !0u8 << (8 - remaining_bits);
        if (octets[full_bytes] & mask) != (prefix_octets[full_bytes] & mask) {
            return false;
        }
    }
    true
}

fn parse_line(line: &str) -> Result<AsmapEntry, AsmapError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(AsmapError::Parse(format!(
            "Expected 2 parts, got {}: '{}'",
            parts.len(),
            line
        )));
    }
    let prefix_str = parts[0];
    let asn_str = parts[1];
    let asn = asn_str
        .strip_prefix("AS")
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| AsmapError::Parse(format!("Invalid ASN: '{}'", asn_str)))?;

    let (prefix, prefix_len) = parse_prefix(prefix_str)?;
    Ok(AsmapEntry { prefix, prefix_len, asn })
}

fn parse_prefix(s: &str) -> Result<(IpAddr, u8), AsmapError> {
    let Some((addr_part, len_part)) = s.split_once('/') else {
        return Err(AsmapError::InvalidPrefix(format!("Missing '/' in prefix: {}", s)));
    };
    let prefix_len = len_part
        .parse()
        .map_err(|_| AsmapError::InvalidPrefix(format!("Invalid prefix length: {}", len_part)))?;

    let ip: IpAddr = if addr_part.contains(':') {
        let ip: Ipv6Addr = addr_part.parse().map_err(|_| {
            AsmapError::InvalidPrefix(format!("Invalid IPv6 address: {}", addr_part))
        })?;
        IpAddr::V6(ip)
    } else {
        let ip: Ipv4Addr = addr_part.parse().map_err(|_| {
            AsmapError::InvalidPrefix(format!("Invalid IPv4 address: {}", addr_part))
        })?;
        IpAddr::V4(ip)
    };

    let max_len = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix_len > max_len {
        return Err(AsmapError::InvalidPrefix(format!(
            "Prefix length {} exceeds maximum {}",
            prefix_len, max_len
        )));
    }

    Ok((ip, prefix_len))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    const SAMPLE_ASMAP: &str = r#"
#
103.152.34.0/23 AS14618
2406:4440:10::/44 AS142641
2406:4440:f000::/44 AS38173
103.152.35.0/24 AS38008
"#;

    #[test]
    fn test_parse_asmap_from_str() {
        let asmap: Asmap = SAMPLE_ASMAP.parse().unwrap();
        assert_eq!(asmap.entries.len(), 4);
    }

    #[test]
    fn test_lookup_ipv4_exact() {
        let asmap: Asmap = SAMPLE_ASMAP.parse().unwrap();
        assert_eq!(asmap.lookup(IpAddr::V4(Ipv4Addr::new(103, 152, 34, 5))), Some(14618));
    }

    #[test]
    fn test_lookup_ipv4_subnet() {
        let asmap: Asmap = SAMPLE_ASMAP.parse().unwrap();
        assert_eq!(asmap.lookup(IpAddr::V4(Ipv4Addr::new(103, 152, 35, 1))), Some(38008));
    }

    #[test]
    fn test_lookup_ipv4_in_23_bit_prefix() {
        let asmap: Asmap = SAMPLE_ASMAP.parse().unwrap();
        assert_eq!(asmap.lookup(IpAddr::V4(Ipv4Addr::new(103, 152, 34, 255))), Some(14618));
    }

    #[test]
    fn test_lookup_ipv6() {
        let asmap: Asmap = SAMPLE_ASMAP.parse().unwrap();
        let ip: IpAddr = "2406:4440:10::1".parse().unwrap();
        assert_eq!(asmap.lookup(ip), Some(142641));
    }

    #[test]
    fn test_lookup_ipv6_other() {
        let asmap: Asmap = SAMPLE_ASMAP.parse().unwrap();
        let ip: IpAddr = "2406:4440:f000::1".parse().unwrap();
        assert_eq!(asmap.lookup(ip), Some(38173));
    }

    #[test]
    fn test_lookup_no_match() {
        let asmap: Asmap = SAMPLE_ASMAP.parse().unwrap();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(asmap.lookup(ip), None);
    }

    #[test]
    fn test_parse_empty_lines_and_comments() {
        let content = r#"
#
103.152.34.0/23 AS14618

#

2406:4440:10::/44 AS142641
"#;
        let asmap: Asmap = content.parse().unwrap();
        assert_eq!(asmap.entries.len(), 2);
    }

    #[test]
    fn test_parse_invalid_asn() {
        let result = Asmap::from_str("103.152.34.0/23 INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_prefix() {
        let result = Asmap::from_str("not-an-ip/24 AS14618");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_prefix_too_long() {
        let result = Asmap::from_str("103.152.34.0/33 AS14618");
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_prefix_len_zero() {
        let prefix: Ipv4Addr = "0.0.0.0".parse().unwrap();
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert!(ipv4_in_prefix(ip, prefix, 0));
    }

    #[test]
    fn test_ipv6_partial_byte_mask_bug() {
        // Use prefix with non-zero byte at /44 boundary to expose mask bug
        // 2406:4440:f000::/44 means byte 4 = 0xf0, byte 5 = 0x00
        let prefix: Ipv6Addr = "2406:4440:f000::".parse().unwrap();
        // IP with different high nibble in byte 4: 0xff0... should NOT match
        let ip_should_not_match: Ipv6Addr =
            "2406:4440:ff00:0000:0000:0000:0000:0001".parse().unwrap();
        // IP with matching high nibble: 0xf000... SHOULD match
        let ip_should_match: Ipv6Addr = "2406:4440:f001:0000:0000:0000:0000:0001".parse().unwrap();

        let result_not_match = ipv6_in_prefix(ip_should_not_match, prefix, 44);
        let result_match = ipv6_in_prefix(ip_should_match, prefix, 44);

        assert!(
            !result_not_match,
            "IP (byte4=0x{:02x}) should NOT be in /44 prefix (byte4=0xf0)",
            ip_should_not_match.octets()[4]
        );
        assert!(result_match, "IP should match /44 prefix");
    }

    #[test]
    fn test_ipv6_prefix_len_zero() {
        let prefix: Ipv6Addr = "::".parse().unwrap();
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(ipv6_in_prefix(ip, prefix, 0));
    }

    #[test]
    fn test_longest_prefix_match() {
        let content = r#"
10.0.0.0/8 AS1
10.0.0.0/16 AS2
10.0.0.0/24 AS3
"#;
        let asmap: Asmap = content.parse().unwrap();
        assert_eq!(asmap.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), Some(3));
        assert_eq!(asmap.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))), Some(2));
        assert_eq!(asmap.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1))), Some(1));
    }

    #[test]
    fn test_asmap_seed_deterministic() {
        let pubkey: [u8; 33] = [
            0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let seed1 = AsmapSeed::from_receiver_pubkey(&pubkey);
        let seed2 = AsmapSeed::from_receiver_pubkey(&pubkey);
        assert_eq!(seed1.as_bytes(), seed2.as_bytes());
    }

    #[test]
    fn test_asmap_seed_different_pubkeys() {
        let pubkey1: [u8; 33] = [
            0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let pubkey2: [u8; 33] = [
            0x03, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let seed1 = AsmapSeed::from_receiver_pubkey(&pubkey1);
        let seed2 = AsmapSeed::from_receiver_pubkey(&pubkey2);
        assert_ne!(seed1.as_bytes(), seed2.as_bytes());
    }

    #[test]
    fn test_asmap_seed_vector() {
        // Test vector for AsmapSeed::from_receiver_pubkey with known input
        let pubkey: [u8; 33] = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let seed = AsmapSeed::from_receiver_pubkey(&pubkey);
        assert_eq!(
            seed.as_bytes(),
            &[
                0x3e, 0xaa, 0xe1, 0x39, 0xee, 0xaf, 0x34, 0x11, 0x7c, 0xa2, 0xeb, 0xb1, 0x76, 0x23,
                0xd2, 0x65, 0x64, 0x83, 0x29, 0x4f, 0xfc, 0x04, 0x41, 0xe5, 0x83, 0x45, 0xbf, 0x47,
                0x4e, 0xeb, 0x5e, 0x83,
            ]
        );
    }
}

use std::fmt;

use bitcoin::bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use bitcoin::bech32::{self, EncodeError, Hrp, NoChecksum};

pub mod nochecksum {
    use super::*;

    pub fn decode(encoded: &str) -> Result<(Hrp, Vec<u8>), CheckedHrpstringError> {
        let hrp_string = CheckedHrpstring::new::<NoChecksum>(encoded)?;
        Ok((hrp_string.hrp(), hrp_string.byte_iter().collect::<Vec<u8>>()))
    }

    pub fn encode(hrp: Hrp, data: &[u8]) -> Result<String, EncodeError> {
        bech32::encode_upper::<NoChecksum>(hrp, data)
    }

    pub fn encode_to_fmt(f: &mut fmt::Formatter, hrp: Hrp, data: &[u8]) -> Result<(), EncodeError> {
        bech32::encode_upper_to_fmt::<NoChecksum, fmt::Formatter>(f, hrp, data)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bech32_for_qr() {
        let bytes = vec![0u8, 1, 2, 3, 31, 32, 33, 95, 0, 96, 127, 128, 129, 254, 255, 0];
        let hrp = Hrp::parse("STUFF").unwrap();
        let encoded = nochecksum::encode(hrp, &bytes).unwrap();
        let decoded = nochecksum::decode(&encoded).unwrap();
        assert_eq!(decoded, (hrp, bytes.to_vec()));

        // no checksum
        assert_eq!(
            encoded.len() as f32,
            (hrp.as_str().len() + 1) as f32 + (bytes.len() as f32 * 8.0 / 5.0).ceil()
        );

        // TODO assert uppercase

        // should not error
        let corrupted = encoded + "QQPP";
        let decoded = nochecksum::decode(&corrupted).unwrap();
        assert_eq!(decoded.0, hrp);
        assert_ne!(decoded, (hrp, bytes.to_vec()));
    }
}

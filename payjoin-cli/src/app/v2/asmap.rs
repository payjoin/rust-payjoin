#[cfg(feature = "asmap")]
use std::net::IpAddr;

#[cfg(feature = "asmap")]
use crate::app::config::LoadedAsmap;

pub(crate) type Asn = u32;

#[cfg(feature = "asmap")]
const INVALID_ASN: Asn = u32::MAX;
#[cfg(feature = "asmap")]
const IPV4_IN_IPV6_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
#[cfg(feature = "asmap")]
const TYPE_BIT_SIZES: [u8; 3] = [0, 0, 1];
#[cfg(feature = "asmap")]
const ASN_BIT_SIZES: [u8; 10] = [15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
#[cfg(feature = "asmap")]
const MATCH_BIT_SIZES: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
#[cfg(feature = "asmap")]
const JUMP_BIT_SIZES: [u8; 26] = [
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30,
];

#[cfg(feature = "asmap")]
#[derive(Debug, Clone)]
pub(crate) struct AsmapInterpreter<'a> {
    data: &'a [u8],
}

#[cfg(feature = "asmap")]
impl<'a> AsmapInterpreter<'a> {
    pub(crate) fn new(asmap: &'a LoadedAsmap) -> Self { Self { data: asmap.data() } }

    pub(crate) fn lookup(&self, ip: IpAddr) -> Option<Asn> {
        let bytes = ip_to_asmap_input(ip);
        let asn = interpret_asmap(self.data, &bytes);
        (asn != 0).then_some(asn)
    }
}

#[cfg(feature = "asmap")]
fn ip_to_asmap_input(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ipv4) => {
            let mut bytes = [0_u8; 16];
            bytes[..12].copy_from_slice(&IPV4_IN_IPV6_PREFIX);
            bytes[12..].copy_from_slice(&ipv4.octets());
            bytes
        }
        IpAddr::V6(ipv6) => ipv6.octets(),
    }
}

#[cfg(feature = "asmap")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Instruction {
    Return,
    Jump,
    Match,
    Default,
}

#[cfg(feature = "asmap")]
fn interpret_asmap(asmap: &[u8], ip: &[u8; 16]) -> Asn {
    let mut pos = 0_usize;
    let end = asmap.len() * 8;
    let mut ip_bit = 0_usize;
    let ip_end = ip.len() * 8;
    let mut default_asn = 0_u32;

    while pos < end {
        let opcode = match decode_type(&mut pos, asmap) {
            Some(opcode) => opcode,
            None => return 0,
        };

        match opcode {
            Instruction::Return => {
                let asn = decode_asn(&mut pos, asmap);
                return if asn == INVALID_ASN { 0 } else { asn };
            }
            Instruction::Jump => {
                let jump = decode_jump(&mut pos, asmap);
                if jump == INVALID_ASN
                    || ip_bit == ip_end
                    || jump as usize >= end.saturating_sub(pos)
                {
                    return 0;
                }
                if consume_bit_be(&mut ip_bit, ip) {
                    pos += jump as usize;
                }
            }
            Instruction::Match => {
                let value = decode_match(&mut pos, asmap);
                if value == INVALID_ASN {
                    return 0;
                }
                let match_len = (u32::BITS - value.leading_zeros() - 1) as usize;
                if ip_end.saturating_sub(ip_bit) < match_len {
                    return 0;
                }
                for offset in 0..match_len {
                    let expected = ((value >> (match_len - 1 - offset)) & 1) != 0;
                    if consume_bit_be(&mut ip_bit, ip) != expected {
                        return default_asn;
                    }
                }
            }
            Instruction::Default => {
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID_ASN {
                    return 0;
                }
                default_asn = asn;
            }
        }
    }

    0
}

#[cfg(feature = "asmap")]
pub(crate) fn check_standard_asmap(data: &[u8]) -> bool { sanity_check_asmap(data, 128) }

#[cfg(feature = "asmap")]
fn sanity_check_asmap(asmap: &[u8], mut bits: usize) -> bool {
    let mut pos = 0_usize;
    let end = asmap.len() * 8;
    let mut jumps = Vec::<(usize, usize)>::with_capacity(bits);
    let mut prev_opcode = Instruction::Jump;
    let mut had_incomplete_match = false;

    while pos != end {
        if let Some((jump_target, _)) = jumps.last() {
            if pos >= *jump_target {
                return false;
            }
        }

        let opcode = match decode_type(&mut pos, asmap) {
            Some(opcode) => opcode,
            None => return false,
        };

        match opcode {
            Instruction::Return => {
                if prev_opcode == Instruction::Default {
                    return false;
                }
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID_ASN {
                    return false;
                }

                if jumps.is_empty() {
                    if end.saturating_sub(pos) > 7 {
                        return false;
                    }
                    while pos != end {
                        if consume_bit_le(&mut pos, asmap) {
                            return false;
                        }
                    }
                    return true;
                }

                let (jump_target, remaining_bits) = jumps.pop().expect("checked is_empty");
                if pos != jump_target {
                    return false;
                }
                bits = remaining_bits;
                prev_opcode = Instruction::Jump;
            }
            Instruction::Jump => {
                let jump = decode_jump(&mut pos, asmap);
                if jump == INVALID_ASN || jump as usize > end.saturating_sub(pos) {
                    return false;
                }
                if bits == 0 {
                    return false;
                }
                bits -= 1;

                let jump_target = pos + jump as usize;
                if let Some((last_target, _)) = jumps.last() {
                    if jump_target >= *last_target {
                        return false;
                    }
                }
                jumps.push((jump_target, bits));
                prev_opcode = Instruction::Jump;
            }
            Instruction::Match => {
                let value = decode_match(&mut pos, asmap);
                if value == INVALID_ASN {
                    return false;
                }
                let match_len = (u32::BITS - value.leading_zeros() - 1) as usize;
                if prev_opcode != Instruction::Match {
                    had_incomplete_match = false;
                }
                if match_len < 8 && had_incomplete_match {
                    return false;
                }
                had_incomplete_match = match_len < 8;
                if bits < match_len {
                    return false;
                }
                bits -= match_len;
                prev_opcode = Instruction::Match;
            }
            Instruction::Default => {
                if prev_opcode == Instruction::Default {
                    return false;
                }
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID_ASN {
                    return false;
                }
                prev_opcode = Instruction::Default;
            }
        }
    }

    false
}

#[cfg(feature = "asmap")]
fn decode_type(pos: &mut usize, data: &[u8]) -> Option<Instruction> {
    match decode_bits(pos, data, 0, &TYPE_BIT_SIZES) {
        0 => Some(Instruction::Return),
        1 => Some(Instruction::Jump),
        2 => Some(Instruction::Match),
        3 => Some(Instruction::Default),
        _ => None,
    }
}

#[cfg(feature = "asmap")]
fn decode_asn(pos: &mut usize, data: &[u8]) -> Asn { decode_bits(pos, data, 1, &ASN_BIT_SIZES) }

#[cfg(feature = "asmap")]
fn decode_match(pos: &mut usize, data: &[u8]) -> Asn { decode_bits(pos, data, 2, &MATCH_BIT_SIZES) }

#[cfg(feature = "asmap")]
fn decode_jump(pos: &mut usize, data: &[u8]) -> Asn { decode_bits(pos, data, 17, &JUMP_BIT_SIZES) }

#[cfg(feature = "asmap")]
fn decode_bits(pos: &mut usize, data: &[u8], min_val: u8, bit_sizes: &[u8]) -> Asn {
    let mut value = u32::from(min_val);

    for (index, bit_size) in bit_sizes.iter().enumerate() {
        let continuation = if index + 1 != bit_sizes.len() {
            if *pos >= data.len() * 8 {
                return INVALID_ASN;
            }
            consume_bit_le(pos, data)
        } else {
            false
        };

        if continuation {
            value += 1_u32 << u32::from(*bit_size);
            continue;
        }

        for bit in 0..usize::from(*bit_size) {
            if *pos >= data.len() * 8 {
                return INVALID_ASN;
            }
            let current = consume_bit_le(pos, data);
            value += u32::from(current) << ((usize::from(*bit_size) - 1 - bit) as u32);
        }
        return value;
    }

    INVALID_ASN
}

#[cfg(feature = "asmap")]
fn consume_bit_le(pos: &mut usize, bytes: &[u8]) -> bool {
    let byte = bytes[*pos / 8];
    let bit = ((byte >> (*pos % 8)) & 1) != 0;
    *pos += 1;
    bit
}

#[cfg(feature = "asmap")]
fn consume_bit_be(pos: &mut usize, bytes: &[u8]) -> bool {
    let byte = bytes[*pos / 8];
    let bit = ((byte >> (7 - (*pos % 8))) & 1) != 0;
    *pos += 1;
    bit
}

#[cfg(all(test, feature = "asmap"))]
mod tests {
    use super::check_standard_asmap;

    #[test]
    fn accepts_minimal_valid_asmap() {
        assert!(check_standard_asmap(&[0x00, 0x00, 0x00]));
    }

    #[test]
    fn rejects_asmap_with_excessive_padding() {
        assert!(!check_standard_asmap(&[0x00, 0x00, 0x00, 0x00]));
    }
}

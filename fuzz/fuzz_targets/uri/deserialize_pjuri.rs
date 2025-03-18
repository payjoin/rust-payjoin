#![no_main]

use std::any::{Any, TypeId};

use bitcoin::Amount;
use bitcoin_uri::Param;
#[cfg(feature = "fuzzing")]
use libfuzzer_sys::fuzz_target;
use payjoin::{Uri, UriExt};

fn do_test(data: &[u8]) {
    let data_str = String::from_utf8_lossy(data).trim_end_matches('\n').to_string();
    let pj_uri = match data_str.parse::<Uri<_>>() {
        Ok(pj_uri) => pj_uri.assume_checked(),
        Err(_) => return,
    };
    let address = pj_uri.address.is_spend_standard();
    if !address {
        return;
    }
    let amount = pj_uri.amount;

    if let Some(label) = pj_uri.clone().label {
        if TypeId::of::<Param>() != label.type_id() {
            return;
        }
    };
    if let Some(message) = pj_uri.clone().message {
        if TypeId::of::<Param>() != message.type_id() {
            return;
        }
    };
    let extras = pj_uri.clone().check_pj_supported().unwrap().extras;
    assert_eq!(pj_uri.to_string(), data_str);
    assert!(amount.is_none_or(|btc| btc < Amount::MAX_MONEY));
    assert!(TypeId::of::<payjoin::OutputSubstitution>() == extras.output_substitution().type_id());
    assert!(TypeId::of::<String>() == extras.endpoint().type_id())
}

#[cfg(feature = "fuzzing")]
fuzz_target!(|data| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00000000", &mut a);
        super::do_test(&a);
    }
}

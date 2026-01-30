#![cfg_attr(any(feature = "libfuzzer_fuzz", clippy), no_main)]

use std::any::{Any, TypeId};

#[cfg(all(feature = "afl_fuzz", not(clippy)))]
use afl::fuzz;
use bitcoin::Amount;
use bitcoin_uri::Param;
#[cfg(all(feature = "honggfuzz_fuzz", not(clippy)))]
use honggfuzz::fuzz;
#[cfg(feature = "libfuzzer_fuzz")]
use libfuzzer_sys::fuzz_target;
use payjoin::{Uri, UriExt};

fn do_test(data: &[u8]) {
    if let Ok(uri_str) = std::str::from_utf8(data) {
        let pj_uri = match Uri::try_from(uri_str.to_string()) {
            Ok(uri) => uri.assume_checked(),
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
        let extras = match pj_uri.clone().check_pj_supported() {
            Ok(res) => res.extras,
            Err(_) => return,
        };
        // Removed as this is not guaranteed with unknown params
        // let uri_owned = uri_str.to_string();
        // assert_eq!(uri_owned.clone(), pj_uri.to_string());
        assert!(amount.is_none_or(|btc| btc < Amount::MAX_MONEY));
        assert!(
            TypeId::of::<payjoin::OutputSubstitution>() == extras.output_substitution().type_id()
        );
        assert!(TypeId::of::<String>() == extras.endpoint().type_id())
    }
}

#[cfg(all(feature = "afl_fuzz", not(clippy)))]
fn main() {
    fuzz!(|data| {
        do_test(data);
    });
}

#[cfg(all(feature = "honggfuzz_fuzz", not(clippy)))]
fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(feature = "libfuzzer_fuzz")]
fuzz_target!(|data| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    #[test]
    fn duplicate_crash() {
        let data = b"\x42\x69\x74\x63\x6f\x69\x6e\x3a\x31\x32\x63\x36\x44\x53\x69\x55\x34\x52\x71\x33\x50\x34\x5a\x78\x7a\x69\x4b\x78\x7a\x72\x4c\x35\x4c\x6d\x4d\x42\x72\x7a\x6a\x72\x4a\x58\x3f\x3d\x26\x70\x6a\x3d\x68\x74\x74\x70\x3a\x2e\x6f\x6e\x69\x6f\x6e";
        super::do_test(&data[..]);
    }
}

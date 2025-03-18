#![no_main]

use std::any::{Any, TypeId};

use bitcoin::Amount;
use bitcoin_uri::Param;
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

fuzz_target!(|data| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    #[test]
    fn duplicate_crash() {
        let data = b"\x00";
        super::do_test(&data[..]);
    }
}

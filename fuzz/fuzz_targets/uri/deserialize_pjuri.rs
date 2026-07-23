#![no_main]

use std::any::{Any, TypeId};

use libfuzzer_sys::fuzz_target;
use payjoin::Uri;

fn do_test(data: &[u8]) {
    if let Ok(uri_str) = std::str::from_utf8(data) {
        let pj_uri = match Uri::try_from(uri_str.to_string()) {
            Ok(uri) => uri.assume_checked(),
            Err(_) => return,
        };
        if !pj_uri.address().is_spend_standard() {
            return;
        }

        if let Some(label) = pj_uri.label() {
            if TypeId::of::<String>() != label.type_id() {
                return;
            }
        };
        if let Some(message) = pj_uri.message() {
            if TypeId::of::<String>() != message.type_id() {
                return;
            }
        };
        let extras = match pj_uri.check_pj_supported() {
            Ok(res) => res,
            Err(_) => return,
        };
        assert!(
            TypeId::of::<payjoin::OutputSubstitution>()
                == extras.extras().output_substitution().type_id()
        );
        assert!(TypeId::of::<String>() == extras.extras().endpoint().type_id())
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

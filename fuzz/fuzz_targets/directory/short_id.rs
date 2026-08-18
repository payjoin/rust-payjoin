#![no_main]

use libfuzzer_sys::fuzz_target;
use payjoin::directory::ShortId;

fn do_test(data: &[u8]) {
    // Path 1: raw 8-byte identifier, as stored internally and compared
    // against database keys. Any length other than 8 must be rejected.
    match ShortId::try_from(data) {
        Ok(id) => {
            assert_eq!(id.as_bytes(), data);
            assert_eq!(id.as_slice(), data);

            let encoded = id.to_string();
            let reparsed: ShortId =
                encoded.parse().expect("Display output of a valid ShortId must re-parse");
            assert_eq!(reparsed, id, "round-trip mismatch via Display/FromStr: {encoded}");
        }
        Err(_) => assert_ne!(data.len(), 8, "an 8-byte slice must always convert"),
    }

    // Path 2: attacker-controlled URL path segment, decoded as bech32
    // without a checksum. This is the actual parsing path exercised by
    // payjoin-mailroom when routing /{id} requests.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(id) = s.parse::<ShortId>() {
            let reencoded = id.to_string();
            let reparsed: ShortId =
                reencoded.parse().expect("re-encoding a parsed ShortId must re-parse");
            assert_eq!(reparsed, id, "round-trip mismatch via FromStr/Display: {s}");
        }
    }
}

fuzz_target!(|data| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    #[test]
    fn empty_input_does_not_crash() { super::do_test(&[]); }

    #[test]
    fn eight_zero_bytes_round_trip() { super::do_test(&[0u8; 8]); }

    #[test]
    fn every_length_boundary() {
        super::do_test(&[0u8; 7]);
        super::do_test(&[0u8; 9]);
    }
}

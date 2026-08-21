#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use payjoin::bitcoin::address::{Address, NetworkUnchecked};
use payjoin::Uri;

const SCHEME: &str = "bitcoin:";

/// One canonical address per script type, so the mutator keeps every type
/// the target inspects in rotation.
const ADDRESSES: [&str; 4] = [
    "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",
    "3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
];

/// Query handed to an input that carries none, so the first mutation
/// already lands on the payjoin parameters.
const DEFAULT_QUERY: &str = "amount=1&pj=https://example.com&pjos=0";

/// Share of mutations left to libFuzzer untouched. Everything the mutator
/// emits parses as a BIP 21 URI, so without a raw share the parser's reject
/// paths, and non-UTF-8 input, stop being covered at all.
const RAW_MUTATION_IN: u32 = 4;

/// Split `bitcoin:<address>?<query>`, substituting a canonical address
/// whenever the input does not carry one that parses.
///
/// A bitcoin address is checksummed, so libFuzzer cannot construct one:
/// unlike a character-set check, which it learns from the comparisons it
/// traces, a checksum gives it no way to turn the constant it needs into
/// input bytes. Without help every input is rejected before the payjoin
/// parameters are ever read. Substituting an address here bootstraps the
/// target from an empty corpus, and re-emitting an intact one keeps
/// mutations from falling straight back out of the parser.
fn split_uri(input: &str, seed: u32) -> (&str, &str) {
    let rest = input.strip_prefix(SCHEME).unwrap_or_default();
    let (address, query) = match rest.find('?') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, DEFAULT_QUERY),
    };

    if address.parse::<Address<NetworkUnchecked>>().is_ok() {
        (address, query)
    } else {
        (ADDRESSES[seed as usize % ADDRESSES.len()], query)
    }
}

// Spend the mutation budget on the query, where the payjoin parameters
// live, rather than on the address.
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if seed.is_multiple_of(RAW_MUTATION_IN) {
        return fuzzer_mutate(data, size, max_size);
    }

    let input = std::str::from_utf8(&data[..size]).unwrap_or_default();
    let (address, query) = split_uri(input, seed);
    let prefix = format!("{SCHEME}{address}?");
    let mut buf = query.as_bytes().to_vec();

    let query_max = max_size.saturating_sub(prefix.len());
    if query_max == 0 {
        return fuzzer_mutate(data, size, max_size);
    }
    let query_len = buf.len().min(query_max);
    buf.resize(query_max, 0);
    let query_len = fuzzer_mutate(&mut buf, query_len, query_max);

    data[..prefix.len()].copy_from_slice(prefix.as_bytes());
    data[prefix.len()..prefix.len() + query_len].copy_from_slice(&buf[..query_len]);
    prefix.len() + query_len
});

fn do_test(data: &[u8]) {
    if let Ok(uri_str) = std::str::from_utf8(data) {
        let pj_uri = match Uri::try_from(uri_str.to_string()) {
            Ok(uri) => uri.assume_checked(),
            Err(_) => return,
        };
        let _ = pj_uri.address().is_spend_standard();
        let _ = pj_uri.label();
        let _ = pj_uri.message();
        let Ok(pj_extras) = pj_uri.check_pj_supported() else { return };
        let _ = pj_extras.extras().output_substitution();
        let _ = pj_extras.extras().endpoint();
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

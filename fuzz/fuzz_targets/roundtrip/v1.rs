#![cfg_attr(not(test), no_main)]

use std::str::FromStr;
use std::sync::LazyLock;

use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{Address, FeeRate, Network};
use payjoin::receive::v1::{build_v1_pj_uri, Headers, UncheckedOriginalPayload};
use payjoin::send::v1::SenderBuilder;
use payjoin::OutputSubstitution;

/// The BIP-78 test vector original PSBT, the same one payjoin-test-utils
/// hands to the send and receive unit tests.
///
/// A PSBT that survives the sender builder is not something libFuzzer can
/// assemble: it needs funded inputs, an output paying the URI's address,
/// and consistent values. Measured over 200k runs, roughly 4% of raw
/// inputs deserialize as a PSBT at all and none of those reach the
/// receiver. Seeding a known-good one is what puts the state machine,
/// rather than the rust-bitcoin PSBT parser, under test.
const SEED_PSBT_B64: &str = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

static SEED_PSBT: LazyLock<Vec<u8>> =
    LazyLock::new(|| Psbt::from_str(SEED_PSBT_B64).expect("BIP-78 vector must parse").serialize());

/// Endpoint the sender posts to. Fixed: URL parsing has its own target.
const ENDPOINT: &str = "https://example.com";

/// Query handed to an input that carries none, so the first mutation
/// already lands on the BIP-78 parameters rather than on empty bytes.
const DEFAULT_QUERY: &str = "maxadditionalfeecontribution=182&additionalfeeoutputindex=0";

/// Share of mutations left to libFuzzer untouched. This is also the only
/// path that reaches the PSBT bytes, so it doubles as coverage of the
/// sender builder's own rejection paths.
const RAW_MUTATION_IN: u32 = 4;

/// Length prefix, in bytes, of the PSBT section.
const HEADER: usize = 2;

/// Split `[len:2][psbt][query]`. A truncated or oversized length yields as
/// much PSBT as the buffer actually holds, so the split never panics.
fn split_input(data: &[u8]) -> (&[u8], &[u8]) {
    if data.len() < HEADER {
        return (&[], &[]);
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let rest = &data[HEADER..];
    rest.split_at(len.min(rest.len()))
}

struct FuzzHeaders {
    length: String,
}

impl Headers for FuzzHeaders {
    fn get_header(&self, key: &str) -> Option<&str> {
        match key.to_lowercase().as_str() {
            "content-length" => Some(&self.length),
            "content-type" => Some("text/plain"),
            _ => None,
        }
    }
}

// Keep the PSBT section intact and spend the mutation budget on the query,
// where the attacker-controlled BIP-78 parameters live.
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if seed.is_multiple_of(RAW_MUTATION_IN) {
        return fuzzer_mutate(data, size, max_size);
    }

    let (psbt, query) = split_input(&data[..size]);
    let psbt: Vec<u8> =
        if Psbt::deserialize(psbt).is_ok() { psbt.to_vec() } else { SEED_PSBT.clone() };
    let query: Vec<u8> =
        if query.is_empty() { DEFAULT_QUERY.as_bytes().to_vec() } else { query.to_vec() };

    let Ok(psbt_len) = u16::try_from(psbt.len()) else {
        return fuzzer_mutate(data, size, max_size);
    };
    if max_size <= HEADER + psbt.len() {
        return fuzzer_mutate(data, size, max_size);
    }
    let query_max = max_size - HEADER - psbt.len();

    let mut buf = query.to_vec();
    let query_len = buf.len().min(query_max);
    buf.resize(query_max, 0);
    let query_len = fuzzer_mutate(&mut buf, query_len, query_max);

    data[..HEADER].copy_from_slice(&psbt_len.to_be_bytes());
    data[HEADER..HEADER + psbt.len()].copy_from_slice(&psbt);
    data[HEADER + psbt.len()..HEADER + psbt.len() + query_len].copy_from_slice(&buf[..query_len]);
    HEADER + psbt.len() + query_len
});

fn do_test(data: &[u8]) -> bool {
    let (psbt_bytes, query_bytes) = split_input(data);
    let Ok(psbt) = Psbt::deserialize(psbt_bytes) else { return false };
    let Ok(query) = std::str::from_utf8(query_bytes) else { return false };

    // The payee is output 1 of the BIP-78 vector. Deriving the URI address
    // from the PSBT rather than hardcoding it keeps the two in agreement:
    // a mismatch makes the sender builder reject every input, which is how
    // the first version of this target ended up never reaching a receiver.
    let Some(txout) = psbt.unsigned_tx.output.get(1) else { return false };
    let Ok(address) = Address::from_script(&txout.script_pubkey, Network::Bitcoin) else {
        return false;
    };
    let Ok(uri) = build_v1_pj_uri(&address, ENDPOINT, OutputSubstitution::Enabled) else {
        return false;
    };

    let Ok(sender) = SenderBuilder::new(psbt, uri).build_non_incentivizing(FeeRate::ZERO) else {
        return false;
    };
    let (request, v1_ctx) = sender.create_v1_post_request();

    let headers = FuzzHeaders { length: request.body.len().to_string() };
    let Ok(unchecked) = UncheckedOriginalPayload::from_request(&request.body, query, headers)
    else {
        return false;
    };

    // Every check answers unconditionally: a real receiver's answers depend
    // on its own UTXO set, which is not what this target exercises.
    let Ok(seen) =
        unchecked.assume_interactive_receiver().check_inputs_not_owned(&mut |_| Ok(false))
    else {
        return false;
    };
    let Ok(unknown) = seen.check_no_inputs_seen_before(&mut |_| Ok(false)) else { return false };
    let Ok(wants_outputs) = unknown.identify_receiver_outputs(&mut |_| Ok(true)) else {
        return false;
    };

    // substitute_receiver_script, replace_receiver_outputs and
    // contribute_inputs all take receiver-chosen values, so committing
    // straight through keeps the target on the untrusted path.
    let wants_fee_range = wants_outputs.commit_outputs().commit_inputs();

    let Ok(provisional) = wants_fee_range.apply_fee_range(None, None) else { return false };
    let Ok(proposal) = provisional.finalize_proposal(|psbt| Ok(psbt.clone())) else { return false };

    // Close the loop: the sender validates the receiver's proposal.
    // Rejections are expected during fuzzing; the seed test requires success.
    let response = proposal.psbt().to_string();
    v1_ctx.process_response(response.as_bytes()).is_ok()
}

fuzz_target!(|data| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    #[test]
    fn empty_input_does_not_crash() { super::do_test(&[]); }

    #[test]
    fn length_prefix_beyond_buffer_does_not_panic() { super::do_test(&[0xff, 0xff, 0x00]); }

    /// The seed PSBT with a well-formed query must walk the whole chain.
    /// If this stops holding, the target has silently stopped testing the
    /// roundtrip and is only exercising rejection paths again.
    #[test]
    fn seed_psbt_reaches_the_receiver() {
        let psbt = &*super::SEED_PSBT;
        let len = u16::try_from(psbt.len()).expect("seed fits in u16");
        let mut input = len.to_be_bytes().to_vec();
        input.extend_from_slice(psbt);
        input.extend_from_slice(super::DEFAULT_QUERY.as_bytes());
        assert!(super::do_test(&input));
    }
}

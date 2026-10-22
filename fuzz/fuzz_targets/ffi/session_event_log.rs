#![no_main]

use std::sync::{Arc, LazyLock};

use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use payjoin::bitcoin::hex::{DisplayHex, FromHex};
use payjoin::{receive, send};
use payjoin_ffi::error::ForeignError;
use payjoin_ffi::{
    replay_receiver_event_log, replay_sender_event_log, JsonReceiverSessionPersister,
    JsonSenderSessionPersister, ReceiverSessionEvent, SenderSessionEvent,
};
use serde_json::Value;

/// Complete receiver and sender sessions, one event per line. Every prefix
/// replays successfully, so mutations start from a reachable state.
const SEED_LOGS: [&str; 2] =
    [include_str!("seeds/receiver.jsonl"), include_str!("seeds/sender.jsonl")];

/// Share of mutations left to libFuzzer untouched, so malformed JSON and
/// non-UTF-8 input stay covered.
const RAW_MUTATION_IN: u32 = 4;

/// Extra bytes a mutated leaf may grow by.
const LEAF_HEADROOM: usize = 32;

static SEEDS: LazyLock<Vec<Vec<Value>>> = LazyLock::new(|| {
    SEED_LOGS
        .iter()
        .map(|log| log.lines().map(|e| serde_json::from_str(e).expect("valid seed")).collect())
        .collect()
});

/// Event log handed back by the host, as a JSON persister would on resume.
struct EventLog(Vec<String>);

impl JsonReceiverSessionPersister for EventLog {
    fn save(&self, _: String) -> Result<(), ForeignError> { Ok(()) }
    fn load(&self) -> Result<Vec<String>, ForeignError> { Ok(self.0.clone()) }
    fn close(&self) -> Result<(), ForeignError> { Ok(()) }
}

impl JsonSenderSessionPersister for EventLog {
    fn save(&self, _: String) -> Result<(), ForeignError> { Ok(()) }
    fn load(&self) -> Result<Vec<String>, ForeignError> { Ok(self.0.clone()) }
    fn close(&self) -> Result<(), ForeignError> { Ok(()) }
}

struct Rng(u32);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0 as usize % n.max(1)
    }
}

fn mutate_bytes(mut bytes: Vec<u8>) -> Vec<u8> {
    let len = bytes.len();
    bytes.resize(len + LEAF_HEADROOM, 0);
    let max = bytes.len();
    let new_len = fuzzer_mutate(&mut bytes, len, max);
    bytes.truncate(new_len);
    bytes
}

/// Byte fields (keys, ids, OHTTP configs) serialize as arrays of numbers.
fn as_bytes(value: &Value) -> Option<Vec<u8>> {
    value.as_array()?.iter().map(|v| u8::try_from(v.as_u64()?).ok()).collect()
}

fn is_leaf(value: &Value) -> bool {
    !(value.is_array() || value.is_object()) || as_bytes(value).is_some()
}

fn count_leaves(value: &Value) -> usize {
    match value {
        _ if is_leaf(value) => 1,
        Value::Array(items) => items.iter().map(count_leaves).sum(),
        Value::Object(map) => map.values().map(count_leaves).sum(),
        _ => 0,
    }
}

// Scripts, txids and signatures are hex strings, and byte fields are number
// arrays. Mutating their decoded bytes, rather than the JSON text, keeps
// mutations past the encoding check and into the bitcoin and payjoin
// decoders behind it.
fn mutate_leaf(value: &mut Value) {
    if let Some(bytes) = as_bytes(value) {
        *value = mutate_bytes(bytes).into_iter().map(Value::from).collect();
        return;
    }
    match value {
        Value::String(s) => match Vec::<u8>::from_hex(s) {
            Ok(bytes) if !s.is_empty() => *s = mutate_bytes(bytes).to_lower_hex_string(),
            _ => *s = String::from_utf8_lossy(&mutate_bytes(s.clone().into_bytes())).into_owned(),
        },
        Value::Number(n) => {
            let mut bytes = n.as_u64().unwrap_or_default().to_le_bytes();
            fuzzer_mutate(&mut bytes, 8, 8);
            *value = u64::from_le_bytes(bytes).into();
        }
        Value::Bool(b) => *b = !*b,
        _ => {}
    }
}

fn mutate_nth_leaf(value: &mut Value, n: &mut usize) -> bool {
    if is_leaf(value) {
        if *n == 0 {
            mutate_leaf(value);
            return true;
        }
        *n -= 1;
        return false;
    }
    match value {
        Value::Array(items) => items.iter_mut().any(|v| mutate_nth_leaf(v, n)),
        Value::Object(map) => map.values_mut().any(|v| mutate_nth_leaf(v, n)),
        _ => false,
    }
}

fn mutate_log(log: &mut Vec<Value>, rng: &mut Rng) {
    let seed = &SEEDS[rng.below(SEEDS.len())];
    let i = rng.below(log.len());
    let j = rng.below(log.len());
    match rng.below(5) {
        0 | 1 => {
            let mut n = rng.below(count_leaves(&log[i]));
            mutate_nth_leaf(&mut log[i], &mut n);
        }
        // Reordering, dropping and repeating events drives replay through
        // transitions a well-behaved persister never produces.
        2 if log.len() > 1 => {
            log.remove(i);
        }
        2 => log.push(log[i].clone()),
        3 => log.swap(i, j),
        _ => log.insert(rng.below(log.len() + 1), seed[rng.below(seed.len())].clone()),
    }
}

fn seed_prefix(rng: &mut Rng, max_size: usize) -> Vec<Value> {
    let seed = &SEEDS[rng.below(SEEDS.len())];
    let mut len = rng.below(seed.len()) + 1;
    while len > 1 && encode(&seed[..len]).len() > max_size {
        len -= 1;
    }
    seed[..len].to_vec()
}

fn encode(log: &[Value]) -> Vec<u8> {
    log.iter().map(Value::to_string).collect::<Vec<_>>().join("\n").into_bytes()
}

// Libfuzzer cannot write a valid PSBT, key or OHTTP config into JSON on its
// own, so start from a real session and mutate it event by event.
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if seed.is_multiple_of(RAW_MUTATION_IN) {
        return fuzzer_mutate(data, size, max_size);
    }

    let mut rng = Rng(seed);
    let input = std::str::from_utf8(&data[..size]).unwrap_or_default();
    let mut log: Vec<Value> = input.lines().filter_map(|e| serde_json::from_str(e).ok()).collect();
    if log.is_empty() {
        log = seed_prefix(&mut rng, max_size);
    } else {
        mutate_log(&mut log, &mut rng);
    }

    let out = encode(&log);
    if out.len() > max_size {
        return fuzzer_mutate(data, size, max_size);
    }
    data[..out.len()].copy_from_slice(&out);
    out.len()
});

fn check_round_trip(event: &str) {
    if let Ok(decoded) = ReceiverSessionEvent::from_json(event.to_string()) {
        let encoded = decoded.to_json().expect("a decoded receiver event must re-encode");
        let reparsed = ReceiverSessionEvent::from_json(encoded.clone())
            .expect("a re-encoded receiver event must decode");
        assert_eq!(
            receive::v2::SessionEvent::from(decoded),
            receive::v2::SessionEvent::from(reparsed),
            "receiver event round-trip mismatch: {encoded}"
        );
    }

    if let Ok(decoded) = SenderSessionEvent::from_json(event.to_string()) {
        let encoded = decoded.to_json().expect("a decoded sender event must re-encode");
        let reparsed = SenderSessionEvent::from_json(encoded.clone())
            .expect("a re-encoded sender event must decode");
        assert_eq!(
            send::v2::SessionEvent::from(decoded),
            send::v2::SessionEvent::from(reparsed),
            "sender event round-trip mismatch: {encoded}"
        );
    }
}

// Bindings persist session events as JSON in host-side storage and replay
// them on resume, so both the events and their order come from outside Rust.
fn do_test(data: &[u8]) {
    let Ok(input) = std::str::from_utf8(data) else { return };
    let events: Vec<String> = input.lines().map(str::to_owned).collect();
    for event in &events {
        check_round_trip(event);
    }

    let log = Arc::new(EventLog(events));
    if let Ok(replay) = replay_receiver_event_log(log.clone()) {
        let history = replay.session_history();
        let _ = history.pj_uri();
        let _ = history.fallback_tx();
        let _ = history.status();
    }
    if let Ok(replay) = replay_sender_event_log(log) {
        let history = replay.session_history();
        let _ = history.pj_param();
        let _ = history.fallback_tx();
        let _ = history.status();
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
    fn non_utf8_input_does_not_crash() { super::do_test(&[0xff, 0xfe]); }

    #[test]
    fn seed_logs_do_not_crash() {
        for log in super::SEED_LOGS {
            super::do_test(log.as_bytes());
        }
    }
}

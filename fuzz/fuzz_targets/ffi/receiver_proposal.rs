#![no_main]

use std::future::Future;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use payjoin::bitcoin::consensus::encode::serialize;
use payjoin::bitcoin::hashes::Hash as _;
use payjoin::bitcoin::hex::FromHex;
use payjoin::bitcoin::psbt::{raw, Psbt};
use payjoin::bitcoin::{
    absolute, transaction, Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Weight, Witness,
};
use payjoin_ffi::error::ForeignError;
use payjoin_ffi::{
    replay_receiver_event_log, InputPair, JsonReceiverSessionPersister,
    JsonReceiverSessionPersisterAsync, OutputSubstitution, PayjoinProposal, ProcessPsbt,
    ProvisionalProposal, ReceiveSession, WantsFeeRange, WantsInputs, WantsOutputs,
};
use serde_json::Value;

/// A receiver session whose first five events replay to an OutputsUnknown.
const SESSION: &str = include_str!("seeds/receiver.jsonl");
const EVENTS_TO_OUTPUTS_UNKNOWN: usize = 5;

/// Choices that end a session early, or that leave the honest path, are
/// decoded as rare ones, otherwise almost no input would reach the later
/// stages.
const RARE_IN: u8 = 8;

const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
/// The FFI's limit on a script, as in payjoin-ffi's validation.
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_ORIGINAL_OUTPUTS: usize = 4;
const MAX_REPLACEMENTS: usize = 4;
const MAX_CANDIDATES: usize = 4;
const MAX_OUTPUT_OPS: usize = 3;
const MAX_RAW_SCRIPT: usize = 40;
const MAX_OUTPUT_SAT: u64 = 100_000_000;
/// The sender's minfeerate is capped at parse time at this many sat/kwu.
const MAX_SENDER_FEE_RATE_SAT_PER_KWU: u64 = 6_250_000;
const MAX_FEE_RATE_SAT_PER_VB: u64 = 500;

/// The seed's sender and receiver scripts, then one of each common type.
const SCRIPTS: [&str; 7] = [
    "a9141de849f069d274150e3afeae8d72eb5a6b09443087",
    "a914774096dbcf486743c22f4347e9b469febe8b677a87",
    "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    "0020751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45",
    "51200101010101010101010101010101010101010101010101010101010101010101",
    "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    "6a",
];

const RELAYS: [&str; 3] = ["https://relay.example.com", "http://127.0.0.1:8000", ""];

// ---------------------------------------------------------------------------
// Host-side persistence
// ---------------------------------------------------------------------------

/// Records what each transition persists, or refuses every save when the
/// host's storage is failing. Replay only reads the log.
struct Persister {
    log: Vec<String>,
    failing: bool,
    saved: Mutex<Vec<String>>,
}

impl Persister {
    fn new(log: &[String], failing: bool) -> Arc<Self> {
        Arc::new(Self { log: log.to_vec(), failing, saved: Mutex::default() })
    }

    fn saved(&self) -> Vec<String> { self.saved.lock().expect("not poisoned").clone() }
}

impl JsonReceiverSessionPersister for Persister {
    fn save(&self, event: String) -> Result<(), ForeignError> {
        if self.failing {
            return Err(ForeignError::InternalError("storage failure".to_string()));
        }
        self.saved.lock().expect("not poisoned").push(event);
        Ok(())
    }
    fn load(&self) -> Result<Vec<String>, ForeignError> { Ok(self.log.clone()) }
    fn close(&self) -> Result<(), ForeignError> { Ok(()) }
}

#[async_trait::async_trait]
impl JsonReceiverSessionPersisterAsync for Persister {
    async fn save(&self, event: String) -> Result<(), ForeignError> {
        JsonReceiverSessionPersister::save(self, event)
    }
    async fn load(&self) -> Result<Vec<String>, ForeignError> {
        JsonReceiverSessionPersister::load(self)
    }
    async fn close(&self) -> Result<(), ForeignError> { JsonReceiverSessionPersister::close(self) }
}

/// The persister never suspends, so a future here is ready on its first
/// poll; looping guards against one that is not.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

/// How one transition is saved: through the sync or the async persister
/// adapter, against working or failing storage.
struct Store<'a> {
    log: &'a [String],
    asynchronous: bool,
    failing: bool,
}

impl<'a> Store<'a> {
    fn draw(log: &'a [String], u: &mut Unstructured) -> arbitrary::Result<Self> {
        Ok(Self { log, asynchronous: u.arbitrary()?, failing: false })
    }

    fn failing(log: &'a [String], u: &mut Unstructured) -> arbitrary::Result<Self> {
        Ok(Self { failing: true, ..Self::draw(log, u)? })
    }
}

/// What a transition did once saved: whether it advanced, and which events
/// it persisted on the way.
#[derive(Debug, PartialEq)]
struct Outcome {
    advanced: bool,
    events: Vec<String>,
}

const REJECTED: Outcome = Outcome { advanced: false, events: Vec::new() };

// The sync and async adapters wrap the same transition, so the store picks
// one per save and every comparison below also checks that they agree.
macro_rules! save {
    ($store:expr, $transition:expr) => {{
        let store: &Store = $store;
        let persister = Persister::new(store.log, store.failing);
        let transition = $transition;
        let result = if store.asynchronous {
            block_on(transition.save_async(persister.clone()))
        } else {
            transition.save(persister.clone())
        };
        let outcome = Outcome { advanced: result.is_ok(), events: persister.saved() };
        (result.ok(), outcome)
    }};
}

/// Before a stage, a host that saved one transition but crashed before the
/// next one has to save it again, so a failing store must leave the session
/// where it was.
macro_rules! check_failing_store {
    ($log:expr, $u:expr, $transition:expr) => {
        if rare($u)? {
            let (_, outcome) = save!(&Store::failing($log, $u)?, $transition);
            assert_eq!(outcome, REJECTED, "a session advanced without its storage");
        }
    };
}

fn replay(log: &[String]) -> ReceiveSession {
    replay_receiver_event_log(Persister::new(log, false))
        .expect("a session the receiver persisted replays")
        .state()
}

fn extend(log: &[String], outcome: &Outcome) -> Vec<String> {
    log.iter().chain(&outcome.events).cloned().collect()
}

/// The single event a save persisted, parsed, under its variant name.
fn event(outcome: &Outcome, variant: &str) -> Value {
    assert_eq!(outcome.events.len(), 1, "a transition persisted {:?}", outcome.events);
    let mut event: Value = serde_json::from_str(&outcome.events[0]).expect("events are JSON");
    event
        .get_mut(variant)
        .map(Value::take)
        .unwrap_or_else(|| panic!("expected {variant}, persisted {}", outcome.events[0]))
}

// A macro rather than a function, so the fuzz crate needs no serde bound.
macro_rules! from_value {
    ($ty:ty, $value:expr) => {
        serde_json::from_value::<$ty>($value.clone()).expect("persisted bitcoin types decode")
    };
}

// ---------------------------------------------------------------------------
// Input decoding
// ---------------------------------------------------------------------------

/// True one time in RARE_IN, and false for an exhausted input.
fn rare(u: &mut Unstructured) -> arbitrary::Result<bool> {
    Ok(u.int_in_range(0..=RARE_IN - 1)? == RARE_IN - 1)
}

fn below(u: &mut Unstructured, len: usize) -> arbitrary::Result<usize> {
    u.int_in_range(0..=len.saturating_sub(1))
}

fn bytes(u: &mut Unstructured, max: usize) -> arbitrary::Result<Vec<u8>> {
    let len = below(u, max + 1)?;
    Ok(u.bytes(len)?.to_vec())
}

fn script_from_hex(hex: &str) -> ScriptBuf {
    ScriptBuf::from_bytes(Vec::from_hex(hex).expect("table scripts are hex"))
}

/// A script from the original outputs, the table or raw bytes, or rarely
/// one the FFI must refuse.
fn script(u: &mut Unstructured, original: &[TxOut]) -> arbitrary::Result<ScriptBuf> {
    let choice = below(u, original.len() + SCRIPTS.len() + 1)?;
    if let Some(output) = original.get(choice) {
        return Ok(output.script_pubkey.clone());
    }
    if let Some(script) = SCRIPTS.get(choice - original.len()) {
        return Ok(script_from_hex(script));
    }
    if rare(u)? {
        let len = if u.arbitrary()? { 0 } else { MAX_SCRIPT_BYTES + 1 };
        return Ok(ScriptBuf::from_bytes(vec![0; len]));
    }
    let len = u.int_in_range(1..=MAX_RAW_SCRIPT)?;
    Ok(ScriptBuf::from_bytes(u.bytes(len)?.to_vec()))
}

/// Near a reference value, or rarely any u64, so the FFI's MAX_MONEY check
/// is reachable.
fn amount(u: &mut Unstructured, reference: u64) -> arbitrary::Result<u64> {
    if rare(u)? {
        return u.arbitrary();
    }
    let delta = u.int_in_range(0..=reference.min(MAX_OUTPUT_SAT))?;
    Ok(match u.int_in_range(0..=3u8)? {
        0 => reference,
        1 => reference.saturating_add(delta),
        2 => reference - delta,
        _ => delta,
    })
}

fn ffi_valid_script(script: &ScriptBuf) -> bool {
    !script.is_empty() && script.len() <= MAX_SCRIPT_BYTES
}

fn ffi_tx_out(output: &TxOut) -> payjoin_ffi::TxOut {
    payjoin_ffi::TxOut {
        value_sat: output.value.to_sat(),
        script_pubkey: output.script_pubkey.to_bytes(),
    }
}

/// TxOut amounts above MAX_MONEY never reach the core, so outputs here are
/// built from u64s the FFI has not seen yet.
fn tx_out(value_sat: u64, script_pubkey: ScriptBuf) -> TxOut {
    TxOut { value: Amount::from_sat(value_sat), script_pubkey }
}

// ---------------------------------------------------------------------------
// The original proposal
// ---------------------------------------------------------------------------

/// What the receiver knows about the sender's proposal once its own outputs
/// are identified.
struct Original {
    log: Vec<String>,
    outputs: Vec<TxOut>,
    owned: Vec<usize>,
    substitution: OutputSubstitution,
    /// The fee contribution as it survives the core's sanitization.
    fee_contribution: Option<(Amount, usize)>,
    min_fee_rate: FeeRate,
    max_fee_rate: FeeRate,
    inputs: Vec<OutPoint>,
    sequence: Sequence,
}

impl Original {
    fn sender_outputs(&self) -> Vec<TxOut> {
        self.outputs
            .iter()
            .enumerate()
            .filter(|(vout, _)| !self.owned.contains(vout))
            .map(|(_, output)| output.clone())
            .collect()
    }

    fn receiver_outputs(&self) -> Vec<TxOut> {
        self.owned.iter().map(|&vout| self.outputs[vout].clone()).collect()
    }

    fn output_sum(&self) -> u64 { self.outputs.iter().map(|o| o.value.to_sat()).sum() }

    fn output_weight(&self) -> Weight { self.outputs.iter().map(TxOut::weight).sum() }
}

/// Rebuild the seed's original proposal with fuzzer-chosen outputs, owned
/// outputs and sender parameters. The seed's own values are the common case.
fn original(u: &mut Unstructured) -> arbitrary::Result<Original> {
    let mut log: Vec<String> =
        SESSION.lines().take(EVENTS_TO_OUTPUTS_UNKNOWN).map(str::to_owned).collect();
    let mut retrieved: Value = serde_json::from_str(&log[1]).expect("valid seed");
    let created: Value = serde_json::from_str(&log[0]).expect("valid seed");
    let original = &mut retrieved["RetrievedOriginalPayload"]["original"];

    let mut outputs = from_value!(Vec<TxOut>, original["psbt"]["unsigned_tx"]["output"]);
    if rare(u)? {
        let seed = outputs.clone();
        outputs.clear();
        for _ in 0..u.int_in_range(1..=MAX_ORIGINAL_OUTPUTS)? {
            let value = u.int_in_range(0..=MAX_OUTPUT_SAT)?;
            outputs.push(tx_out(value, script(u, &seed)?));
        }
    }
    let psbt_output = original["psbt"]["outputs"][1].clone();
    original["psbt"]["unsigned_tx"]["output"] = serde_json::to_value(&outputs).expect("encodes");
    original["psbt"]["outputs"] = vec![psbt_output; outputs.len()].into();

    // The seed pays the receiver at vout 1.
    let mut owned = vec![1.min(outputs.len() - 1)];
    if rare(u)? {
        let mask: u8 = u.arbitrary()?;
        let picked: Vec<usize> = (0..outputs.len()).filter(|i| mask & (1 << i) != 0).collect();
        if !picked.is_empty() {
            owned = picked;
        }
    }

    let params = &mut original["params"];
    let substitution = if rare(u)? {
        params["output_substitution"] = "Disabled".into();
        OutputSubstitution::Disabled
    } else {
        OutputSubstitution::Enabled
    };
    if rare(u)? {
        params["additional_fee_contribution"] = if u.arbitrary()? {
            Value::Null
        } else {
            let index = u.int_in_range(0..=outputs.len())?;
            serde_json::json!([amount(u, 182)?, index])
        };
    }
    if rare(u)? {
        params["min_fee_rate"] = u.int_in_range(0..=MAX_SENDER_FEE_RATE_SAT_PER_KWU)?.into();
    }

    let fee_contribution = params["additional_fee_contribution"].as_array().and_then(|pair| {
        let amount = Amount::from_sat(pair[0].as_u64()?);
        let index = usize::try_from(pair[1].as_u64()?).ok()?;
        let fee_output = outputs.get(index)?;
        (!owned.contains(&index) && fee_output.value >= amount).then_some((amount, index))
    });
    let min_fee_rate = FeeRate::from_sat_per_kwu(params["min_fee_rate"].as_u64().expect("u64"));
    let max_fee_rate =
        FeeRate::from_sat_per_kwu(created["Created"]["max_fee_rate"].as_u64().expect("u64"));
    let unsigned_inputs = from_value!(Vec<TxIn>, original["psbt"]["unsigned_tx"]["input"]);

    log[1] = retrieved.to_string();
    log.push(serde_json::json!({ "IdentifiedReceiverOutputs": owned }).to_string());
    Ok(Original {
        log,
        outputs,
        owned,
        substitution,
        fee_contribution,
        min_fee_rate,
        max_fee_rate,
        inputs: unsigned_inputs.iter().map(|txin| txin.previous_output).collect(),
        sequence: unsigned_inputs[0].sequence,
    })
}

// ---------------------------------------------------------------------------
// Stage 1: output substitution
// ---------------------------------------------------------------------------

/// The receiver outputs and drain script the last successful substitution
/// left, as the core should compute them.
struct Substitution {
    receiver_outputs: Vec<TxOut>,
    drain: ScriptBuf,
    /// False when a substitute_receiver_script kept a drain value the model
    /// could not pin down, so only scripts can be compared.
    exact: bool,
}

/// Whether the core should accept these replacement outputs, mirroring its
/// matching: each original receiver output, in order, takes a replacement
/// with the same script, or any replacement when substitution is enabled.
fn replacement_accepted(original: &Original, replacements: &[TxOut], drain: &ScriptBuf) -> bool {
    let mut remaining = replacements.to_vec();
    for receiver_output in original.receiver_outputs() {
        if remaining.is_empty() {
            return false;
        }
        match remaining.iter().position(|o| o.script_pubkey == receiver_output.script_pubkey) {
            Some(index) => {
                let replacement = remaining.swap_remove(index);
                if original.substitution == OutputSubstitution::Disabled
                    && replacement.value < receiver_output.value
                {
                    return false;
                }
            }
            None if original.substitution == OutputSubstitution::Disabled => return false,
            // Which one the core takes is random, and nothing below depends
            // on it.
            None => {
                remaining.pop();
            }
        }
    }
    // The drain is the receiver's change: it must be one of the replacement
    // outputs, and never a script a sender output carries, which the core now
    // rejects as DrainScriptPaysSender even when a receiver output shares it.
    replacements.iter().any(|o| o.script_pubkey == *drain)
        && original.sender_outputs().iter().all(|o| o.script_pubkey != *drain)
}

fn substitute_outputs(
    state: &Arc<WantsOutputs>,
    original: &Original,
    u: &mut Unstructured,
) -> arbitrary::Result<(Arc<WantsOutputs>, Option<Substitution>)> {
    assert_eq!(state.output_substitution(), original.substitution);
    let mut state = state.clone();
    let mut last: Option<Substitution> = None;
    let receiver_value = original.receiver_outputs()[0].value.to_sat();

    for _ in 0..u.int_in_range(0..=MAX_OUTPUT_OPS)? {
        if u.arbitrary()? {
            let script = script(u, &original.outputs)?;
            // The core keeps the drain output's value, which only the model
            // of the last substitution knows.
            let sender_scripts: Vec<_> =
                original.sender_outputs().into_iter().map(|o| o.script_pubkey).collect();
            let value = match &last {
                None => Some(original.outputs[original.owned[0]].value),
                Some(last) if last.exact && !sender_scripts.contains(&last.drain) => {
                    let mut drains =
                        last.receiver_outputs.iter().filter(|o| o.script_pubkey == last.drain);
                    match (drains.next(), drains.next()) {
                        (Some(drain), None) => Some(drain.value),
                        _ => None,
                    }
                }
                Some(_) => None,
            };
            let result = state.substitute_receiver_script(script.to_bytes());
            if !ffi_valid_script(&script) {
                assert!(result.is_err(), "the FFI accepted an invalid script");
                continue;
            }
            if let Some(value) = value {
                let replacement = vec![TxOut { value, script_pubkey: script.clone() }];
                assert_eq!(
                    result.is_ok(),
                    replacement_accepted(original, &replacement, &script),
                    "substitute_receiver_script disagreed with the substitution rules"
                );
            }
            if let Ok(next) = result {
                let output =
                    TxOut { value: value.unwrap_or(Amount::ZERO), script_pubkey: script.clone() };
                last = Some(Substitution {
                    receiver_outputs: vec![output],
                    drain: script,
                    exact: value.is_some(),
                });
                state = Arc::new(next);
            }
        } else {
            let mut values = Vec::new();
            let mut replacements = Vec::new();
            for _ in 0..u.int_in_range(1..=MAX_REPLACEMENTS)? {
                let value = amount(u, receiver_value)?;
                let script = script(u, &original.outputs)?;
                values.push(value);
                replacements.push(tx_out(value.min(MAX_MONEY), script));
            }
            let drain = match u.arbitrary::<bool>()? {
                false => replacements[below(u, replacements.len())?].script_pubkey.clone(),
                true => script(u, &original.outputs)?,
            };
            let ffi_outputs: Vec<_> = replacements
                .iter()
                .zip(&values)
                .map(|(o, v)| payjoin_ffi::TxOut { value_sat: *v, ..ffi_tx_out(o) })
                .collect();
            let result = state.replace_receiver_outputs(ffi_outputs, drain.to_bytes());

            let ffi_valid = values.iter().all(|v| *v <= MAX_MONEY)
                && replacements.iter().all(|o| ffi_valid_script(&o.script_pubkey))
                && ffi_valid_script(&drain);
            if !ffi_valid {
                assert!(result.is_err(), "the FFI accepted an invalid replacement");
                continue;
            }
            assert_eq!(
                result.is_ok(),
                replacement_accepted(original, &replacements, &drain),
                "replace_receiver_outputs disagreed with the substitution rules"
            );
            if let Ok(next) = result {
                last = Some(Substitution { receiver_outputs: replacements, drain, exact: true });
                state = Arc::new(next);
            }
        }
    }
    Ok((state, last))
}

fn sorted(mut outputs: Vec<TxOut>) -> Vec<TxOut> {
    outputs.sort_by(|a, b| (a.value, &a.script_pubkey).cmp(&(b.value, &b.script_pubkey)));
    outputs
}

fn is_subsequence(needle: &[TxOut], haystack: &[TxOut]) -> bool {
    let mut haystack = haystack.iter();
    needle.iter().all(|n| haystack.any(|h| h == n))
}

/// The committed outputs are the sender's, untouched and in order, plus the
/// last substitution's receiver outputs, and the change output is one of the
/// receiver's.
fn check_committed_outputs(
    original: &Original,
    substitution: &Option<Substitution>,
    outputs: &[TxOut],
    change_vout: usize,
) {
    let sender_outputs = original.sender_outputs();
    let Some(substitution) = substitution else {
        assert_eq!(outputs, original.outputs, "outputs changed without a substitution");
        assert_eq!(change_vout, original.owned[0], "change moved without a substitution");
        return;
    };
    let expected: Vec<TxOut> =
        sender_outputs.iter().chain(&substitution.receiver_outputs).cloned().collect();
    if substitution.exact {
        assert_eq!(
            sorted(outputs.to_vec()),
            sorted(expected),
            "committed outputs are not the sender's plus the receiver's"
        );
    } else {
        let scripts = |list: &[TxOut]| {
            let mut scripts: Vec<_> = list.iter().map(|o| o.script_pubkey.clone()).collect();
            scripts.sort();
            scripts
        };
        assert_eq!(scripts(outputs), scripts(&expected), "committed output scripts are wrong");
    }
    assert!(is_subsequence(&sender_outputs, outputs), "sender outputs were reordered or changed");

    let change = &outputs[change_vout];
    assert_eq!(change.script_pubkey, substitution.drain, "change output is not the drain script");
    // Equal outputs are interchangeable, so the change output only has to
    // have a receiver copy among them.
    let copies = |list: &[TxOut]| list.iter().filter(|o| *o == change).count();
    assert!(
        copies(outputs) > copies(&sender_outputs),
        "the drain script resolved to a sender output, so the receiver's change goes to the sender"
    );

    if original.substitution == OutputSubstitution::Disabled {
        // Equal scripts are interchangeable, so a receiver output only counts
        // as changed when no assignment keeps every receiver value. Match the
        // largest receiver values first, each against the smallest committed
        // output that still covers it, which succeeds whenever any assignment
        // does.
        let mut remaining = outputs.to_vec();
        let mut receiver_outputs = original.receiver_outputs();
        receiver_outputs.sort_by_key(|o| std::cmp::Reverse(o.value));
        for receiver_output in receiver_outputs {
            let index = remaining
                .iter()
                .enumerate()
                .filter(|(_, o)| {
                    o.script_pubkey == receiver_output.script_pubkey
                        && o.value >= receiver_output.value
                })
                .min_by_key(|(_, o)| o.value)
                .map(|(index, _)| index)
                .expect("a receiver output changed while substitution is disabled");
            remaining.swap_remove(index);
        }
    }
}

// ---------------------------------------------------------------------------
// Stage 2: input contribution
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Candidate {
    pair: Arc<InputPair>,
    outpoint: OutPoint,
    value: u64,
}

fn outpoint(u: &mut Unstructured, index: usize, taken: &[OutPoint]) -> arbitrary::Result<OutPoint> {
    if rare(u)? && !taken.is_empty() {
        return Ok(taken[below(u, taken.len())?]);
    }
    let mut txid = [index as u8 + 1; 32];
    txid[0] ^= u.arbitrary::<u8>()?;
    Ok(OutPoint { txid: Txid::from_byte_array(txid), vout: u32::from(u.arbitrary::<u8>()?) })
}

fn ffi_outpoint(outpoint: &OutPoint) -> payjoin_ffi::OutPoint {
    payjoin_ffi::OutPoint { txid: outpoint.txid.to_string(), vout: outpoint.vout }
}

/// Build one receiver input through an FFI constructor and check that the
/// constructor accepts exactly the inputs it documents.
fn candidate(
    u: &mut Unstructured,
    index: usize,
    taken: &[OutPoint],
    outputs: &[TxOut],
) -> arbitrary::Result<Option<Candidate>> {
    let outpoint = outpoint(u, index, taken)?;
    let mut ffi_out = ffi_outpoint(&outpoint);
    let bad_txid = rare(u)?;
    if bad_txid {
        ffi_out.txid = ffi_out.txid[..u.int_in_range(0..=63)?].to_string();
    }
    let value = amount(u, 100_000)?;
    let weight = payjoin_ffi::Weight {
        weight_units: if rare(u)? { u.arbitrary()? } else { u.int_in_range(1..=1_000)? },
    };
    let weight_valid = (1..=Weight::MAX_BLOCK.to_wu()).contains(&weight.weight_units);

    let kind = u.int_in_range(0..=5u8)?;
    let right_script = script_from_hex(
        SCRIPTS[match kind {
            1 | 3 => 4,
            2 => 3,
            4 => 5,
            _ => 2,
        }],
    );
    let script = if rare(u)? { script(u, outputs)? } else { right_script };
    let txout = payjoin_ffi::TxOut { value_sat: value, script_pubkey: script.to_bytes() };
    let base_valid = !bad_txid && value <= MAX_MONEY && ffi_valid_script(&script);

    let (result, expected) = match kind {
        0 => (InputPair::new_p2wpkh(txout, ffi_out), Some(base_valid && script.is_p2wpkh())),
        1 => (InputPair::new_p2tr_keyspend(txout, ffi_out), Some(base_valid && script.is_p2tr())),
        2 => (
            InputPair::new_p2wsh(txout, ffi_out, weight),
            Some(base_valid && weight_valid && script.is_p2wsh()),
        ),
        3 => (
            InputPair::new_p2tr_scriptpath_spend(txout, ffi_out, weight),
            Some(base_valid && weight_valid && script.is_p2tr()),
        ),
        4 => {
            // A legacy input is identified by its whole previous transaction.
            let tx = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: vec![tx_out(value.min(MAX_MONEY), script.clone())],
            };
            let bytes = if rare(u)? { bytes(u, 64)? } else { serialize(&tx) };
            let outpoint = OutPoint { txid: tx.compute_txid(), vout: 0 };
            let result = InputPair::new_p2pkh(bytes, ffi_outpoint(&outpoint));
            if let Ok(pair) = &result {
                assert_eq!(pair.outpoint().txid, outpoint.txid.to_string());
            }
            let pair = result.ok().map(Arc::new);
            let value = tx.output[0].value.to_sat();
            return Ok(pair.map(|pair| Candidate { pair, outpoint, value }));
        }
        _ => {
            let txin = payjoin_ffi::TxIn {
                previous_output: ffi_out,
                script_sig: if rare(u)? { bytes(u, 64)? } else { vec![] },
                sequence: u.arbitrary()?,
                witness: if rare(u)? { vec![bytes(u, 72)?] } else { vec![] },
            };
            let psbtin = payjoin_ffi::PsbtInput {
                witness_utxo: (!rare(u)?).then_some(txout),
                redeem_script: None,
                witness_script: rare(u)?.then(|| script_from_hex(SCRIPTS[2]).to_bytes()),
            };
            let expected_weight = rare(u)?.then_some(weight);
            (InputPair::new(txin, psbtin, expected_weight), None)
        }
    };
    if let Some(expected) = expected {
        assert_eq!(result.is_ok(), expected, "an InputPair constructor misjudged its input");
    }
    if let Ok(pair) = &result {
        let reported = pair.outpoint();
        assert_eq!(reported.txid, outpoint.txid.to_string(), "the input reports another txid");
        assert_eq!(reported.vout, outpoint.vout, "the input reports another vout");
    }
    Ok(result.ok().map(|pair| Candidate { pair: Arc::new(pair), outpoint, value }))
}

struct Contribution {
    inputs: Vec<Candidate>,
}

fn contribute_inputs(
    state: Arc<WantsInputs>,
    original: &Original,
    committed: &[TxOut],
    u: &mut Unstructured,
) -> arbitrary::Result<(Arc<WantsInputs>, Contribution)> {
    let mut candidates = Vec::new();
    let mut taken = original.inputs.clone();
    for index in 0..u.int_in_range(1..=MAX_CANDIDATES)? {
        if let Some(candidate) = candidate(u, index, &taken, &original.outputs)? {
            taken.push(candidate.outpoint);
            candidates.push(candidate);
        }
    }

    let pairs = |list: &[Candidate]| list.iter().map(|c| c.pair.clone()).collect::<Vec<_>>();
    let mut first = None;
    if u.arbitrary()? {
        let result = state.try_preserving_privacy(pairs(&candidates));
        assert_eq!(result.is_ok(), !candidates.is_empty(), "coin selection misjudged its list");
        if let Ok(selected) = result {
            let selected = selected.outpoint();
            let position = candidates
                .iter()
                .position(|c| c.outpoint.txid.to_string() == selected.txid)
                .expect("coin selection picked an input it was not offered");
            if committed.len() != 2 {
                assert_eq!(position, 0, "coin selection without two outputs must take the first");
            }
            first = Some(vec![candidates[position].clone()]);
        }
    }

    let original_sum = original.output_sum();
    let committed_sum: u64 = committed.iter().map(|o| o.value.to_sat()).sum();
    let deficit = committed_sum.saturating_sub(original_sum);
    let mut state = state;
    let mut contributed: Vec<Candidate> = Vec::new();
    let calls = if rare(u)? { 2 } else { 1 };
    for call in 0..calls {
        let batch = match first.take().filter(|_| call == 0) {
            Some(batch) => batch,
            None => {
                let mask: u8 = u.arbitrary()?;
                let picked: Vec<_> = candidates
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, c)| c.clone())
                    .collect();
                if picked.is_empty() {
                    candidates.clone()
                } else {
                    picked
                }
            }
        };

        let mut seen: Vec<OutPoint> = original
            .inputs
            .iter()
            .chain(contributed.iter().map(|c| &c.outpoint))
            .cloned()
            .collect();
        let duplicate = batch.iter().any(|c| {
            let dup = seen.contains(&c.outpoint);
            seen.push(c.outpoint);
            dup
        });
        let value: u64 = batch.iter().map(|c| c.value).sum();
        let previous: u64 = contributed.iter().map(|c| c.value).sum();
        // Contributions are cumulative: once an earlier call has covered
        // the receiver's added output value, a later one owes nothing more.
        let owed = deficit.saturating_sub(previous);

        let result = state.contribute_inputs(pairs(&batch));
        assert_eq!(
            result.is_ok(),
            !duplicate && value >= owed,
            "contribute_inputs misjudged {value} sat owing {owed} after {previous}"
        );
        if let Ok(next) = result {
            state = next;
            contributed.extend(batch);
        }
    }
    Ok((state, Contribution { inputs: contributed }))
}

/// The receiver's inputs join the sender's without disturbing them, and
/// their value pays for whatever the receiver added to its outputs, with the
/// rest credited to the change output.
fn check_committed_inputs(
    original: &Original,
    committed: &[TxOut],
    change_vout: usize,
    contribution: &Contribution,
    inputs_event: &Value,
) -> Psbt {
    let psbt = from_value!(Psbt, inputs_event["payjoin_psbt"]);
    let receiver_inputs = inputs_event["receiver_inputs"].as_array().expect("an array");
    assert_eq!(receiver_inputs.len(), contribution.inputs.len(), "contributed inputs went missing");

    let outpoints: Vec<OutPoint> =
        psbt.unsigned_tx.input.iter().map(|i| i.previous_output).collect();
    let mut expected = original.inputs.clone();
    expected.extend(contribution.inputs.iter().map(|c| c.outpoint));
    let (mut got, mut want) = (outpoints.clone(), expected);
    got.sort();
    want.sort();
    assert_eq!(got, want, "the proposal does not spend exactly the sender's and receiver's inputs");
    let mut rest = outpoints.iter();
    assert!(
        original.inputs.iter().all(|o| rest.any(|p| p == o)),
        "the sender's inputs were reordered"
    );
    for txin in &psbt.unsigned_tx.input {
        if !original.inputs.contains(&txin.previous_output) {
            assert_eq!(txin.sequence, original.sequence, "a receiver input has its own sequence");
            assert!(
                txin.script_sig.is_empty() && txin.witness.is_empty(),
                "a receiver input left the unsigned transaction signed"
            );
        }
    }
    assert_eq!(psbt.inputs.len(), psbt.unsigned_tx.input.len(), "PSBT inputs out of step");
    assert_eq!(psbt.outputs.len(), psbt.unsigned_tx.output.len(), "PSBT outputs out of step");

    let outputs = &psbt.unsigned_tx.output;
    assert_eq!(outputs.len(), committed.len(), "contributing inputs changed the outputs");
    for (vout, (output, before)) in outputs.iter().zip(committed).enumerate() {
        assert_eq!(output.script_pubkey, before.script_pubkey, "an output script changed");
        if vout != change_vout {
            assert_eq!(output.value, before.value, "an output other than change changed value");
        }
    }

    let committed_sum: u64 = committed.iter().map(|o| o.value.to_sat()).sum();
    let original_sum = original.output_sum();
    let contributed: u64 = contribution.inputs.iter().map(|c| c.value).sum();
    // A contribution only succeeds once it covers what the receiver added to
    // its outputs; without one the outputs stay as committed.
    let expected_sum = match contribution.inputs.is_empty() {
        true => committed_sum,
        false => committed_sum + contributed - committed_sum.saturating_sub(original_sum),
    };
    let sum: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
    assert_eq!(
        sum,
        expected_sum,
        "{contributed} sat of receiver inputs credited {} sat to change; the rest went to fees",
        sum as i128 - committed_sum as i128
    );
    psbt
}

// ---------------------------------------------------------------------------
// Stage 3: fee range
// ---------------------------------------------------------------------------

fn fee_rate_arg(u: &mut Unstructured) -> arbitrary::Result<Option<u64>> {
    Ok(match u.int_in_range(0..=2u8)? {
        0 => None,
        _ if rare(u)? => Some(u.arbitrary()?),
        _ => Some(u.int_in_range(0..=MAX_FEE_RATE_SAT_PER_VB)?),
    })
}

/// The receiver's additional fee is shared with the sender up to the
/// sender's contribution, is taken only from the contributing output and
/// the change output, and never exceeds the receiver's maximum fee rate.
#[allow(clippy::too_many_arguments)]
fn check_fee_range(
    original: &Original,
    inputs: &Psbt,
    inputs_event: &Value,
    change_vout: usize,
    min_vb: Option<u64>,
    max_vb: Option<u64>,
    outcome: &Outcome,
) {
    let input_weight: Weight = inputs_event["receiver_inputs"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|pair| from_value!(Weight, pair["expected_weight"]))
        .sum();
    let output_weight: Weight = inputs.unsigned_tx.output.iter().map(TxOut::weight).sum();
    let output_weight = output_weight.checked_sub(original.output_weight()).unwrap_or(Weight::ZERO);
    let min_rate = min_vb
        .and_then(FeeRate::from_sat_per_vb)
        .unwrap_or(FeeRate::BROADCAST_MIN)
        .max(original.min_fee_rate);
    let max_rate = max_vb.and_then(FeeRate::from_sat_per_vb).unwrap_or(original.max_fee_rate);
    let (Some(input_fee), Some(output_fee), Some(max_fee)) = (
        min_rate.checked_mul_by_weight(input_weight),
        min_rate.checked_mul_by_weight(output_weight),
        max_rate.checked_mul_by_weight(input_weight + output_weight),
    ) else {
        return;
    };
    let sender_fee = match original.fee_contribution {
        Some((max, _)) if input_fee >= Amount::ONE_SAT => max.min(input_fee),
        _ => Amount::ZERO,
    };
    let receiver_fee = input_fee + output_fee - sender_fee;
    let change = inputs.unsigned_tx.output[change_vout].value;
    let affordable = receiver_fee <= max_fee && receiver_fee <= change;

    if !outcome.advanced {
        assert!(!affordable, "a fee range the receiver can afford was rejected");
        assert_eq!(*outcome, REJECTED, "a rejected fee range persisted events");
        return;
    }
    assert!(affordable, "the receiver pays {receiver_fee} over its limit {max_fee}");
    let applied = event(outcome, "AppliedFeeRange");
    let psbt = from_value!(Psbt, applied["payjoin_psbt"]);
    assert_eq!(psbt.unsigned_tx.input, inputs.unsigned_tx.input, "the fee range changed inputs");

    let sender_fee_output = original.fee_contribution.map(|(_, vout)| &original.outputs[vout]);
    let mut paid = Amount::ZERO;
    for (vout, (after, before)) in
        psbt.unsigned_tx.output.iter().zip(&inputs.unsigned_tx.output).enumerate()
    {
        assert_eq!(after.script_pubkey, before.script_pubkey, "the fee range changed a script");
        assert!(after.value <= before.value, "the fee range raised an output");
        if after.value == before.value {
            continue;
        }
        assert!(
            vout == change_vout || Some(before) == sender_fee_output,
            "the fee range charged an output that is neither change nor the sender's fee output"
        );
        paid += before.value - after.value;
    }
    assert_eq!(paid, input_fee + output_fee, "the fee range charged the wrong total");
}

// ---------------------------------------------------------------------------
// Stage 4: signing
// ---------------------------------------------------------------------------

/// The host wallet that signs the proposal, answering with a fixed response.
struct Wallet {
    response: Result<String, ()>,
    asked: Mutex<Vec<String>>,
}

impl ProcessPsbt for Wallet {
    fn callback(&self, psbt: String) -> Result<String, ForeignError> {
        self.asked.lock().expect("not poisoned").push(psbt);
        self.response.clone().map_err(|()| ForeignError::InternalError("wallet failure".into()))
    }
}

/// What the wallet hands back, and whether the receiver must accept it.
fn wallet_response(
    u: &mut Unstructured,
    to_sign: &Psbt,
    sender_inputs: &[usize],
) -> arbitrary::Result<(Result<String, ()>, bool)> {
    let mut psbt = to_sign.clone();
    let receiver_inputs: Vec<usize> =
        (0..psbt.inputs.len()).filter(|i| !sender_inputs.contains(i)).collect();
    let witness = || Witness::from_slice(&[vec![0x30; 72], vec![0x02; 33]]);
    let accepted = match u.int_in_range(0..=6u8)? {
        // An honest wallet that signs its own inputs.
        0 => {
            for &i in &receiver_inputs {
                psbt.inputs[i].final_script_witness = Some(witness());
            }
            true
        }
        // Fields the sender must never see.
        1 => {
            psbt.unknown.insert(raw::Key { type_value: 0xf0, key: vec![1] }, vec![2]);
            for input in &mut psbt.inputs {
                input.redeem_script = Some(script_from_hex(SCRIPTS[2]));
                input.unknown.insert(raw::Key { type_value: 0xf0, key: vec![3] }, vec![4]);
            }
            for output in &mut psbt.outputs {
                output.witness_script = Some(script_from_hex(SCRIPTS[2]));
            }
            true
        }
        2 => true,
        // A signature on an input the receiver does not own.
        3 => {
            let i = sender_inputs[below(u, sender_inputs.len())?];
            psbt.inputs[i].final_script_witness = Some(witness());
            false
        }
        // Any change to the transaction itself.
        4 => {
            let tx = &mut psbt.unsigned_tx;
            match u.int_in_range(0..=3u8)? {
                0 =>
                    tx.lock_time =
                        absolute::LockTime::from_consensus(tx.lock_time.to_consensus_u32() ^ 1),
                1 => tx.input[0].sequence = Sequence(tx.input[0].sequence.0 ^ 1),
                2 => tx.output[0].value += Amount::ONE_SAT,
                _ => {
                    tx.output.push(tx_out(1, script_from_hex(SCRIPTS[6])));
                    psbt.outputs.push(Default::default());
                }
            }
            false
        }
        5 => {
            let text = psbt.to_string();
            let cut = below(u, text.len())?;
            return Ok((Ok(text[..cut].to_string()), false));
        }
        _ => return Ok((Err(()), false)),
    };
    Ok((Ok(psbt.to_string()), accepted))
}

fn check_finalized(to_sign: &Psbt, finalized: &str, outcome: &Outcome) {
    let psbt = Psbt::from_str(finalized).expect("the proposal is a PSBT");
    let event = event(outcome, "FinalizedProposal");
    assert_eq!(psbt, from_value!(Psbt, event), "the proposal is not what was persisted");
    assert_eq!(
        psbt.unsigned_tx.compute_ntxid(),
        to_sign.unsigned_tx.compute_ntxid(),
        "the finalized transaction is not the one the wallet signed"
    );
    assert!(psbt.xpub.is_empty() && psbt.proprietary.is_empty() && psbt.unknown.is_empty());
    for input in &psbt.inputs {
        let kept = payjoin::bitcoin::psbt::Input {
            witness_utxo: input.witness_utxo.clone(),
            non_witness_utxo: input.non_witness_utxo.clone(),
            final_script_sig: input.final_script_sig.clone(),
            final_script_witness: input.final_script_witness.clone(),
            ..Default::default()
        };
        assert_eq!(*input, kept, "a proposal input carries fields the sender must not see");
    }
    assert!(
        psbt.outputs.iter().all(|o| *o == Default::default()),
        "a proposal output carries fields the sender must not see"
    );
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

macro_rules! replayed {
    ($log:expr, $variant:ident) => {
        match replay($log) {
            ReceiveSession::$variant { inner } => inner,
            other => panic!(
                "a persisted session replayed to {} instead of {}",
                session_name(&other),
                stringify!($variant)
            ),
        }
    };
}

fn session_name(session: &ReceiveSession) -> &'static str {
    match session {
        ReceiveSession::Initialized { .. } => "Initialized",
        ReceiveSession::UncheckedOriginalPayload { .. } => "UncheckedOriginalPayload",
        ReceiveSession::MaybeInputsOwned { .. } => "MaybeInputsOwned",
        ReceiveSession::MaybeInputsSeen { .. } => "MaybeInputsSeen",
        ReceiveSession::OutputsUnknown { .. } => "OutputsUnknown",
        ReceiveSession::WantsOutputs { .. } => "WantsOutputs",
        ReceiveSession::WantsInputs { .. } => "WantsInputs",
        ReceiveSession::WantsFeeRange { .. } => "WantsFeeRange",
        ReceiveSession::ProvisionalProposal { .. } => "ProvisionalProposal",
        ReceiveSession::PayjoinProposal { .. } => "PayjoinProposal",
        ReceiveSession::HasReplyableError { .. } => "HasReplyableError",
        ReceiveSession::Monitor { .. } => "Monitor",
        ReceiveSession::ReceiverPendingFallback { .. } => "ReceiverPendingFallback",
        ReceiveSession::Closed { .. } => "Closed",
    }
}

/// A host may resume from its own storage between any two steps, so each
/// stage continues either from the live state or from the replayed one.
fn resume<T>(live: T, replayed: impl FnOnce() -> T, u: &mut Unstructured) -> arbitrary::Result<T> {
    Ok(if rare(u)? { replayed() } else { live })
}

/// Returns how many stages the session passed, so tests can pin the
/// bootstrap path.
fn run(u: &mut Unstructured) -> arbitrary::Result<usize> {
    let original = original(u)?;
    let log = original.log.clone();
    let state = replayed!(&log, WantsOutputs);

    // Stage 1: output substitution.
    let (state, substitution) = substitute_outputs(&state, &original, u)?;
    check_failing_store!(&log, u, state.commit_outputs());
    let (next, outcome) = save!(&Store::draw(&log, u)?, state.commit_outputs());
    let committed = event(&outcome, "CommittedOutputs");
    let outputs = from_value!(Vec<TxOut>, committed["outputs"]);
    let change_vout = committed["change_vout"].as_u64().expect("a vout") as usize;
    check_committed_outputs(&original, &substitution, &outputs, change_vout);
    let log = extend(&log, &outcome);
    let state = next.map(Arc::new).expect("committing outputs advances");
    let state = resume(state, || replayed!(&log, WantsInputs), u)?;

    // Stage 2: input contribution.
    let (state, contribution) = contribute_inputs(state, &original, &outputs, u)?;
    check_failing_store!(&log, u, state.commit_inputs());
    let (next, outcome) = save!(&Store::draw(&log, u)?, state.commit_inputs());
    let inputs_event = event(&outcome, "CommittedInputs");
    let inputs =
        check_committed_inputs(&original, &outputs, change_vout, &contribution, &inputs_event);
    let log = extend(&log, &outcome);
    let state: Arc<WantsFeeRange> = next.map(Arc::new).expect("committing inputs advances");
    let state = resume(state, || replayed!(&log, WantsFeeRange), u)?;

    // Stage 3: fee range. The same range on the replayed state must persist
    // the same proposal.
    let min_vb = fee_rate_arg(u)?;
    let max_vb = match u.int_in_range(0..=2u8)? {
        0 => None,
        1 => Some(min_vb.unwrap_or(1).saturating_add(u.int_in_range(0..=MAX_FEE_RATE_SAT_PER_VB)?)),
        _ => fee_rate_arg(u)?,
    };
    let Ok(transition) = state.apply_fee_range(min_vb, max_vb) else { return Ok(2) };
    let (next, outcome) = save!(&Store::draw(&log, u)?, transition);
    check_fee_range(&original, &inputs, &inputs_event, change_vout, min_vb, max_vb, &outcome);
    let replayed = replayed!(&log, WantsFeeRange)
        .apply_fee_range(min_vb, max_vb)
        .expect("validated once already");
    let (_, replayed_outcome) = save!(&Store::draw(&log, u)?, replayed);
    assert_eq!(outcome, replayed_outcome, "the replayed session applied the fee range differently");
    let Some(state) = next.map(Arc::new) else { return Ok(2) };
    let log = extend(&log, &outcome);
    let state: Arc<ProvisionalProposal> =
        resume(state, || replayed!(&log, ProvisionalProposal), u)?;

    // Stage 4: signing. The callback and the signed-PSBT paths must agree.
    let to_sign_text = state.psbt_to_sign();
    let to_sign = Psbt::from_str(&to_sign_text).expect("the proposal to sign is a PSBT");
    let applied = from_value!(Psbt, event(&outcome, "AppliedFeeRange")["payjoin_psbt"]);
    assert_eq!(to_sign.unsigned_tx, applied.unsigned_tx, "the wallet is asked to sign another tx");
    let sender_inputs: Vec<usize> = (0..to_sign.unsigned_tx.input.len())
        .filter(|&i| original.inputs.contains(&to_sign.unsigned_tx.input[i].previous_output))
        .collect();
    for &i in &sender_inputs {
        let input = &to_sign.inputs[i];
        assert!(
            input.final_script_sig.is_none() && input.final_script_witness.is_none(),
            "the wallet is asked to sign over the sender's stale signatures"
        );
    }

    let (response, accepted) = wallet_response(u, &to_sign, &sender_inputs)?;
    let wallet = Arc::new(Wallet { response: response.clone(), asked: Mutex::default() });
    check_failing_store!(&log, u, state.finalize_proposal(wallet.clone()));
    let wallet = Arc::new(Wallet { response: response.clone(), asked: Mutex::default() });
    let (next, outcome) = save!(&Store::draw(&log, u)?, state.finalize_proposal(wallet.clone()));
    assert_eq!(*wallet.asked.lock().expect("not poisoned"), vec![to_sign_text]);
    assert_eq!(outcome.advanced, accepted, "the receiver misjudged the wallet's PSBT");
    if !accepted {
        assert_eq!(outcome, REJECTED, "a rejected PSBT persisted events");
    }
    if let Ok(signed) = &response {
        let by_signed = match state.finalize_signed_proposal(signed.clone()) {
            Ok(transition) => save!(&Store::draw(&log, u)?, transition).1,
            Err(_) => REJECTED,
        };
        assert_eq!(outcome, by_signed, "the callback and signed-PSBT paths disagree");
        let replayed = replayed!(&log, ProvisionalProposal);
        let by_replay = match replayed.finalize_signed_proposal(signed.clone()) {
            Ok(transition) => save!(&Store::draw(&log, u)?, transition).1,
            Err(_) => REJECTED,
        };
        assert_eq!(outcome, by_replay, "the replayed session finalized differently");
    }
    let Some(state) = next.map(Arc::new) else { return Ok(3) };
    check_finalized(&to_sign, &state.psbt(), &outcome);
    let log = extend(&log, &outcome);
    let state: Arc<PayjoinProposal> = resume(state, || replayed!(&log, PayjoinProposal), u)?;

    // Stage 5: the directory's answer to the proposal is untrusted.
    let relay = match RELAYS.get(below(u, RELAYS.len() + 1)?) {
        Some(relay) => relay.to_string(),
        None => String::from_utf8_lossy(&bytes(u, 32)?).into_owned(),
    };
    if let Ok(request) = state.create_post_request(relay) {
        let body = bytes(u, 256)?;
        let transition = state.process_response(&body, &request.client_response);
        let (_, outcome) = save!(&Store::draw(&log, u)?, transition);
        if !outcome.events.is_empty() {
            replay(&extend(&log, &outcome));
        }
    }
    Ok(5)
}

fn do_test(data: &[u8]) { let _ = run(&mut Unstructured::new(data)); }

fuzz_target!(|data| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    use arbitrary::Unstructured;

    #[test]
    fn empty_input_completes_the_session() {
        assert_eq!(super::run(&mut Unstructured::new(&[])).expect("empty input decodes"), 5);
    }

    #[test]
    fn arbitrary_bytes_do_not_crash() {
        for seed in 0u8..=255 {
            let data: Vec<u8> = (0..128).map(|i| seed.wrapping_mul(31).wrapping_add(i)).collect();
            super::do_test(&data);
        }
    }
}

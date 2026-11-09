#![no_main]

use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use payjoin::bitcoin::hex::{DisplayHex, FromHex};
use payjoin::receive::{
    ChecklistKind, InputOwnership, InputSeenBefore, MarkedChecklistItem, OutputOwnership,
};
use payjoin_ffi::error::ForeignError;
use payjoin_ffi::{
    replay_receiver_event_log, CanBroadcast, IsInputOwned, IsOutputKnown, IsScriptOwned,
    JsonReceiverSessionPersister, JsonReceiverSessionPersisterAsync, MaybeInputsOwned, OutPoint,
    ReceiveSession, UncheckedOriginalPayload,
};
use serde_json::Value;

/// A receiver session whose first two events, Created and
/// RetrievedOriginalPayload, replay to an UncheckedOriginalPayload.
const SESSION: &str = include_str!("seeds/receiver.jsonl");

const MAX_INPUTS: usize = 4;
const MAX_OUTPUTS: usize = 4;
const MAX_OUTPUT_SAT: u64 = 100_000_000;
const MAX_INPUT_SAT: u64 = 200_000_000;
const MAX_RAW_SCRIPT: usize = 40;
const MAX_FEE_RATE_SAT_PER_KWU: u64 = 50_000;

/// Choices that end a session early are decoded as rare ones, otherwise
/// almost no input would reach the later checks.
const RARE_IN: u8 = 8;

/// The seed's own scripts plus one of each common type, so the outputs
/// checklist sees more than P2SH.
const SCRIPTS: [&str; 5] = [
    "a9141de849f069d274150e3afeae8d72eb5a6b09443087",
    "a914774096dbcf486743c22f4347e9b469febe8b677a87",
    "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    "51200101010101010101010101010101010101010101010101010101010101010101",
    "6a",
];

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

/// After a save, the log plus what it persisted must replay to the state
/// the transition reported.
fn check_replay(log: &[String], outcome: &Outcome, advanced_to: fn(&ReceiveSession) -> bool) {
    if outcome.events.is_empty() {
        return;
    }
    let log: Vec<String> = log.iter().chain(&outcome.events).cloned().collect();
    let state = replay_receiver_event_log(Persister::new(&log, false))
        .expect("a persisted session replays")
        .state();
    if outcome.advanced {
        assert!(advanced_to(&state), "replay did not reach the state the transition advanced to");
    } else {
        assert!(
            matches!(state, ReceiveSession::HasReplyableError { .. }),
            "a session that persisted an error did not replay to it"
        );
    }
}

/// Host-side callback that answers in call order and records what it was
/// asked, optionally failing at one call.
struct Oracle {
    answers: Vec<bool>,
    fail_at: Option<usize>,
    asked: Mutex<Vec<String>>,
}

impl Oracle {
    fn new(answers: Vec<bool>, fail_at: Option<usize>) -> Arc<Self> {
        Arc::new(Self { answers, fail_at, asked: Mutex::default() })
    }

    fn answer(&self, asked: impl Debug) -> Result<bool, ForeignError> {
        let mut log = self.asked.lock().expect("not poisoned");
        let index = log.len();
        log.push(format!("{asked:?}"));
        if self.fail_at == Some(index) {
            return Err(ForeignError::InternalError("oracle failure".to_string()));
        }
        Ok(self.answers.get(index).copied().unwrap_or_default())
    }

    fn asked(&self) -> Vec<String> { self.asked.lock().expect("not poisoned").clone() }
}

impl CanBroadcast for Oracle {
    fn callback(&self, tx: Vec<u8>) -> Result<bool, ForeignError> { self.answer(tx) }
}

impl IsInputOwned for Oracle {
    fn callback(&self, outpoint: OutPoint) -> Result<bool, ForeignError> { self.answer(outpoint) }
}

impl IsOutputKnown for Oracle {
    fn callback(&self, outpoint: OutPoint) -> Result<bool, ForeignError> { self.answer(outpoint) }
}

impl IsScriptOwned for Oracle {
    fn callback(&self, script: Vec<u8>) -> Result<bool, ForeignError> { self.answer(script) }
}

/// True one time in RARE_IN, and false for an exhausted input.
fn rare(u: &mut Unstructured) -> arbitrary::Result<bool> {
    Ok(u.int_in_range(0..=RARE_IN - 1)? == RARE_IN - 1)
}

fn below(u: &mut Unstructured, len: usize) -> arbitrary::Result<usize> {
    u.int_in_range(0..=len.saturating_sub(1))
}

fn outpoint(u: &mut Unstructured, seed: &str) -> arbitrary::Result<String> {
    let (txid, _) = seed.split_once(':').expect("seed outpoint has a vout");
    let mut txid = Vec::<u8>::from_hex(txid).expect("seed txid is hex");
    let index = below(u, txid.len())?;
    txid[index] ^= u.arbitrary::<u8>()?;
    Ok(format!("{}:{}", txid.to_lower_hex_string(), u.arbitrary::<u8>()?))
}

fn script(u: &mut Unstructured) -> arbitrary::Result<String> {
    let choice = below(u, SCRIPTS.len() + 1)?;
    match SCRIPTS.get(choice) {
        Some(script) => Ok(script.to_string()),
        None => {
            let len = below(u, MAX_RAW_SCRIPT + 1)?;
            Ok(u.bytes(len)?.to_lower_hex_string())
        }
    }
}

/// Rebuild the seed's original PSBT with fuzzer-chosen inputs and outputs.
/// Replay does not revalidate the original, so any shape reaches the checks.
fn session_log(u: &mut Unstructured) -> arbitrary::Result<Vec<String>> {
    let mut lines = SESSION.lines();
    let created = lines.next().expect("seed has Created").to_string();
    let mut retrieved: Value =
        serde_json::from_str(lines.next().expect("seed has RetrievedOriginalPayload"))
            .expect("valid seed");

    let psbt = &mut retrieved["RetrievedOriginalPayload"]["original"]["psbt"];
    let txin = psbt["unsigned_tx"]["input"][0].clone();
    let psbt_in = psbt["inputs"][0].clone();
    let txout = psbt["unsigned_tx"]["output"][0].clone();
    let psbt_out = psbt["outputs"][1].clone();
    let seed_outpoint = txin["previous_output"].as_str().expect("outpoint string").to_string();

    // The fee rate check predicts each input's weight from its prevout
    // script and signatures, so those vary too, rarely, to keep the seed's
    // P2SH-P2WPKH spend as the common case.
    let (mut inputs, mut psbt_inputs) = (Vec::new(), Vec::new());
    for _ in 0..u.int_in_range(1..=MAX_INPUTS)? {
        let mut input = txin.clone();
        input["previous_output"] = outpoint(u, &seed_outpoint)?.into();
        inputs.push(input);
        let mut psbt_input = psbt_in.clone();
        if rare(u)? {
            psbt_input["witness_utxo"]["value"] = u.int_in_range(0..=MAX_INPUT_SAT)?.into();
        }
        if rare(u)? {
            psbt_input["witness_utxo"]["script_pubkey"] = script(u)?.into();
        }
        if rare(u)? {
            psbt_input["final_script_sig"] = Value::Null;
            psbt_input["final_script_witness"] = Value::Null;
        }
        psbt_inputs.push(psbt_input);
    }

    let (mut outputs, mut psbt_outputs) = (Vec::new(), Vec::new());
    for _ in 0..u.int_in_range(1..=MAX_OUTPUTS)? {
        let mut output = txout.clone();
        output["value"] = u.int_in_range(0..=MAX_OUTPUT_SAT)?.into();
        output["script_pubkey"] = script(u)?.into();
        outputs.push(output);
        psbt_outputs.push(psbt_out.clone());
    }

    psbt["unsigned_tx"]["input"] = inputs.into();
    psbt["inputs"] = psbt_inputs.into();
    psbt["unsigned_tx"]["output"] = outputs.into();
    psbt["outputs"] = psbt_outputs.into();
    Ok(vec![created, retrieved.to_string()])
}

fn unchecked(log: &[String]) -> Option<Arc<UncheckedOriginalPayload>> {
    match replay_receiver_event_log(Persister::new(log, false)).ok()?.state() {
        ReceiveSession::UncheckedOriginalPayload { inner } => Some(inner),
        _ => None,
    }
}

/// Reorder, drop, duplicate or splice in foreign items, as a buggy or
/// malicious host might before handing a checklist back.
fn tamper<T: Clone>(
    mut list: Vec<T>,
    foreign: &[T],
    u: &mut Unstructured,
) -> arbitrary::Result<Vec<T>> {
    let i = below(u, list.len())?;
    let j = below(u, list.len())?;
    let f = below(u, foreign.len())?;
    match u.int_in_range(0..=6u8)? {
        0 => list.reverse(),
        1 if !list.is_empty() => {
            list.remove(i);
        }
        2 if !list.is_empty() => list.insert(i, list[i].clone()),
        3 if !list.is_empty() && !foreign.is_empty() => list[i] = foreign[f].clone(),
        4 if !foreign.is_empty() => list.push(foreign[f].clone()),
        5 => list.clear(),
        _ if list.len() > 1 => list.swap(i, j),
        _ => {}
    }
    Ok(list)
}

// Compare the values themselves: two different malformed scripts can share a
// Debug rendering.
fn values<K, M>(list: &[Arc<M>]) -> Vec<K::Value>
where
    K: ChecklistKind,
    M: AsRef<MarkedChecklistItem<K>>,
{
    list.iter().map(|m| AsRef::<MarkedChecklistItem<K>>::as_ref(&**m).value().clone()).collect()
}

fn results<K, M>(list: &[Arc<M>]) -> Vec<bool>
where
    K: ChecklistKind,
    M: AsRef<MarkedChecklistItem<K>>,
{
    list.iter().map(|m| AsRef::<MarkedChecklistItem<K>>::as_ref(&**m).result()).collect()
}

fn broadcast_stage(
    state: &UncheckedOriginalPayload,
    log: &[String],
    u: &mut Unstructured,
) -> arbitrary::Result<(Option<MaybeInputsOwned>, Vec<String>)> {
    // Mostly a realistic rate, so the below-fee-rate rejection is reachable;
    // rarely a raw u64, so the FFI's range validation is too.
    let min_fee_rate = match u.arbitrary::<bool>()? {
        false => None,
        true if rare(u)? => Some(u.arbitrary::<u64>()?),
        true => Some(u.int_in_range(0..=MAX_FEE_RATE_SAT_PER_KWU)?),
    };
    let suitable = !rare(u)?;

    if rare(u)? {
        let oracle = Oracle::new(vec![suitable], Some(0));
        if let Ok(transition) = state.check_broadcast_suitability(min_fee_rate, oracle) {
            let (_, outcome) = save!(&Store::draw(log, u)?, transition);
            assert_eq!(outcome, REJECTED, "a failing broadcast callback advanced the session");
        }
    }

    let oracle = Oracle::new(vec![suitable], None);
    let by_callback = state.check_broadcast_suitability(min_fee_rate, oracle.clone());
    let by_flag = state.apply_broadcast_suitability(min_fee_rate, suitable);
    let (Ok(by_callback), Ok(by_flag)) = (by_callback, by_flag) else {
        return Ok((None, Vec::new()));
    };

    let (next, callback_outcome) = save!(&Store::draw(log, u)?, by_callback);
    let (_, flag_outcome) = save!(&Store::draw(log, u)?, by_flag);
    assert_eq!(
        oracle.asked(),
        vec![format!("{:?}", state.extract_tx_to_check_broadcast_suitability())],
        "the broadcast callback saw a different transaction than the extract API"
    );
    assert_eq!(callback_outcome, flag_outcome, "broadcast callback and flag disagree");
    check_replay(log, &callback_outcome, |s| matches!(s, ReceiveSession::MaybeInputsOwned { .. }));

    if rare(u)?
        && let Ok(transition) = state.apply_broadcast_suitability(min_fee_rate, suitable)
    {
        let (_, outcome) = save!(&Store::failing(log, u)?, transition);
        assert_eq!(outcome, REJECTED, "a session advanced without its storage");
    }
    Ok((next, callback_outcome.events))
}

// Each checklist stage offers a callback API and a checklist API over the
// same check. For the same answers they must persist the same events, and a
// checklist that is not a complete, in-order marking of this receiver's own
// values must be rejected without persisting anything.
macro_rules! checklist_stage {
    (
        $state:expr, $foreign:expr, $log:expr, $u:expr, $kind:ty, $next:ident,
        $checklist:ident, $apply:ident, $check:ident, invert = $invert:expr
    ) => {{
        let (state, log) = ($state, $log);
        let items = state.$checklist();
        let mut answers = Vec::with_capacity(items.len());
        for _ in &items {
            answers.push(rare($u)? ^ $invert);
        }
        let honest: Vec<_> = items.iter().zip(&answers).map(|(i, a)| i.mark(*a)).collect();
        let expected = values::<$kind, _>(&honest);

        let mut foreign = Vec::new();
        if let Some(f) = $foreign {
            for item in f.$checklist() {
                foreign.push(item.mark($u.arbitrary::<bool>()?));
            }
        }

        let oracle = Oracle::new(answers.clone(), None);
        let (next, by_callback) = save!(&Store::draw(log, $u)?, state.$check(oracle.clone()));
        let asked: Vec<_> = items.iter().map(|i| format!("{:?}", i.value())).collect();
        assert_eq!(oracle.asked(), asked, "the callback saw different values than the checklist");
        let (_, by_checklist) =
            save!(&Store::draw(log, $u)?, state.$apply(honest.clone()).expect("apply never fails"));
        assert_eq!(by_callback, by_checklist, "callback and checklist disagree");
        check_replay(log, &by_callback, |s| matches!(s, ReceiveSession::$next { .. }));

        if !items.is_empty() && rare($u)? {
            let fail_at = below($u, items.len())?;
            let oracle = Oracle::new(answers.clone(), Some(fail_at));
            let (_, outcome) = save!(&Store::draw(log, $u)?, state.$check(oracle));
            assert_eq!(outcome, REJECTED, "a failing callback advanced the session");
        }

        if rare($u)? {
            let oracle = Oracle::new(answers.clone(), None);
            let (_, outcome) = save!(&Store::failing(log, $u)?, state.$check(oracle));
            assert_eq!(outcome, REJECTED, "a session advanced without its storage");
        }

        let tampered = tamper(honest, &foreign, $u)?;
        let (_, outcome) = save!(
            &Store::draw(log, $u)?,
            state.$apply(tampered.clone()).expect("apply never fails")
        );
        if values::<$kind, _>(&tampered) == expected {
            let oracle = Oracle::new(results::<$kind, _>(&tampered), None);
            let (_, reference) = save!(&Store::draw(log, $u)?, state.$check(oracle));
            assert_eq!(outcome, reference, "an equivalent checklist was treated differently");
        } else {
            assert_eq!(outcome, REJECTED, "a checklist not matching this receiver was accepted");
        }
        (next, by_callback.events)
    }};
}

/// The log after a stage, with what the stage persisted appended, as the
/// host would hand it back on resume.
fn extend(log: &[String], events: Vec<String>) -> Vec<String> {
    log.iter().cloned().chain(events).collect()
}

/// Advance a receiver through one check with every answer false.
fn all_false() -> Arc<Oracle> { Oracle::new(Vec::new(), None) }

/// Advance a foreign receiver through one check, saving synchronously.
fn advance<T, E>(
    log: &[String],
    save: impl FnOnce(Arc<dyn JsonReceiverSessionPersister>) -> Result<T, E>,
) -> Option<T> {
    save(Persister::new(log, false)).ok()
}

/// Returns how many checks the session passed, so tests can pin the
/// bootstrap path.
fn run(u: &mut Unstructured) -> arbitrary::Result<usize> {
    let log = session_log(u)?;
    let foreign_log = session_log(u)?;
    let Some(state) = unchecked(&log) else { return Ok(0) };
    let foreign = unchecked(&foreign_log);

    let (Some(state), events) = broadcast_stage(&state, &log, u)? else { return Ok(0) };
    let log = extend(&log, events);
    let foreign = foreign
        .and_then(|f| f.apply_broadcast_suitability(None, true).ok())
        .and_then(|t| advance(&foreign_log, |p| t.save(p)));

    let (Some(state), events) = checklist_stage!(
        &state,
        foreign.as_ref(),
        &log,
        u,
        InputOwnership,
        MaybeInputsSeen,
        inputs_owned_checklist,
        apply_inputs_owned_checklist,
        check_inputs_not_owned,
        invert = false
    ) else {
        return Ok(1);
    };
    let log = extend(&log, events);
    let foreign = foreign
        .and_then(|f| advance(&foreign_log, |p| f.check_inputs_not_owned(all_false()).save(p)));

    let (Some(state), events) = checklist_stage!(
        &state,
        foreign.as_ref(),
        &log,
        u,
        InputSeenBefore,
        OutputsUnknown,
        inputs_seen_checklist,
        apply_inputs_seen_checklist,
        check_no_inputs_seen_before,
        invert = false
    ) else {
        return Ok(2);
    };
    let log = extend(&log, events);
    let foreign = foreign.and_then(|f| {
        advance(&foreign_log, |p| f.check_no_inputs_seen_before(all_false()).save(p))
    });

    // Inverted so that outputs are the receiver's unless rare, since a
    // proposal with no receiver output is rejected.
    let (next, _) = checklist_stage!(
        &state,
        foreign.as_ref(),
        &log,
        u,
        OutputOwnership,
        WantsOutputs,
        outputs_owned_checklist,
        apply_outputs_owned_checklist,
        identify_receiver_outputs,
        invert = true
    );
    Ok(if next.is_some() { 4 } else { 3 })
}

fn do_test(data: &[u8]) { let _ = run(&mut Unstructured::new(data)); }

fuzz_target!(|data| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    use arbitrary::Unstructured;

    #[test]
    fn empty_input_passes_every_check() {
        assert_eq!(super::run(&mut Unstructured::new(&[])).expect("empty input decodes"), 4);
    }

    // Two distinct malformed scripts with the same Debug rendering, swapped
    // by the tamper step.
    #[test]
    fn swapped_scripts_with_equal_debug_are_rejected() {
        let data = [
            36, 36, 5, 111, 226, 250, 255, 201, 111, 239, 5, 57, 0, 107, 194, 194, 194, 194, 194,
            194, 5, 0, 0, 0, 69, 239, 239, 5, 57, 0, 4, 111, 5,
        ];
        super::do_test(&data);
    }

    #[test]
    fn arbitrary_bytes_do_not_crash() {
        for seed in 0u8..=255 {
            let data: Vec<u8> = (0..64).map(|i| seed.wrapping_mul(31).wrapping_add(i)).collect();
            super::do_test(&data);
        }
    }
}

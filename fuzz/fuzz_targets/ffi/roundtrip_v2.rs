#![cfg_attr(not(test), no_main)]

//! End to end v2 payjoin through the `payjoin-ffi` bindings: a real sender
//! and receiver, both driven entirely through the FFI types, talk through an
//! in-process mock directory.
//!
//! `roundtrip/v2.rs` runs the same protocol against the core API. This target
//! exercises the binding layer the core target cannot reach: the JSON event
//! persisters, the callback adapters, the transition `save`/replay surface,
//! and, on the sender side, `process_response` validating a real proposal.
//! That sender validation is only reachable through a full roundtrip, since
//! it needs the receiver's genuine OHTTP/HPKE context.
//!
//! Both parties are honest, so every message passes both crypto layers on its
//! own and the fuzzer never touches ciphertext. What it controls is the
//! wallet choices, the receiver's answers, the directory's statuses, polling
//! order and whether either party resumes from its event log.
//!
//! The input is `[len:2][psbt][scenario]`. An empty scenario decodes to the
//! happy path, which `seed_completes_the_roundtrip` pins down.

use std::collections::HashMap;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use arbitrary::Unstructured;
use bhttp::{
    ControlData, Message as BhttpMessage, Mode as BhttpMode, StatusCode as BhttpStatusCode,
};
use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyConfig as OhttpKeyConfig, Server as OhttpServer, SymmetricSuite};
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{Address, Amount, Network};
use payjoin::directory::ENCAPSULATED_MESSAGE_BYTES;
use payjoin_ffi::error::ForeignError;
use payjoin_ffi::{
    replay_sender_event_log, CanBroadcast, InitializedTransitionOutcome, IsInputOwned,
    IsOutputKnown, IsScriptOwned, JsonReceiverSessionPersister, JsonSenderSessionPersister,
    OhttpKeys, PjUri, PollingForProposalTransitionOutcome, ProcessPsbt, ReceiveSession,
    ReceiverBuilder, SendSession, SenderBuilder,
};

const INFALLIBLE: &str = "the in-memory persister cannot fail";

/// The BIP-78 test vector original PSBT, shared with the other roundtrip
/// targets.
const SEED_PSBT_B64: &str = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

static SEED_PSBT: LazyLock<Vec<u8>> =
    LazyLock::new(|| Psbt::from_str(SEED_PSBT_B64).expect("BIP-78 vector must parse").serialize());

const DIRECTORY: &str = "https://directory.example";
const RELAY: &str = "http://relay.example";

/// OHTTP key agreement parameters, matching the receiver's constants.
const KEY_ID: u8 = 1;
const KEM: Kem = Kem::K256Sha256;
const SYMMETRIC: &[SymmetricSuite] =
    &[SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

/// Deterministic seed for the OHTTP key config, so both parties and the
/// gateway agree in every process without any cross-iteration state.
const KEY_CONFIG_SEED: [u8; 32] = [0x42; 32];

fn derived_key_config() -> OhttpKeyConfig {
    OhttpKeyConfig::derive(KEY_ID, KEM, SYMMETRIC.to_vec(), &KEY_CONFIG_SEED)
        .expect("valid key config")
}

static KEY_CONFIG_BYTES: LazyLock<Vec<u8>> =
    LazyLock::new(|| derived_key_config().encode().expect("valid key config encoding"));

static OHTTP_SERVER: LazyLock<OhttpServer> =
    LazyLock::new(|| OhttpServer::new(derived_key_config()).expect("valid ohttp server"));

/// Bytes `ServerResponse::encapsulate` adds to a reply. It depends only on
/// the fixed suite, so `MockDirectory::handle` probes it once per process.
static RESPONSE_OVERHEAD: OnceLock<usize> = OnceLock::new();

/// Statuses the directory can answer with instead of delivering.
const FAULT_STATUSES: [u16; 5] = [400, 404, 413, 500, 503];

const SENDER_POST: usize = 0;
const RECEIVER_POLL: usize = 1;
const RECEIVER_POST: usize = 2;
const SENDER_POLL: usize = 3;

/// Upper bound for fuzzed fee rates, kept well inside the FFI validators.
const MAX_FEE_RATE: u64 = 250_000;

/// Scenario bytes at or above this value trigger a rare choice (one in eight).
const RARE_FROM: u8 = 224;

/// Which sender builder to finish with.
#[derive(Clone, Copy)]
enum Build {
    Recommended,
    NonIncentivizing,
    AdditionalFee { max: u64, change_index: Option<u8>, clamp: bool },
}

/// Everything the fuzzer decides about a session. Every field decodes to its
/// happy-path value from zero or exhausted bytes, so an empty scenario is a
/// plain successful payjoin. Choices that end a session early are decoded as
/// rare, so most mutated scenarios still reach the end of the protocol.
struct Scenario {
    build: Build,
    sender_min_fee_rate: u64,
    disable_output_substitution: bool,
    receiver_polls_early: bool,
    sender_polls_early: bool,
    sender_restarts: bool,
    receiver_restarts: bool,
    check_broadcast: bool,
    cannot_broadcast: bool,
    inputs_owned: bool,
    inputs_seen: bool,
    outputs_not_mine: bool,
    receiver_min_fee_rate: Option<u64>,
    receiver_max_fee_rate: Option<u64>,
    faults: [Option<u16>; 4],
}

fn flag(u: &mut Unstructured<'_>) -> bool { u.arbitrary().unwrap_or(false) }

fn rarely(u: &mut Unstructured<'_>) -> bool { u.arbitrary::<u8>().unwrap_or(0) >= RARE_FROM }

// The bindings take fee rates as plain integers, not `FeeRate`: sat/kwu for
// the sender builders and sat/vb for `apply_fee_range`. The core roundtrip
// uses `FeeRate` because it calls the Rust API directly; here u64 is what the
// FFI surface accepts, so the scenario generates it directly.
fn fee_rate(u: &mut Unstructured<'_>) -> u64 { u.int_in_range(0..=MAX_FEE_RATE).unwrap_or(0) }

fn optional_fee_rate(u: &mut Unstructured<'_>) -> Option<u64> { rarely(u).then(|| fee_rate(u)) }

fn fault(u: &mut Unstructured<'_>) -> Option<u16> {
    let byte = u.arbitrary::<u8>().unwrap_or(0);
    (byte >= RARE_FROM).then(|| FAULT_STATUSES[usize::from(byte) % FAULT_STATUSES.len()])
}

impl Scenario {
    fn from_bytes(data: &[u8]) -> Self {
        let mut u = Unstructured::new(data);
        let build = match u.int_in_range(0..=2u8).unwrap_or(0) {
            0 => Build::Recommended,
            1 => Build::NonIncentivizing,
            _ => Build::AdditionalFee {
                max: u.int_in_range(0..=Amount::MAX_MONEY.to_sat()).unwrap_or(0),
                change_index: u.arbitrary::<Option<u8>>().unwrap_or(None),
                clamp: flag(&mut u),
            },
        };
        Self {
            build,
            sender_min_fee_rate: optional_fee_rate(&mut u).unwrap_or(0),
            disable_output_substitution: flag(&mut u),
            receiver_polls_early: flag(&mut u),
            sender_polls_early: flag(&mut u),
            sender_restarts: flag(&mut u),
            receiver_restarts: flag(&mut u),
            check_broadcast: flag(&mut u),
            cannot_broadcast: rarely(&mut u),
            inputs_owned: rarely(&mut u),
            inputs_seen: rarely(&mut u),
            outputs_not_mine: rarely(&mut u),
            receiver_min_fee_rate: optional_fee_rate(&mut u),
            receiver_max_fee_rate: optional_fee_rate(&mut u),
            faults: [fault(&mut u), fault(&mut u), fault(&mut u), fault(&mut u)],
        }
    }
}

/// How far a session got. Only the tests inspect this.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Stage {
    Rejected,
    SenderCreated,
    OriginalPosted,
    OriginalReceived,
    Replied,
    Completed,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Reply {
    Nothing,
    Error,
    Proposal,
}

/// In-memory JSON event log, as a host-side persister. Both parties keep
/// their own; `save` appends and `load` returns the whole log so either side
/// can replay.
#[derive(Default)]
struct Persister {
    events: Mutex<Vec<String>>,
}

impl Persister {
    fn arc() -> Arc<Self> { Arc::new(Self::default()) }
}

impl JsonReceiverSessionPersister for Persister {
    fn save(&self, event: String) -> Result<(), ForeignError> {
        self.events.lock().expect("not poisoned").push(event);
        Ok(())
    }
    fn load(&self) -> Result<Vec<String>, ForeignError> {
        Ok(self.events.lock().expect("not poisoned").clone())
    }
    fn close(&self) -> Result<(), ForeignError> { Ok(()) }
}

impl JsonSenderSessionPersister for Persister {
    fn save(&self, event: String) -> Result<(), ForeignError> {
        self.events.lock().expect("not poisoned").push(event);
        Ok(())
    }
    fn load(&self) -> Result<Vec<String>, ForeignError> {
        Ok(self.events.lock().expect("not poisoned").clone())
    }
    fn close(&self) -> Result<(), ForeignError> { Ok(()) }
}

/// The receiver's wallet, answering every callback from the scenario.
struct Wallet {
    cannot_broadcast: bool,
    inputs_owned: bool,
    inputs_seen: bool,
    outputs_not_mine: bool,
}

impl CanBroadcast for Wallet {
    fn callback(&self, _tx: Vec<u8>) -> Result<bool, ForeignError> { Ok(!self.cannot_broadcast) }
}
impl IsInputOwned for Wallet {
    fn callback(&self, _outpoint: payjoin_ffi::OutPoint) -> Result<bool, ForeignError> {
        Ok(self.inputs_owned)
    }
}
impl IsOutputKnown for Wallet {
    fn callback(&self, _outpoint: payjoin_ffi::OutPoint) -> Result<bool, ForeignError> {
        Ok(self.inputs_seen)
    }
}
impl IsScriptOwned for Wallet {
    fn callback(&self, _script: Vec<u8>) -> Result<bool, ForeignError> {
        Ok(!self.outputs_not_mine)
    }
}

/// The receiver signs nothing here: with no contributed inputs the proposal
/// PSBT is returned unchanged.
struct IdentitySigner;

impl ProcessPsbt for IdentitySigner {
    fn callback(&self, psbt: String) -> Result<String, ForeignError> { Ok(psbt) }
}

/// In-process stand-in for the directory's OHTTP gateway. Reused verbatim
/// from `roundtrip/v2.rs`: it routes requests by method and mailbox path.
#[derive(Default)]
struct MockDirectory {
    mailboxes: HashMap<String, Vec<u8>>,
}

impl MockDirectory {
    fn handle(&mut self, req_body: &[u8], fault: Option<u16>) -> Vec<u8> {
        let overhead = *RESPONSE_OVERHEAD.get_or_init(|| {
            let (_, probe) = OHTTP_SERVER.decapsulate(req_body).expect("request decapsulates");
            probe.encapsulate(&[]).expect("probe encapsulates").len()
        });

        let (bhttp_req, server_response) =
            OHTTP_SERVER.decapsulate(req_body).expect("request decapsulates");

        let request =
            BhttpMessage::read_bhttp(&mut Cursor::new(&bhttp_req)).expect("request parses");

        let (method, path) = match request.control() {
            ControlData::Request { method, path, .. } => (
                String::from_utf8_lossy(method).into_owned(),
                String::from_utf8_lossy(path).into_owned(),
            ),
            ControlData::Response(_) => unreachable!("the gateway only sees requests"),
        };

        let (status, content): (u16, Option<Vec<u8>>) = match fault {
            Some(status) => (status, None),
            None => match (method.as_str(), self.mailboxes.get(&path)) {
                ("GET", Some(content)) => (200, Some(content.clone())),
                ("GET", None) => (202, None),
                _ => {
                    self.mailboxes.insert(path, request.content().to_vec());
                    (200, None)
                }
            },
        };

        let mut response =
            BhttpMessage::response(BhttpStatusCode::try_from(status).expect("valid status code"));
        if let Some(content) = &content {
            response.write_content(content);
        }
        let mut buf = vec![0u8; ENCAPSULATED_MESSAGE_BYTES - overhead];
        response
            .write_bhttp(BhttpMode::KnownLength, &mut buf.as_mut_slice())
            .expect("bhttp response encodes");
        server_response.encapsulate(&buf).expect("response encapsulates")
    }
}

const HEADER: usize = 2;

fn split_input(data: &[u8]) -> (&[u8], &[u8]) {
    if data.len() < HEADER {
        return (&[], &[]);
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let rest = &data[HEADER..];
    rest.split_at(len.min(rest.len()))
}

const DEFAULT_SCENARIO: [u8; 24] = [0; 24];

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    const RAW_MUTATION_IN: u32 = 4;
    if seed.is_multiple_of(RAW_MUTATION_IN) {
        return fuzzer_mutate(data, size, max_size);
    }

    let (psbt, scenario) = split_input(&data[..size]);
    let psbt: Vec<u8> =
        if Psbt::deserialize(psbt).is_ok() { psbt.to_vec() } else { SEED_PSBT.clone() };
    let scenario: Vec<u8> =
        if scenario.is_empty() { DEFAULT_SCENARIO.to_vec() } else { scenario.to_vec() };

    let Ok(psbt_len) = u16::try_from(psbt.len()) else {
        return fuzzer_mutate(data, size, max_size);
    };
    if max_size <= HEADER + psbt.len() {
        return fuzzer_mutate(data, size, max_size);
    }
    let scenario_max = max_size - HEADER - psbt.len();

    let mut buf = scenario;
    let scenario_len = buf.len().min(scenario_max);
    buf.resize(scenario_max, 0);
    let scenario_len = fuzzer_mutate(&mut buf, scenario_len, scenario_max);

    data[..HEADER].copy_from_slice(&psbt_len.to_be_bytes());
    data[HEADER..HEADER + psbt.len()].copy_from_slice(&psbt);
    data[HEADER + psbt.len()..HEADER + psbt.len() + scenario_len]
        .copy_from_slice(&buf[..scenario_len]);
    HEADER + psbt.len() + scenario_len
});

fn amounts_within_max_money(psbt: &Psbt) -> bool {
    let max = u128::from(Amount::MAX_MONEY.to_sat());
    let input_total = psbt
        .unsigned_tx
        .input
        .iter()
        .zip(&psbt.inputs)
        .map(|(txin, psbtin)| {
            psbtin
                .witness_utxo
                .as_ref()
                .map(|txout| txout.value.to_sat())
                .or_else(|| {
                    psbtin.non_witness_utxo.as_ref().and_then(|tx| {
                        tx.output
                            .get(usize::try_from(txin.previous_output.vout).ok()?)
                            .map(|txout| txout.value.to_sat())
                    })
                })
                .unwrap_or(0)
        })
        .map(u128::from)
        .sum::<u128>();
    let output_total =
        psbt.unsigned_tx.output.iter().map(|txout| u128::from(txout.value.to_sat())).sum::<u128>();
    input_total <= max && output_total <= max
}

/// The receiver rejected a check and owes the sender an error. Reach the
/// error state by replaying the log (the failing transition persisted it),
/// then post the error to the sender's reply mailbox.
fn post_error(
    recv_persister: &Arc<Persister>,
    s: &Scenario,
    directory: &mut MockDirectory,
) -> Reply {
    let Ok(replay) = payjoin_ffi::replay_receiver_event_log(recv_persister.clone()) else {
        return Reply::Nothing;
    };
    let ReceiveSession::HasReplyableError { inner } = replay.state() else {
        return Reply::Nothing;
    };
    let Ok(rr) = inner.create_error_request(RELAY.to_string()) else { return Reply::Nothing };
    let fault = s.faults[RECEIVER_POST];
    let res = directory.handle(&rr.request.body, fault);
    let _ = inner.process_error_response(&res, &rr.client_response).save(recv_persister.clone());
    if fault.is_none() {
        Reply::Error
    } else {
        Reply::Nothing
    }
}

/// Walk the receiver from the unchecked original payload to its reply.
fn receive(
    unchecked: Arc<payjoin_ffi::UncheckedOriginalPayload>,
    s: &Scenario,
    directory: &mut MockDirectory,
    recv_persister: &Arc<Persister>,
) -> Reply {
    let wallet = Arc::new(Wallet {
        cannot_broadcast: s.cannot_broadcast,
        inputs_owned: s.inputs_owned,
        inputs_seen: s.inputs_seen,
        outputs_not_mine: s.outputs_not_mine,
    });

    // The core roundtrip recovers the error state from a failed save with
    // `e.fatal_state()`. The FFI save surface does not expose that: it maps
    // every failure to an opaque `ReceiverPersistedError`. The failing
    // transition still persists the error event, so `post_error` recovers the
    // state by replaying the log instead.
    macro_rules! replyable {
        ($result:expr) => {
            match $result {
                Ok(next) => next,
                Err(_) => return post_error(recv_persister, s, directory),
            }
        };
    }

    let maybe_owned = if s.check_broadcast {
        let transition =
            match unchecked.check_broadcast_suitability(s.receiver_min_fee_rate, wallet.clone()) {
                Ok(t) => t,
                Err(_) => return Reply::Nothing,
            };
        replyable!(transition.save(recv_persister.clone()))
    } else {
        unchecked.assume_interactive_receiver().save(recv_persister.clone()).expect(INFALLIBLE)
    };

    let maybe_seen =
        replyable!(maybe_owned.check_inputs_not_owned(wallet.clone()).save(recv_persister.clone()));
    let outputs_unknown = replyable!(maybe_seen
        .check_no_inputs_seen_before(wallet.clone())
        .save(recv_persister.clone()));
    let wants_outputs = replyable!(outputs_unknown
        .identify_receiver_outputs(wallet.clone())
        .save(recv_persister.clone()));

    let wants_inputs =
        wants_outputs.commit_outputs().save(recv_persister.clone()).expect(INFALLIBLE);
    let wants_fee_range =
        wants_inputs.commit_inputs().save(recv_persister.clone()).expect(INFALLIBLE);
    let Ok(fee_transition) =
        wants_fee_range.apply_fee_range(s.receiver_min_fee_rate, s.receiver_max_fee_rate)
    else {
        return Reply::Nothing;
    };
    let Ok(provisional) = fee_transition.save(recv_persister.clone()) else {
        return Reply::Nothing;
    };

    let Ok(proposal) =
        provisional.finalize_proposal(Arc::new(IdentitySigner)).save(recv_persister.clone())
    else {
        return Reply::Nothing;
    };

    let Ok(rr) = proposal.create_post_request(RELAY.to_string()) else { return Reply::Nothing };
    let res = directory.handle(&rr.request.body, s.faults[RECEIVER_POST]);
    match proposal.process_response(&res, &rr.client_response).save(recv_persister.clone()) {
        Ok(_monitor) => Reply::Proposal,
        Err(_) => Reply::Nothing,
    }
}

fn run_session(
    psbt_b64: &str,
    address: &str,
    s: &Scenario,
    recv_persister: &Arc<Persister>,
    send_persister: &Arc<Persister>,
) -> Stage {
    let Ok(ohttp_keys) = OhttpKeys::decode(KEY_CONFIG_BYTES.clone()) else {
        return Stage::Rejected;
    };
    let mut directory = MockDirectory::default();

    let Ok(builder) =
        ReceiverBuilder::new(address.to_string(), DIRECTORY.to_string(), Arc::new(ohttp_keys))
    else {
        return Stage::Rejected;
    };
    let session = builder.build().save(recv_persister.clone()).expect(INFALLIBLE);

    // A receiver polling an empty mailbox stays where it is.
    let session = if s.receiver_polls_early {
        let Ok(rr) = session.create_poll_request(RELAY.to_string()) else { return Stage::Rejected };
        let res = directory.handle(&rr.request.body, None);
        match session.process_response(&res, &rr.client_response).save(recv_persister.clone()) {
            Ok(InitializedTransitionOutcome::Stasis { inner }) => inner,
            _ => return Stage::Rejected,
        }
    } else {
        Arc::new(session)
    };

    // The sender reads the receiver's v2 parameters from the session URI.
    let pj_uri: PjUri = session.pj_uri();
    let Ok(builder) = SenderBuilder::new(psbt_b64.to_string(), Arc::new(pj_uri)) else {
        return Stage::Rejected;
    };
    let builder = if s.disable_output_substitution {
        builder.always_disable_output_substitution()
    } else {
        builder
    };
    let built = match s.build {
        Build::Recommended => builder.build_recommended(s.sender_min_fee_rate),
        Build::NonIncentivizing => builder.build_non_incentivizing(s.sender_min_fee_rate),
        Build::AdditionalFee { max, change_index, clamp } =>
            builder.build_with_additional_fee(max, change_index, s.sender_min_fee_rate, clamp),
    };
    let Ok(built) = built else { return Stage::Rejected };
    let sender = built.save(send_persister.clone()).expect(INFALLIBLE);
    let mut stage = Stage::SenderCreated;

    // Sender posts the original PSBT (message A).
    let Ok(rc) = sender.create_v2_post_request(RELAY.to_string()) else { return stage };
    let res = directory.handle(&rc.request.body, s.faults[SENDER_POST]);
    let Ok(sender) = sender.process_response(&res, &rc.ohttp_ctx).save(send_persister.clone())
    else {
        return stage;
    };
    stage = Stage::OriginalPosted;

    // A wallet that restarts here resumes from its event log.
    let sender = if s.sender_restarts {
        match replay_sender_event_log(send_persister.clone()).map(|r| r.state()) {
            Ok(SendSession::PollingForProposal { inner }) => inner,
            _ => panic!("a sender that posted its original must replay as polling"),
        }
    } else {
        Arc::new(sender)
    };

    // A sender polling before the receiver replied stays where it is.
    let sender = if s.sender_polls_early {
        let Ok(rc) = sender.create_poll_request(RELAY.to_string()) else { return stage };
        let res = directory.handle(&rc.request.body, None);
        match sender.process_response(&res, &rc.ohttp_ctx).save(send_persister.clone()) {
            Ok(PollingForProposalTransitionOutcome::Stasis { inner }) => inner,
            _ => return stage,
        }
    } else {
        sender
    };

    // Receiver retrieves and decrypts the original PSBT.
    let Ok(rr) = session.create_poll_request(RELAY.to_string()) else { return stage };
    let res = directory.handle(&rr.request.body, s.faults[RECEIVER_POLL]);
    let unchecked =
        match session.process_response(&res, &rr.client_response).save(recv_persister.clone()) {
            Ok(InitializedTransitionOutcome::Progress { inner }) => inner,
            _ => return stage,
        };
    stage = Stage::OriginalReceived;

    // A receiver that restarts here resumes from its event log.
    let unchecked = if s.receiver_restarts {
        match payjoin_ffi::replay_receiver_event_log(recv_persister.clone()).map(|r| r.state()) {
            Ok(ReceiveSession::UncheckedOriginalPayload { inner }) => inner,
            _ => panic!("a receiver holding an original must replay as unchecked"),
        }
    } else {
        unchecked
    };

    let reply = receive(unchecked, s, &mut directory, recv_persister);
    if reply != Reply::Nothing {
        stage = Stage::Replied;
    }

    // Sender polls its reply mailbox, decrypts message B and validates the
    // proposal.
    let Ok(rc) = sender.create_poll_request(RELAY.to_string()) else { return stage };
    let res = directory.handle(&rc.request.body, s.faults[SENDER_POLL]);
    match sender.process_response(&res, &rc.ohttp_ctx).save(send_persister.clone()) {
        Ok(PollingForProposalTransitionOutcome::Progress { psbt_base64: _ }) => {
            assert_eq!(reply, Reply::Proposal, "the sender completed without a proposal");
            Stage::Completed
        }
        _ => stage,
    }
}

fn run(psbt_bytes: &[u8], s: &Scenario) -> Stage {
    let Ok(psbt) = Psbt::deserialize(psbt_bytes) else { return Stage::Rejected };
    if !amounts_within_max_money(&psbt) {
        return Stage::Rejected;
    }
    let Some(txout) = psbt.unsigned_tx.output.get(1) else { return Stage::Rejected };
    let Ok(address) = Address::from_script(&txout.script_pubkey, Network::Bitcoin) else {
        return Stage::Rejected;
    };
    let psbt_b64 = psbt.to_string();

    let recv_persister = Persister::arc();
    let send_persister = Persister::arc();
    let stage = run_session(&psbt_b64, &address.to_string(), s, &recv_persister, &send_persister);

    // Wherever the session stopped, a wallet must be able to replay without
    // panicking.
    let _ = payjoin_ffi::replay_receiver_event_log(recv_persister);
    if stage >= Stage::SenderCreated {
        let replayed = replay_sender_event_log(send_persister).map(|r| r.state());
        if stage == Stage::Completed {
            assert!(
                matches!(replayed, Ok(SendSession::Closed { .. })),
                "a completed sender session must replay as closed"
            );
        }
    }
    stage
}

fn do_fuzz(data: &[u8]) -> Stage {
    let (psbt_bytes, scenario_bytes) = split_input(data);
    run(psbt_bytes, &Scenario::from_bytes(scenario_bytes))
}

fuzz_target!(|data| {
    let _ = do_fuzz(data);
});

#[cfg(test)]
mod tests {
    use super::{do_fuzz, run, Scenario, Stage, SEED_PSBT, SENDER_POST};

    fn happy_path() -> Scenario { Scenario::from_bytes(&[]) }

    #[test]
    fn empty_input_does_not_crash() {
        assert_eq!(do_fuzz(&[]), Stage::Rejected);
    }

    #[test]
    fn length_prefix_beyond_buffer_does_not_panic() {
        assert_eq!(do_fuzz(&[0xff, 0xff, 0x00]), Stage::Rejected);
    }

    #[test]
    fn seed_completes_the_roundtrip() {
        let psbt = &*SEED_PSBT;
        let len = u16::try_from(psbt.len()).expect("seed fits in u16");
        let mut input = len.to_be_bytes().to_vec();
        input.extend_from_slice(psbt);
        assert_eq!(do_fuzz(&input), Stage::Completed);
    }

    #[test]
    fn restarted_sender_completes_the_roundtrip() {
        let mut s = happy_path();
        s.sender_restarts = true;
        assert_eq!(run(&SEED_PSBT, &s), Stage::Completed);
    }

    #[test]
    fn restarted_receiver_completes_the_roundtrip() {
        let mut s = happy_path();
        s.receiver_restarts = true;
        assert_eq!(run(&SEED_PSBT, &s), Stage::Completed);
    }

    #[test]
    fn early_polls_do_not_derail_the_session() {
        let mut s = happy_path();
        s.receiver_polls_early = true;
        s.sender_polls_early = true;
        assert_eq!(run(&SEED_PSBT, &s), Stage::Completed);
    }

    #[test]
    fn receiver_rejection_reaches_the_sender() {
        let mut s = happy_path();
        s.inputs_owned = true;
        assert_eq!(run(&SEED_PSBT, &s), Stage::Replied);
    }

    #[test]
    fn directory_error_stops_the_sender_post() {
        let mut s = happy_path();
        s.faults[SENDER_POST] = Some(500);
        assert_eq!(run(&SEED_PSBT, &s), Stage::SenderCreated);
    }
}

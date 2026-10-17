#![cfg_attr(not(test), no_main)]

//! End to end v2 payjoin under fuzz: a real `send::v2` sender and a real
//! `receive::v2` receiver talk through an in-process mock directory.
//!
//! Both parties are honest, so every message passes both crypto layers on
//! its own and the fuzzer never touches ciphertext. What it controls is
//! everything around the messages:
//!
//! - the sender's wallet choices: which builder is used, fee contribution,
//!   minimum fee rate, output substitution;
//! - the receiver's wallet answers: broadcast suitability, input ownership,
//!   inputs seen before, output ownership, fee range;
//! - the directory: any of the four exchanges that carry the session can
//!   answer with an error status instead of delivering;
//! - timing: either party may poll before the other has posted;
//! - persistence: either party may drop its in-memory state mid session
//!   and resume from its event log.
//!
//! The input is `[len:2][psbt][scenario]`. An empty scenario decodes to the
//! happy path, which the `seed_completes_the_roundtrip` test pins down.
//!
//! `receiver/v2.rs` covers what this target cannot: payloads no honest
//! sender would build.

use std::collections::HashMap;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::LazyLock;

use arbitrary::Unstructured;
use bhttp::{
    ControlData, Message as BhttpMessage, Mode as BhttpMode, StatusCode as BhttpStatusCode,
};
use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyConfig as OhttpKeyConfig, Server as OhttpServer, SymmetricSuite};
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{Address, Amount, FeeRate, Network};
use payjoin::directory::ENCAPSULATED_MESSAGE_BYTES;
use payjoin::persist::{InMemoryPersister, OptionalTransitionOutcome};
use payjoin::receive::v2::{
    replay_event_log as replay_receiver_log, HasReplyableError, ReceiveSession, Receiver,
    ReceiverBuilder, SessionEvent as ReceiverEvent, UncheckedOriginalPayload,
};
use payjoin::send::v2::{
    replay_event_log as replay_sender_log, SendSession, SenderBuilder, SessionEvent as SenderEvent,
};
use payjoin::OhttpKeys;

type RecvPersister = InMemoryPersister<ReceiverEvent>;
type SendPersister = InMemoryPersister<SenderEvent>;

const INFALLIBLE: &str = "the in-memory persister cannot fail";

/// The BIP-78 test vector original PSBT, the same one the other roundtrip
/// and receiver targets seed from.
const SEED_PSBT_B64: &str = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

static SEED_PSBT: LazyLock<Vec<u8>> =
    LazyLock::new(|| Psbt::from_str(SEED_PSBT_B64).expect("BIP-78 vector must parse").serialize());

/// Directory and relay the parties talk to. Nothing dials out; the mock
/// directory routes on the request's mailbox path only.
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

/// Gateway side of the OHTTP key config, built once per process.
static OHTTP_SERVER: LazyLock<OhttpServer> =
    LazyLock::new(|| OhttpServer::new(derived_key_config()).expect("valid ohttp server"));

/// Statuses the directory can answer with instead of delivering.
const FAULT_STATUSES: [u16; 5] = [400, 404, 413, 500, 503];

/// The four exchanges that carry the session, as indexes into
/// `Scenario::faults`.
const SENDER_POST: usize = 0;
const RECEIVER_POLL: usize = 1;
const RECEIVER_POST: usize = 2;
const SENDER_POLL: usize = 3;

/// Upper bound for fuzzed fee rates: 1000 sat/vB.
const MAX_FEE_RATE_SAT_PER_KWU: u64 = 250_000;

/// Scenario bytes at or above this value trigger a rare choice, which
/// makes it one in eight.
const RARE_FROM: u8 = 224;

/// Which sender builder to finish with.
#[derive(Clone, Copy)]
enum Build {
    Recommended,
    NonIncentivizing,
    AdditionalFee { max: Amount, change_index: Option<usize>, clamp: bool },
}

/// Everything the fuzzer decides about a session. Every field decodes to
/// its happy path value from zero bytes or from exhausted input, so an
/// empty scenario is a plain successful payjoin. The choices that end a
/// session early are decoded as rare ones, otherwise almost no mutated
/// scenario would reach the end of the protocol.
struct Scenario {
    build: Build,
    sender_min_fee_rate: FeeRate,
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
    receiver_min_fee_rate: Option<FeeRate>,
    receiver_max_fee_rate: Option<FeeRate>,
    faults: [Option<u16>; 4],
}

/// An even coin, for choices that do not end a session.
fn flag(u: &mut Unstructured<'_>) -> bool { u.arbitrary().unwrap_or(false) }

/// True for one byte value in eight. Used for the choices that end a
/// session early, so most mutated scenarios still run to the end.
fn rarely(u: &mut Unstructured<'_>) -> bool { u.arbitrary::<u8>().unwrap_or(0) >= RARE_FROM }

fn fee_rate(u: &mut Unstructured<'_>) -> FeeRate {
    FeeRate::from_sat_per_kwu(u.int_in_range(0..=MAX_FEE_RATE_SAT_PER_KWU).unwrap_or(0))
}

fn optional_fee_rate(u: &mut Unstructured<'_>) -> Option<FeeRate> {
    if rarely(u) {
        Some(fee_rate(u))
    } else {
        None
    }
}

/// One exchange in eight answers with an error status. The same byte
/// picks which one.
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
                max: Amount::from_sat(u.int_in_range(0..=Amount::MAX_MONEY.to_sat()).unwrap_or(0)),
                change_index: u.arbitrary::<Option<u8>>().unwrap_or(None).map(usize::from),
                clamp: flag(&mut u),
            },
        };
        Self {
            build,
            sender_min_fee_rate: optional_fee_rate(&mut u).unwrap_or(FeeRate::ZERO),
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

/// How far a session got. Only the tests inspect this; the fuzz harness
/// discards it.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Stage {
    /// The input was unusable or the sender builder refused the PSBT.
    Rejected,
    /// The sender session exists but its original PSBT was not accepted
    /// by the directory.
    SenderCreated,
    /// The original PSBT sits in the receiver's mailbox.
    OriginalPosted,
    /// The receiver retrieved and decrypted the original PSBT.
    OriginalReceived,
    /// The receiver posted a proposal or an error for the sender.
    Replied,
    /// The sender retrieved and validated the payjoin proposal.
    Completed,
}

/// What the receiver left in the sender's reply mailbox.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Reply {
    Nothing,
    Error,
    Proposal,
}

/// In-process stand-in for the directory's OHTTP gateway: decapsulates
/// requests, routes them by method and mailbox path, and encapsulates the
/// response. The mailboxes are the only per-execution state; the gateway
/// keys live in `OHTTP_SERVER`.
#[derive(Default)]
struct MockDirectory {
    mailboxes: HashMap<String, Vec<u8>>,
}

impl MockDirectory {
    /// Handle one request. With a `fault` the directory answers with that
    /// status and neither stores nor delivers anything.
    fn handle(&mut self, req_body: &[u8], fault: Option<u16>) -> Vec<u8> {
        // `ServerResponse::encapsulate` consumes the response context, and
        // the response overhead is only measurable by encapsulating, so
        // decapsulate the request twice: once to probe the overhead, once
        // to carry the reply. Same technique as `ohttp_response_for` in
        // payjoin's v2 receiver unit tests.
        let (_, probe) = OHTTP_SERVER.decapsulate(req_body).expect("request decapsulates");
        let overhead = probe.encapsulate(&[]).expect("probe encapsulates").len();

        let (bhttp_req, server_response) =
            OHTTP_SERVER.decapsulate(req_body).expect("request decapsulates");

        // Safe: both parties are payjoin's own clients, so this is a
        // request payjoin encapsulated itself, never fuzzer bytes.
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
                // POST/PUT: store and forward into the mailbox named by the path.
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
        // Pad the bhttp response so the encapsulated response fills
        // ENCAPSULATED_MESSAGE_BYTES exactly, as both clients require.
        let mut buf = vec![0u8; ENCAPSULATED_MESSAGE_BYTES - overhead];
        response
            .write_bhttp(BhttpMode::KnownLength, &mut buf.as_mut_slice())
            .expect("bhttp response encodes");
        server_response.encapsulate(&buf).expect("response encapsulates")
    }
}

/// Length prefix, in bytes, of the PSBT section.
const HEADER: usize = 2;

/// Split `[len:2][psbt][scenario]`. A truncated or oversized length yields
/// as much PSBT as the buffer actually holds, so the split never panics.
fn split_input(data: &[u8]) -> (&[u8], &[u8]) {
    if data.len() < HEADER {
        return (&[], &[]);
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let rest = &data[HEADER..];
    rest.split_at(len.min(rest.len()))
}

/// Scenario bytes handed to an input that carries none, so the first
/// mutation already lands on a scenario field.
const DEFAULT_SCENARIO: [u8; 24] = [0; 24];

// Keep the PSBT section intact and spend the mutation budget on the
// scenario, which is where this target's decisions live.
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

/// The original PSBT plays the sender's own wallet here, and payjoin's
/// sender-side fee arithmetic assumes the wallet built a consensus-valid
/// transaction. Amounts above max money are a wallet bug, not a payjoin
/// input, so those PSBTs are skipped. `receiver/v2.rs` is where hostile
/// amounts are thrown at the receiver.
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

/// Post the receiver's replyable error to the sender's reply mailbox.
fn post_error(
    receiver: Receiver<HasReplyableError>,
    s: &Scenario,
    directory: &mut MockDirectory,
    persister: &RecvPersister,
) -> Reply {
    let Ok((req, ctx)) = receiver.create_error_request(RELAY) else { return Reply::Nothing };
    let fault = s.faults[RECEIVER_POST];
    let res = directory.handle(&req.body, fault);
    let _ = receiver.process_error_response(&res, ctx).save(persister);
    if fault.is_none() {
        Reply::Error
    } else {
        Reply::Nothing
    }
}

/// Walk the receiver from the original payload to its reply. Every wallet
/// answer comes from the scenario.
fn receive(
    receiver: Receiver<UncheckedOriginalPayload>,
    s: &Scenario,
    directory: &mut MockDirectory,
    persister: &RecvPersister,
) -> Reply {
    // Save a transition whose failure leaves the receiver with an error it
    // owes the sender, and post that error when it happens.
    macro_rules! replyable {
        ($transition:expr) => {
            match $transition.save(persister) {
                Ok(next) => next,
                Err(e) =>
                    return match e.fatal_state() {
                        Some(error_state) => post_error(error_state, s, directory, persister),
                        None => Reply::Nothing,
                    },
            }
        };
    }

    let rx = if s.check_broadcast {
        replyable!(receiver
            .check_broadcast_suitability(s.receiver_min_fee_rate, |_| Ok(!s.cannot_broadcast)))
    } else {
        receiver.assume_interactive_receiver().save(persister).expect(INFALLIBLE)
    };
    let rx = replyable!(rx.check_inputs_not_owned(&mut |_| Ok(s.inputs_owned)));
    let rx = replyable!(rx.check_no_inputs_seen_before(&mut |_| Ok(s.inputs_seen)));
    let rx = replyable!(rx.identify_receiver_outputs(&mut |_| Ok(!s.outputs_not_mine)));
    let rx = rx.commit_outputs().save(persister).expect(INFALLIBLE);
    let rx = rx.commit_inputs().save(persister).expect(INFALLIBLE);
    let Ok(rx) =
        rx.apply_fee_range(s.receiver_min_fee_rate, s.receiver_max_fee_rate).save(persister)
    else {
        return Reply::Nothing;
    };
    let Ok(proposal) = rx.finalize_proposal(|psbt| Ok(psbt.clone())).save(persister) else {
        return Reply::Nothing;
    };

    let Ok((req, ctx)) = proposal.create_post_request(RELAY) else { return Reply::Nothing };
    let res = directory.handle(&req.body, s.faults[RECEIVER_POST]);
    match proposal.process_response(&res, ctx).save(persister) {
        Ok(_monitor) => Reply::Proposal,
        Err(_) => Reply::Nothing,
    }
}

fn run_session(
    psbt: &Psbt,
    address: &Address,
    s: &Scenario,
    recv_persister: &RecvPersister,
    send_persister: &SendPersister,
) -> Stage {
    let ohttp_keys = OhttpKeys::decode(&KEY_CONFIG_BYTES).expect("derived config decodes");
    let mut directory = MockDirectory::default();

    let session = ReceiverBuilder::new(address.clone(), DIRECTORY, ohttp_keys)
        .expect("valid directory url")
        .build()
        .save(recv_persister)
        .expect(INFALLIBLE);

    // A receiver polling an empty mailbox stays where it is.
    let session = if s.receiver_polls_early {
        let (req, ctx) = session.create_poll_request(RELAY).expect("poll request");
        let res = directory.handle(&req.body, None);
        match session.process_response(&res, ctx).save(recv_persister) {
            Ok(OptionalTransitionOutcome::Stasis(session)) => session,
            _ => return Stage::Rejected,
        }
    } else {
        session
    };

    // The sender reads the receiver's v2 parameters from the session's own
    // URI, as a wallet would after scanning it. The borrow of the URI ends
    // with this block, before the session moves on.
    let built = {
        let pj_uri = session.pj_uri();
        let pj_param = match pj_uri.extras().pj_param() {
            payjoin::PjParam::V2(v2) => v2,
            // The session was just built by ReceiverBuilder; it is always v2.
            _ => unreachable!("a v2 receiver session carries a v2 pj param"),
        };
        let builder = SenderBuilder::from_parts(psbt.clone(), pj_param, address, None);
        let builder = if s.disable_output_substitution {
            builder.always_disable_output_substitution()
        } else {
            builder
        };
        match s.build {
            Build::Recommended => builder.build_recommended(s.sender_min_fee_rate),
            Build::NonIncentivizing => builder.build_non_incentivizing(s.sender_min_fee_rate),
            Build::AdditionalFee { max, change_index, clamp } =>
                builder.build_with_additional_fee(max, change_index, s.sender_min_fee_rate, clamp),
        }
    };
    let Ok(built) = built else { return Stage::Rejected };
    let sender = built.save(send_persister).expect(INFALLIBLE);
    let mut stage = Stage::SenderCreated;

    // Sender posts the original PSBT (message A) to the receiver's mailbox.
    let Ok((req, ctx)) = sender.create_v2_post_request(RELAY) else { return stage };
    let res = directory.handle(&req.body, s.faults[SENDER_POST]);
    let Ok(sender) = sender.process_response(&res, ctx).save(send_persister) else {
        return stage;
    };
    stage = Stage::OriginalPosted;

    // A wallet that restarts here resumes from its event log.
    let sender = if s.sender_restarts {
        match replay_sender_log(send_persister) {
            Ok((SendSession::PollingForProposal(sender), _)) => sender,
            _ => panic!("a sender that posted its original must replay as polling"),
        }
    } else {
        sender
    };

    // A sender polling before the receiver replied stays where it is.
    let sender = if s.sender_polls_early {
        let Ok((req, ctx)) = sender.create_poll_request(RELAY) else { return stage };
        let res = directory.handle(&req.body, None);
        match sender.process_response(&res, ctx).save(send_persister) {
            Ok(OptionalTransitionOutcome::Stasis(sender)) => sender,
            _ => return stage,
        }
    } else {
        sender
    };

    // Receiver retrieves and decrypts the original PSBT.
    let (req, ctx) = session.create_poll_request(RELAY).expect("poll request");
    let res = directory.handle(&req.body, s.faults[RECEIVER_POLL]);
    let receiver = match session.process_response(&res, ctx).save(recv_persister) {
        Ok(OptionalTransitionOutcome::Progress(receiver)) => receiver,
        _ => return stage,
    };
    stage = Stage::OriginalReceived;

    let receiver = if s.receiver_restarts {
        match replay_receiver_log(recv_persister) {
            Ok((ReceiveSession::UncheckedOriginalPayload(receiver), _)) => receiver,
            _ => panic!("a receiver holding an original must replay as unchecked"),
        }
    } else {
        receiver
    };

    let reply = receive(receiver, s, &mut directory, recv_persister);
    if reply != Reply::Nothing {
        stage = Stage::Replied;
    }

    // Sender polls its reply mailbox, decrypts message B and validates the
    // proposal. An error reply or an empty mailbox ends the session here.
    let Ok((req, ctx)) = sender.create_poll_request(RELAY) else { return stage };
    let res = directory.handle(&req.body, s.faults[SENDER_POLL]);
    match sender.process_response(&res, ctx).save(send_persister) {
        Ok(OptionalTransitionOutcome::Progress(_proposal)) => {
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

    // The payee is output 1 of the BIP-78 vector; deriving the address
    // from the PSBT keeps the two in agreement, as in `roundtrip/v1.rs`.
    let Some(txout) = psbt.unsigned_tx.output.get(1) else { return Stage::Rejected };
    let Ok(address) = Address::from_script(&txout.script_pubkey, Network::Bitcoin) else {
        return Stage::Rejected;
    };

    let recv_persister = RecvPersister::default();
    let send_persister = SendPersister::default();
    let stage = run_session(&psbt, &address, s, &recv_persister, &send_persister);

    // Wherever the session stopped, a wallet must be able to replay its
    // event log without panicking.
    let _ = replay_receiver_log(&recv_persister);
    if stage >= Stage::SenderCreated {
        let replayed = replay_sender_log(&send_persister);
        if stage == Stage::Completed {
            assert!(
                matches!(replayed, Ok((SendSession::Closed(_), _))),
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
    use super::{run, Scenario, Stage, SEED_PSBT, SENDER_POST};

    fn happy_path() -> Scenario { Scenario::from_bytes(&[]) }

    #[test]
    fn empty_input_does_not_crash() {
        assert_eq!(super::do_fuzz(&[]), Stage::Rejected);
    }

    #[test]
    fn length_prefix_beyond_buffer_does_not_panic() {
        assert_eq!(super::do_fuzz(&[0xff, 0xff, 0x00]), Stage::Rejected);
    }

    /// The seed PSBT with an empty scenario must complete the payjoin. If
    /// this stops holding, the target is no longer reaching the end of the
    /// protocol and is only exercising early exits.
    #[test]
    fn seed_completes_the_roundtrip() {
        let psbt = &*SEED_PSBT;
        let len = u16::try_from(psbt.len()).expect("seed fits in u16");
        let mut input = len.to_be_bytes().to_vec();
        input.extend_from_slice(psbt);
        assert_eq!(super::do_fuzz(&input), Stage::Completed);
    }

    #[test]
    fn restarted_parties_complete_the_roundtrip() {
        let mut s = happy_path();
        s.sender_restarts = true;
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

    /// A receiver that finds its own input in the original replies with an
    /// error, and the sender must not complete on it.
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

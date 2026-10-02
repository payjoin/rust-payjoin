#![no_main]

//! v2 payjoin roundtrip under fuzz, mirroring `roundtrip/v1.rs`.
//!
//! V2 wraps everything the state machine sees in two layers of crypto:
//! HPKE messages A/B and an OHTTP request/response envelope. Random
//! mutation cannot pass an AEAD tag, so both layers are created
//! harness-side and the fuzzer only ever mutates plaintext:
//!
//! - The OHTTP key config is derived once per process from a fixed seed
//!   and shared by the receiver session, the harness sender and the
//!   in-process mock directory gateway. `LazyLock` statistics make the
//!   setup cost vanish across the millions of execs in one fuzz process.
//! - The receiver's HPKE key stays inside the receiver where it belongs;
//!   the harness sender reads its public key from the session's own
//!   `pj_uri` and encrypts the fuzz-controlled plaintext
//!   (`base64(psbt)\nquery`) to it.
//! - The mock directory is a pure function from request bytes to
//!   response bytes: decapsulate, route on method and mailbox path,
//!   store-and-forward, encapsulate. No network, no threads.
//!
//! Reproducibility: the random values (reply keypair, HPKE and OHTTP
//! ephemerals) only key the transport layer. Downstream execution is a
//! function of the plaintext alone, so a crash replays under fresh keys:
//! the harness re-encrypts the same input and the state machine walks
//! the same path. The `seed_psbt_completes_the_roundtrip` test guards
//! this property; if it fails the target has silently stopped reaching
//! the state machine and is only fuzzing rejection paths.

use std::collections::HashMap;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::LazyLock;

use bhttp::{
    ControlData, Message as BhttpMessage, Mode as BhttpMode, StatusCode as BhttpStatusCode,
};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::SecpK256HkdfSha256 as HpkeKem;
use hpke::rand_core::OsRng;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};
use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{
    ClientRequest as OhttpClientRequest, ClientResponse as OhttpClientResponse,
    KeyConfig as OhttpKeyConfig, Server as OhttpServer, SymmetricSuite,
};
use payjoin::bitcoin::key::constants::{ELLSWIFT_ENCODING_SIZE, PUBLIC_KEY_SIZE};
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::secp256k1::ellswift::ElligatorSwift;
use payjoin::bitcoin::secp256k1::PublicKey as SecpPublicKey;
use payjoin::bitcoin::{Address, Amount, FeeRate, Network};
use payjoin::directory::{ShortId, ENCAPSULATED_MESSAGE_BYTES};
use payjoin::persist::{InMemoryPersister, OptionalTransitionOutcome};
use payjoin::receive::v1::build_v1_pj_uri;
use payjoin::receive::v2::{ReceiverBuilder, SessionEvent};
use payjoin::send::v1::SenderBuilder as V1SenderBuilder;
use payjoin::{HpkePublicKey, OhttpKeys, OutputSubstitution};

type KemPublicKey = <HpkeKem as hpke::Kem>::PublicKey;
type KemSecretKey = <HpkeKem as hpke::Kem>::PrivateKey;
type KemEncappedKey = <HpkeKem as hpke::Kem>::EncappedKey;

/// Wire-format constants of the payjoin v2 message framing, mirroring
/// `payjoin/src/core/hpke.rs`. Kept honest by the round-trip test below.
const POLY1305_TAG_SIZE: usize = 16;
const PADDED_MESSAGE_BYTES: usize = 7168;
const PADDED_PLAINTEXT_A_LENGTH: usize =
    PADDED_MESSAGE_BYTES - (ELLSWIFT_ENCODING_SIZE + PUBLIC_KEY_SIZE + POLY1305_TAG_SIZE);
const INFO_A: &[u8; 8] = b"PjV2MsgA";
const INFO_B: &[u8; 8] = b"PjV2MsgB";

fn compressed_bytes_from_pubkey(pk: &KemPublicKey) -> [u8; PUBLIC_KEY_SIZE] {
    SecpPublicKey::from_slice(&pk.to_bytes())
        .expect("serializing then parsing a pubkey must succeed")
        .serialize()
}

fn kem_pubkey_from_compressed(bytes: &[u8]) -> Result<KemPublicKey, Box<dyn std::error::Error>> {
    let uncompressed = SecpPublicKey::from_slice(bytes)?.serialize_uncompressed();
    Ok(<KemPublicKey as Deserializable>::from_bytes(&uncompressed)?)
}

fn payjoin_pubkey_from_kem(pk: &KemPublicKey) -> Result<HpkePublicKey, Box<dyn std::error::Error>> {
    HpkePublicKey::from_compressed_bytes(&compressed_bytes_from_pubkey(pk)).map_err(Into::into)
}

/// Message A: what a v2 sender posts to the receiver's mailbox. Mirrors
/// `payjoin::hpke::encrypt_message_a`, which is not exported: ellswift
/// encapsulated key, then the sealed `reply_pk || padded plaintext`.
fn encrypt_message_a(
    mut body: Vec<u8>,
    reply_pk: &KemPublicKey,
    receiver_pk: &KemPublicKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if body.len() > PADDED_PLAINTEXT_A_LENGTH {
        return Err("plaintext too large for message A".into());
    }
    let (enc, mut sender_ctx) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, HpkeKem, _>(
        &OpModeS::Base,
        receiver_pk,
        INFO_A,
        &mut OsRng,
    )?;
    body.resize(PADDED_PLAINTEXT_A_LENGTH, 0);
    let mut plaintext = compressed_bytes_from_pubkey(reply_pk).to_vec();
    plaintext.extend_from_slice(&body);
    let ciphertext = sender_ctx.seal(&plaintext, &[])?;
    let mut message_a = ElligatorSwift::from_pubkey(SecpPublicKey::from_slice(&enc.to_bytes())?)
        .to_array()
        .to_vec();
    message_a.extend_from_slice(&ciphertext);
    Ok(message_a)
}

/// Message B: what the receiver posts to the sender's reply mailbox.
/// Mirrors `payjoin::hpke::decrypt_message_b`: recover the encapsulated
/// key from its ellswift encoding, open the sender-authenticated
/// ciphertext with the reply secret key.
fn decrypt_message_b(
    message_b: &[u8],
    receiver_pk: &KemPublicKey,
    sender_sk: &KemSecretKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut enc_bytes = [0u8; ELLSWIFT_ENCODING_SIZE];
    enc_bytes.copy_from_slice(
        message_b
            .get(..ELLSWIFT_ENCODING_SIZE)
            .ok_or("message B shorter than an encapsulated key")?,
    );
    let secp_pk = SecpPublicKey::from_ellswift(ElligatorSwift::from_array(enc_bytes));
    let enc = <KemEncappedKey as Deserializable>::from_bytes(&secp_pk.serialize_uncompressed())?;
    let mut receiver_ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, HpkeKem>(
        &OpModeR::Auth(receiver_pk.clone()),
        sender_sk,
        &enc,
        INFO_B,
    )?;
    let ciphertext =
        message_b.get(ELLSWIFT_ENCODING_SIZE..).ok_or("message B has no ciphertext")?;
    Ok(receiver_ctx.open(ciphertext, &[])?)
}

/// The BIP-78 test vector original PSBT, the same one `roundtrip/v1.rs`
/// seeds from. See that target for why seeding beats raw mutation.
const SEED_PSBT_B64: &str = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

static SEED_PSBT: LazyLock<Vec<u8>> =
    LazyLock::new(|| Psbt::from_str(SEED_PSBT_B64).expect("BIP-78 vector must parse").serialize());

/// Query handed to an input that carries none, so the first mutation
/// already lands on the BIP-77 parameters. `v=2` selects the v2 path
/// through `parse_payload`; a v1-style query is a mutation away.
const DEFAULT_QUERY: &str = "v=2&maxadditionalfeecontribution=182&additionalfeeoutputindex=0";

/// Directory and relay the harness parties talk to. Nothing dials out;
/// the mock directory routes on the request's mailbox path only.
const DIRECTORY: &str = "https://directory.example";
const RELAY: &str = "http://relay.example";
const AUTHORITY: &str = "directory.example";
const V1_ENDPOINT: &str = "https://example.com";

/// OHTTP key agreement parameters, matching the receiver's constants.
const KEY_ID: u8 = 1;
const KEM: Kem = Kem::K256Sha256;
const SYMMETRIC: &[SymmetricSuite] =
    &[SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

/// Deterministic seed for the OHTTP key config. Deriving the config
/// rather than generating it keeps the receiver session, the harness
/// sender and the mock gateway in agreement in every process without
/// any cross-iteration state.
const KEY_CONFIG_SEED: [u8; 32] = [0x42; 32];

/// Deterministically derive the OHTTP key config from a fixed seed. One
/// derived config keeps the receiver session, the harness sender and the
/// mock gateway in agreement in every process without cross-iteration
/// state. Deriving (rather than generating) also preserves the secret
/// half, which the gateway server needs and an encoded config loses.
fn derived_key_config() -> OhttpKeyConfig {
    OhttpKeyConfig::derive(KEY_ID, KEM, SYMMETRIC.to_vec(), &KEY_CONFIG_SEED)
        .expect("valid key config")
}

static KEY_CONFIG_BYTES: LazyLock<Vec<u8>> =
    LazyLock::new(|| derived_key_config().encode().expect("valid key config encoding"));

/// OHTTP request envelope size arithmetic, mirroring the constants in
/// `payjoin/src/core/ohttp.rs`: a padded bhttp request plus the
/// encapsulation overhead fills `ENCAPSULATED_MESSAGE_BYTES` exactly.
const OHTTP_REQ_HEADER_BYTES: usize = 7; // OHTTP binary request framing header
const N_ENC: usize = 65; // uncompressed secp256k1 public key
const N_T: usize = 16; // Poly1305 tag
const PADDED_BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (N_ENC + N_T + OHTTP_REQ_HEADER_BYTES);

/// How far an input traveled through the session. Only the round-trip
/// test inspects this; the fuzz harness itself discards it.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Stage {
    /// The fuzz input was rejected somewhere on the untrusted path.
    Rejected,
    /// Message A was decrypted and parsed; the receiver state machine
    /// holds the fuzz-controlled original payload.
    ProposalRetrieved,
    /// The receiver produced and posted a payjoin proposal (message B).
    ProposalPosted,
    /// The sender-side proposal validation accepted the payjoin PSBT.
    Validated,
}

/// In-process stand-in for the directory's OHTTP gateway: decapsulates
/// requests, routes them by method and mailbox path, and encapsulates
/// the response. Store-and-forward keeps one blob per mailbox, which is
/// all a single-session roundtrip needs.
struct MockDirectory {
    server: OhttpServer,
    mailboxes: HashMap<String, Vec<u8>>,
}

impl MockDirectory {
    fn new() -> Self {
        Self {
            server: OhttpServer::new(derived_key_config()).expect("valid ohttp server"),
            mailboxes: HashMap::new(),
        }
    }

    fn handle(&mut self, req_body: &[u8]) -> Vec<u8> {
        // `ServerResponse::encapsulate` consumes the response context, and
        // the response overhead is only measurable by encapsulating, so
        // decapsulate the request twice: once to probe the overhead, once
        // to carry the reply. Same technique as `ohttp_response_for` in
        // payjoin's v2 receiver unit tests.
        let (_, probe) = self.server.decapsulate(req_body).expect("harness request decapsulates");
        let overhead = probe.encapsulate(&[]).expect("probe encapsulates").len();

        let (bhttp_req, server_response) =
            self.server.decapsulate(req_body).expect("harness request decapsulates");

        // Safe: these bytes came from decapsulating a request the harness
        // itself encapsulated in `ohttp_request`, never fuzzer bytes. A
        // panic here is a harness bug, not a finding.
        let request =
            BhttpMessage::read_bhttp(&mut Cursor::new(&bhttp_req)).expect("harness request parses");

        let (method, path) = match request.control() {
            ControlData::Request { method, path, .. } => (
                String::from_utf8_lossy(method).into_owned(),
                String::from_utf8_lossy(path).into_owned(),
            ),
            ControlData::Response(_) => unreachable!("the gateway only sees requests"),
        };

        let (status, content): (u16, Option<Vec<u8>>) =
            match (method.as_str(), self.mailboxes.get(&path)) {
                ("GET", Some(content)) => (200, Some(content.clone())),
                ("GET", None) => (202, None),
                // POST/PUT: store and forward into the mailbox named by the path.
                _ => {
                    self.mailboxes.insert(path, request.content().to_vec());
                    (200, None)
                }
            };

        let mut response =
            BhttpMessage::response(BhttpStatusCode::try_from(status).expect("valid status code"));
        if let Some(content) = &content {
            response.write_content(content);
        }
        // Pad the bhttp response so the encapsulated response fills
        // ENCAPSULATED_MESSAGE_BYTES exactly, as the receiver requires.
        let mut buf = vec![0u8; ENCAPSULATED_MESSAGE_BYTES - overhead];
        response
            .write_bhttp(BhttpMode::KnownLength, &mut buf.as_mut_slice())
            .expect("bhttp response encodes");
        server_response.encapsulate(&buf).expect("response encapsulates")
    }
}

/// Encapsulate an OHTTP request to the directory gateway, mirroring
/// `ohttp_encapsulate` in `payjoin/src/core/ohttp.rs`, which is not
/// exported. The zero padding sits inside the encrypted envelope, so it
/// is invisible to the receiver's bhttp parser.
fn ohttp_request(method: &str, path: &str, body: Option<&[u8]>) -> (Vec<u8>, OhttpClientResponse) {
    let mut config = OhttpKeyConfig::decode(&KEY_CONFIG_BYTES).expect("derived config decodes");
    let ctx = OhttpClientRequest::from_config(&mut config).expect("client context");
    let mut message = BhttpMessage::request(
        method.as_bytes().to_vec(),
        b"https".to_vec(),
        AUTHORITY.as_bytes().to_vec(),
        path.as_bytes().to_vec(),
    );
    if let Some(body) = body {
        message.write_content(body);
    }
    let mut buf = vec![0u8; PADDED_BHTTP_REQ_BYTES];
    message
        .write_bhttp(BhttpMode::KnownLength, &mut buf.as_mut_slice())
        .expect("bhttp request encodes");
    let (encapsulated, ctx) = ctx.encapsulate(&buf).expect("ohttp request encapsulates");
    (encapsulated, ctx)
}

/// Split `[len:2][psbt][query]`. A truncated or oversized length yields as
/// much PSBT as the buffer actually holds, so the split never panics.
fn split_input(data: &[u8]) -> (&[u8], &[u8]) {
    const HEADER: usize = 2;
    if data.len() < HEADER {
        return (&[], &[]);
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let rest = &data[HEADER..];
    rest.split_at(len.min(rest.len()))
}

// Keep the PSBT section intact and spend the mutation budget on the query,
// where the attacker-controlled BIP-77 parameters live.
fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    const RAW_MUTATION_IN: u32 = 4;
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
    if max_size <= 2 + psbt.len() {
        return fuzzer_mutate(data, size, max_size);
    }
    let query_max = max_size - 2 - psbt.len();

    let mut buf = query.to_vec();
    let query_len = buf.len().min(query_max);
    buf.resize(query_max, 0);
    let query_len = fuzzer_mutate(&mut buf, query_len, query_max);

    data[..2].copy_from_slice(&psbt_len.to_be_bytes());
    data[2..2 + psbt.len()].copy_from_slice(&psbt);
    data[2 + psbt.len()..2 + psbt.len() + query_len].copy_from_slice(&buf[..query_len]);
    2 + psbt.len() + query_len
});

/// Wallet-role bound, applied only to the harness's own sender closer.
/// Payjoin's sender-side fee arithmetic assumes the wallet built a
/// consensus-valid PSBT (the #1/#2 overflow sites are the wallet's own
/// inputs, enforced client-side, not by the state machine). Mutations
/// that inflate a value past max money — 21M BTC total — are a wallet
/// bug, so the closer is skipped for them rather than crashing.
///
/// The receiver is deliberately NOT gated: it must tolerate arbitrary
/// posted amounts, so extreme values still exercise the receiver's
/// parse and validation paths.
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

fn do_fuzz(data: &[u8]) -> Stage {
    let (psbt_bytes, query_bytes) = split_input(data);
    let Ok(psbt) = Psbt::deserialize(psbt_bytes) else { return Stage::Rejected };
    let Ok(query) = std::str::from_utf8(query_bytes) else { return Stage::Rejected };

    // The payee is output 1 of the BIP-78 vector; deriving the address
    // from the PSBT keeps the two in agreement, as in `roundtrip/v1.rs`.
    let Some(txout) = psbt.unsigned_tx.output.get(1) else { return Stage::Rejected };
    let Ok(address) = Address::from_script(&txout.script_pubkey, Network::Bitcoin) else {
        return Stage::Rejected;
    };

    let ohttp_keys = OhttpKeys::decode(&KEY_CONFIG_BYTES).expect("derived config decodes");
    let recv_persister = InMemoryPersister::<SessionEvent>::default();
    let mut directory = MockDirectory::new();

    let session = ReceiverBuilder::new(address.clone(), DIRECTORY, ohttp_keys)
        .expect("valid directory url")
        .build()
        .save(&recv_persister)
        .expect("session creation persists");

    // First poll hits the empty-mailbox stasis path (202, no results).
    let (req, ctx) = session.create_poll_request(RELAY).expect("poll request");
    let res = directory.handle(&req.body);
    let session = match session.process_response(&res, ctx).save(&recv_persister) {
        Ok(OptionalTransitionOutcome::Stasis(session)) => session,
        _ => return Stage::Rejected,
    };

    // Harness sender: read the receiver's v2 parameters from the session's
    // own URI, then encrypt the fuzz-controlled plaintext to them. The
    // receiver's secret key never leaves the receiver.
    let pj_uri = session.pj_uri();
    let receiver_pk = match pj_uri.extras().pj_param() {
        payjoin::PjParam::V2(v2) => v2.receiver_pubkey().clone(),
        // The session was just built by ReceiverBuilder; it is always v2.
        _ => unreachable!("a v2 receiver session carries a v2 pj param"),
    };
    let Ok(receiver_kem_pk) = kem_pubkey_from_compressed(&receiver_pk.to_compressed_bytes()) else {
        return Stage::Rejected;
    };
    let (reply_sk, reply_pk) = <HpkeKem as hpke::Kem>::gen_keypair(&mut OsRng);
    let Ok(reply_payjoin_pk) = payjoin_pubkey_from_kem(&reply_pk) else { return Stage::Rejected };
    let reply_path = format!("/{}", ShortId::from(&reply_payjoin_pk));

    let plaintext = format!("{psbt}\n{query}").into_bytes();
    let Ok(message_a) = encrypt_message_a(plaintext, &reply_pk, &receiver_kem_pk) else {
        return Stage::Rejected; // oversized payload: a legitimate sender refusal
    };
    let receiver_path = format!("/{}", ShortId::from(&receiver_pk));
    let (post_body, _) = ohttp_request("POST", &receiver_path, Some(&message_a));
    let _ = directory.handle(&post_body);

    // The receiver's next poll delivers message A: OHTTP decapsulation,
    // HPKE decryption and `parse_payload` all run on the way in.
    let (req, ctx) = session.create_poll_request(RELAY).expect("poll request");
    let res = directory.handle(&req.body);
    let receiver = match session.process_response(&res, ctx).save(&recv_persister) {
        Ok(OptionalTransitionOutcome::Progress(receiver)) => receiver,
        _ => return Stage::Rejected, // fuzz payload rejected before the state machine
    };
    let mut stage = Stage::ProposalRetrieved;

    // Every check answers unconditionally, as in the v1 target: a real
    // receiver's answers depend on its own UTXO set.
    let rx = receiver
        .assume_interactive_receiver()
        .save(&recv_persister)
        .expect("interactive transition persists");
    let Ok(rx) = rx.check_inputs_not_owned(&mut |_| Ok(false)).save(&recv_persister) else {
        return stage;
    };
    let Ok(rx) = rx.check_no_inputs_seen_before(&mut |_| Ok(false)).save(&recv_persister) else {
        return stage;
    };
    let Ok(rx) = rx.identify_receiver_outputs(&mut |_| Ok(true)).save(&recv_persister) else {
        return stage;
    };
    let rx = rx.commit_outputs().save(&recv_persister).expect("commit_outputs persists");
    let rx = rx.commit_inputs().save(&recv_persister).expect("commit_inputs persists");
    let Ok(rx) = rx.apply_fee_range(None, None).save(&recv_persister) else { return stage };
    let Ok(proposal) = rx.finalize_proposal(|psbt| Ok(psbt.clone())).save(&recv_persister) else {
        return stage;
    };

    // Post message B to the sender's reply mailbox and advance to Monitor.
    let (req, ctx) = proposal.create_post_request(RELAY).expect("post request");
    let res = directory.handle(&req.body);
    let Ok(_monitor) = proposal.process_response(&res, ctx).save(&recv_persister) else {
        return stage;
    };
    stage = Stage::ProposalPosted;

    // Close the loop as the sender: poll the reply mailbox, decapsulate,
    // decrypt message B and parse the proposal PSBT, mirroring
    // `send::v2::PollingForProposal::process_response`.
    let (get_body, client_ctx) = ohttp_request("GET", &reply_path, None);
    let res = directory.handle(&get_body);
    let Ok(bhttp_res) = client_ctx.decapsulate(&res) else { return stage };
    // Safe: the harness encapsulated this response itself; fuzzer-controlled
    // content rides inside as opaque bytes, never parsed as bhttp here.
    let response =
        BhttpMessage::read_bhttp(&mut Cursor::new(&bhttp_res)).expect("harness response parses");
    let content = match response.control() {
        ControlData::Response(status) if status.code() == 200 => response.content(),
        _ => return stage,
    };
    let Ok(plaintext_b) = decrypt_message_b(content, &receiver_kem_pk, &reply_sk) else {
        return stage;
    };
    let Ok(payjoin_psbt) = Psbt::deserialize(&plaintext_b) else { return stage };

    // Sender-side validation via the v1 sender context, whose
    // `process_response` runs the same `PsbtContext::process_proposal`
    // checks the v2 sender would. Built last so a v1-builder rejection
    // cannot gate the v2 receiver coverage above. The closer plays the
    // sender's wallet, so consensus-invalid amounts (a wallet bug) skip
    // it: the payload above already ran the receiver with those values.
    if amounts_within_max_money(&psbt)
        && let Ok(v1_uri) = build_v1_pj_uri(&address, V1_ENDPOINT, OutputSubstitution::Enabled)
        && let Ok(sender) =
            V1SenderBuilder::new(psbt.clone(), v1_uri).build_non_incentivizing(FeeRate::ZERO)
    {
        let (_request, v1_ctx) = sender.create_v1_post_request();
        // The v1 wire format is the base64 PSBT string, not raw bytes.
        if v1_ctx.process_response(payjoin_psbt.to_string().as_bytes()).is_ok() {
            return Stage::Validated;
        }
    }
    stage
}

fuzz_target!(|data| {
    let _ = do_fuzz(data);
});

#[cfg(test)]
mod tests {
    use super::Stage;

    #[test]
    fn empty_input_does_not_crash() {
        assert_eq!(super::do_fuzz(&[]), Stage::Rejected);
    }

    #[test]
    fn length_prefix_beyond_buffer_does_not_panic() {
        assert_eq!(super::do_fuzz(&[0xff, 0xff, 0x00]), Stage::Rejected);
    }

    /// The seed PSBT with a well-formed query must walk the whole chain,
    /// through both crypto layers and both state machines. If this stops
    /// holding, the harness-side framing has drifted from payjoin's and
    /// the fuzzer is silently only exercising rejection paths again.
    #[test]
    fn seed_psbt_completes_the_roundtrip() {
        let psbt = &*super::SEED_PSBT;
        let len = u16::try_from(psbt.len()).expect("seed fits in u16");
        let mut input = len.to_be_bytes().to_vec();
        input.extend_from_slice(psbt);
        input.extend_from_slice(super::DEFAULT_QUERY.as_bytes());
        assert_eq!(super::do_fuzz(&input), Stage::Validated);
    }
}

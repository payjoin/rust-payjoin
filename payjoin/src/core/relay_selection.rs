//! Stateless relay selection for BIP 77 sessions.
//!
//! Applications prepare relay candidates after applying their own network
//! policy. This module only provides deterministic, AS-aware ordering; it does
//! not perform DNS resolution, ASMap lookup, or HTTP requests.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bitcoin::hashes::{sha256, Hash, HashEngine};

use crate::{HpkePublicKey, Url};

// Keep the existing domain tag so moving the algorithm does not change the
// relay order produced by the CLI.
const RELAY_SELECTION_TAG: &[u8] = b"payjoin-cli-stateless-relay-selection-v1";
const CLOCK_SKEW_WINDOWS: i64 = 2;
const POST_RESERVED_COUNT: usize = 3;

/// Number of seconds in one relay-selection window.
pub const WINDOW_SECS: u64 = 30;

/// A wallet-specific relay value with a URL used for deterministic selection.
///
/// This keeps transport data generic without storing the URL twice.
pub trait Relay {
    /// Return the relay URL used for hashing and URL-based fallback grouping.
    fn url(&self) -> &Url;
}

/// Whether the current OHTTP request posts or polls a BIP 77 message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// Post a message to the directory.
    Post(MessageKind),
    /// Poll the directory for a message.
    Poll(MessageKind),
}

/// Identifies which BIP 77 message is being transferred.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// The sender's original PSBT message.
    Original = 0,
    /// The receiver's proposal or replyable error message.
    Proposal = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RelayBucket {
    Asn(u32),
    Url(String),
}

impl RelayBucket {
    fn identifier_bytes(&self) -> Vec<u8> {
        match self {
            Self::Asn(asn) => asn.to_be_bytes().to_vec(),
            Self::Url(url) => url.as_bytes().to_vec(),
        }
    }
}

/// A relay together with the identifiers needed for deterministic selection.
///
/// `T` is owned by the application. It may be a URL, a DNS-pinned transport
/// target, or another wallet-specific relay representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCandidate<T> {
    relay: T,
    bucket: RelayBucket,
}

impl<T> RelayCandidate<T> {
    /// Return the application-owned relay value.
    pub fn relay(&self) -> &T { &self.relay }

    /// Consume the candidate and return its application-owned relay value.
    pub fn into_relay(self) -> T { self.relay }
}

impl<T: Relay> RelayCandidate<T> {
    /// Construct a relay grouped with other relays in the same autonomous system.
    pub fn with_asn(relay: T, asn: u32) -> Self { Self { relay, bucket: RelayBucket::Asn(asn) } }

    /// Construct a relay treated as its own URL bucket when its ASN is unknown.
    pub fn individual(relay: T) -> Self {
        let url = relay.url().as_str().to_owned();
        Self { relay, bucket: RelayBucket::Url(url) }
    }
}

/// A deterministic relay-selection time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimeWindow(u64);

impl TimeWindow {
    /// Derive the selection window from Unix time and the receiver key.
    ///
    /// The key-derived offset prevents every session from changing its relay
    /// preference at the same wall-clock boundary.
    pub fn from_unix_seconds(unix_seconds: u64, receiver_pubkey: &HpkePublicKey) -> Self {
        let offset = receiver_key_offset(receiver_pubkey);
        Self((unix_seconds + offset) / WINDOW_SECS)
    }

    fn saturating_offset(self, offset: i64) -> Self {
        if offset.is_negative() {
            Self(self.0.saturating_sub(offset.unsigned_abs()))
        } else {
            Self(self.0.saturating_add(offset as u64))
        }
    }
}

/// Return the deterministic relay order for one POST or POLL request.
///
/// POST requests try one relay from each preferred privacy bucket. POLL
/// requests avoid buckets reserved for matching POST requests in nearby time
/// windows. If too few buckets exist, POLL falls back to the complete ordering.
pub fn select_relay_candidates<'a, T: Relay>(
    candidates: &'a [RelayCandidate<T>],
    request_kind: RequestKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<&'a RelayCandidate<T>> {
    match request_kind {
        RequestKind::Post(message) =>
            select_post_candidates(candidates, message, receiver_pubkey, window),
        RequestKind::Poll(message) =>
            select_poll_candidates(candidates, message, receiver_pubkey, window),
    }
}

fn select_post_candidates<'a, T: Relay>(
    candidates: &'a [RelayCandidate<T>],
    message: MessageKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<&'a RelayCandidate<T>> {
    let reserved = ranked_buckets(candidates, message, receiver_pubkey, window)
        .into_iter()
        .take(POST_RESERVED_COUNT)
        .collect::<BTreeSet<_>>();
    let mut selected_buckets = BTreeSet::new();

    ordered_candidates(candidates, message, receiver_pubkey, window)
        .into_iter()
        .filter(|candidate| {
            reserved.contains(&candidate.bucket)
                && selected_buckets.insert(candidate.bucket.clone())
        })
        .collect()
}

fn select_poll_candidates<'a, T: Relay>(
    candidates: &'a [RelayCandidate<T>],
    message: MessageKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<&'a RelayCandidate<T>> {
    let reserved = post_reserved_buckets(candidates, message, receiver_pubkey, window);
    let poll_candidates = candidates
        .iter()
        .filter(|candidate| !reserved.contains(&candidate.bucket))
        .collect::<Vec<_>>();

    let ordered_poll_candidates =
        ordered_candidates(poll_candidates, message, receiver_pubkey, window);
    if !ordered_poll_candidates.is_empty() {
        return ordered_poll_candidates;
    }

    tracing::warn!(
        "Not enough relay buckets to keep POLL separate from POST, POLL may reuse POST-reserved buckets"
    );
    ordered_candidates(candidates, message, receiver_pubkey, window)
}

fn post_reserved_buckets<T: Relay>(
    candidates: &[RelayCandidate<T>],
    message: MessageKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> BTreeSet<RelayBucket> {
    let mut reserved = BTreeSet::new();
    for offset in -CLOCK_SKEW_WINDOWS..=CLOCK_SKEW_WINDOWS {
        let adjacent_window = window.saturating_offset(offset);
        reserved.extend(
            ranked_buckets(candidates, message, receiver_pubkey, adjacent_window)
                .into_iter()
                .take(POST_RESERVED_COUNT),
        );
    }
    reserved
}

fn ordered_candidates<'a, T: Relay>(
    candidates: impl IntoIterator<Item = &'a RelayCandidate<T>>,
    message: MessageKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<&'a RelayCandidate<T>> {
    let mut buckets = BTreeMap::<RelayBucket, Vec<&RelayCandidate<T>>>::new();
    for candidate in candidates {
        buckets.entry(candidate.bucket.clone()).or_default().push(candidate);
    }

    let mut bucket_entries = buckets
        .into_iter()
        .map(|(bucket, mut relays)| {
            relays
                .sort_by_key(|candidate| relay_score(message, receiver_pubkey, window, candidate));
            let bucket_score = bucket_score(message, receiver_pubkey, window, &bucket);
            (bucket_score, VecDeque::from(relays))
        })
        .collect::<Vec<_>>();
    bucket_entries.sort_by_key(|(score, _)| *score);

    let mut ordered = vec![];
    loop {
        let mut emitted = false;
        for (_, bucket) in &mut bucket_entries {
            if let Some(candidate) = bucket.pop_front() {
                ordered.push(candidate);
                emitted = true;
            }
        }
        if !emitted {
            break;
        }
    }
    ordered
}

fn ranked_buckets<T: Relay>(
    candidates: &[RelayCandidate<T>],
    message: MessageKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<RelayBucket> {
    let mut buckets = candidates
        .iter()
        .map(|candidate| candidate.bucket.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    buckets.sort_by_key(|bucket| bucket_score(message, receiver_pubkey, window, bucket));
    buckets
}

fn receiver_key_offset(receiver_pubkey: &HpkePublicKey) -> u64 {
    let hash = sha256::Hash::hash(&receiver_pubkey.to_compressed_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&Hash::as_byte_array(&hash)[..8]);
    u64::from_be_bytes(bytes) % WINDOW_SECS
}

fn bucket_score(
    message: MessageKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
    bucket: &RelayBucket,
) -> [u8; 32] {
    let bucket_identifier = bucket.identifier_bytes();
    selection_hash(message, receiver_pubkey, window, b"bucket", &bucket_identifier)
}

fn relay_score<T: Relay>(
    message: MessageKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
    candidate: &RelayCandidate<T>,
) -> [u8; 32] {
    selection_hash(
        message,
        receiver_pubkey,
        window,
        b"relay",
        candidate.relay.url().as_str().as_bytes(),
    )
}

fn selection_hash(
    message: MessageKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
    label: &[u8],
    payload: &[u8],
) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(RELAY_SELECTION_TAG);
    engine.input(&[message as u8]);
    engine.input(&receiver_pubkey.to_compressed_bytes());
    engine.input(&window.0.to_be_bytes());
    engine.input(label);
    engine.input(payload);
    *sha256::Hash::from_engine(engine).as_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestRelay(Url);

    impl Relay for TestRelay {
        fn url(&self) -> &Url { &self.0 }
    }

    const RECEIVER_PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn receiver_pubkey() -> HpkePublicKey {
        HpkePublicKey::from_compressed_bytes(&RECEIVER_PUBKEY).unwrap()
    }

    fn candidate(relay: &str, asn: u32) -> RelayCandidate<TestRelay> {
        let url = Url::parse(&format!("https://{relay}.example")).unwrap();
        RelayCandidate::with_asn(TestRelay(url), asn)
    }

    fn individual_candidate(relay: &str) -> RelayCandidate<TestRelay> {
        let url = Url::parse(&format!("https://{relay}.example")).unwrap();
        RelayCandidate::individual(TestRelay(url))
    }

    #[test]
    fn selection_is_deterministic() {
        let candidates = vec![
            candidate("relay-a", 1),
            candidate("relay-b", 2),
            candidate("relay-c", 3),
            candidate("relay-d", 4),
        ];
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow::from_unix_seconds(1_700_000_000, &receiver_pubkey);

        let first = select_relay_candidates(
            &candidates,
            RequestKind::Post(MessageKind::Original),
            &receiver_pubkey,
            window,
        );
        let second = select_relay_candidates(
            &candidates,
            RequestKind::Post(MessageKind::Original),
            &receiver_pubkey,
            window,
        );

        assert_eq!(first, second);
    }

    #[test]
    fn post_uses_at_most_one_relay_per_bucket() {
        let candidates = vec![
            candidate("relay-a", 1),
            candidate("relay-b", 1),
            candidate("relay-c", 2),
            candidate("relay-d", 3),
        ];
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow::from_unix_seconds(1_700_000_000, &receiver_pubkey);

        let selected = select_relay_candidates(
            &candidates,
            RequestKind::Post(MessageKind::Proposal),
            &receiver_pubkey,
            window,
        );
        let selected_buckets =
            selected.iter().map(|candidate| &candidate.bucket).collect::<BTreeSet<_>>();

        assert_eq!(selected.len(), 3);
        assert_eq!(selected.len(), selected_buckets.len());
    }

    #[test]
    fn individual_relays_use_their_urls_as_buckets() {
        let candidates = vec![individual_candidate("relay-a"), individual_candidate("relay-b")];
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow::from_unix_seconds(1_700_000_000, &receiver_pubkey);

        let selected = select_relay_candidates(
            &candidates,
            RequestKind::Post(MessageKind::Original),
            &receiver_pubkey,
            window,
        );

        assert_eq!(selected.len(), 2);
    }
}

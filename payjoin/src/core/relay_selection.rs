//! Deterministic OHTTP relay ordering for BIP 77 sessions.
//!
//! Given the same relay candidates, receiver public key, request kind, and time
//! window, both sender and receiver derive the same relay order without storing
//! relay-selection state. POST requests use the preferred bucket for the current
//! window; POLL requests avoid POST buckets from the previous, current, and next
//! windows so the two mailbox directions do not use the same relay bucket when
//! enough buckets are available.
//!
//! Relay candidates are grouped into privacy buckets by the application. With
//! ASMap, a bucket is an ASN; without ASMap, each relay URL is its own bucket.
//! This module only orders those prepared candidates. DNS resolution, ASMap
//! lookup, directory filtering, and HTTP requests stay with the application.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bitcoin::hashes::{sha256, Hash, HashEngine};

use crate::{HpkePublicKey, Url};

const RELAY_SELECTION_TAG: &[u8] = b"payjoin-relay-selection";
const CLOCK_SKEW_WINDOWS: i64 = 1;
const POST_RESERVED_COUNT: usize = 1;

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
    Post,
    /// Poll the directory for a message.
    Poll,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RelayBucket {
    Asn(u32),
    Url(String),
}

impl RelayBucket {
    /// Return the stable bytes hashed when ordering this privacy bucket.
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
        RequestKind::Post => select_post_candidates(candidates, receiver_pubkey, window),
        RequestKind::Poll => select_poll_candidates(candidates, receiver_pubkey, window),
    }
}

// POST uses the first bucket for this window. If several relays are in that
// bucket, keep only the first hash-ordered relay so POST does not consume every
// relay in one ASN.
fn select_post_candidates<'a, T: Relay>(
    candidates: &'a [RelayCandidate<T>],
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<&'a RelayCandidate<T>> {
    let reserved = ranked_relay_buckets_for_post(candidates, receiver_pubkey, window)
        .into_iter()
        .take(POST_RESERVED_COUNT)
        .collect::<BTreeSet<_>>();
    let mut selected_buckets = BTreeSet::new();

    bucket_round_robin_candidates(candidates, receiver_pubkey, window)
        .into_iter()
        .filter(|candidate| {
            reserved.contains(&candidate.bucket)
                && selected_buckets.insert(candidate.bucket.clone())
        })
        .collect()
}

// POLL avoids buckets that POST may use in the previous, current, or next
// window. If that leaves no candidate, fall back so the session can still make
// progress with degraded separation.
fn select_poll_candidates<'a, T: Relay>(
    candidates: &'a [RelayCandidate<T>],
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<&'a RelayCandidate<T>> {
    let reserved = reserved_relay_buckets_for_poll(candidates, receiver_pubkey, window);
    let poll_candidates =
        candidates.iter().filter(|candidate| !reserved.contains(&candidate.bucket));

    let ordered_poll_candidates =
        bucket_round_robin_candidates(poll_candidates, receiver_pubkey, window);
    if !ordered_poll_candidates.is_empty() {
        return ordered_poll_candidates;
    }

    tracing::warn!(
        "Not enough relay buckets to keep POLL separate from POST, POLL may reuse POST-reserved buckets"
    );
    bucket_round_robin_candidates(candidates, receiver_pubkey, window)
}

// Reserve the POST bucket from nearby windows to tolerate small clock skew
// between sender and receiver.
fn reserved_relay_buckets_for_poll<T: Relay>(
    candidates: &[RelayCandidate<T>],
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> BTreeSet<RelayBucket> {
    let mut reserved = BTreeSet::new();
    for offset in -CLOCK_SKEW_WINDOWS..=CLOCK_SKEW_WINDOWS {
        let adjacent_window = window.saturating_offset(offset);
        reserved.extend(
            ranked_relay_buckets_for_post(candidates, receiver_pubkey, adjacent_window)
                .into_iter()
                .take(POST_RESERVED_COUNT),
        );
    }
    reserved
}

/// Return candidates in hash order, taking one relay from each bucket per round.
///
/// This reduces to simple hash ordering when each bucket has one relay. When
/// ASMap groups several relays into the same ASN bucket, round-robin keeps that
/// bucket from dominating the front of the order before other ASNs are tried.
fn bucket_round_robin_candidates<'a, T: Relay>(
    candidates: impl IntoIterator<Item = &'a RelayCandidate<T>>,
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
            relays.sort_by_key(|candidate| relay_score(receiver_pubkey, window, candidate));
            let bucket_score = bucket_score(receiver_pubkey, window, &bucket);
            (bucket_score, VecDeque::from(relays))
        })
        .collect::<Vec<_>>();
    bucket_entries.sort_by_key(|(score, _)| *score);

    let rounds = bucket_entries.iter().map(|(_, bucket)| bucket.len()).max().unwrap_or(0);
    let mut ordered = Vec::new();
    for _ in 0..rounds {
        for (_, bucket) in &mut bucket_entries {
            if let Some(candidate) = bucket.pop_front() {
                ordered.push(candidate);
            }
        }
    }
    ordered
}

// Deduplicate buckets first: POST reservation is by privacy bucket, not by
// individual relay. With ASMap, multiple relays may share the same ASN.
fn ranked_relay_buckets_for_post<T: Relay>(
    candidates: &[RelayCandidate<T>],
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<RelayBucket> {
    let mut buckets = candidates
        .iter()
        .map(|candidate| candidate.bucket.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    buckets.sort_by_key(|bucket| bucket_score(receiver_pubkey, window, bucket));
    buckets
}

// Stagger window boundaries per session so all sessions do not rotate relay
// preferences at the same wall-clock second.
fn receiver_key_offset(receiver_pubkey: &HpkePublicKey) -> u64 {
    let hash = sha256::Hash::hash(&receiver_pubkey.to_compressed_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&Hash::as_byte_array(&hash)[..8]);
    u64::from_be_bytes(bytes) % WINDOW_SECS
}

// Order privacy buckets, e.g. ASNs when ASMap is available or relay URLs when
// ASMap is unavailable.
fn bucket_score(
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
    bucket: &RelayBucket,
) -> [u8; 32] {
    let bucket_identifier = bucket.identifier_bytes();
    selection_hash(receiver_pubkey, window, b"bucket", &bucket_identifier)
}

// Order relays inside a bucket. This is separate from bucket ordering so relay
// URLs cannot change which bucket is preferred for POST.
fn relay_score<T: Relay>(
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
    candidate: &RelayCandidate<T>,
) -> [u8; 32] {
    selection_hash(receiver_pubkey, window, b"relay", candidate.relay.url().as_str().as_bytes())
}

// Scope all relay-selection hashes with a tag and use labels to separate bucket
// ordering from relay ordering.
fn selection_hash(
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
    label: &[u8],
    payload: &[u8],
) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(RELAY_SELECTION_TAG);
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
    fn time_window_matches_fixed_vector() {
        let receiver_pubkey = receiver_pubkey();

        assert_eq!(receiver_key_offset(&receiver_pubkey), 25);
        assert_eq!(TimeWindow::from_unix_seconds(0, &receiver_pubkey), TimeWindow(0));
        assert_eq!(TimeWindow::from_unix_seconds(4, &receiver_pubkey), TimeWindow(0));
        assert_eq!(TimeWindow::from_unix_seconds(5, &receiver_pubkey), TimeWindow(1));
        assert_eq!(TimeWindow::from_unix_seconds(34, &receiver_pubkey), TimeWindow(1));
        assert_eq!(TimeWindow::from_unix_seconds(35, &receiver_pubkey), TimeWindow(2));
    }

    #[test]
    fn scores_depend_on_bucket_and_relay_identifiers() {
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow(100);
        let relay_a = individual_candidate("relay-a");
        let relay_b = individual_candidate("relay-b");

        assert_ne!(
            bucket_score(&receiver_pubkey, window, &RelayBucket::Asn(1)),
            bucket_score(&receiver_pubkey, window, &RelayBucket::Asn(2))
        );
        assert_ne!(
            bucket_score(&receiver_pubkey, window, &relay_a.bucket),
            bucket_score(&receiver_pubkey, window, &relay_b.bucket)
        );
        assert_ne!(
            relay_score(&receiver_pubkey, window, &relay_a),
            relay_score(&receiver_pubkey, window, &relay_b)
        );
    }

    #[test]
    fn bucket_round_robin_candidates_matches_fixed_vector() {
        let candidates = vec![
            candidate("relay-a", 1),
            candidate("relay-b", 1),
            candidate("relay-c", 2),
            candidate("relay-d", 2),
            candidate("relay-e", 3),
            candidate("relay-f", 4),
        ];
        let receiver_pubkey = receiver_pubkey();

        let ordered = bucket_round_robin_candidates(&candidates, &receiver_pubkey, TimeWindow(100));

        // Buckets are hash-ordered, relays are hash-ordered within each
        // bucket, and round-robin selection eventually returns every relay.
        assert_eq!(
            ordered,
            vec![
                &candidates[4],
                &candidates[5],
                &candidates[3],
                &candidates[0],
                &candidates[2],
                &candidates[1],
            ]
        );
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

        let first =
            select_relay_candidates(&candidates, RequestKind::Post, &receiver_pubkey, window);
        let second =
            select_relay_candidates(&candidates, RequestKind::Post, &receiver_pubkey, window);

        assert_eq!(first, second);
    }

    #[test]
    fn relays_in_same_asn_share_one_bucket() {
        let candidates = vec![
            candidate("relay-a", 1),
            candidate("relay-b", 1),
            candidate("relay-c", 2),
            candidate("relay-d", 3),
        ];
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow::from_unix_seconds(1_700_000_000, &receiver_pubkey);

        let buckets = ranked_relay_buckets_for_post(&candidates, &receiver_pubkey, window);

        assert_eq!(buckets.len(), 3);
    }

    #[test]
    fn individual_relays_use_their_urls_as_buckets() {
        let candidates = vec![individual_candidate("relay-a"), individual_candidate("relay-b")];
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow::from_unix_seconds(1_700_000_000, &receiver_pubkey);

        let buckets = ranked_relay_buckets_for_post(&candidates, &receiver_pubkey, window);

        assert_eq!(buckets.len(), 2);
        assert_ne!(buckets[0], buckets[1]);
    }

    #[test]
    fn post_uses_first_bucket_for_current_window() {
        let candidates = vec![
            candidate("relay-a", 1),
            candidate("relay-b", 2),
            candidate("relay-c", 3),
            candidate("relay-d", 4),
        ];
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow(100);

        let selected =
            select_relay_candidates(&candidates, RequestKind::Post, &receiver_pubkey, window);
        let first_bucket = ranked_relay_buckets_for_post(&candidates, &receiver_pubkey, window)
            .into_iter()
            .next()
            .expect("candidate buckets are not empty");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].bucket, first_bucket);
    }

    #[test]
    fn four_buckets_keep_poll_separate_from_nearby_posts() {
        let candidates = vec![
            candidate("relay-a", 1),
            candidate("relay-b", 2),
            candidate("relay-c", 3),
            candidate("relay-d", 4),
        ];
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow(100);
        let nearby_post_buckets = (-CLOCK_SKEW_WINDOWS..=CLOCK_SKEW_WINDOWS)
            .flat_map(|offset| {
                select_relay_candidates(
                    &candidates,
                    RequestKind::Post,
                    &receiver_pubkey,
                    window.saturating_offset(offset),
                )
            })
            .map(|candidate| candidate.bucket.clone())
            .collect::<BTreeSet<_>>();

        let poll =
            select_relay_candidates(&candidates, RequestKind::Poll, &receiver_pubkey, window);

        assert!(!poll.is_empty());
        assert!(poll.iter().all(|candidate| !nearby_post_buckets.contains(&candidate.bucket)));
    }

    #[test]
    fn eight_buckets_leave_several_poll_candidates() {
        let candidates =
            (1..=8).map(|asn| candidate(&format!("relay-{asn}"), asn)).collect::<Vec<_>>();
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow(100);

        let poll =
            select_relay_candidates(&candidates, RequestKind::Poll, &receiver_pubkey, window);

        // At most one distinct bucket is reserved in each of three nearby windows.
        assert!(poll.len() >= 5);
    }

    #[test]
    fn one_bucket_uses_degraded_poll_fallback() {
        let candidates = vec![candidate("relay-a", 1)];
        let receiver_pubkey = receiver_pubkey();
        let window = TimeWindow(100);

        let post =
            select_relay_candidates(&candidates, RequestKind::Post, &receiver_pubkey, window);
        let poll =
            select_relay_candidates(&candidates, RequestKind::Poll, &receiver_pubkey, window);

        assert_eq!(post, poll);
    }
}

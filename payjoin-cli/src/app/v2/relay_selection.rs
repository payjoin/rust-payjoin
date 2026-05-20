//! Stateless OHTTP relay selection for BIP77 sessions.
//!
//! This module has two jobs:
//! - choose the receiver's directory and usable relay set before the receiver key exists
//! - use the receiver key, request kind, and time window to choose relays without
//!   storing a current relay index or failed-relay state
//!
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use payjoin::bitcoin::hashes::{sha256, Hash, HashEngine};
use payjoin::bitcoin::key::rand::seq::SliceRandom;
use payjoin::bitcoin::key::rand::{thread_rng, Rng};
use payjoin::{HpkePublicKey, PjParam, Url};

use crate::app::config::V2Config;
#[cfg(feature = "asmap")]
use crate::app::config::{AsmapConfig, LoadedAsmap};
const RELAY_SELECTION_TAG: &[u8] = b"payjoin-cli-stateless-relay-selection-v1";

#[cfg(any(feature = "asmap", test))]
type Asn = u32;

pub(crate) const WINDOW_SECS: u64 = 30;
const CLOCK_SKEW_WINDOWS: i64 = 2;
const POST_RESERVED_COUNT: usize = 3;

// CLI/app primitive: this includes resolved network addresses, so it is tied to
// how payjoin-cli performs DNS and HTTP requests.
/// Directory and relay set chosen before the receiver key is available.
///
/// The receiver needs this during session creation: it must choose a directory
/// and fetch OHTTP keys before the receiver pubkey can be read from the endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceiverNetworkSelection {
    pub(crate) directory: ResolvedUrl,
    pub(crate) relays: Vec<RelayCandidate>,
}

/// Chooses which OHTTP relays to try for a request.
///
/// It stores the usable relay candidates and the receiver public key. For each
/// POST or POLL request, it combines those values with the current time window
/// to compute a fresh relay order. It does not remember the last relay used or
/// keep a cursor into the previous ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelaySelector {
    relays: Vec<RelayCandidate>,
    receiver_pubkey: HpkePublicKey,
}

// Candidate for the main crate: every wallet should use the same protocol
// request labels so relay selection is derived consistently.
/// Whether the current OHTTP request is posting data or polling for data.
///
/// POST and POLL intentionally derive different relay orderings so that a
/// sender POST is less likely to interrupt a receiver POLL on the same AS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestKind {
    Post(MessageKind),
    Poll(MessageKind),
}

impl RequestKind {
    fn method_tag(self) -> &'static [u8] {
        match self {
            RequestKind::Post(_) => b"post",
            RequestKind::Poll(_) => b"poll",
        }
    }

    fn message(self) -> MessageKind {
        match self {
            RequestKind::Post(message) | RequestKind::Poll(message) => message,
        }
    }
}

// Candidate for the main crate: this is the issue's "message 0 or 1" domain
// separator, mapped onto BIP77's two mailbox/message directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageKind {
    /// Sender's original PSBT message.
    Original,
    /// Receiver's payjoin proposal or replyable error message.
    Proposal,
}

impl MessageKind {
    fn tag(self) -> &'static [u8] {
        match self {
            MessageKind::Original => b"original",
            MessageKind::Proposal => b"proposal",
        }
    }
}

// Candidate for the main crate: the main crate should expose construction from
// a caller-provided unix timestamp, while the CLI can call SystemTime::now().
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TimeWindow(u64);

impl TimeWindow {
    /// Current 30 second selection window with a receiver-key-derived offset.
    ///
    /// The offset keeps all sessions from switching relay preferences at the
    /// exact same wall-clock boundary.
    pub(crate) fn current(receiver_pubkey: &HpkePublicKey) -> Self {
        let unix_seconds =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self::from_unix_seconds(unix_seconds, receiver_pubkey)
    }

    fn from_unix_seconds(unix_seconds: u64, receiver_pubkey: &HpkePublicKey) -> Self {
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

// CLI/app primitive: this carries the concrete socket addresses that reqwest
// should use for a URL after DNS and optional ASMap checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedUrl {
    pub(crate) url: Url,
    /// Socket addresses that were resolved and, when ASMap is enabled, ASN-checked.
    pub(crate) socket_addrs: Vec<SocketAddr>,
}

impl ResolvedUrl {
    pub(crate) fn new(url: Url, socket_addrs: Vec<SocketAddr>) -> Self {
        Self { url, socket_addrs }
    }

    pub(crate) fn domain(&self) -> Option<&str> { self.url.domain() }
}

// Possible main-crate shape: `RelayCandidate { uri, bucket }`. The CLI version
// carries `ResolvedUrl` because it also owns concrete network routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayCandidate {
    pub(crate) resolved: ResolvedUrl,
    /// Selection bucket. With ASMap this is the ASN; otherwise it is the URL.
    bucket: RelayBucket,
}

impl RelayCandidate {
    fn new(resolved: ResolvedUrl, bucket: RelayBucket) -> Self { Self { resolved, bucket } }
}

// Candidate for the main crate: the selector only needs stable bucket IDs. ASNs
// are one bucket source, but a future library type could also allow opaque IDs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RelayBucket {
    #[cfg(feature = "asmap")]
    Asn(Asn),
    /// Fallback bucket when ASMap is unavailable or not configured.
    Url(String),
}

impl RelayBucket {
    fn score_payload(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "asmap")]
            RelayBucket::Asn(asn) => asn.to_be_bytes().to_vec(),
            RelayBucket::Url(url) => url.as_bytes().to_vec(),
        }
    }
}

impl RelaySelector {
    /// Return the relay order to try for one POST or POLL request.
    ///
    /// The ordering is recomputed from the receiver key and current time, so no
    /// relay-selection progress needs to be stored between requests.
    pub(crate) fn select_relays_for_request(
        &self,
        request_kind: RequestKind,
    ) -> Result<Vec<ResolvedUrl>> {
        select_relay_candidates(
            &self.relays,
            request_kind,
            &self.receiver_pubkey,
            TimeWindow::current(&self.receiver_pubkey),
        )
        .map(|candidates| candidates.into_iter().map(|candidate| candidate.resolved).collect())
    }
}

/// Convert the receiver network selection into request-time relay selection after
/// the receiver endpoint exists and contains the receiver pubkey.
pub(crate) fn relay_selector_from_network_selection(
    endpoint: &str,
    network_selection: ReceiverNetworkSelection,
) -> Result<RelaySelector> {
    let endpoint_directory = directory_from_endpoint(endpoint)?;
    if normalized_url(&endpoint_directory) != normalized_url(&network_selection.directory.url) {
        bail!(
            "Receiver endpoint directory {} does not match selected directory {}",
            endpoint_directory.as_str(),
            network_selection.directory.url.as_str()
        );
    }
    Ok(RelaySelector {
        relays: network_selection.relays,
        receiver_pubkey: receiver_pubkey_from_endpoint(endpoint)?,
    })
}

fn select_relay_candidates(
    candidates: &[RelayCandidate],
    request_kind: RequestKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Result<Vec<RelayCandidate>> {
    if candidates.is_empty() {
        bail!("No valid relays available");
    }

    match request_kind {
        RequestKind::Post(_) =>
            Ok(select_post_candidates(candidates, request_kind, receiver_pubkey, window)),
        RequestKind::Poll(_) =>
            select_poll_candidates(candidates, request_kind, receiver_pubkey, window),
    }
}

// Candidate for the main crate: pure selection policy. It only depends on
// candidates, receiver key, request label, and time window.
// POSTs are rare, so reserve up to POST_RESERVED_COUNT preferred AS buckets and
// try one relay from each bucket.
fn select_post_candidates(
    candidates: &[RelayCandidate],
    request_kind: RequestKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<RelayCandidate> {
    let reserved = ranked_buckets(candidates, request_kind, receiver_pubkey, window)
        .into_iter()
        .take(POST_RESERVED_COUNT)
        .collect::<BTreeSet<_>>();
    let mut selected_buckets = BTreeSet::new();

    ordered_candidates(candidates, request_kind, receiver_pubkey, window)
        .into_iter()
        .filter(|candidate| {
            reserved.contains(&candidate.bucket)
                && selected_buckets.insert(candidate.bucket.clone())
        })
        .collect()
}

// Candidate for the main crate: pure selection policy. This is the central
// stateless POST/POLL separation described in the issue.
// POLLs avoid the AS buckets that a matching POST would use around the current
// time window. This is the main traffic-analysis mitigation.
fn select_poll_candidates(
    candidates: &[RelayCandidate],
    request_kind: RequestKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Result<Vec<RelayCandidate>> {
    let reserved =
        post_reserved_buckets(candidates, request_kind.message(), receiver_pubkey, window);
    let poll_candidates = candidates
        .iter()
        .filter(|candidate| !reserved.contains(&candidate.bucket))
        .cloned()
        .collect::<Vec<_>>();

    let ordered_poll_candidates =
        ordered_candidates(&poll_candidates, request_kind, receiver_pubkey, window);
    if !ordered_poll_candidates.is_empty() {
        return Ok(ordered_poll_candidates);
    }

    tracing::warn!(
        "Not enough relay buckets to keep POLL separate from POST, POLL may reuse POST-reserved buckets"
    );
    Ok(ordered_candidates(candidates, request_kind, receiver_pubkey, window))
}

// Candidate for the main crate: clock-skew tolerant POST-reservation logic.
// Compute POST-reserved buckets for nearby windows so small sender/receiver
// clock drift does not make POST and POLL choose the same AS.
fn post_reserved_buckets(
    candidates: &[RelayCandidate],
    message: MessageKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> BTreeSet<RelayBucket> {
    let mut reserved = BTreeSet::new();
    for offset in -CLOCK_SKEW_WINDOWS..=CLOCK_SKEW_WINDOWS {
        let adjacent_window = window.saturating_offset(offset);
        reserved.extend(
            ranked_buckets(
                candidates,
                RequestKind::Post(message),
                receiver_pubkey,
                adjacent_window,
            )
            .into_iter()
            .take(POST_RESERVED_COUNT),
        );
    }
    reserved
}

// Candidate for the main crate: pure deterministic ordering. It should operate
// on generic bucket IDs, not on DNS or ASMap directly.
// Order buckets by hash, order relays within each bucket by hash, then
// round-robin across buckets so one AS with many relays is not over-weighted.
fn ordered_candidates(
    candidates: &[RelayCandidate],
    request_kind: RequestKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<RelayCandidate> {
    // Group relays by privacy bucket: ASN with ASMap, URL fallback otherwise.
    let mut buckets = BTreeMap::<RelayBucket, Vec<RelayCandidate>>::new();
    for candidate in candidates {
        buckets.entry(candidate.bucket.clone()).or_default().push(candidate.clone());
    }

    // Sort relays within each bucket, then sort the buckets themselves.
    let mut bucket_entries = buckets
        .into_iter()
        .map(|(bucket, mut relays)| {
            relays.sort_by_key(|candidate| {
                relay_score(request_kind, receiver_pubkey, window, candidate)
            });
            let bucket_score = bucket_score(request_kind, receiver_pubkey, window, &bucket);
            (bucket_score, VecDeque::from(relays))
        })
        .collect::<Vec<_>>();
    bucket_entries.sort_by_key(|(score, _)| *score);

    // Round-robin across buckets so one AS with many relays cannot dominate.
    let mut ordered = vec![];
    loop {
        let mut emitted = false;
        for (_, bucket) in bucket_entries.iter_mut() {
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

fn ranked_buckets(
    candidates: &[RelayCandidate],
    request_kind: RequestKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
) -> Vec<RelayBucket> {
    let mut buckets = candidates
        .iter()
        .map(|candidate| candidate.bucket.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    buckets.sort_by_key(|bucket| bucket_score(request_kind, receiver_pubkey, window, bucket));
    buckets
}

fn receiver_key_offset(receiver_pubkey: &HpkePublicKey) -> u64 {
    let hash = sha256::Hash::hash(&receiver_pubkey.to_compressed_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&Hash::as_byte_array(&hash)[..8]);
    u64::from_be_bytes(bytes) % WINDOW_SECS
}

// Candidate for the main crate: pure hash scoring.
// Score an AS bucket or URL bucket for deterministic pseudo-random ordering.
fn bucket_score(
    request_kind: RequestKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
    bucket: &RelayBucket,
) -> [u8; 32] {
    let payload = bucket.score_payload();
    selection_hash(request_kind, receiver_pubkey, window, b"bucket", &payload)
}

// Candidate for the main crate: pure hash scoring.
// Score one relay within its bucket.
fn relay_score(
    request_kind: RequestKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
    candidate: &RelayCandidate,
) -> [u8; 32] {
    selection_hash(
        request_kind,
        receiver_pubkey,
        window,
        b"relay",
        candidate.resolved.url.as_str().as_bytes(),
    )
}

// Candidate for the main crate: this is the core deterministic derivation. The
// tag may need a final protocol/library name before being stabilized.
// Domain-separated hash used for deterministic relay selection.
fn selection_hash(
    request_kind: RequestKind,
    receiver_pubkey: &HpkePublicKey,
    window: TimeWindow,
    label: &[u8],
    payload: &[u8],
) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(RELAY_SELECTION_TAG);
    engine.input(request_kind.method_tag());
    engine.input(request_kind.message().tag());
    engine.input(&receiver_pubkey.to_compressed_bytes());
    engine.input(&window.0.to_be_bytes());
    engine.input(label);
    engine.input(payload);
    *sha256::Hash::from_engine(engine).as_byte_array()
}

// Relay utils
//
// These helpers prepare clean relay/directory inputs for the selector. They are
// intentionally kept below the pure ordering code because they are CLI/app
// concerns: endpoint parsing, trusted-directory checks, DNS resolution, ASMap
// lookup, and reqwest address resolution.

// CLI/app primitive: this joins DNS results with optional ASMap classification.
// It should not move wholesale to the main crate because DNS and ASMap loading
// are wallet/application responsibilities.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedServer {
    /// URL plus resolved socket addresses.
    resolved: ResolvedUrl,
    /// ASN is present only when the server was resolved through ASMap.
    #[cfg(feature = "asmap")]
    asn: Option<Asn>,
}

// CLI/app abstraction: keeps DNS and ASMap lookup testable without putting IO
// into the selection algorithm itself.
pub(crate) trait NetworkView {
    /// Resolve hostnames behind a trait so tests can use deterministic DNS data.
    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<IpAddr>>;
    #[cfg(feature = "asmap")]
    /// Look up the ASN for an IP. Returns None when ASMap has no mapping.
    fn lookup_asn(&self, ip: IpAddr) -> Result<Option<Asn>>;
}

#[derive(Debug, Clone)]
pub(crate) struct SystemNetwork {
    #[cfg(feature = "asmap")]
    asmap: Option<LoadedAsmap>,
}

impl SystemNetwork {
    #[cfg(feature = "asmap")]
    pub(crate) fn new(v2: &V2Config) -> Self {
        Self { asmap: v2.asmap.as_ref().map(|cfg| cfg.asmap.clone()) }
    }

    #[cfg(not(feature = "asmap"))]
    pub(crate) fn new(_v2: &V2Config) -> Self { Self {} }
}

impl NetworkView for SystemNetwork {
    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let resolved = (host, port)
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve host {host}:{port}"))?
            .map(|addr| addr.ip())
            .collect::<Vec<_>>();
        Ok(resolved)
    }

    #[cfg(feature = "asmap")]
    fn lookup_asn(&self, ip: IpAddr) -> Result<Option<Asn>> {
        let Some(asmap) = &self.asmap else {
            return Ok(None);
        };
        let asn = asmap.lookup(ip);
        Ok((asn != 0).then_some(asn))
    }
}

// CLI/app code: chooses and resolves the receiver's directory before the
// receiver key exists. A main-crate selector cannot do this because it should
// not know about config, DNS, ASMap files, or OHTTP key fetching.
// This network selection can filter by user and directory ASNs, but request-time
// ordering waits until RelaySelector has the receiver pubkey.
pub(crate) fn choose_receiver_network_selection(
    v2: &V2Config,
    network: &impl NetworkView,
) -> Result<ReceiverNetworkSelection> {
    let chosen_directory = choose_directory(v2, network)?;
    #[cfg(feature = "asmap")]
    let directory_asn = chosen_directory.asn;
    let directory = chosen_directory.resolved;
    let mut relays = relay_candidates(
        v2,
        network,
        #[cfg(feature = "asmap")]
        directory_asn,
    )?;

    if relays.is_empty() {
        bail!("No valid relays available for the selected directory {}", directory.url.as_str());
    }

    relays.shuffle(&mut thread_rng());
    Ok(ReceiverNetworkSelection { directory, relays })
}

pub(crate) fn relay_selector_from_endpoint(
    v2: &V2Config,
    endpoint: &str,
    network: &impl NetworkView,
) -> Result<RelaySelector> {
    let pj_param = parse_v2_pj_param(endpoint)?;
    let directory_url = directory_from_endpoint(endpoint)?;
    ensure_directory_trusted(v2, &directory_url)?;
    #[cfg(feature = "asmap")]
    let (directory, directory_asn) = if let Some(asmap) = &v2.asmap {
        let user_asns = user_asns(asmap, network)?;
        let directory = resolve_asn_server(network, &directory_url)?;
        let directory_asn = directory.asn.expect("ASMap directory candidates carry a resolved ASN");
        if user_asns.contains(&directory_asn) {
            bail!(
                "Endpoint directory {} shares ASN {} with the user",
                directory.resolved.url.as_str(),
                directory_asn
            );
        }
        (directory.resolved, Some(directory_asn))
    } else {
        (resolve_server(network, &directory_url)?.resolved, None)
    };
    #[cfg(not(feature = "asmap"))]
    let directory = resolve_server(network, &directory_url)?.resolved;

    let receiver_pubkey = receiver_pubkey_from_pj_param(&pj_param);
    let relays = relay_candidates(
        v2,
        network,
        #[cfg(feature = "asmap")]
        directory_asn,
    )?;
    if relays.is_empty() {
        bail!(
            "No valid relays available after filtering user and directory ASNs for {}",
            directory.url.as_str()
        );
    }

    Ok(RelaySelector { relays, receiver_pubkey: receiver_pubkey.clone() })
}

// CLI/app code: directory trust and user-AS filtering are wallet policy. The
// main crate can provide selection primitives, but should not own the trusted
// directory list or public-IP/user-AS discovery.
// Choose a directory from the trusted set. With ASMap, reject directories that
// share an ASN with the user. Without ASMap, still resolve and pin the chosen
// directory so later network code uses the checked addresses.
fn choose_directory(v2: &V2Config, network: &impl NetworkView) -> Result<ResolvedServer> {
    #[cfg(feature = "asmap")]
    if let Some(asmap) = &v2.asmap {
        let user_asns = user_asns(asmap, network)?;
        let mut directories = resolve_asn_servers(network, v2.trusted_directories())?
            .into_iter()
            .filter(|candidate| candidate.asn.map(|asn| !user_asns.contains(&asn)).unwrap_or(false))
            .collect::<Vec<_>>();
        if directories.is_empty() {
            bail!("No trusted directories remain after excluding the user's ASNs");
        }
        let index = thread_rng().gen_range(0..directories.len());
        return Ok(directories.swap_remove(index));
    }

    let mut directories = v2.trusted_directories().to_vec();
    if directories.is_empty() {
        bail!("At least one trusted directory must be configured");
    }
    let index = thread_rng().gen_range(0..directories.len());
    let directory = directories.swap_remove(index);
    resolve_server(network, &directory)
}

// Bridge between CLI policy and protocol-like selection: the CLI resolves,
// filters, and buckets relays; the pure selector only consumes RelayCandidate.
// Build relay candidates for request selection. With ASMap this filters out
// relay ASNs that match the user or chosen directory. Without ASMap, it keeps
// all configured relays and buckets them by URL.
fn relay_candidates(
    v2: &V2Config,
    network: &impl NetworkView,
    #[cfg(feature = "asmap")] directory_asn: Option<Asn>,
) -> Result<Vec<RelayCandidate>> {
    #[cfg(feature = "asmap")]
    if let Some(asmap) = &v2.asmap {
        let user_asns = user_asns(asmap, network)?;
        let directory_asn = directory_asn.expect("ASMap directory candidates carry a resolved ASN");
        return asn_relay_candidates(
            resolve_asn_servers(network, &v2.ohttp_relays)?,
            user_asns,
            directory_asn,
        );
    }
    let mut relays = resolve_servers(network, &v2.ohttp_relays)?
        .into_iter()
        .map(|target| url_bucket_candidate(target.resolved))
        .collect::<Vec<_>>();
    relays.sort_by(|left, right| left.resolved.url.as_str().cmp(right.resolved.url.as_str()));
    Ok(relays)
}

#[cfg(feature = "asmap")]
// CLI/app code: ASMap filtering policy. The main crate should not know how ASNs
// were obtained; it only needs bucket IDs after filtering.
// Convert ASN-resolved servers into relay candidates, dropping relays in ASNs
// that would overlap with the user or selected directory.
fn asn_relay_candidates(
    candidates: Vec<ResolvedServer>,
    user_asns: BTreeSet<Asn>,
    directory_asn: Asn,
) -> Result<Vec<RelayCandidate>> {
    let mut filtered = vec![];
    for candidate in candidates {
        let asn =
            candidate.asn.ok_or_else(|| anyhow!("ASMap relay candidate lacks a resolved ASN"))?;
        if asn != directory_asn && !user_asns.contains(&asn) {
            filtered.push((candidate.resolved, asn));
        }
    }

    if filtered.is_empty() {
        return Ok(vec![]);
    }

    filtered.sort_by(|(left, _), (right, _)| left.url.as_str().cmp(right.url.as_str()));
    Ok(filtered
        .into_iter()
        .map(|(resolved, asn)| RelayCandidate::new(resolved, RelayBucket::Asn(asn)))
        .collect())
}

pub(crate) fn ensure_directory_trusted(v2: &V2Config, directory: &Url) -> Result<()> {
    if v2
        .trusted_directories()
        .iter()
        .any(|candidate| normalized_url(candidate) == normalized_url(directory))
    {
        return Ok(());
    }

    bail!(
        "The directory embedded in the BIP21 URI is not in the configured trusted directory set: {}",
        directory.as_str()
    );
}

fn normalized_url(url: &Url) -> String {
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url.host_str().to_ascii_lowercase();
    let default_port = known_default_port(url);

    let mut normalized = format!("{scheme}://{host}");
    if let Some(port) = url.port() {
        if Some(port) != default_port {
            normalized.push(':');
            normalized.push_str(&port.to_string());
        }
    }

    let path = url.path().trim_end_matches('/');
    if !path.is_empty() && path != "/" {
        normalized.push_str(path);
    }

    normalized
}

#[cfg(feature = "asmap")]
// CLI/app code: user ASNs come from local config or local public-IP discovery.
// This is intentionally outside the deterministic selector.
// Collect configured user ASNs and ASNs derived from configured public IPs.
fn user_asns(asmap: &AsmapConfig, network: &impl NetworkView) -> Result<BTreeSet<Asn>> {
    let mut user_asns = asmap.user_asns.iter().copied().collect::<BTreeSet<_>>();
    for ip in &asmap.user_public_ips {
        let asn = network.lookup_asn(*ip)?.ok_or_else(|| {
            anyhow!("Failed to map user public IP {ip} to an ASN using the ASMap")
        })?;
        user_asns.insert(asn);
    }
    Ok(user_asns)
}

#[cfg(feature = "asmap")]
// CLI/app code: DNS plus ASMap lookup. A future main-crate API could receive
// `RelayBucket::Asn(asn)` from the caller instead of doing this lookup.
// Resolve each server and require all returned IPs to map to exactly one ASN.
fn resolve_asn_servers(network: &impl NetworkView, urls: &[Url]) -> Result<Vec<ResolvedServer>> {
    urls.iter().map(|url| resolve_asn_server(network, url)).collect()
}

// CLI/app code: plain DNS resolution for non-ASMap mode.
// Resolve each server without ASMap classification.
fn resolve_servers(network: &impl NetworkView, urls: &[Url]) -> Result<Vec<ResolvedServer>> {
    urls.iter().map(|url| resolve_server(network, url)).collect()
}

// CLI/app code: concrete socket addresses are reqwest/network specific.
// DNS resolution plus socket address capture. ASMap is not consulted here.
fn resolve_server(network: &impl NetworkView, url: &Url) -> Result<ResolvedServer> {
    Ok(ResolvedServer {
        resolved: resolved_url(url, &resolved_ips(network, url)?)?,
        #[cfg(feature = "asmap")]
        asn: None,
    })
}

#[cfg(feature = "asmap")]
// CLI/app code: conservative ASMap resolver. Mixed-ASN rejection is policy that
// prepares clean ASN buckets for the pure selector.
// DNS resolution plus ASMap lookup. Mixed-ASN hostnames are rejected because the
// selector reasons about one AS bucket per server.
fn resolve_asn_server(network: &impl NetworkView, url: &Url) -> Result<ResolvedServer> {
    let ips = resolved_ips(network, url)?;

    let mut asns = BTreeSet::new();
    for ip in &ips {
        let asn = network.lookup_asn(*ip)?.ok_or_else(|| {
            anyhow!("{} resolved to {ip}, which could not be mapped to an ASN", url.as_str())
        })?;
        asns.insert(asn);
    }

    match asns.len() {
        1 => Ok(ResolvedServer {
            resolved: resolved_url(url, &ips)?,
            asn: Some(*asns.first().expect("checked len")),
        }),
        0 => bail!("{} resolved to no ASN-mapped addresses", url.as_str()),
        _ => bail!(
            "{} resolves to multiple ASNs {:?}; mixed-ASN hostnames are rejected",
            url.as_str(),
            asns
        ),
    }
}

// CLI/app code: concrete DNS result processing.
// Resolve to unique IPs before storing socket addresses or doing ASMap lookup.
fn resolved_ips(network: &impl NetworkView, url: &Url) -> Result<Vec<IpAddr>> {
    let port = relay_port(url)?;
    let host = url.host_str();
    let mut ips = if let Some(ip) = parse_ip_literal(&host) {
        vec![ip]
    } else {
        network.resolve_host(&host, port)?
    };
    if ips.is_empty() {
        bail!("{} resolved to no IP addresses", url.as_str());
    }
    ips.sort();
    ips.dedup();
    Ok(ips)
}

// CLI/app code: used by reqwest `resolve_to_addrs`, not a protocol primitive.
// Preserve the exact addresses that were resolved and checked.
fn resolved_url(url: &Url, ips: &[IpAddr]) -> Result<ResolvedUrl> {
    let port = relay_port(url)?;
    let socket_addrs = ips.iter().copied().map(|ip| SocketAddr::new(ip, port)).collect();
    Ok(ResolvedUrl::new(url.clone(), socket_addrs))
}

fn url_bucket_candidate(resolved: ResolvedUrl) -> RelayCandidate {
    let bucket = RelayBucket::Url(resolved.url.as_str().to_owned());
    RelayCandidate::new(resolved, bucket)
}

fn parse_v2_pj_param(endpoint: &str) -> Result<PjParam> {
    match PjParam::parse(endpoint)? {
        pj_param @ PjParam::V2(_) => Ok(pj_param),
        #[cfg(feature = "v1")]
        PjParam::V1(_) => bail!("Expected a BIP77 endpoint, got a BIP78 endpoint"),
        _ => bail!("Expected a BIP77 endpoint"),
    }
}

fn receiver_pubkey_from_endpoint(endpoint: &str) -> Result<HpkePublicKey> {
    let pj_param = parse_v2_pj_param(endpoint)?;
    Ok(receiver_pubkey_from_pj_param(&pj_param).clone())
}

fn receiver_pubkey_from_pj_param(pj_param: &PjParam) -> &HpkePublicKey {
    match pj_param {
        PjParam::V2(pj_param) => pj_param.receiver_pubkey(),
        #[cfg(feature = "v1")]
        PjParam::V1(_) => unreachable!("parse_v2_pj_param only returns BIP77 endpoints"),
        _ => unreachable!("parse_v2_pj_param only returns BIP77 endpoints"),
    }
}

pub(crate) fn directory_from_endpoint(endpoint: &str) -> Result<Url> {
    let endpoint = Url::parse(endpoint)?;
    let mut raw = format!("{}://{}", endpoint.scheme(), endpoint.host_str());
    if let Some(port) = endpoint.port() {
        raw.push(':');
        raw.push_str(&port.to_string());
    }

    let mut segments = endpoint
        .path_segments()
        .expect("payjoin::Url path_segments() is always available")
        .collect::<Vec<_>>();
    if segments.is_empty() {
        bail!("The BIP77 endpoint has no session path segment");
    }
    segments.pop();

    if segments.is_empty() {
        raw.push('/');
    } else {
        raw.push('/');
        raw.push_str(&segments.join("/"));
    }

    Url::parse(&raw)
        .with_context(|| format!("Failed to derive the directory from endpoint {endpoint}"))
}

fn relay_port(url: &Url) -> Result<u16> {
    url.port().or_else(|| known_default_port(url)).ok_or_else(|| {
        anyhow!("Unsupported scheme {} for relay/directory URL {}", url.scheme(), url.as_str())
    })
}

fn known_default_port(url: &Url) -> Option<u16> {
    match url.scheme() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
}

fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>()
        .ok()
        .or_else(|| host.strip_prefix('[')?.strip_suffix(']')?.parse::<IpAddr>().ok())
}

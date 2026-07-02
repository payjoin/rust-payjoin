//! Stateless OHTTP relay selection for BIP77 sessions.
//!
//! This module has two jobs:
//! - choose the receiver's directory and usable relay set before the receiver key exists
//! - use the receiver key, request kind, and time window to choose relays without
//!   storing a current relay index or failed-relay state
//!
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use payjoin::bitcoin::key::rand::seq::SliceRandom;
use payjoin::bitcoin::key::rand::thread_rng;
use payjoin::relay_selection::{
    select_relay_candidates, Relay as SelectionRelay, RelayCandidate as SelectionCandidate,
    RequestKind, TimeWindow,
};
use payjoin::{HpkePublicKey, PjParam, Url};

use crate::app::config::V2Config;
#[cfg(feature = "asmap")]
use crate::app::config::{AsmapConfig, LoadedAsmap};

#[cfg(any(feature = "asmap", test))]
type Asn = u32;

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

// CLI/app primitive: this carries the concrete socket addresses that reqwest
// should use for a URL after DNS and optional ASMap checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedUrl {
    pub(crate) url: Url,
    /// Socket addresses that were resolved and, when ASMap is enabled, ASN-checked.
    pub(crate) socket_addrs: Vec<SocketAddr>,
}

impl ResolvedUrl {
    pub(crate) fn domain(&self) -> Option<&str> { self.url.domain() }
}

impl SelectionRelay for ResolvedUrl {
    fn url(&self) -> &Url { &self.url }
}

type RelayCandidate = SelectionCandidate<ResolvedUrl>;

impl RelaySelector {
    /// Return the relay order to try for one POST or POLL request.
    ///
    /// The ordering is recomputed from the receiver key and current time, so no
    /// relay-selection progress needs to be stored between requests.
    pub(crate) fn select_relays_for_request(
        &self,
        request_kind: RequestKind,
    ) -> Result<Vec<ResolvedUrl>> {
        let selected = select_relay_candidates(
            &self.relays,
            request_kind,
            &self.receiver_pubkey,
            current_time_window(&self.receiver_pubkey),
        );
        if selected.is_empty() {
            bail!("No valid relays available");
        }
        Ok(selected.into_iter().map(|candidate| candidate.relay().clone()).collect())
    }
}

fn current_time_window(receiver_pubkey: &HpkePublicKey) -> TimeWindow {
    let unix_seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    TimeWindow::from_unix_seconds(unix_seconds, receiver_pubkey)
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

// Relay utils
//
// These helpers prepare relay and directory inputs for the library selector.
// They remain CLI concerns: endpoint parsing, trusted-directory checks, DNS
// resolution, ASMap lookup, and reqwest address resolution.

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
    excluded_directories: &[Url],
) -> Result<ReceiverNetworkSelection> {
    let chosen_directory = choose_directory(v2, network, excluded_directories)?;
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
fn choose_directory(
    v2: &V2Config,
    network: &impl NetworkView,
    excluded_directories: &[Url],
) -> Result<ResolvedServer> {
    let mut directories = v2
        .pj_directories
        .iter()
        .filter(|candidate| {
            !excluded_directories
                .iter()
                .any(|excluded| normalized_url(excluded) == normalized_url(candidate))
        })
        .cloned()
        .collect::<Vec<_>>();
    directories.shuffle(&mut thread_rng());
    if directories.is_empty() {
        bail!("No trusted directories remain after excluding failed directories");
    }

    #[cfg(feature = "asmap")]
    if let Some(asmap) = &v2.asmap {
        let user_asns = user_asns(asmap, network)?;
        for directory in directories {
            match resolve_asn_server(network, &directory) {
                Ok(candidate)
                    if candidate.asn.map(|asn| !user_asns.contains(&asn)).unwrap_or(false) =>
                {
                    return Ok(candidate);
                }
                Ok(candidate) => tracing::debug!(
                    "Skipping directory {} because it shares an ASN with the user",
                    candidate.resolved.url
                ),
                Err(error) => tracing::debug!(
                    "Skipping directory {} because resolution failed: {error:#}",
                    directory
                ),
            }
        }
        bail!("No trusted directories remain after resolution and ASMap filtering");
    }

    for directory in directories {
        match resolve_server(network, &directory) {
            Ok(candidate) => return Ok(candidate),
            Err(error) => tracing::debug!(
                "Skipping directory {} because resolution failed: {error:#}",
                directory
            ),
        }
    }
    bail!("No trusted directories could be resolved")
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
        let candidates = v2
            .ohttp_relays
            .iter()
            .filter_map(|url| match resolve_asn_server(network, url) {
                Ok(candidate) => Some(candidate),
                Err(error) => {
                    tracing::debug!("Skipping relay {url} because resolution failed: {error:#}");
                    None
                }
            })
            .collect();
        return asn_relay_candidates(candidates, user_asns, directory_asn);
    }
    let relays = v2
        .ohttp_relays
        .iter()
        .filter_map(|url| match resolve_server(network, url) {
            Ok(target) => Some(RelayCandidate::individual(target.resolved)),
            Err(error) => {
                tracing::debug!("Skipping relay {url} because resolution failed: {error:#}");
                None
            }
        })
        .collect();
    Ok(relays)
}

#[cfg(feature = "asmap")]
// Prepare ASN-resolved relays for the library selector: remove relays sharing
// the user or directory ASN and attach each remaining relay's ASN. The library
// groups and deterministically orders candidates by the attached ASN.
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
    Ok(filtered
        .into_iter()
        .map(|(resolved, asn)| RelayCandidate::with_asn(resolved, asn))
        .collect())
}

pub(crate) fn ensure_directory_trusted(v2: &V2Config, directory: &Url) -> Result<()> {
    if v2
        .pj_directories
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
    Ok(ResolvedUrl { url: url.clone(), socket_addrs })
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TestNetwork;

    impl NetworkView for TestNetwork {
        fn resolve_host(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>> {
            if host.starts_with("down-") {
                bail!("simulated DNS failure for {host}");
            }
            Ok(vec!["192.0.2.1".parse().expect("valid test IP")])
        }

        #[cfg(feature = "asmap")]
        fn lookup_asn(&self, _ip: IpAddr) -> Result<Option<Asn>> { Ok(Some(64500)) }
    }

    #[test]
    fn skips_unresolvable_directories_and_relays() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![
                Url::parse("https://down-relay.example").expect("valid URL"),
                Url::parse("https://relay.example").expect("valid URL"),
            ],
            pj_directories: vec![
                Url::parse("https://down-directory.example").expect("valid URL"),
                Url::parse("https://directory.example").expect("valid URL"),
            ],
            #[cfg(feature = "asmap")]
            asmap: None,
        };

        let selection =
            choose_receiver_network_selection(&config, &TestNetwork, &[]).expect("fallback works");

        assert_eq!(selection.directory.url.as_str(), "https://directory.example/");
        assert_eq!(selection.relays.len(), 1);
        assert_eq!(selection.relays[0].relay().url.as_str(), "https://relay.example/");
    }
}

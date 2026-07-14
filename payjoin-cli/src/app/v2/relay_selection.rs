//! Stateless OHTTP relay selection for BIP77 sessions.
//!
//! This module has two jobs:
//! - choose the receiver's directory and usable relay set before the receiver key exists
//! - use the receiver key, request kind, and time window to choose relays without
//!   storing a current relay index or failed-relay state
//!
#[cfg(feature = "asmap")]
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "asmap")]
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use payjoin::bitcoin::key::rand::seq::SliceRandom;
use payjoin::bitcoin::key::rand::thread_rng;
use payjoin::relay_selection::{
    select_relay_candidates, RelayCandidate as SelectionCandidate, RequestKind, TimeWindow,
};
use payjoin::uri::v2::PjParam as V2PjParam;
use payjoin::{HpkePublicKey, PjParam, Url};

use super::network::{known_default_port, resolve_url, ResolvedServer, ResolvedUrl, UrlResolver};
#[cfg(feature = "asmap")]
use super::network::{resolve_url_with_asn, user_asns, Asn};
use crate::app::config::V2Config;

/// Directory and relay set chosen before the receiver key is available.
///
/// The receiver needs this during session creation: it must choose a directory
/// and fetch OHTTP keys before the receiver pubkey can be read from the endpoint.
/// The resolved addresses are kept so later HTTP requests use the same DNS
/// results that were checked during selection.
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
    let pj_param = parse_v2_pj_param(endpoint)?;
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
        receiver_pubkey: pj_param.receiver_pubkey().clone(),
    })
}

/// Choose the receiver directory and usable relay set for a new session.
///
/// This runs before the receiver pubkey is available. It can filter directories
/// and relays by DNS and ASMap data, but request-time relay ordering waits until
/// the endpoint has been created and the receiver pubkey is known.
pub(crate) fn choose_receiver_network_selection(
    v2: &V2Config,
    network: &impl UrlResolver,
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
    network: &impl UrlResolver,
) -> Result<RelaySelector> {
    let pj_param = parse_v2_pj_param(endpoint)?;
    let directory_url = directory_from_endpoint(endpoint)?;
    ensure_directory_trusted(v2, &directory_url)?;
    #[cfg(feature = "asmap")]
    let (directory, directory_asn) = if let Some(asmap) = &v2.asmap {
        let user_asns = user_asns(asmap, network)?;
        let directory = resolve_url_with_asn(network, &directory_url)?;
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
        (resolve_url(network, &directory_url)?.resolved, None)
    };
    #[cfg(not(feature = "asmap"))]
    let directory = resolve_url(network, &directory_url)?.resolved;

    let receiver_pubkey = pj_param.receiver_pubkey();
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

/// Choose a resolvable trusted directory.
///
/// With ASMap enabled, directories sharing an ASN with the user are skipped.
/// Without ASMap, the first resolvable trusted directory is used.
fn choose_directory(
    v2: &V2Config,
    network: &impl UrlResolver,
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
            match resolve_url_with_asn(network, &directory) {
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
        match resolve_url(network, &directory) {
            Ok(candidate) => return Ok(candidate),
            Err(error) => tracing::debug!(
                "Skipping directory {} because resolution failed: {error:#}",
                directory
            ),
        }
    }
    bail!("No trusted directories could be resolved")
}

/// Build relay candidates for request-time selection.
///
/// With ASMap enabled, relays sharing the user ASN or chosen directory ASN are
/// skipped and the remaining relays are bucketed by ASN. Without ASMap, each
/// resolved relay is kept as its own URL bucket.
fn relay_candidates(
    v2: &V2Config,
    network: &impl UrlResolver,
    #[cfg(feature = "asmap")] directory_asn: Option<Asn>,
) -> Result<Vec<RelayCandidate>> {
    #[cfg(feature = "asmap")]
    if let Some(asmap) = &v2.asmap {
        let user_asns = user_asns(asmap, network)?;
        let directory_asn = directory_asn.expect("ASMap directory candidates carry a resolved ASN");
        let candidates = v2
            .ohttp_relays
            .iter()
            .filter_map(|url| match resolve_url_with_asn(network, url) {
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
        .filter_map(|url| match resolve_url(network, url) {
            Ok(target) => Some(RelayCandidate::individual(target.resolved)),
            Err(error) => {
                tracing::debug!("Skipping relay {url} because resolution failed: {error:#}");
                None
            }
        })
        .collect();
    Ok(relays)
}

/// Convert ASN-resolved relays into library relay candidates.
///
/// Relays in the user ASN or selected directory ASN are removed. The remaining
/// relays carry their ASN so the library selector can group them by AS.
#[cfg(feature = "asmap")]
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

fn parse_v2_pj_param(endpoint: &str) -> Result<V2PjParam> {
    match PjParam::parse(endpoint)? {
        PjParam::V2(pj_param) => Ok(pj_param),
        #[cfg(feature = "v1")]
        PjParam::V1(_) => bail!("Expected a BIP77 endpoint, got a BIP78 endpoint"),
        _ => bail!("Expected a BIP77 endpoint"),
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    struct TestNetwork;

    impl UrlResolver for TestNetwork {
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

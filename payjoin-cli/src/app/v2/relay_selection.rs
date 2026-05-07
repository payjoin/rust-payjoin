#[cfg(feature = "asmap")]
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, bail, Context, Result};
use payjoin::bitcoin::hashes::{sha256, Hash, HashEngine};
use payjoin::bitcoin::key::rand::seq::SliceRandom;
use payjoin::bitcoin::key::rand::{thread_rng, RngCore};
use payjoin::{HpkePublicKey, PjParam, Url};

#[cfg(feature = "asmap")]
use super::asmap::AsmapInterpreter;
use super::asmap::Asn;
use crate::app::config::V2Config;
#[cfg(feature = "asmap")]
use crate::app::config::{AsmapConfig, LoadedAsmap};
const RELAY_ORDER_TAG: &[u8] = b"payjoin-cli-asmap-relay-order-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayPlan {
    pub(crate) key: String,
    pub(crate) directory: PinnedUrl,
    pub(crate) relays: Vec<PinnedUrl>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayRole {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinnedUrl {
    pub(crate) url: Url,
    pub(crate) socket_addrs: Vec<SocketAddr>,
}

impl PinnedUrl {
    pub(crate) fn new(url: Url, socket_addrs: Vec<SocketAddr>) -> Self {
        Self { url, socket_addrs }
    }

    pub(crate) fn domain(&self) -> Option<&str> { self.url.domain() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedCandidate {
    url: Url,
    pinned: PinnedUrl,
    asn: Asn,
}

#[cfg(feature = "asmap")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateKind {
    Relay,
    TrustedDirectory,
}

#[cfg(feature = "asmap")]
impl CandidateKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::TrustedDirectory => "trusted directory",
        }
    }
}

trait NetworkView {
    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<IpAddr>>;
    #[cfg(feature = "asmap")]
    fn lookup_asn(&self, ip: IpAddr) -> Result<Option<Asn>>;
}

#[derive(Debug, Clone)]
struct SystemNetwork {
    #[cfg(feature = "asmap")]
    asmap: Option<LoadedAsmap>,
}

impl SystemNetwork {
    #[cfg(feature = "asmap")]
    fn new(v2: &V2Config) -> Self { Self { asmap: v2.asmap.as_ref().map(|cfg| cfg.asmap.clone()) } }

    #[cfg(not(feature = "asmap"))]
    fn new(_v2: &V2Config) -> Self { Self {} }
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
        Ok(AsmapInterpreter::new(asmap).lookup(ip))
    }
}

pub(crate) fn choose_receiver_bootstrap_plan(v2: &V2Config) -> Result<RelayPlan> {
    let network = SystemNetwork::new(v2);
    choose_receiver_bootstrap_plan_with_network(v2, &network)
}

pub(crate) fn relay_plan_from_endpoint(
    v2: &V2Config,
    endpoint: &str,
    role: RelayRole,
) -> Result<RelayPlan> {
    let network = SystemNetwork::new(v2);
    relay_plan_from_endpoint_with_network(v2, endpoint, role, &network)
}

pub(crate) fn ensure_trusted_sender_directory(v2: &V2Config, endpoint: &str) -> Result<()> {
    let directory = directory_from_endpoint(endpoint)?;
    ensure_directory_trusted(v2, &directory)
}

fn choose_receiver_bootstrap_plan_with_network(
    v2: &V2Config,
    network: &impl NetworkView,
) -> Result<RelayPlan> {
    let chosen_directory = choose_directory(v2, network)?;
    #[cfg(feature = "asmap")]
    let directory = if v2.asmap.is_some() {
        verified_candidate(network, &chosen_directory)?.pinned
    } else {
        resolved_target(network, &chosen_directory)?
    };
    #[cfg(not(feature = "asmap"))]
    let directory = resolved_target(network, &chosen_directory)?;
    let relays = order_relays(v2, network, &directory, None, None)?;

    if relays.is_empty() {
        bail!("No valid relays available for the selected directory {}", directory.url.as_str());
    }

    let mut rng = thread_rng();
    let bootstrap_id = rng.next_u64();
    Ok(RelayPlan {
        key: format!("bootstrap:{}:{bootstrap_id}", directory.url.as_str()),
        directory,
        relays,
    })
}

fn relay_plan_from_endpoint_with_network(
    v2: &V2Config,
    endpoint: &str,
    role: RelayRole,
    network: &impl NetworkView,
) -> Result<RelayPlan> {
    let pj_param = parse_v2_pj_param(endpoint)?;
    let directory_url = directory_from_endpoint(endpoint)?;
    ensure_directory_trusted(v2, &directory_url)?;
    #[cfg(feature = "asmap")]
    let directory = if v2.asmap.is_some() {
        verified_candidate(network, &directory_url)?.pinned
    } else {
        resolved_target(network, &directory_url)?
    };
    #[cfg(not(feature = "asmap"))]
    let directory = resolved_target(network, &directory_url)?;

    let receiver_pubkey = match &pj_param {
        PjParam::V2(pj_param) => pj_param.receiver_pubkey(),
        #[cfg(feature = "v1")]
        PjParam::V1(_) => unreachable!("parse_v2_pj_param only returns BIP77 endpoints"),
        _ => unreachable!("parse_v2_pj_param only returns BIP77 endpoints"),
    };
    let relays = order_relays(v2, network, &directory, Some(receiver_pubkey), Some(role))?;
    if relays.is_empty() {
        bail!(
            "No valid relays available after filtering user and directory ASNs for {}",
            directory.url.as_str()
        );
    }

    Ok(RelayPlan { key: format!("{role:?}:{}", pj_param.endpoint()), directory, relays })
}

fn choose_directory(v2: &V2Config, network: &impl NetworkView) -> Result<Url> {
    #[cfg(feature = "asmap")]
    if let Some(asmap) = &v2.asmap {
        let user_asns = user_asns(asmap, network)?;
        let mut directories = verified_candidates(
            network,
            v2.trusted_directories(),
            CandidateKind::TrustedDirectory,
        )?
        .into_iter()
        .filter(|candidate| !user_asns.contains(&candidate.asn))
        .collect::<Vec<_>>();
        if directories.is_empty() {
            bail!("No trusted directories remain after excluding the user's ASNs");
        }
        directories.shuffle(&mut thread_rng());
        return Ok(directories.remove(0).url);
    }
    #[cfg(not(feature = "asmap"))]
    let _ = network;

    let mut directories = v2.trusted_directories().to_vec();
    directories.shuffle(&mut thread_rng());
    directories
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("At least one trusted directory must be configured"))
}

fn order_relays(
    v2: &V2Config,
    network: &impl NetworkView,
    directory: &PinnedUrl,
    receiver_pubkey: Option<&HpkePublicKey>,
    role: Option<RelayRole>,
) -> Result<Vec<PinnedUrl>> {
    #[cfg(feature = "asmap")]
    if let Some(asmap) = &v2.asmap {
        let user_asns = user_asns(asmap, network)?;
        let seed = receiver_pubkey.map(shared_seed);
        return asn_deterministic_relay_order(
            verified_candidates(network, &v2.ohttp_relays, CandidateKind::Relay)?,
            user_asns,
            verified_candidate(network, &directory.url)?.asn,
            seed.as_ref(),
            role,
        );
    }
    #[cfg(not(feature = "asmap"))]
    let _ = directory;

    let Some(receiver_pubkey) = receiver_pubkey else {
        let mut relays = resolved_targets(network, &v2.ohttp_relays)?;
        relays.shuffle(&mut thread_rng());
        return Ok(relays);
    };

    Ok(deterministic_session_order(
        resolved_targets(network, &v2.ohttp_relays)?
            .into_iter()
            .map(|pinned| VerifiedCandidate { url: pinned.url.clone(), pinned, asn: 0 })
            .collect(),
        &shared_seed(receiver_pubkey),
        role,
    ))
}

#[cfg(feature = "asmap")]
fn asn_deterministic_relay_order(
    candidates: Vec<VerifiedCandidate>,
    user_asns: BTreeSet<Asn>,
    directory_asn: Asn,
    seed: Option<&[u8; 32]>,
    role: Option<RelayRole>,
) -> Result<Vec<PinnedUrl>> {
    let filtered = candidates
        .into_iter()
        .filter(|candidate| candidate.asn != directory_asn && !user_asns.contains(&candidate.asn))
        .collect::<Vec<_>>();

    if filtered.is_empty() {
        return Ok(vec![]);
    }

    let Some(seed) = seed else {
        let mut relays = filtered.into_iter().map(|candidate| candidate.pinned).collect::<Vec<_>>();
        relays.shuffle(&mut thread_rng());
        return Ok(relays);
    };

    let mut buckets = BTreeMap::<Asn, Vec<VerifiedCandidate>>::new();
    for candidate in filtered {
        buckets.entry(candidate.asn).or_default().push(candidate);
    }

    let mut bucket_entries = buckets
        .into_iter()
        .map(|(asn, mut relays)| {
            relays.sort_by_key(|candidate| seeded_hash(seed, candidate.url.as_str().as_bytes()));
            (seeded_hash(seed, &asn.to_be_bytes()), relays)
        })
        .collect::<Vec<_>>();
    bucket_entries.sort_by_key(|left| left.0);

    let mut ordered = vec![];
    loop {
        let mut emitted = false;
        for (_, bucket) in bucket_entries.iter_mut() {
            if let Some(candidate) = bucket.first().cloned() {
                bucket.remove(0);
                ordered.push(candidate.pinned);
                emitted = true;
            }
        }
        if !emitted {
            break;
        }
    }

    if matches!(role, Some(RelayRole::Sender)) {
        ordered.reverse();
    }

    Ok(ordered)
}

fn deterministic_session_order(
    candidates: Vec<VerifiedCandidate>,
    seed: &[u8; 32],
    role: Option<RelayRole>,
) -> Vec<PinnedUrl> {
    let mut ordered = candidates.into_iter().map(|candidate| candidate.pinned).collect::<Vec<_>>();
    ordered.sort_by_key(|candidate| seeded_hash(seed, candidate.url.as_str().as_bytes()));

    if matches!(role, Some(RelayRole::Sender)) {
        ordered.reverse();
    }

    ordered
}

fn ensure_directory_trusted(v2: &V2Config, directory: &Url) -> Result<()> {
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
    let default_port = match scheme.as_str() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };

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
fn verified_candidates(
    network: &impl NetworkView,
    urls: &[Url],
    candidate_kind: CandidateKind,
) -> Result<Vec<VerifiedCandidate>> {
    let mut verified = Vec::new();
    for url in urls {
        match verified_candidate(network, url) {
            Ok(candidate) => verified.push(candidate),
            Err(error) => tracing::warn!("Skipping {} {}: {error:#}", candidate_kind.as_str(), url),
        }
    }
    if verified.is_empty() {
        bail!("No valid {}s available", candidate_kind.as_str())
    }
    Ok(verified)
}

fn resolved_targets(network: &impl NetworkView, urls: &[Url]) -> Result<Vec<PinnedUrl>> {
    let mut resolved = Vec::new();
    for url in urls {
        match resolved_target(network, url) {
            Ok(pinned) => resolved.push(pinned),
            Err(error) => tracing::warn!("Skipping relay {}: {error:#}", url),
        }
    }
    if resolved.is_empty() {
        bail!("No valid relays available")
    }
    Ok(resolved)
}

fn resolved_target(network: &impl NetworkView, url: &Url) -> Result<PinnedUrl> {
    pinned_url(url, &resolved_ips(network, url)?)
}

#[cfg(feature = "asmap")]
fn verified_candidate(network: &impl NetworkView, url: &Url) -> Result<VerifiedCandidate> {
    let ips = resolved_ips(network, url)?;

    let mut asns = BTreeSet::new();
    for ip in &ips {
        let asn = network.lookup_asn(*ip)?.ok_or_else(|| {
            anyhow!("{} resolved to {ip}, which could not be mapped to an ASN", url.as_str())
        })?;
        asns.insert(asn);
    }

    match asns.len() {
        1 => Ok(VerifiedCandidate {
            url: url.clone(),
            pinned: pinned_url(url, &ips)?,
            asn: *asns.first().expect("checked len"),
        }),
        0 => bail!("{} resolved to no ASN-mapped addresses", url.as_str()),
        _ => bail!(
            "{} resolves to multiple ASNs {:?}; mixed-ASN hostnames are rejected",
            url.as_str(),
            asns
        ),
    }
}

fn resolved_ips(network: &impl NetworkView, url: &Url) -> Result<Vec<IpAddr>> {
    let host = url.host_str();
    let port = url.port().unwrap_or(default_port(url)?);
    let mut ips = network.resolve_host(trim_ipv6_brackets(&host), port)?;
    if ips.is_empty() {
        bail!("{} resolved to no IP addresses", url.as_str());
    }
    ips.sort();
    ips.dedup();
    Ok(ips)
}

fn pinned_url(url: &Url, ips: &[IpAddr]) -> Result<PinnedUrl> {
    let port = url.port().unwrap_or(default_port(url)?);
    let socket_addrs = ips.iter().copied().map(|ip| SocketAddr::new(ip, port)).collect();
    Ok(PinnedUrl::new(url.clone(), socket_addrs))
}

fn shared_seed(receiver_pubkey: &HpkePublicKey) -> [u8; 32] {
    tagged_hash(RELAY_ORDER_TAG, &receiver_pubkey.to_compressed_bytes())
}

fn seeded_hash(seed: &[u8; 32], payload: &[u8]) -> [u8; 32] { tagged_hash(seed, payload) }

fn tagged_hash(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(payload);
    *sha256::Hash::from_engine(engine).as_byte_array()
}

fn parse_v2_pj_param(endpoint: &str) -> Result<PjParam> {
    match PjParam::parse(endpoint)? {
        pj_param @ PjParam::V2(_) => Ok(pj_param),
        #[cfg(feature = "v1")]
        PjParam::V1(_) => bail!("Expected a BIP77 endpoint, got a BIP78 endpoint"),
        _ => bail!("Expected a BIP77 endpoint"),
    }
}

fn directory_from_endpoint(endpoint: &str) -> Result<Url> {
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

fn default_port(url: &Url) -> Result<u16> {
    match url.scheme() {
        "https" => Ok(443),
        "http" => Ok(80),
        scheme => bail!("Unsupported scheme {scheme} for relay/directory URL {}", url.as_str()),
    }
}

fn trim_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[').and_then(|host| host.strip_suffix(']')).unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::app::config::V2Config;
    #[cfg(feature = "asmap")]
    use crate::app::config::{AsmapConfig, LoadedAsmap};

    #[derive(Debug, Clone, Default)]
    struct StubNetwork {
        hosts: HashMap<String, Vec<IpAddr>>,
        asns: HashMap<IpAddr, Option<Asn>>,
    }

    impl NetworkView for StubNetwork {
        fn resolve_host(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>> {
            Ok(self.hosts.get(host).cloned().unwrap_or_default())
        }

        #[cfg(feature = "asmap")]
        fn lookup_asn(&self, ip: IpAddr) -> Result<Option<Asn>> {
            Ok(self.asns.get(&ip).cloned().unwrap_or(None))
        }
    }

    fn url(input: &str) -> Url { Url::parse(input).expect("valid URL") }

    #[cfg(feature = "asmap")]
    fn verified(input: &str, asn: Asn) -> VerifiedCandidate {
        let url = url(input);
        let pinned =
            PinnedUrl::new(url.clone(), vec!["203.0.113.10:443".parse().expect("socket addr")]);
        VerifiedCandidate { url, pinned, asn }
    }

    const TEST_BIP77_ENDPOINT: &str = "https://directory.example/TXJCGKTKXLUUZ#EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

    #[cfg(feature = "asmap")]
    fn config_with_asmap() -> V2Config {
        V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![
                url("https://relay-a.example"),
                url("https://relay-b.example"),
                url("https://relay-c.example"),
                url("https://relay-d.example"),
            ],
            trusted_directories: vec![url("https://directory.example")],
            asmap: Some(AsmapConfig {
                asmap: LoadedAsmap::new(vec![0, 0, 0]),
                user_public_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
                user_asns: vec![64501],
            }),
        }
    }

    #[cfg(feature = "asmap")]
    #[test]
    fn rejects_mixed_asn_hostnames() {
        let network = StubNetwork {
            hosts: HashMap::from([(
                "relay-a.example".to_owned(),
                vec![
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
                ],
            )]),
            asns: HashMap::from([
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), Some(64510)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)), Some(64511)),
            ]),
        };

        let err = verified_candidate(&network, &url("https://relay-a.example"))
            .expect_err("mixed-ASN hostname must fail");
        assert!(err.to_string().contains("multiple ASNs"));
    }

    #[cfg(feature = "asmap")]
    #[test]
    fn accepts_same_asn_multi_ip_hostnames() {
        let network = StubNetwork {
            hosts: HashMap::from([(
                "relay-a.example".to_owned(),
                vec![
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
                ],
            )]),
            asns: HashMap::from([
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), Some(64510)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)), Some(64510)),
            ]),
        };

        let candidate =
            verified_candidate(&network, &url("https://relay-a.example")).expect("same ASN");
        assert_eq!(candidate.asn, 64510);
        assert_eq!(candidate.pinned.socket_addrs.len(), 2);
    }

    #[cfg(feature = "asmap")]
    #[test]
    fn rejects_unmapped_candidates() {
        let network = StubNetwork {
            hosts: HashMap::from([(
                "relay-a.example".to_owned(),
                vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))],
            )]),
            asns: HashMap::from([(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), None)]),
        };

        let err = verified_candidate(&network, &url("https://relay-a.example"))
            .expect_err("unmapped ASN must fail");
        assert!(err.to_string().contains("could not be mapped"));
    }

    #[cfg(feature = "asmap")]
    #[test]
    fn deterministic_sender_order_reverses_receiver_order() {
        let candidates = vec![
            verified("https://relay-a.example", 64510),
            verified("https://relay-b.example", 64510),
            verified("https://relay-c.example", 64511),
            verified("https://relay-d.example", 64512),
        ];
        let receiver_pubkey =
            match parse_v2_pj_param(TEST_BIP77_ENDPOINT).expect("valid v2 endpoint") {
                PjParam::V2(pj_param) => pj_param.receiver_pubkey().clone(),
                #[cfg(feature = "v1")]
                PjParam::V1(_) => unreachable!("test endpoint is BIP77"),
                _ => unreachable!("test endpoint is BIP77"),
            };
        let seed = shared_seed(&receiver_pubkey);

        let receiver = asn_deterministic_relay_order(
            candidates.clone(),
            BTreeSet::new(),
            64509,
            Some(&seed),
            Some(RelayRole::Receiver),
        )
        .expect("receiver order");
        let sender = asn_deterministic_relay_order(
            candidates,
            BTreeSet::new(),
            64509,
            Some(&seed),
            Some(RelayRole::Sender),
        )
        .expect("sender order");

        let mut reversed = receiver.clone();
        reversed.reverse();
        assert_eq!(sender, reversed);
    }

    #[cfg(feature = "asmap")]
    #[test]
    fn round_robin_interleaves_asn_buckets() {
        let seed = [7_u8; 32];
        let ordered = asn_deterministic_relay_order(
            vec![
                verified("https://relay-a.example", 64510),
                verified("https://relay-b.example", 64510),
                verified("https://relay-c.example", 64511),
            ],
            BTreeSet::new(),
            64509,
            Some(&seed),
            Some(RelayRole::Receiver),
        )
        .expect("ordered relays");

        assert_eq!(ordered.len(), 3);
        assert_ne!(ordered[0], ordered[1]);
        assert_ne!(ordered[1], ordered[2]);
    }

    #[cfg(feature = "asmap")]
    #[test]
    fn filters_user_and_directory_asns() {
        let ordered = asn_deterministic_relay_order(
            vec![
                verified("https://relay-a.example", 64501),
                verified("https://relay-b.example", 64502),
                verified("https://relay-c.example", 64503),
            ],
            BTreeSet::from([64501]),
            64502,
            Some(&[1_u8; 32]),
            Some(RelayRole::Receiver),
        )
        .expect("ordered relays");

        assert_eq!(
            ordered.into_iter().map(|candidate| candidate.url).collect::<Vec<_>>(),
            vec![url("https://relay-c.example")]
        );
    }

    #[test]
    fn non_asmap_session_order_is_stable_across_recomputation() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![
                url("https://relay-a.example"),
                url("https://relay-b.example"),
                url("https://relay-c.example"),
            ],
            trusted_directories: vec![url("https://directory.example")],
            #[cfg(feature = "asmap")]
            asmap: None,
        };
        let network = StubNetwork {
            hosts: HashMap::from([
                ("directory.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]),
                ("relay-a.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
                ("relay-b.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11))]),
                ("relay-c.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12))]),
            ]),
            asns: HashMap::from([
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), Some(64509)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), Some(64510)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)), Some(64511)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12)), Some(64512)),
            ]),
        };
        let endpoint = TEST_BIP77_ENDPOINT;

        let first =
            relay_plan_from_endpoint_with_network(&config, endpoint, RelayRole::Sender, &network)
                .expect("first relay plan");
        let second =
            relay_plan_from_endpoint_with_network(&config, endpoint, RelayRole::Sender, &network)
                .expect("second relay plan");

        assert_eq!(first.relays, second.relays);
    }

    #[test]
    fn relay_plan_pins_checked_socket_addresses() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![url("https://relay-a.example"), url("https://relay-b.example")],
            trusted_directories: vec![url("https://directory.example")],
            #[cfg(feature = "asmap")]
            asmap: None,
        };
        let network = StubNetwork {
            hosts: HashMap::from([
                ("directory.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]),
                (
                    "relay-a.example".to_owned(),
                    vec![
                        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
                    ],
                ),
                ("relay-b.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12))]),
            ]),
            asns: HashMap::new(),
        };
        let endpoint = TEST_BIP77_ENDPOINT;

        let plan =
            relay_plan_from_endpoint_with_network(&config, endpoint, RelayRole::Receiver, &network)
                .expect("relay plan");

        assert_eq!(
            plan.directory.socket_addrs,
            vec!["203.0.113.1:443".parse().expect("socket addr")]
        );
        assert!(
            plan.relays.iter().any(|relay| {
                relay.url == url("https://relay-a.example")
                    && relay.socket_addrs
                        == vec![
                            "203.0.113.10:443".parse().expect("socket addr"),
                            "203.0.113.11:443".parse().expect("socket addr"),
                        ]
            }),
            "relay plan should retain the exact ASN-checked relay addresses"
        );
    }

    #[test]
    fn relay_plan_skips_unresolvable_relays() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![
                url("https://relay-good.example"),
                url("https://relay-bad.example"),
                url("https://relay-better.example"),
            ],
            trusted_directories: vec![url("https://directory.example")],
            #[cfg(feature = "asmap")]
            asmap: None,
        };
        let network = StubNetwork {
            hosts: HashMap::from([
                ("directory.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]),
                ("relay-good.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
                (
                    "relay-better.example".to_owned(),
                    vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12))],
                ),
            ]),
            asns: HashMap::new(),
        };

        let plan = relay_plan_from_endpoint_with_network(
            &config,
            TEST_BIP77_ENDPOINT,
            RelayRole::Receiver,
            &network,
        )
        .expect("relay plan should ignore the bad relay");

        let relays = plan.relays.into_iter().map(|relay| relay.url).collect::<Vec<_>>();
        assert_eq!(relays.len(), 2);
        assert!(relays.contains(&url("https://relay-good.example")));
        assert!(relays.contains(&url("https://relay-better.example")));
    }

    #[test]
    fn relay_plan_fails_when_all_relays_are_unresolvable() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![url("https://relay-bad.example")],
            trusted_directories: vec![url("https://directory.example")],
            #[cfg(feature = "asmap")]
            asmap: None,
        };
        let network = StubNetwork {
            hosts: HashMap::from([(
                "directory.example".to_owned(),
                vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))],
            )]),
            asns: HashMap::new(),
        };

        let err = relay_plan_from_endpoint_with_network(
            &config,
            TEST_BIP77_ENDPOINT,
            RelayRole::Receiver,
            &network,
        )
        .expect_err("all relays are invalid");
        assert!(err.to_string().contains("No valid relays available"));
    }

    #[cfg(feature = "asmap")]
    #[test]
    fn sender_requires_trusted_directory() {
        let config = config_with_asmap();
        let err = ensure_trusted_sender_directory(
            &config,
            "https://unknown.example/TXJCGKTKXLUUZ#EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV",
        )
        .expect_err("unknown directory must fail");
        assert!(err.to_string().contains("trusted directory set"));
    }

    #[test]
    fn sender_accepts_case_and_default_port_variants_of_trusted_directory() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![url("https://relay-a.example")],
            trusted_directories: vec![url("https://localhost")],
            #[cfg(feature = "asmap")]
            asmap: None,
        };

        ensure_trusted_sender_directory(
            &config,
            "https://LOCALHOST:443/TXJCGKTKXLUUZ#EX1C4UC6ES-OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV",
        )
        .expect("normalized directory should be trusted");
    }

    #[cfg(feature = "asmap")]
    #[test]
    fn receiver_bootstrap_filters_same_asn_directories() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![url("https://relay-a.example")],
            trusted_directories: vec![
                url("https://directory-a.example"),
                url("https://directory-b.example"),
            ],
            asmap: Some(AsmapConfig {
                asmap: LoadedAsmap::new(vec![0, 0, 0]),
                user_public_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
                user_asns: vec![],
            }),
        };
        let network = StubNetwork {
            hosts: HashMap::from([
                ("directory-a.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]),
                ("directory-b.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))]),
                ("relay-a.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3))]),
            ]),
            asns: HashMap::from([
                (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), Some(64500)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), Some(64500)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), Some(64501)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)), Some(64502)),
            ]),
        };

        let plan = choose_receiver_bootstrap_plan_with_network(&config, &network)
            .expect("must choose filtered directory");
        assert_eq!(plan.directory.url, url("https://directory-b.example"));
    }

    #[cfg(feature = "asmap")]
    #[test]
    fn asmap_relay_plan_skips_invalid_relays() {
        let config = V2Config {
            ohttp_keys: None,
            ohttp_relays: vec![
                url("https://relay-a.example"),
                url("https://relay-bad.example"),
                url("https://relay-c.example"),
            ],
            trusted_directories: vec![url("https://directory.example")],
            asmap: Some(AsmapConfig {
                asmap: LoadedAsmap::new(vec![0, 0, 0]),
                user_public_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
                user_asns: vec![],
            }),
        };
        let network = StubNetwork {
            hosts: HashMap::from([
                ("directory.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]),
                ("relay-a.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]),
                ("relay-c.example".to_owned(), vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12))]),
            ]),
            asns: HashMap::from([
                (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), Some(64500)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), Some(64501)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), Some(64510)),
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12)), Some(64511)),
            ]),
        };

        let plan = relay_plan_from_endpoint_with_network(
            &config,
            TEST_BIP77_ENDPOINT,
            RelayRole::Receiver,
            &network,
        )
        .expect("ASMap relay plan should ignore the bad relay");
        assert_eq!(plan.relays.len(), 2);
        assert!(plan.relays.iter().all(|relay| relay.url != url("https://relay-bad.example")));
    }
}

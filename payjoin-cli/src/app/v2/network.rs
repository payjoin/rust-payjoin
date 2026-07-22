#[cfg(feature = "asmap")]
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, bail, Context, Result};
use payjoin::relay_selection::Relay as SelectionRelay;
use payjoin::Url;

use crate::app::config::V2Config;
#[cfg(feature = "asmap")]
use crate::app::config::{AsmapConfig, LoadedAsmap};

#[cfg(feature = "asmap")]
pub(crate) type Asn = u32;

/// A URL together with the socket addresses resolved for its host.
///
/// Requests keep using `url` for the HTTP target and TLS hostname validation,
/// while `socket_addrs` pins reqwest to the addresses that were already
/// resolved and, when ASMap is enabled, ASN-checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedUrl {
    pub(crate) url: Url,
    /// Addresses later passed to reqwest so it does not re-resolve the host.
    pub(crate) socket_addrs: Vec<SocketAddr>,
}

impl SelectionRelay for ResolvedUrl {
    fn url(&self) -> &Url { &self.url }
}

/// A resolved relay or directory, optionally annotated with its ASN.
///
/// The ASN is present only after ASMap lookup succeeds. The resolved URL is
/// kept in both ASMap and non-ASMap paths so later HTTP requests can reuse the
/// DNS result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedServer {
    /// URL plus resolved socket addresses.
    pub(crate) resolved: ResolvedUrl,
    /// ASN is present only when the server was resolved through ASMap.
    #[cfg(feature = "asmap")]
    pub(crate) asn: Option<Asn>,
}

/// Supplies DNS and optional ASMap lookups for relay and directory URLs.
///
/// Tests implement this trait with fixed answers. The runtime implementation
/// uses system DNS and the configured ASMap.
pub(crate) trait UrlResolver {
    /// Return IP addresses for a host and port.
    fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<IpAddr>>;
    #[cfg(feature = "asmap")]
    /// Return the ASN for an IP, or `None` when ASMap has no mapping.
    fn lookup_asn(&self, ip: IpAddr) -> Result<Option<Asn>>;
}

/// Resolves mailroom relay and directory hosts using system DNS.
///
/// When ASMap is configured, it also maps resolved IP addresses to ASNs.
#[derive(Debug, Clone)]
pub(crate) struct MailroomUrlResolver {
    #[cfg(feature = "asmap")]
    asmap: Option<LoadedAsmap>,
}

impl MailroomUrlResolver {
    #[cfg(feature = "asmap")]
    pub(crate) fn new(v2: &V2Config) -> Self {
        Self { asmap: v2.asmap.as_ref().map(|cfg| cfg.asmap.clone()) }
    }

    #[cfg(not(feature = "asmap"))]
    pub(crate) fn new(_v2: &V2Config) -> Self { Self {} }
}

impl UrlResolver for MailroomUrlResolver {
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

/// Return the user's configured ASNs plus ASNs found from configured public IPs.
#[cfg(feature = "asmap")]
pub(crate) fn user_asns(asmap: &AsmapConfig, network: &impl UrlResolver) -> Result<BTreeSet<Asn>> {
    let mut user_asns = asmap.user_asns.iter().copied().collect::<BTreeSet<_>>();
    for ip in &asmap.user_public_ips {
        let asn = network.lookup_asn(*ip)?.ok_or_else(|| {
            anyhow!("Failed to map user public IP {ip} to an ASN using the ASMap")
        })?;
        user_asns.insert(asn);
    }
    Ok(user_asns)
}

/// Resolve a URL to socket addresses without assigning an ASN.
///
/// This is used when ASMap is unavailable or disabled. The returned
/// `ResolvedServer` can still pin later HTTP requests to the resolved
/// addresses.
pub(crate) fn resolve_url(network: &impl UrlResolver, url: &Url) -> Result<ResolvedServer> {
    Ok(ResolvedServer {
        resolved: resolved_url_from_ips(url, &resolve_url_ips(network, url)?)?,
        #[cfg(feature = "asmap")]
        asn: None,
    })
}

/// Resolve a URL and require all resolved IPs to map to one ASN.
///
/// Mixed-ASN hostnames are rejected because relay selection treats each resolved
/// server as belonging to one privacy bucket.
#[cfg(feature = "asmap")]
pub(crate) fn resolve_url_with_asn(
    network: &impl UrlResolver,
    url: &Url,
) -> Result<ResolvedServer> {
    let ips = resolve_url_ips(network, url)?;

    let mut asns = BTreeSet::new();
    for ip in &ips {
        let asn = network.lookup_asn(*ip)?.ok_or_else(|| {
            anyhow!("{} resolved to {ip}, which could not be mapped to an ASN", url.as_str())
        })?;
        asns.insert(asn);
    }

    match asns.len() {
        1 => Ok(ResolvedServer {
            resolved: resolved_url_from_ips(url, &ips)?,
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

/// Resolve the URL host to a sorted, deduplicated list of IP addresses.
///
/// IP literals are returned directly. Domain names are resolved through the
/// supplied resolver.
fn resolve_url_ips(network: &impl UrlResolver, url: &Url) -> Result<Vec<IpAddr>> {
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

/// Build a `ResolvedUrl` from IPs that were already resolved for `url`.
///
/// The IPs are paired with the URL port so reqwest can later use them with
/// `resolve_to_addrs`.
fn resolved_url_from_ips(url: &Url, ips: &[IpAddr]) -> Result<ResolvedUrl> {
    let port = relay_port(url)?;
    let socket_addrs = ips.iter().copied().map(|ip| SocketAddr::new(ip, port)).collect();
    Ok(ResolvedUrl { url: url.clone(), socket_addrs })
}

fn relay_port(url: &Url) -> Result<u16> {
    url.port().or_else(|| known_default_port(url)).ok_or_else(|| {
        anyhow!("Unsupported scheme {} for relay/directory URL {}", url.scheme(), url.as_str())
    })
}

pub(crate) fn known_default_port(url: &Url) -> Option<u16> {
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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use super::asmap::{Asmap, AsmapSeed};
use super::Config;

#[derive(Debug, Clone)]
pub struct RelayManager {
    selected_relay: Option<url::Url>,
    failed_relays: Vec<url::Url>,
}

impl RelayManager {
    pub fn new() -> Self { RelayManager { selected_relay: None, failed_relays: Vec::new() } }

    pub fn set_selected_relay(&mut self, relay: url::Url) { self.selected_relay = Some(relay); }

    pub fn get_selected_relay(&self) -> Option<url::Url> { self.selected_relay.clone() }

    pub fn add_failed_relay(&mut self, relay: url::Url) { self.failed_relays.push(relay); }

    pub fn get_failed_relays(&self) -> Vec<url::Url> { self.failed_relays.clone() }
}

pub(crate) struct ValidatedOhttpKeys {
    pub(crate) ohttp_keys: payjoin::OhttpKeys,
    pub(crate) relay_url: url::Url,
    pub(crate) directory_url: url::Url,
}

pub(crate) enum RelayRole {
    Sender,
    Receiver,
}

fn random_directory(directories: &[url::Url]) -> Result<url::Url> {
    use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;
    directories
        .choose(&mut payjoin::bitcoin::key::rand::thread_rng())
        .cloned()
        .ok_or_else(|| anyhow!("No payjoin directories configured"))
}

pub(crate) async fn unwrap_ohttp_keys_or_else_fetch(
    config: &Config,
    directory: Option<url::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
    receiver_pubkey: Option<&[u8; 33]>,
    role: RelayRole,
    asmap: Option<&Asmap>,
) -> Result<ValidatedOhttpKeys> {
    let seed = receiver_pubkey.map(|pk| AsmapSeed::from_receiver_pubkey(pk));
    let seed_ref = seed.as_ref();
    // NOTE: `ohttp_keys` in config creates a potential mismatch when ASmap selects
    // a different directory than the one the keys were fetched from. There are issues
    // discussing removing it from config, which would eliminate the mismatch.
    if let Some(ohttp_keys) = config.v2()?.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        let validated =
            fetch_ohttp_keys(config, directory, relay_manager, seed_ref, role, asmap).await?;
        Ok(ValidatedOhttpKeys {
            ohttp_keys,
            relay_url: validated.relay_url,
            directory_url: validated.directory_url,
        })
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        fetch_ohttp_keys(config, directory, relay_manager, seed_ref, role, asmap).await
    }
}

async fn fetch_ohttp_keys(
    config: &Config,
    directory: Option<url::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
    seed: Option<&AsmapSeed>,
    role: RelayRole,
    asmap: Option<&Asmap>,
) -> Result<ValidatedOhttpKeys> {
    use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;
    let v2_config = config.v2()?;
    let relays = v2_config.ohttp_relays.clone();
    let directories = &v2_config.pj_directories;

    let asmap_enabled = asmap.is_some() && v2_config.user_asn.is_some();

    if asmap.is_some() && v2_config.user_asn.is_none() {
        tracing::warn!("--asmap provided but --user-asn missing; AS-aware selection disabled");
    }

    let (payjoin_directory, asmap_context) = if let Some(dir) = directory {
        if let (true, Some(asmap)) = (asmap_enabled, asmap) {
            tracing::debug!("ASmap loaded, using for relay selection with fixed directory");
            let relay_asns = resolve_relays_asn(&relays, asmap).await;
            let directory_asn = url_to_asn(&dir, asmap).await;
            (
                dir,
                Some(AsmapContext {
                    user_asn: v2_config.user_asn.unwrap(),
                    directory_asn,
                    relay_asns,
                }),
            )
        } else {
            (dir, None)
        }
    } else if let (true, Some(asmap)) = (asmap_enabled, asmap) {
        let user_asn = v2_config.user_asn.unwrap();
        tracing::debug!("ASmap loaded successfully, using AS-aware directory selection");
        let (payjoin_directory, directory_asn) =
            match select_directory(directories, user_asn, asmap).await {
                Some(result) => result,
                None => {
                    let dir = random_directory(directories)
                        .expect("At least one directory must be configured");
                    let asn = url_to_asn(&dir, asmap).await;
                    (dir, asn)
                }
            };
        tracing::debug!("Selected directory: {}", payjoin_directory);
        let relay_asns = resolve_relays_asn(&relays, asmap).await;
        (payjoin_directory, Some(AsmapContext { user_asn, directory_asn, relay_asns }))
    } else {
        let payjoin_directory = random_directory(directories)?;
        (payjoin_directory, None)
    };

    loop {
        let failed_relays =
            relay_manager.lock().expect("Lock should not be poisoned").get_failed_relays();

        let remaining_relays: Vec<_> =
            relays.iter().filter(|r| !failed_relays.contains(r)).cloned().collect();

        if remaining_relays.is_empty() {
            return Err(anyhow!("No valid relays available"));
        }

        let selected_relay = if let Some(ctx) = &asmap_context {
            if let Some(seed) = seed {
                let mut ordered = asmap_order(
                    &remaining_relays,
                    Some(ctx.user_asn),
                    ctx.directory_asn,
                    &ctx.relay_asns,
                    seed,
                );
                if matches!(role, RelayRole::Sender) {
                    ordered.reverse();
                }
                ordered
                    .first()
                    .cloned()
                    // Fallback to random selection to preserve upstream behavior when
                    // AS-aware ordering yields no candidates (e.g. all relays share
                    // the user's or directory's ASN, or none appear in the asmap).
                    // This ensures connectivity is never blocked by asmap coverage gaps.
                    .or_else(|| {
                        remaining_relays
                            .choose(&mut payjoin::bitcoin::key::rand::thread_rng())
                            .cloned()
                    })
            } else {
                remaining_relays.choose(&mut payjoin::bitcoin::key::rand::thread_rng()).cloned()
            }
        } else {
            remaining_relays.choose(&mut payjoin::bitcoin::key::rand::thread_rng()).cloned()
        };

        let selected_relay = match selected_relay {
            Some(relay) => relay,
            None => return Err(anyhow!("Failed to select from remaining relays")),
        };

        relay_manager
            .lock()
            .expect("Lock should not be poisoned")
            .set_selected_relay(selected_relay.clone());

        let ohttp_keys = {
            #[cfg(feature = "_manual-tls")]
            {
                if let Some(cert_path) = config.root_certificate.as_ref() {
                    let cert_der = std::fs::read(cert_path)?;
                    payjoin::io::fetch_ohttp_keys_with_cert(
                        selected_relay.as_str(),
                        payjoin_directory.as_str(),
                        &cert_der,
                    )
                    .await
                } else {
                    payjoin::io::fetch_ohttp_keys(
                        selected_relay.as_str(),
                        payjoin_directory.as_str(),
                    )
                    .await
                }
            }
            #[cfg(not(feature = "_manual-tls"))]
            payjoin::io::fetch_ohttp_keys(selected_relay.as_str(), payjoin_directory.as_str()).await
        };

        match ohttp_keys {
            Ok(keys) =>
                return Ok(ValidatedOhttpKeys {
                    ohttp_keys: keys,
                    relay_url: selected_relay,
                    directory_url: payjoin_directory.clone(),
                }),
            Err(payjoin::io::Error::UnexpectedStatusCode(e)) => {
                return Err(payjoin::io::Error::UnexpectedStatusCode(e).into());
            }
            Err(e) => {
                tracing::debug!("Failed to connect to relay: {selected_relay}, {e:?}");
                relay_manager
                    .lock()
                    .expect("Lock should not be poisoned")
                    .add_failed_relay(selected_relay);
            }
        }
    }
}

struct AsmapContext {
    user_asn: u32,
    directory_asn: Option<u32>,
    relay_asns: HashMap<url::Url, u32>,
}

fn asmap_order(
    relays: &[url::Url],
    user_asn: Option<u32>,
    directory_asn: Option<u32>,
    relay_asns: &HashMap<url::Url, u32>,
    seed: &AsmapSeed,
) -> Vec<url::Url> {
    let filtered: Vec<&url::Url> = relays
        .iter()
        .filter(|relay| {
            let Some(asn) = relay_asns.get(*relay).copied() else {
                return false;
            };
            user_asn.is_none_or(|u| asn != u) && directory_asn.is_none_or(|d| asn != d)
        })
        .collect();

    let mut buckets: HashMap<u32, Vec<&url::Url>> = HashMap::new();

    for relay in &filtered {
        if let Some(asn) = relay_asns.get(*relay).copied() {
            buckets.entry(asn).or_default().push(relay);
        }
    }

    for bucket in buckets.values_mut() {
        bucket.sort_by_key(|relay| seed.hash_relay(relay.as_str()));
    }

    let mut sorted_buckets: Vec<(u32, Vec<&url::Url>)> = buckets.into_iter().collect();
    sorted_buckets.sort_by_key(|(asn, _)| seed.hash_asn(*asn));

    let max_bucket_size = sorted_buckets.iter().map(|(_, bucket)| bucket.len()).max().unwrap_or(0);
    let mut result = Vec::new();
    for round in 0..max_bucket_size {
        for (_, bucket) in &sorted_buckets {
            if round < bucket.len() {
                result.push((*bucket[round]).clone());
            }
        }
    }

    result
}

async fn url_to_asn(relay: &url::Url, asmap: &Asmap) -> Option<u32> {
    let host = relay.host_str()?;
    let port = relay.port_or_known_default()?;
    let addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host(format!("{host}:{port}")).await.ok()?.collect();

    let ipv4_count = addrs.iter().filter(|a| a.is_ipv4()).count();
    let ipv6_count = addrs.iter().filter(|a| a.is_ipv6()).count();
    if ipv4_count > 1 || ipv6_count > 1 {
        tracing::warn!(
            "Relay {} has {} A and {} AAAA records (max 1 each allowed), excluding from AS-aware selection",
            relay, ipv4_count, ipv6_count
        );
        return None;
    }

    let preferred: Vec<_> = {
        let v6: Vec<_> = addrs.iter().filter(|a| a.is_ipv6()).collect();
        if v6.is_empty() {
            addrs.iter().collect()
        } else {
            v6
        }
    };

    let asns: std::collections::HashSet<u32> =
        preferred.iter().filter_map(|addr| asmap.lookup(addr.ip())).collect();

    match asns.len() {
        0 => {
            tracing::debug!(
                "Relay {} has no ASN mapping, excluding from AS-aware selection",
                relay
            );
            None
        }
        1 => asns.into_iter().next(),
        _ => {
            tracing::warn!(
                "Relay {} resolves to multiple ASes, excluding from AS-aware selection",
                relay
            );
            None
        }
    }
}

async fn resolve_relays_asn(relays: &[url::Url], asmap: &Asmap) -> HashMap<url::Url, u32> {
    let mut set = tokio::task::JoinSet::new();
    for relay in relays {
        let relay = relay.clone();
        let asmap = asmap.clone();
        set.spawn(async move { (relay.clone(), url_to_asn(&relay, &asmap).await) });
    }
    let mut result = HashMap::new();
    while let Some(Ok((relay, Some(asn)))) = set.join_next().await {
        result.insert(relay, asn);
    }
    result
}

async fn select_directory(
    directories: &[url::Url],
    user_asn: u32,
    asmap: &Asmap,
) -> Option<(url::Url, Option<u32>)> {
    use payjoin::bitcoin::key::rand::prelude::SliceRandom;

    let mut set = tokio::task::JoinSet::new();
    for dir in directories {
        let dir = dir.clone();
        let asmap = asmap.clone();
        set.spawn(async move { (dir.clone(), url_to_asn(&dir, &asmap).await) });
    }
    let mut directory_asns: HashMap<url::Url, u32> = HashMap::new();
    while let Some(Ok((dir, Some(asn)))) = set.join_next().await {
        directory_asns.insert(dir, asn);
    }

    let candidates: Vec<_> = directory_asns
        .iter()
        .filter(|(_, asn)| **asn != user_asn)
        .map(|(dir, asn)| (dir.clone(), Some(*asn)))
        .collect();

    if candidates.is_empty() {
        tracing::debug!("All directories share user ASN, selecting randomly");
        None
    } else {
        candidates.choose(&mut payjoin::bitcoin::key::rand::thread_rng()).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_seed() -> AsmapSeed { AsmapSeed::from_receiver_pubkey(&[0x02; 33]) }

    fn url(s: &str) -> url::Url { url::Url::parse(s).unwrap() }

    #[test]
    fn test_filters_user_asn() {
        let relays = vec![url("https://relay1.example.com"), url("https://relay2.example.com")];
        let mut relay_asns = HashMap::new();
        relay_asns.insert(url("https://relay1.example.com"), 1111u32);
        relay_asns.insert(url("https://relay2.example.com"), 2222u32);

        let result = asmap_order(&relays, Some(1111), None, &relay_asns, &make_seed());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], url("https://relay2.example.com"));
    }

    #[test]
    fn test_filters_directory_asn() {
        let relays = vec![url("https://relay1.example.com"), url("https://relay2.example.com")];
        let mut relay_asns = HashMap::new();
        relay_asns.insert(url("https://relay1.example.com"), 1111u32);
        relay_asns.insert(url("https://relay2.example.com"), 3333u32);

        let result = asmap_order(&relays, Some(9999), Some(1111), &relay_asns, &make_seed());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], url("https://relay2.example.com"));
    }

    #[test]
    fn test_deterministic_ordering() {
        let relays = vec![
            url("https://relay1.example.com"),
            url("https://relay2.example.com"),
            url("https://relay3.example.com"),
        ];
        let mut relay_asns = HashMap::new();
        relay_asns.insert(url("https://relay1.example.com"), 1111u32);
        relay_asns.insert(url("https://relay2.example.com"), 2222u32);
        relay_asns.insert(url("https://relay3.example.com"), 3333u32);

        let seed = make_seed();
        let result1 = asmap_order(&relays, None, None, &relay_asns, &seed);
        let result2 = asmap_order(&relays, None, None, &relay_asns, &seed);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_sender_receiver_pick_different_ends() {
        let relays = vec![
            url("https://relay1.example.com"),
            url("https://relay2.example.com"),
            url("https://relay3.example.com"),
        ];
        let mut relay_asns = HashMap::new();
        relay_asns.insert(url("https://relay1.example.com"), 1111u32);
        relay_asns.insert(url("https://relay2.example.com"), 2222u32);
        relay_asns.insert(url("https://relay3.example.com"), 3333u32);

        let seed = make_seed();
        let ordered = asmap_order(&relays, None, None, &relay_asns, &seed);

        let receiver_pick = ordered.first().cloned().unwrap();
        let sender_pick = ordered.last().cloned().unwrap();

        assert_ne!(receiver_pick, sender_pick);
    }

    #[test]
    fn test_empty_after_filtering_returns_empty() {
        let relays = vec![url("https://relay1.example.com")];
        let mut relay_asns = HashMap::new();
        relay_asns.insert(url("https://relay1.example.com"), 1111u32);

        let result = asmap_order(&relays, Some(1111), None, &relay_asns, &make_seed());
        assert!(result.is_empty());
    }

    #[test]
    fn test_all_relays_unknown_asn_excluded() {
        let relays = vec![url("https://relay1.example.com"), url("https://relay2.example.com")];
        let relay_asns = HashMap::new();

        let result = asmap_order(&relays, None, None, &relay_asns, &make_seed());
        assert!(result.is_empty(), "Relays without ASN should be excluded from AS-aware selection");
    }
}

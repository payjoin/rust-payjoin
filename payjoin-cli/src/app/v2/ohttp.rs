use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::Config;

// 6 months
const CACHE_DURATION: Duration = Duration::from_secs(6 * 30 * 24 * 60 * 60);

#[derive(Debug, Clone)]
pub struct RelayManager {
    selected_relay: Option<payjoin::Url>,
    failed_relays: Vec<payjoin::Url>,
}

impl RelayManager {
    pub fn new() -> Self { RelayManager { selected_relay: None, failed_relays: Vec::new() } }

    pub fn set_selected_relay(&mut self, relay: payjoin::Url) { self.selected_relay = Some(relay); }

    pub fn get_selected_relay(&self) -> Option<payjoin::Url> { self.selected_relay.clone() }

    pub fn add_failed_relay(&mut self, relay: payjoin::Url) { self.failed_relays.push(relay); }

    pub fn get_failed_relays(&self) -> Vec<payjoin::Url> { self.failed_relays.clone() }
}

pub(crate) struct ValidatedOhttpKeys {
    pub(crate) ohttp_keys: payjoin::OhttpKeys,
    pub(crate) relay_url: payjoin::Url,
}

pub(crate) async fn unwrap_ohttp_keys_or_else_fetch(
    config: &Config,
    directory: Option<payjoin::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
) -> Result<ValidatedOhttpKeys> {
    if let Some(ohttp_keys) = config.v2()?.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        return Ok(ValidatedOhttpKeys {
            ohttp_keys,
            relay_url: config.v2()?.ohttp_relays[0].clone(),
        });
    }

    if let Some(cached_keys) = read_cached_ohttp_keys() {
        if !is_expired(&cached_keys) {
            println!("Using cached OHTTP keys");
            return Ok(ValidatedOhttpKeys {
                ohttp_keys: cached_keys.keys,
                relay_url: cached_keys.relay_url,
            });
        }
    }
    println!("Bootstrapping private network transport over Oblivious HTTP");
    let fetched_keys = fetch_ohttp_keys(config, directory, relay_manager).await?;

    // save the keys to cache
    cache_ohttp_keys(&fetched_keys.ohttp_keys, &fetched_keys.relay_url)?;

    Ok(fetched_keys)
}

async fn fetch_ohttp_keys(
    config: &Config,
    directory: Option<payjoin::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
) -> Result<ValidatedOhttpKeys> {
    use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;
    let payjoin_directory = directory.unwrap_or(config.v2()?.pj_directory.clone());
    let relays = config.v2()?.ohttp_relays.clone();

    loop {
        let failed_relays =
            relay_manager.lock().expect("Lock should not be poisoned").get_failed_relays();

        let remaining_relays: Vec<_> =
            relays.iter().filter(|r| !failed_relays.contains(r)).cloned().collect();

        if remaining_relays.is_empty() {
            return Err(anyhow!("No valid relays available"));
        }

        let selected_relay =
            match remaining_relays.choose(&mut payjoin::bitcoin::key::rand::thread_rng()) {
                Some(relay) => relay.clone(),
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
                        cert_der,
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
                return Ok(ValidatedOhttpKeys { ohttp_keys: keys, relay_url: selected_relay }),
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

#[derive(Serialize, Deserialize, Debug)]
struct CachedOhttpKeys {
    keys: payjoin::OhttpKeys,
    relay_url: payjoin::Url,
    fetched_at: u64,
}

fn get_cache_file() -> PathBuf {
    dirs::cache_dir().unwrap().join("payjoin-cli").join("ohttp-keys.json")
}

fn read_cached_ohttp_keys() -> Option<CachedOhttpKeys> {
    let cache_file = get_cache_file();
    if !cache_file.exists() {
        return None;
    }
    let data = fs::read_to_string(cache_file).ok().unwrap();
    serde_json::from_str(&data).ok()
}

fn cache_ohttp_keys(ohttp_keys: &payjoin::OhttpKeys, relay_url: &payjoin::Url) -> Result<()> {
    let cached = CachedOhttpKeys {
        keys: ohttp_keys.clone(),
        relay_url: relay_url.clone(),
        fetched_at: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
    };

    let serialized = serde_json::to_string(&cached)?;
    let path = get_cache_file();
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(path, serialized)?;
    Ok(())
}

fn is_expired(cached_keys: &CachedOhttpKeys) -> bool {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    now.saturating_sub(cached_keys.fetched_at) > CACHE_DURATION.as_secs()
}

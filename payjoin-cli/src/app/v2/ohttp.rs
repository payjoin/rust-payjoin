use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

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

    pub fn clear_failed_relays(&mut self) { self.failed_relays.clear(); }
}

pub(crate) struct ValidatedOhttpKeys {
    pub(crate) ohttp_keys: payjoin::OhttpKeys,
    pub(crate) relay_url: url::Url,
}

pub(crate) async fn unwrap_ohttp_keys_or_else_fetch(
    config: &Config,
    directory: Option<url::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
) -> Result<ValidatedOhttpKeys> {
    if let Some(ohttp_keys) = config.v2()?.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        return Ok(ValidatedOhttpKeys {
            ohttp_keys,
            relay_url: config.v2()?.ohttp_relays[0].clone(),
        });
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let fetched_keys = fetch_ohttp_keys(config, directory, relay_manager).await?;

        Ok(fetched_keys)
    }
}

async fn fetch_ohttp_keys(
    config: &Config,
    directory: Option<url::Url>,
    relay_manager: Arc<Mutex<RelayManager>>,
) -> Result<ValidatedOhttpKeys> {
    use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;
    let payjoin_directories = if let Some(dir) = directory {
        vec![dir]
    } else {
        config.v2()?.pj_directories.clone()
    };
    let relays = config.v2()?.ohttp_relays.clone();

    // Try each directory in order until one succeeds
    for payjoin_directory in &payjoin_directories {
        tracing::debug!("Trying directory: {}", payjoin_directory);
        
        loop {
            let failed_relays =
                relay_manager.lock().expect("Lock should not be poisoned").get_failed_relays();

            let remaining_relays: Vec<_> =
                relays.iter().filter(|r| !failed_relays.contains(r)).cloned().collect();

            if remaining_relays.is_empty() {
                tracing::debug!("No remaining relays for directory: {}", payjoin_directory);
                break; // Try next directory
            }

            let selected_relay =
                match remaining_relays.choose(&mut payjoin::bitcoin::key::rand::thread_rng()) {
                    Some(relay) => relay.clone(),
                    None => break, // Try next directory
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
                Ok(keys) => {
                    tracing::debug!("Successfully fetched keys from directory: {} via relay: {}", payjoin_directory, selected_relay);
                    return Ok(ValidatedOhttpKeys { ohttp_keys: keys, relay_url: selected_relay });
                }
                Err(payjoin::io::Error::UnexpectedStatusCode(e)) => {
                    tracing::debug!("Unexpected status code from directory: {}, error: {}", payjoin_directory, e);
                    break; // Try next directory
                }
                Err(e) => {
                    tracing::debug!("Failed to connect to relay: {} for directory: {}, error: {:?}", selected_relay, payjoin_directory, e);
                    relay_manager
                        .lock()
                        .expect("Lock should not be poisoned")
                        .add_failed_relay(selected_relay);
                    // Continue to next relay for this directory
                }
            }
        }
        
        // Reset failed relays for next directory attempt
        relay_manager.lock().expect("Lock should not be poisoned").clear_failed_relays();
    }

    Err(anyhow!("Failed to fetch OHTTP keys from all directories"))
}

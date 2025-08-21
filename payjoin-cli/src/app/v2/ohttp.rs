use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use super::Config;

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
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let fetched_keys = fetch_ohttp_keys(config, directory, relay_manager).await?;

        Ok(fetched_keys)
    }
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
                        &selected_relay,
                        &payjoin_directory,
                        cert_der,
                    )
                    .await
                } else {
                    payjoin::io::fetch_ohttp_keys(&selected_relay, &payjoin_directory).await
                }
            }
            #[cfg(not(feature = "_manual-tls"))]
            payjoin::io::fetch_ohttp_keys(&selected_relay, &payjoin_directory).await
        };

        match ohttp_keys {
            Ok(keys) =>
                return Ok(ValidatedOhttpKeys { ohttp_keys: keys, relay_url: selected_relay }),
            Err(payjoin::io::Error::UnexpectedStatusCode(e)) => {
                return Err(payjoin::io::Error::UnexpectedStatusCode(e).into());
            }
            Err(e) => {
                log::debug!("Failed to connect to relay: {selected_relay}, {e:?}");
                relay_manager
                    .lock()
                    .expect("Lock should not be poisoned")
                    .add_failed_relay(selected_relay);
            }
        }
    }
}

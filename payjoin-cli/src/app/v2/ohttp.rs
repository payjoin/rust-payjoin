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

pub(crate) async fn unwrap_ohttp_keys_or_else_fetch(
    config: &Config,
    relay_manager: Arc<Mutex<RelayManager>>,
) -> Result<payjoin::OhttpKeys> {
    if let Some(keys) = config.v2()?.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        Ok(keys)
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");

        fetch_keys(config, relay_manager.clone())
            .await
            .and_then(|keys| keys.ok_or_else(|| anyhow::anyhow!("No OHTTP keys found")))
    }
}

async fn fetch_keys(
    config: &Config,
    relay_manager: Arc<Mutex<RelayManager>>,
) -> Result<Option<payjoin::OhttpKeys>> {
    use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;
    let payjoin_directory = config.v2()?.pj_directory.clone();
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
            #[cfg(not(feature = "pki-https"))]
            {
                let cert_der = crate::app::read_local_cert()?;
                payjoin::io::fetch_ohttp_keys_with_cert(
                    selected_relay.clone(),
                    payjoin_directory.clone(),
                    cert_der,
                )
                .await
            }
            #[cfg(feature = "pki-https")]
            {
                payjoin::io::fetch_ohttp_keys(selected_relay.clone(), payjoin_directory.clone())
                    .await
            }
        };

        match ohttp_keys {
            Ok(keys) => return Ok(Some(keys)),
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

pub(crate) async fn validate_relay(
    config: &Config,
    relay_manager: Arc<Mutex<RelayManager>>,
) -> Result<payjoin::Url> {
    use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;
    let payjoin_directory = config.v2()?.pj_directory.clone();
    let relays = config.v2()?.ohttp_relays.clone();

    if let Some(relay) = config.v2()?.ohttp_relays.first().cloned() {
        return Ok(relay);
    }

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

        let ohttp_keys =
            payjoin::io::fetch_ohttp_keys(selected_relay.clone(), payjoin_directory.clone()).await;

        match ohttp_keys {
            Ok(_) => return Ok(selected_relay),
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

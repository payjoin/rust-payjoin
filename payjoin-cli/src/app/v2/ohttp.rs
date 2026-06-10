//! OHTTP relay selection and key bootstrapping for the payjoin-cli.
//!
//! [`RelayManager`] tracks relays that have failed, excluding them from
//! future selections for the lifetime of the [`RelayManager`].
//!
//! `unwrap_ohttp_keys_or_else_fetch` returns user-supplied keys when present,
//! otherwise selects a relay at random from the configured list,
//! excluding relays that [`RelayManager`] has marked as failed,
//! to avoid a fixed contact pattern at the network layer.
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use payjoin::Url;

use super::Config;

#[derive(Debug, Clone)]
pub struct RelayManager {
    config: Config,
    failed_relays: Arc<Mutex<Vec<Url>>>,
}

impl RelayManager {
    pub fn new(config: Config) -> Self {
        RelayManager { config, failed_relays: Arc::new(Mutex::new(Vec::new())) }
    }

    pub fn add_failed_relay(&self, relay: Url) {
        self.failed_relays.lock().expect("Lock should not be poisoned").push(relay);
    }

    pub fn choose_relay(&self) -> Result<Url> {
        use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;
        let relays = &self.config.v2()?.ohttp_relays;
        let failed_relays = self.failed_relays.lock().expect("Lock should not be poisoned");
        let remaining_relays: Vec<_> =
            relays.iter().filter(|r| !failed_relays.contains(r)).cloned().collect();

        if remaining_relays.is_empty() {
            return Err(anyhow!("No valid relays available"));
        }

        remaining_relays
            .choose(&mut payjoin::bitcoin::key::rand::thread_rng())
            .cloned()
            .ok_or_else(|| anyhow!("Failed to select from remaining relays"))
    }
}

pub(crate) struct ValidatedOhttpKeys {
    pub(crate) ohttp_keys: payjoin::OhttpKeys,
}

pub(crate) async fn unwrap_ohttp_keys_or_else_fetch(
    config: &Config,
    relay_manager: RelayManager,
) -> Result<ValidatedOhttpKeys> {
    if let Some(ohttp_keys) = config.v2()?.ohttp_keys.clone() {
        return Ok(ValidatedOhttpKeys { ohttp_keys });
    }
    fetch_ohttp_keys(config, relay_manager).await
}

async fn fetch_ohttp_keys(
    config: &Config,
    relay_manager: RelayManager,
) -> Result<ValidatedOhttpKeys> {
    let payjoin_directory = config.v2()?.pj_directory.clone();

    loop {
        let selected_relay = relay_manager.choose_relay()?;

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
            Ok(keys) => return Ok(ValidatedOhttpKeys { ohttp_keys: keys }),
            Err(payjoin::io::Error::UnexpectedStatusCode(e)) => {
                return Err(payjoin::io::Error::UnexpectedStatusCode(e).into());
            }
            Err(e) => {
                tracing::debug!("Failed to connect to relay: {selected_relay}, {e:?}");
                relay_manager.add_failed_relay(selected_relay);
            }
        }
    }
}

//! OHTTP relay and payjoin directory selection / key bootstrapping for the payjoin-cli.
//!
//! [`MailroomManager`] tracks relays and directories that have failed,
//! excluding them from future selections for the lifetime of the [`MailroomManager`].
//!
//! `unwrap_ohttp_keys_or_else_fetch_from_directory` returns user-supplied keys
//! when present, otherwise selects a relay at random from the configured list
//! (excluding failed relays) to fetch OHTTP keys from the given directory.
//!
//! `fetch_ohttp_keys_from_directory` retries on relay failures (e.g. connection
//! errors) by selecting another relay. Once a directory is chosen for a session
//! it must not change — the directory is embedded in the BIP21 URI at session
//! creation and recovered from the session event log on resume.
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use payjoin::relay::RelaySelector;
use payjoin::Url;

use super::Config;

#[derive(Debug, Clone)]
pub struct MailroomManager {
    config: Config,
    relay_selector: Arc<Mutex<RelaySelector>>,
    failed_directories: Arc<Mutex<Vec<Url>>>,
}

impl MailroomManager {
    pub fn new(config: Config) -> Result<Self> {
        let relay_selector = RelaySelector::new(config.v2()?.ohttp_relays.clone());
        Ok(MailroomManager {
            config,
            relay_selector: Arc::new(Mutex::new(relay_selector)),
            failed_directories: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn add_failed_relay(&self, relay: Url) {
        self.relay_selector.lock().expect("Lock should not be poisoned").mark_failed(&relay);
    }

    pub fn clear_failed_relays(&self) {
        self.relay_selector.lock().expect("Lock should not be poisoned").clear_failed();
    }

    pub fn add_failed_directory(&self, directory: Url) {
        self.failed_directories.lock().expect("Lock should not be poisoned").push(directory);
    }

    pub fn choose_relay(&self) -> Result<Url> {
        self.relay_selector
            .lock()
            .expect("Lock should not be poisoned")
            .select(&mut payjoin::bitcoin::key::rand::thread_rng())
            .ok_or_else(|| anyhow!("No valid relays available"))
    }

    pub fn choose_directory(&self) -> Result<Url> {
        use payjoin::bitcoin::secp256k1::rand::prelude::SliceRandom;
        let directories = &self.config.v2()?.pj_directories;
        let failed_directories =
            self.failed_directories.lock().expect("Lock should not be poisoned");
        let remaining_directories: Vec<_> =
            directories.iter().filter(|d| !failed_directories.contains(d)).cloned().collect();

        if remaining_directories.is_empty() {
            return Err(anyhow!("No valid directories available"));
        }

        remaining_directories
            .choose(&mut payjoin::bitcoin::key::rand::thread_rng())
            .cloned()
            .ok_or_else(|| anyhow!("Failed to select from remaining directories"))
    }

    pub(crate) async fn unwrap_ohttp_keys_or_else_fetch_from_directory(
        &self,
        directory: &Url,
    ) -> Result<ValidatedOhttpKeys> {
        if let Some(ohttp_keys) = self.config.v2()?.ohttp_keys.clone() {
            return Ok(ValidatedOhttpKeys { ohttp_keys });
        }
        self.fetch_ohttp_keys_from_directory(directory).await
    }

    async fn fetch_ohttp_keys_from_directory(&self, directory: &Url) -> Result<ValidatedOhttpKeys> {
        loop {
            let selected_relay = self.choose_relay()?;

            let ohttp_keys = {
                #[cfg(feature = "_manual-tls")]
                {
                    if let Some(cert_path) = self.config.root_certificate.as_ref() {
                        let cert_der = std::fs::read(cert_path)?;
                        payjoin::io::fetch_ohttp_keys_with_cert(
                            selected_relay.as_str(),
                            directory.as_str(),
                            &cert_der,
                        )
                        .await
                    } else {
                        payjoin::io::fetch_ohttp_keys(selected_relay.as_str(), directory.as_str())
                            .await
                    }
                }
                #[cfg(not(feature = "_manual-tls"))]
                payjoin::io::fetch_ohttp_keys(selected_relay.as_str(), directory.as_str()).await
            };

            match ohttp_keys {
                Ok(keys) => return Ok(ValidatedOhttpKeys { ohttp_keys: keys }),
                Err(payjoin::io::Error::UnexpectedStatusCode(e)) => {
                    tracing::debug!(
                        "Directory {directory} returned unexpected status via relay {selected_relay}: {e:?}"
                    );
                    self.add_failed_directory(directory.clone());
                    return Err(anyhow!("Directory {directory} returned unexpected status: {e}"));
                }
                Err(e) => {
                    tracing::debug!("Failed to connect to relay: {selected_relay}, {e:?}");
                    self.add_failed_relay(selected_relay);
                }
            }
        }
    }
}

pub(crate) struct ValidatedOhttpKeys {
    pub(crate) ohttp_keys: payjoin::OhttpKeys,
}

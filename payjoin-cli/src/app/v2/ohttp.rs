//! OHTTP relay and payjoin directory selection / key bootstrapping for the payjoin-cli.
//!
//! [`MailroomManager`] tracks relays and directories that have failed,
//! excluding them from future selections for the lifetime of the [`MailroomManager`].
//!
//! `unwrap_ohttp_keys_or_else_fetch_from_directory` returns user-supplied keys
//! when present, otherwise returns cached OHTTP keys for the directory when the
//! cache entry is still valid (within three months of being stored).
//!
//! `fetch_ohttp_keys_from_directory` retries on relay failures (e.g. connection
//! errors) by selecting another relay. Once a directory is chosen for a session
//! it must not change — the directory is embedded in the BIP21 URI at session
//! creation and recovered from the session event log on resume.
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use payjoin::Url;

use super::Config;
use crate::db::Database;

#[derive(Debug, Clone)]
pub struct MailroomManager {
    config: Config,
    failed_relays: Arc<Mutex<Vec<Url>>>,
    failed_directories: Arc<Mutex<Vec<Url>>>,
}

impl MailroomManager {
    pub fn new(config: Config) -> Self {
        MailroomManager {
            config,
            failed_relays: Arc::new(Mutex::new(Vec::new())),
            failed_directories: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn add_failed_relay(&self, relay: Url) {
        self.failed_relays.lock().expect("Lock should not be poisoned").push(relay);
    }

    pub fn clear_failed_relays(&self) {
        self.failed_relays.lock().expect("Lock should not be poisoned").clear();
    }

    pub fn add_failed_directory(&self, directory: Url) {
        self.failed_directories.lock().expect("Lock should not be poisoned").push(directory);
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
        db: Arc<Database>,
    ) -> Result<ValidatedOhttpKeys> {
        if let Some(ohttp_keys) = self.config.v2()?.ohttp_keys.clone() {
            return Ok(ValidatedOhttpKeys { ohttp_keys });
        }
        self.fetch_ohttp_keys_from_directory(directory, db, false).await
    }

    async fn fetch_ohttp_keys_from_directory(
        &self,
        directory: &Url,
        db: Arc<Database>,
        force_refresh: bool,
    ) -> Result<ValidatedOhttpKeys> {
        let cached = db.get_cached_ohttp_keys(directory.as_str())?;

        if force_refresh {
            db.invalidate_ohttp_key_cache(directory.as_str())?;
        }

        if !force_refresh {
            if let Some(cached) = cached.as_ref().filter(|c| !c.is_expired()) {
                return Ok(ValidatedOhttpKeys { ohttp_keys: cached.keys.clone() });
            }
        }

        let keys = self.fetch_ohttp_keys(directory).await?;
        if let Some(cached) = cached.as_ref() {
            if keys != cached.keys {
                tracing::debug!("OHTTP keys rotated for directory {directory}");
            }
        }
        db.store_ohttp_keys(directory.as_str(), &keys)?;
        Ok(ValidatedOhttpKeys { ohttp_keys: keys })
    }

    async fn fetch_ohttp_keys(&self, directory: &Url) -> Result<payjoin::OhttpKeys> {
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
                Ok(keys) => return Ok(keys),
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

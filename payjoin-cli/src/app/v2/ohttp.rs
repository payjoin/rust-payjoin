//! Payjoin directory selection / OHTTP key bootstrapping for the payjoin-cli.
//!
//! [`MailroomManager`] tracks directories that have failed, excluding them from
//! future selections for the lifetime of the [`MailroomManager`]. Relay
//! selection and failover are delegated to [`payjoin::io::fetch_ohttp_keys`].
//!
//! `unwrap_ohttp_keys_or_else_fetch_from_directory` returns user-supplied keys
//! when present, otherwise fetches OHTTP keys from the given directory via a
//! relay chosen from the configured list. Once a directory is chosen for a
//! session it must not change — the directory is embedded in the BIP21 URI at
//! session creation and recovered from the session event log on resume.
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use payjoin::Url;

use super::Config;

#[derive(Debug, Clone)]
pub struct MailroomManager {
    config: Config,
    failed_directories: Arc<Mutex<Vec<Url>>>,
}

impl MailroomManager {
    pub fn new(config: Config) -> Self {
        MailroomManager { config, failed_directories: Arc::new(Mutex::new(Vec::new())) }
    }

    pub fn add_failed_directory(&self, directory: Url) {
        self.failed_directories.lock().expect("Lock should not be poisoned").push(directory);
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
        let relays = &self.config.v2()?.ohttp_relays;
        let result = {
            #[cfg(feature = "_manual-tls")]
            {
                if let Some(cert_path) = self.config.root_certificate.as_ref() {
                    let cert_der = std::fs::read(cert_path)?;
                    payjoin::io::fetch_ohttp_keys_with_cert(relays, directory.as_str(), &cert_der)
                        .await
                } else {
                    payjoin::io::fetch_ohttp_keys(relays, directory.as_str()).await
                }
            }
            #[cfg(not(feature = "_manual-tls"))]
            payjoin::io::fetch_ohttp_keys(relays, directory.as_str()).await
        };

        match result {
            Ok((ohttp_keys, _relay)) => Ok(ValidatedOhttpKeys { ohttp_keys }),
            Err(payjoin::io::Error::UnexpectedStatusCode(e)) => {
                tracing::debug!("Directory {directory} returned unexpected status: {e:?}");
                self.add_failed_directory(directory.clone());
                Err(anyhow!("Directory {directory} returned unexpected status: {e}"))
            }
            Err(e) => {
                tracing::debug!("Failed to fetch ohttp keys from directory {directory}: {e:?}");
                Err(anyhow!("Failed to fetch ohttp keys: {e}"))
            }
        }
    }
}

pub(crate) struct ValidatedOhttpKeys {
    pub(crate) ohttp_keys: payjoin::OhttpKeys,
}

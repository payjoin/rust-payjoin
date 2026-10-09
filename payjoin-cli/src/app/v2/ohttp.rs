//! OHTTP relay and payjoin directory selection / key bootstrapping for the payjoin-cli.
//!
//! Thin wrapper around [`payjoin::mailroom::Mailroom`] sharing one instance
//! across sessions and tasks. The `Mailroom` tracks relays and directories
//! that have failed, excluding them from future selection, and fetches
//! OHTTP keys with automatic failover. Because the fetch holds the lock
//! across `.await` points, the instance is shared behind a
//! `tokio::sync::Mutex`.
//!
//! Once a directory is chosen for a session it must not change — the
//! directory is embedded in the BIP21 URI at session creation and recovered
//! from the session event log on resume.
use std::sync::Arc;

use anyhow::Result;
use payjoin::bitcoin::secp256k1::rand::rngs::OsRng;
use payjoin::mailroom::Mailroom;
use payjoin::Url;

use super::Config;

#[derive(Debug, Clone)]
pub struct MailroomManager(Arc<tokio::sync::Mutex<Mailroom>>);

impl MailroomManager {
    pub fn new(config: Config) -> Result<Self> {
        let v2 = config.v2()?;
        let mut mailroom = Mailroom::new(v2.ohttp_relays.clone(), v2.pj_directories.clone());
        if let Some(ohttp_keys) = v2.ohttp_keys.clone() {
            mailroom = mailroom.with_ohttp_keys(ohttp_keys);
        }
        #[cfg(feature = "_manual-tls")]
        if let Some(cert_path) = config.root_certificate.as_ref() {
            mailroom = mailroom.with_cert_der(std::fs::read(cert_path)?);
        }
        Ok(Self(Arc::new(tokio::sync::Mutex::new(mailroom))))
    }

    pub async fn choose_relay(&self) -> Result<Url> {
        self.0.lock().await.select_relay(&mut OsRng).map_err(Into::into)
    }

    pub async fn add_failed_relay(&self, relay: Url) {
        self.0.lock().await.mark_relay_failed(&relay);
    }

    pub async fn fetch_ohttp_keys(&self) -> Result<(Url, payjoin::OhttpKeys)> {
        // OsRng rather than thread_rng: ThreadRng is !Send and must not be
        // held across the fetch's await points.
        self.0.lock().await.fetch_ohttp_keys(&mut OsRng).await.map_err(Into::into)
    }
}

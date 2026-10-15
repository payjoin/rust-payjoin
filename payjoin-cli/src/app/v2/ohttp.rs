//! OHTTP relay and payjoin directory selection / key bootstrapping for the payjoin-cli.
//!
//! Thin wrapper around [`payjoin::request_handler::RequestHandler`] sharing one
//! instance across sessions and tasks. The `RequestHandler` tracks relays and
//! directories that have failed, excluding them from future selection, and
//! fetches OHTTP keys with automatic failover. It takes `&self` and holds its
//! own lock only for synchronous accesses, so it is shared directly (behind an
//! `Arc`) without an external async lock — concurrent sessions never serialize
//! their relay posts.
//!
//! Once a directory is chosen for a session it must not change — the
//! directory is embedded in the BIP21 URI at session creation and recovered
//! from the session event log on resume.
use std::sync::Arc;

use anyhow::Result;
use payjoin::bitcoin::secp256k1::rand::rngs::OsRng;
use payjoin::request_handler::RequestHandler;
use payjoin::Url;

use super::Config;

#[derive(Debug, Clone)]
pub struct MailroomManager(Arc<RequestHandler>);

impl MailroomManager {
    pub fn new(config: Config) -> Result<Self> {
        let v2 = config.v2()?;
        let mailroom = RequestHandler::new(v2.ohttp_relays.clone(), v2.pj_directories.clone());
        if let Some(ohttp_keys) = v2.ohttp_keys.clone() {
            mailroom.set_ohttp_keys(ohttp_keys);
        }
        #[cfg(feature = "_manual-tls")]
        if let Some(cert_path) = config.root_certificate.as_ref() {
            mailroom.set_cert_der(std::fs::read(cert_path)?);
        }
        Ok(Self(Arc::new(mailroom)))
    }

    pub async fn fetch_ohttp_keys(&self) -> Result<(Url, payjoin::OhttpKeys)> {
        // OsRng rather than thread_rng: ThreadRng is !Send and must not be
        // held across the fetch's await points.
        self.0.fetch_ohttp_keys(&mut OsRng).await.map_err(Into::into)
    }

    pub async fn post_via_relay<F, T, E, P, TransportError, Fut>(
        &self,
        directory: &Url,
        build: F,
        post: impl Fn(payjoin::Request) -> Fut,
    ) -> std::result::Result<
        payjoin::request_handler::RelayPost<P, T>,
        payjoin::request_handler::PostError<E>,
    >
    where
        F: FnMut(&payjoin::Url) -> std::result::Result<(payjoin::Request, T), E>,
        E: payjoin::request_handler::RequestExpiry,
        TransportError: std::fmt::Display,
        Fut: std::future::Future<Output = std::result::Result<P, TransportError>>,
    {
        // The directory is never reached through itself: a server serving as
        // both relay and directory rejects the self-loop request.
        let transport = payjoin::request_handler::FnRelayTransport::new(build, post);
        self.0.post_via_relay(&mut OsRng, directory, transport).await
    }
}

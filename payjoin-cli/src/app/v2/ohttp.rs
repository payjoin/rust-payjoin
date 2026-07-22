//! OHTTP relay selection and key bootstrapping for the payjoin-cli.
//!
//! Bootstrap key fetching uses temporary relay failover. Protocol requests use
//! stateless relay selection from the receiver network selection.
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use payjoin::Url;

use super::network::{ResolvedUrl, UrlResolver};
use super::relay_selection::{choose_receiver_network_selection, ReceiverNetworkSelection};
use super::Config;

/// Coordinates receiver bootstrap across configured directories.
///
/// Relay ordering for protocol requests remains stateless. This manager only
/// remembers directories that failed while this application instance is alive.
#[derive(Debug, Clone)]
pub(crate) struct MailroomManager {
    config: Config,
    failed_directories: Arc<Mutex<Vec<Url>>>,
}

impl MailroomManager {
    pub(crate) fn new(config: Config) -> Self {
        Self { config, failed_directories: Arc::new(Mutex::new(Vec::new())) }
    }

    pub(crate) async fn bootstrap_receiver(
        &self,
        network: &impl UrlResolver,
    ) -> Result<(ReceiverNetworkSelection, payjoin::OhttpKeys)> {
        loop {
            let failed_directories =
                self.failed_directories.lock().expect("Lock should not be poisoned").clone();
            let network_selection =
                choose_receiver_network_selection(self.config.v2()?, network, &failed_directories)?;

            match unwrap_ohttp_keys_or_else_fetch(&self.config, &network_selection).await {
                Ok(ohttp_keys) => return Ok((network_selection, ohttp_keys)),
                Err(error) => {
                    tracing::debug!(
                        "Directory {} failed: {error:#}",
                        network_selection.directory.url
                    );
                    self.failed_directories
                        .lock()
                        .expect("Lock should not be poisoned")
                        .push(network_selection.directory.url);
                }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum RelayAttemptError {
    /// Network-shaped failures can try the next relay candidate.
    Retryable(anyhow::Error),
    /// Protocol/configuration-shaped failures should stop immediately.
    Terminal(anyhow::Error),
}

/// Decide whether a reqwest failure should fail over to another relay.
pub(crate) fn classify_reqwest_error(
    err: reqwest::Error,
    context: &'static str,
) -> RelayAttemptError {
    let error = anyhow!("{context}: {err}");
    if err.is_timeout() || err.is_connect() || err.is_request() {
        RelayAttemptError::Retryable(error)
    } else {
        RelayAttemptError::Terminal(error)
    }
}

pub(crate) async fn unwrap_ohttp_keys_or_else_fetch(
    config: &Config,
    network_selection: &ReceiverNetworkSelection,
) -> Result<payjoin::OhttpKeys> {
    if let Some(ohttp_keys) = config.v2()?.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        Ok(ohttp_keys)
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        fetch_ohttp_keys(config, network_selection).await
    }
}

// Fetch directory OHTTP keys through the already chosen receiver network selection.
// This happens before the receiver key exists, so it cannot use RelaySelector.
async fn fetch_ohttp_keys(
    config: &Config,
    network_selection: &ReceiverNetworkSelection,
) -> Result<payjoin::OhttpKeys> {
    if network_selection.relays.is_empty() {
        return Err(anyhow!(
            "No valid relays available for {}",
            network_selection.directory.url.as_str()
        ));
    }

    let last_relay_index = network_selection.relays.len() - 1;
    for (index, relay) in network_selection.relays.iter().enumerate() {
        match fetch_directory_ohttp_keys_via_resolved_relay_url(
            config,
            relay.relay(),
            &network_selection.directory,
        )
        .await
        {
            Ok(keys) => return Ok(keys),
            Err(RelayAttemptError::Retryable(error)) => {
                tracing::debug!(
                    "Failed to fetch OHTTP keys via relay {}: {error:?}",
                    relay.relay().url
                );
                if index == last_relay_index {
                    return Err(error);
                }
            }
            Err(RelayAttemptError::Terminal(error)) => return Err(error),
        }
    }

    unreachable!(
        "empty relay selections return before the loop and successful key fetches return inside it"
    )
}

// Fetch through one relay using addresses checked by relay_selection. The
// library owns the request and decoding while the CLI owns relay failover.
async fn fetch_directory_ohttp_keys_via_resolved_relay_url(
    _config: &Config,
    relay: &ResolvedUrl,
    directory: &ResolvedUrl,
) -> std::result::Result<payjoin::OhttpKeys, RelayAttemptError> {
    #[cfg(feature = "_manual-tls")]
    let result = if let Some(cert_path) = _config.root_certificate.as_ref() {
        let cert_der = std::fs::read(cert_path).map_err(|error| {
            RelayAttemptError::Terminal(anyhow!("Failed to read root certificate: {error}"))
        })?;
        payjoin::io::fetch_ohttp_keys_with_cert_and_relay_addresses(
            relay.url.as_str(),
            directory.url.as_str(),
            &cert_der,
            &relay.socket_addrs,
        )
        .await
    } else {
        payjoin::io::fetch_ohttp_keys_with_relay_addresses(
            relay.url.as_str(),
            directory.url.as_str(),
            &relay.socket_addrs,
        )
        .await
    };

    #[cfg(not(feature = "_manual-tls"))]
    let result = payjoin::io::fetch_ohttp_keys_with_relay_addresses(
        relay.url.as_str(),
        directory.url.as_str(),
        &relay.socket_addrs,
    )
    .await;

    result.map_err(|error| {
        let retryable = error.is_retryable();
        let error = anyhow!("Failed to fetch OHTTP keys: {error}");
        if retryable {
            RelayAttemptError::Retryable(error)
        } else {
            RelayAttemptError::Terminal(error)
        }
    })
}

//! OHTTP relay selection and key bootstrapping for the payjoin-cli.
//!
//! Bootstrap key fetching uses temporary relay failover. Protocol requests use
//! stateless relay selection from the receiver network selection.
use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::header::ACCEPT;
use reqwest::Proxy;

use super::relay_selection::{ReceiverNetworkSelection, ResolvedUrl};
use super::Config;
use crate::app::http_client_builder;

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
            &relay.resolved,
            &network_selection.directory,
        )
        .await
        {
            Ok(keys) => return Ok(keys),
            Err(RelayAttemptError::Retryable(error)) => {
                tracing::debug!(
                    "Failed to fetch OHTTP keys via relay {}: {error:?}",
                    relay.resolved.url
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

// This mirrors payjoin::io::fetch_ohttp_keys, but keeps the CLI-specific
// pieces: resolved socket addresses, configured TLS roots, and relay failover
// error classification.
// Build a proxied request through one resolved relay. The relay address is
// resolved to the DNS result checked by relay_selection.
async fn fetch_directory_ohttp_keys_via_resolved_relay_url(
    config: &Config,
    relay: &ResolvedUrl,
    directory: &ResolvedUrl,
) -> std::result::Result<payjoin::OhttpKeys, RelayAttemptError> {
    let proxy = Proxy::all(relay.url.as_str()).map_err(|err| {
        RelayAttemptError::Terminal(anyhow!("Failed to configure OHTTP relay proxy: {err}"))
    })?;
    let mut builder = http_client_builder(config)
        .map_err(|err| RelayAttemptError::Terminal(anyhow!("Failed to build HTTP client: {err}")))?
        .proxy(proxy);

    if let Some(domain) = relay.domain() {
        builder = builder.resolve_to_addrs(domain, &relay.socket_addrs);
    }

    if let Some(directory_domain) = directory.domain() {
        builder = builder.resolve_to_addrs(directory_domain, &directory.socket_addrs);
    }

    let client = builder.build().map_err(|err| {
        RelayAttemptError::Terminal(anyhow!("Failed to build HTTP client: {err}"))
    })?;
    let ohttp_keys_url = directory.url.join("/.well-known/ohttp-gateway").map_err(|err| {
        RelayAttemptError::Terminal(anyhow!("Failed to construct OHTTP key URL: {err}"))
    })?;
    let response = client
        .get(ohttp_keys_url.as_str())
        .timeout(Duration::from_secs(10))
        .header(ACCEPT, "application/ohttp-keys")
        .send()
        .await
        .map_err(|err| classify_reqwest_error(err, "Failed to fetch OHTTP keys"))?;

    if !response.status().is_success() {
        return Err(RelayAttemptError::Terminal(anyhow!(
            "Unexpected OHTTP key status code {}",
            response.status()
        )));
    }

    let body = response.bytes().await.map_err(|err| {
        RelayAttemptError::Terminal(anyhow!("Failed to read OHTTP key response body: {err}"))
    })?;
    payjoin::OhttpKeys::decode(&body)
        .map_err(|err| RelayAttemptError::Terminal(anyhow!("Failed to decode OHTTP keys: {err}")))
}

//! OHTTP relay selection and key bootstrapping for the payjoin-cli.
//!
//! [`RelaySession`] owns a relay plan plus the current failover cursor for one
//! bootstrap, send, or receive flow. Failures advance to the next relay only
//! within that flow.
use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::header::ACCEPT;
use reqwest::Proxy;

use super::relay_selection::{PinnedUrl, RelayPlan};
use super::Config;

#[derive(Debug)]
pub(crate) enum RelayAttemptError {
    Retryable(anyhow::Error),
    Terminal(anyhow::Error),
}

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

#[derive(Debug, Clone)]
pub(crate) struct RelaySession {
    plan: RelayPlan,
    current_index: usize,
}

impl RelaySession {
    pub(crate) fn new(plan: RelayPlan) -> Self { Self { plan, current_index: 0 } }

    pub(crate) fn directory(&self) -> &PinnedUrl { &self.plan.directory }

    pub(crate) fn current_relay(&self) -> Result<PinnedUrl> {
        self.plan.relays.get(self.current_index).cloned().ok_or_else(|| {
            anyhow!("No valid relays available for {}", self.plan.directory.url.as_str())
        })
    }

    pub(crate) fn record_failure(&mut self) { self.current_index += 1; }
}

pub(crate) struct ValidatedOhttpKeys {
    pub(crate) ohttp_keys: payjoin::OhttpKeys,
}

pub(crate) async fn unwrap_ohttp_keys_or_else_fetch(
    config: &Config,
    relay_session: &mut RelaySession,
) -> Result<ValidatedOhttpKeys> {
    if let Some(ohttp_keys) = config.v2()?.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        Ok(ValidatedOhttpKeys { ohttp_keys })
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        fetch_ohttp_keys(config, relay_session).await
    }
}

pub(crate) fn http_client_builder(config: &Config) -> Result<reqwest::ClientBuilder> {
    #[cfg(feature = "_manual-tls")]
    {
        let mut builder = reqwest::ClientBuilder::new().use_rustls_tls().http1_only();
        if let Some(root_cert_path) = config.root_certificate.as_ref() {
            let cert_der = std::fs::read(root_cert_path)?;
            builder = builder
                .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der.as_slice())?);
        }
        Ok(builder)
    }

    #[cfg(not(feature = "_manual-tls"))]
    {
        let _ = config;
        Ok(reqwest::Client::builder().http1_only())
    }
}

async fn fetch_ohttp_keys(
    config: &Config,
    relay_session: &mut RelaySession,
) -> Result<ValidatedOhttpKeys> {
    loop {
        let selected_relay = relay_session.current_relay()?;

        match fetch_ohttp_keys_with_pinned_targets(
            config,
            &selected_relay,
            relay_session.directory(),
        )
        .await
        {
            Ok(keys) => return Ok(ValidatedOhttpKeys { ohttp_keys: keys }),
            Err(RelayAttemptError::Retryable(error)) => {
                tracing::debug!(
                    "Failed to fetch OHTTP keys via relay {}: {error:?}",
                    selected_relay.url
                );
                relay_session.record_failure();
            }
            Err(RelayAttemptError::Terminal(error)) => return Err(error),
        }
    }
}

async fn fetch_ohttp_keys_with_pinned_targets(
    config: &Config,
    relay: &PinnedUrl,
    directory: &PinnedUrl,
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

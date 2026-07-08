//! OpenTelemetry OTLP meter-provider construction.
//!
//! See [`build_otlp_meter_provider`] for the public entry point used by both
//! the binary (`main.rs`) and the integration tests.

use std::time::Duration;

use async_trait::async_trait;
use opentelemetry::KeyValue;
use opentelemetry_http::hyper::HyperClient;
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;

/// Build an OTLP/HTTP `SdkMeterProvider` pinned to the mailroom's `ring`
/// crypto provider.
///
/// `opentelemetry-otlp`'s `reqwest-rustls` feature pulls in `aws-lc-rs` (plus
/// its native `cmake` build) via `reqwest` 0.13. We avoid that by enabling only
/// the `hyper-client` feature and supplying our own `hyper_rustls`
/// `HttpsConnector`, which reuses the `ring`-backed `rustls` 0.23 already in
/// the dependency graph.
///
/// The caller is responsible for invoking
/// `opentelemetry::global::set_meter_provider` and installing any tracing
/// subscriber; this function deliberately touches no global state so it remains
/// unit-testable.
///
/// # Panics
/// Panics if no Tokio runtime is active on the current thread. The OTLP
/// exporter's `HyperClient` requires a Tokio context, which we capture here
/// (the SDK's `PeriodicReader` otherwise polls exporters from a bare thread
/// with no runtime, panicking on the first export).
pub fn build_otlp_meter_provider(
    endpoint: &str,
    auth_token: &str,
    operator_domain: &str,
) -> SdkMeterProvider {
    let resource = Resource::builder()
        .with_service_name("payjoin-mailroom")
        .with_attribute(KeyValue::new("operator.domain", operator_domain.to_string()))
        .build();

    let headers: std::collections::HashMap<String, String> =
        [("Authorization".to_string(), format!("Basic {auth_token}"))].into();

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    // The SDK's `PeriodicReader` drives exports on a plain OS thread via
    // `futures_executor::block_on`, with no Tokio context. `HyperClient` calls
    // `tokio::time::timeout`, which panics outside a Tokio runtime. Capture the
    // ambient handle and dispatch each request onto it.
    let handle = tokio::runtime::Handle::try_current()
        .expect("build_otlp_meter_provider must be called from a Tokio runtime");
    let http_client = TokioDispatchClient {
        inner: HyperClient::new(connector, Duration::from_secs(10), None),
        handle,
    };

    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(format!("{endpoint}/v1/metrics"))
        .with_headers(headers)
        .with_http_client(http_client)
        .build()
        .expect("Failed to build OTLP metric exporter");

    SdkMeterProvider::builder()
        .with_periodic_exporter(metric_exporter)
        .with_resource(resource)
        .build()
}

/// `HttpClient` adapter that runs the inner client on a captured Tokio handle.
///
/// The OpenTelemetry SDK's `PeriodicReader` polls exporters from a standalone
/// thread (via `futures_executor::block_on`), not from the application's Tokio
/// runtime. `HyperClient::send_bytes` uses `tokio::time::timeout`, which panics
/// without a Tokio context. This wrapper spawns each request onto the captured
/// handle and awaits the `JoinHandle`, which is safe to poll from any executor.
#[derive(Debug, Clone)]
struct TokioDispatchClient<C>
where
    C: hyper_util::client::legacy::connect::Connect
        + Clone
        + Send
        + Sync
        + std::fmt::Debug
        + 'static,
{
    inner: HyperClient<C>,
    handle: tokio::runtime::Handle,
}

#[async_trait]
impl<C> HttpClient for TokioDispatchClient<C>
where
    C: hyper_util::client::legacy::connect::Connect
        + Clone
        + Send
        + Sync
        + std::fmt::Debug
        + 'static,
{
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let inner = self.inner.clone();
        self.handle.spawn(async move { HttpClient::send_bytes(&inner, request).await }).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::MetricsService;

    /// Regression test for the OTLP transport swap (opentelemetry 0.32).
    ///
    /// Replaces the manual `mock_otlp.py` + `curl` + 65s-wait smoke test.
    /// Confirms the telemetry feature functions end-to-end:
    ///
    /// 1. The exporter builds without panicking (`NoHttpClient` is gone, since
    ///    we supply a `hyper-client` explicitly instead of the dropped
    ///    `reqwest-rustls` feature).
    /// 2. The HTTP transport works under the SDK's `PeriodicReader` -- the
    ///    `TokioDispatchClient` bridges the standalone export thread onto the
    ///    test's Tokio runtime, so no "no reactor running" panic.
    /// 3. The wire request is well-formed OTLP/protobuf with the configured
    ///    Basic-auth header, proving the encoding + auth path survived the
    ///    version bump.
    ///
    /// If crypto-provider overlap ever returns (e.g. `aws-lc-rs` sneaks back
    /// in alongside `ring`), the existing compile-time / link-time tests that
    /// guard the rustls provider selection catch that; this test does not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn otlp_exporter_posts_metrics_over_http() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v1/metrics")
            .match_header("authorization", "Basic dXNlcjpwYXNz")
            .match_header("content-type", "application/x-protobuf")
            .with_status(200)
            .create_async()
            .await;

        let provider = build_otlp_meter_provider(&server.url(), "dXNlcjpwYXNz", "test.example.com");

        // Drive a real meter through the same MetricsService the app uses so
        // the export batch is non-empty.
        let metrics = MetricsService::new(Some(provider.clone()));
        metrics.record_http_request("/health", "GET", 200);

        provider.force_flush().expect("force_flush");

        mock.assert_async().await;

        let _ = provider.shutdown();
    }
}

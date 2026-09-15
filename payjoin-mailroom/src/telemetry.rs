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
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;

/// How often the exporter pushes to the collection endpoint.
///
/// Exported values cover one completed UTC reporting week. Daily delivery
/// retries the same frozen value, avoiding a single weekly delivery attempt
/// without exposing daily traffic volume.
const EXPORT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Resource attributes attached to every exported metric.
///
/// Built from an empty resource rather than the SDK default so nothing about
/// the host environment leaks into the export: the default builder includes
/// an environment detector (`OTEL_RESOURCE_ATTRIBUTES`) through which
/// hostnames or other identifying attributes could silently join the stream.
/// The export carries exactly the service name and a Foundation-issued opaque
/// reporter ID. The ID is necessary only until a collector aggregates reports;
/// its mapping to an operator belongs outside Grafana.
pub(crate) fn export_resource(reporter_id: &str) -> Resource {
    Resource::builder_empty()
        .with_service_name("payjoin-mailroom")
        .with_attribute(KeyValue::new("reporter.id", reporter_id.to_string()))
        .build()
}

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
    reporter_id: &str,
) -> SdkMeterProvider {
    let resource = export_resource(reporter_id);

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

    let reader = PeriodicReader::builder(metric_exporter).with_interval(EXPORT_INTERVAL).build();

    SdkMeterProvider::builder().with_reader(reader).with_resource(resource).build()
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

    #[test]
    fn exporter_retries_frozen_weekly_values_daily() {
        assert_eq!(EXPORT_INTERVAL, Duration::from_secs(24 * 60 * 60));
    }

    /// The exported resource must carry exactly the service name and the
    /// Foundation-issued opaque reporting identifier. Anything else (hostname,
    /// IP, instance id, domain, env-injected attributes) could identify the operator's
    /// infrastructure, so this pins the exact key set rather than a subset.
    #[test]
    fn export_resource_carries_only_allowlisted_attributes() {
        let resource = export_resource("reporter-opaque-test-id");
        let mut keys: Vec<&str> = resource.iter().map(|(key, _)| key.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["reporter.id", "service.name"]);
    }

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

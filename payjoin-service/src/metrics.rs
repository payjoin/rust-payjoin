use opentelemetry::metrics::{Counter, MeterProvider, UpDownCounter};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;

pub(crate) const TOTAL_CONNECTIONS: &str = "total_connections";
pub(crate) const ACTIVE_CONNECTIONS: &str = "active_connections";
pub(crate) const HTTP_REQUESTS: &str = "http_request_total";

#[derive(Clone)]
pub struct MetricsService {
    /// Total number of HTTP requests by endpoint type, method, and status code
    http_requests_total: Counter<u64>,
    /// Total number of connections
    total_connections: Counter<u64>,
    /// Number of active connections right now
    active_connections: UpDownCounter<i64>,
}

impl MetricsService {
    pub fn new(provider: Option<SdkMeterProvider>) -> Self {
        let provider = provider.unwrap_or_default();
        let meter = provider.meter("payjoin-service");

        let http_requests_total = meter
            .u64_counter(HTTP_REQUESTS)
            .with_description("Total number of HTTP requests")
            .build();

        let total_connections = meter
            .u64_counter(TOTAL_CONNECTIONS)
            .with_description("Total number of connections")
            .build();

        let active_connections = meter
            .i64_up_down_counter(ACTIVE_CONNECTIONS)
            .with_description("Number of active connections")
            .build();

        Self { http_requests_total, total_connections, active_connections }
    }

    pub fn record_http_request(&self, endpoint: &str, method: &str, status_code: u16) {
        self.http_requests_total.add(
            1,
            &[
                KeyValue::new("endpoint", endpoint.to_string()),
                KeyValue::new("method", method.to_string()),
                KeyValue::new("status_code", status_code.to_string()),
            ],
        );
    }

    pub fn record_connection_open(&self) {
        self.total_connections.add(1, &[]);
        self.active_connections.add(1, &[]);
    }

    pub fn record_connection_close(&self) { self.active_connections.add(-1, &[]); }
}

use std::sync::Arc;

use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

const TOTAL_CONNECTIONS: &str = "total_connections";
const ACTIVE_CONNECTIONS: &str = "active_connections";
const HTTP_REQUESTS: &str = "http_request_total";

#[derive(Clone)]
pub struct MetricsService {
    registry: Arc<Registry>,
    /// Total number of HTTP requests by endpoint type, method, and status code
    pub http_requests_total: IntCounterVec,

    /// Total number of Connections
    pub total_connections: IntCounter,
    /// Total number of active connections right now
    pub active_connections: IntGauge,
}

impl MetricsService {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let http_requests_total = IntCounterVec::new(
            Opts::new(HTTP_REQUESTS, "Total number of HTTP requests"),
            &["endpoint", "method", "status_code"],
        )?;
        registry.register(Box::new(http_requests_total.clone()))?;

        let total_connections = IntCounter::new(TOTAL_CONNECTIONS, "Total number of connections")?;
        registry.register(Box::new(total_connections.clone()))?;

        let active_connections = IntGauge::new(ACTIVE_CONNECTIONS, "Number of active connections")?;
        registry.register(Box::new(active_connections.clone()))?;

        Ok(Self {
            registry: Arc::new(registry),
            http_requests_total,
            total_connections,
            active_connections,
        })
    }

    pub fn record_http_request(&self, endpoint: &str, method: &str, status_code: u16) {
        self.http_requests_total
            .with_label_values(&[endpoint, method, &status_code.to_string()])
            .inc();
    }

    pub fn record_connection_open(&self) {
        self.total_connections.inc();
        self.active_connections.inc();
    }
    pub fn record_connection_close(&self) { self.active_connections.dec(); }

    pub(crate) fn encode_metrics(&self) -> Result<Vec<u8>, anyhow::Error> {
        let encode = TextEncoder::new();
        let all_metrics = self.registry.gather();
        let mut buffer = Vec::new();
        encode.encode(&all_metrics, &mut buffer)?;
        Ok(buffer)
    }
}

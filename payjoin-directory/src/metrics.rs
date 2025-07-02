//use http_body_util::combinators::BoxBody;
//use hyper::body::Bytes;
use hyper::{Method, StatusCode};
use lazy_static::lazy_static;
use prometheus::{Encoder, IntCounter, IntCounterVec, Opts, Registry, TextEncoder};

lazy_static! {
    static ref REGISTRY: Registry = Registry::new();
    static ref METRICS: Metrics = Metrics::new();
}

///Container for all metrics types
/// add more metrics by updating the struct
#[derive(Debug)]
pub struct Metrics {
    /// Counter for HTTP request with labels for method , status and path
    pub http_requests_total: IntCounterVec,

    /// Total number of connections accepted by the directory
    pub connections_total: IntCounter,
}

impl Metrics {
    fn new() -> Self {
        let http_requests_total = IntCounterVec::new(
            Opts::new("http_requests_total", "Total number of HTTP requests seen"),
            &["method", "status", "path"],
        )
        .expect("Failed to create http_requests_total metrics");

        let connections_total =
            IntCounter::new("connections_total", "Total number of tcp connections")
                .expect("Failed to create connections_total metrics ");

        REGISTRY
            .register(Box::new(http_requests_total.clone()))
            .expect("Failed to register http_request_total");
        REGISTRY
            .register(Box::new(connections_total.clone()))
            .expect("Failed to register connections_total");

        Self { http_requests_total, connections_total }
    }
}

///avoids calling METRICS.<metric> everywhere
pub fn metrics() -> &'static Metrics { &METRICS }

/// Records HTTP request with method, status and path as labels
pub fn record_http_request(method: &Method, status: StatusCode, path: &str) {
    let method_str = method.as_str();
    let status_str = status.as_u16().to_string();
    let normalized_path = path_normalizer(path);

    metrics()
        .http_requests_total
        .with_label_values(&[method_str, &status_str, &normalized_path])
        .inc();
}

///Records a new connection
pub fn record_connection() { metrics().connections_total.inc(); }

fn is_valid_shortid(id: &str) -> bool {
    // Validates a 13-character uppercase bech32 ID.
    if id.len() == 13 {
        return true;
    }

    false
}

///Dynamic path segments such as the ShortID shoudn't be recorded as unique path
/// This function group similar paths together to prevent metrics explosion
fn path_normalizer(path: &str) -> String {
    let path_segments: Vec<&str> = path.split('/').collect();

    match path_segments.as_slice() {
        ["", "health"] => "/health".to_string(),

        ["", ".well-known", "ohttp-gateway"] => "/.well-known/ohttp-gateway".to_string(),
        ["", "ohttp-keys"] => "/ohttp-keys".to_string(),

        ["", ""] => "/".to_string(),

        ["", _id] if is_valid_shortid(_id) => "/{id}".to_string(),

        //Fallback for unknown paths
        _ => "/other".to_string(),
    }
}

pub fn generate_metrics() -> Result<String, Box<dyn std::error::Error>> {
    let encoder = TextEncoder::new();
    let all_metrics = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&all_metrics, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

pub struct MetricsCollector {
    method: Method,
    path: String,
}

impl MetricsCollector {
    pub fn new(method: Method, path: String) -> Self { Self { method, path } }

    pub fn record_response(&self, status: StatusCode) {
        record_http_request(&self.method, status, &self.path);
    }
}

#[cfg(test)]
mod tests {
    use hyper::Method;

    use super::*;

    #[test]
    fn test_recording_metrics() {
        record_http_request(&Method::GET, StatusCode::OK, "/health");
        record_connection();

        let metrics_recorded = generate_metrics().expect("Failed to generate metrics");
        assert!(metrics_recorded.contains("http_requests_total"));
        assert!(metrics_recorded.contains("connections_total"));
    }

    #[test]
    fn test_path_normalization() {
        assert_eq!(path_normalizer("/health"), "/health");
        assert_eq!(path_normalizer("/.well-known/ohttp-gateway"), "/.well-known/ohttp-gateway");
        assert_eq!(path_normalizer("/ohttp-keys"), "/ohttp-keys");
        assert_eq!(path_normalizer("/"), "/");
        assert_eq!(path_normalizer("/abc1234567df1"), "/{id}");
        assert_eq!(path_normalizer("/unknown/directory/path"), "/other");
    }
}

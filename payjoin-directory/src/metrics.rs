use lazy_static::lazy_static;
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};

lazy_static! {
    static ref REGISTRY: Registry = Registry::new();
    static ref METRICS: Metrics = Metrics::new();
}

/// Container for all metrics types
/// add more metrics by updating the struct
#[derive(Debug)]
pub struct Metrics {
    /// Total number of connections accepted by the directory
    pub connections_total: IntCounter,
}

impl Metrics {
    fn new() -> Self {
        let connections_total =
            IntCounter::new("connections_total", "Total number of tcp connections")
                .expect("Failed to create connections_total metrics ");

        REGISTRY
            .register(Box::new(connections_total.clone()))
            .expect("Failed to register connections_total");

        Self { connections_total }
    }
}

/// Returns a reference to the global `Metrics` instance.
/// Useful when working extensively with metrics throughout the codebase
pub fn metrics() -> &'static Metrics { &METRICS }

///Records a new connection
pub fn record_connection() { metrics().connections_total.inc(); }

pub fn generate_metrics() -> Result<String, Box<dyn std::error::Error>> {
    let encoder = TextEncoder::new();
    let all_metrics = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&all_metrics, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_recording_metrics() {
        record_connection();

        let metrics_recorded = generate_metrics().expect("Failed to generate metrics");
        assert!(metrics_recorded.contains("connections_total"));
    }
}

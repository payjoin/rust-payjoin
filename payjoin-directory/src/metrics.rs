use prometheus::{Encoder, IntCounter, Registry, TextEncoder};

#[derive(Debug, Clone)]
pub struct Metrics {
    /// Total number of connections accepted by the directory
    pub connections_total: IntCounter,
    registry: Registry,
}

impl Default for Metrics {
    fn default() -> Self { Self::new() }
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let connections_total =
            IntCounter::new("connections_total", "Total number of tcp connections")
                .expect("Failed to create connections_total metrics ");

        registry
            .register(Box::new(connections_total.clone()))
            .expect("Failed to register connections_total");

        Self { connections_total, registry }
    }

    /// Records a new connection
    pub fn record_connection(&self) { self.connections_total.inc(); }

    pub fn generate_metrics(&self) -> Result<String, Box<dyn std::error::Error>> {
        let encoder = TextEncoder::new();
        let all_metrics = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&all_metrics, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_recording_metrics() {
        let metrics = Metrics::new();
        metrics.record_connection();

        let metrics_recorded = metrics.generate_metrics().expect("Failed to generate metrics");
        assert!(metrics_recorded.contains("connections_total"));
    }

    #[test]
    fn does_not_error_on_empty_metrics() {
        let metrics = Metrics::new();
        let metrics_recorded = metrics.generate_metrics().expect("Failed to generate metrics");
        assert!(metrics_recorded.contains("connections_total 0"));
    }
}

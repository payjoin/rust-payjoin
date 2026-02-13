use clap::Parser;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use payjoin_service::{cli, config};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    let config_path = args.config.unwrap_or_else(|| "config.toml".into());
    let config = config::Config::from_file(&config_path)?;

    #[cfg(feature = "telemetry")]
    let meter_provider = match &config.telemetry {
        Some(telemetry) => Some(init_tracing_with_telemetry(telemetry)),
        None => init_tracing(),
    };
    #[cfg(not(feature = "telemetry"))]
    let meter_provider = init_tracing();

    #[cfg(feature = "acme")]
    if config.acme.is_some() {
        return payjoin_service::serve_acme(config, meter_provider).await;
    }

    payjoin_service::serve(config, meter_provider).await
}

fn init_tracing() -> Option<SdkMeterProvider> {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();
    None
}

#[cfg(feature = "telemetry")]
fn init_tracing_with_telemetry(telemetry: &config::TelemetryConfig) -> SdkMeterProvider {
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
    use opentelemetry_sdk::Resource;

    let resource = Resource::builder()
        .with_service_name("payjoin-service")
        .with_attribute(KeyValue::new("operator.domain", telemetry.operator_domain.clone()))
        .build();

    let headers: std::collections::HashMap<String, String> =
        [("Authorization".to_string(), format!("Basic {}", telemetry.auth_token))].into();

    // Initialize metric exporter and provider
    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(format!("{}/v1/metrics", &telemetry.endpoint))
        .with_headers(headers)
        .build()
        .expect("Failed to build OTLP metric exporter");
    let meter_provider = SdkMeterProvider::builder()
        .with_periodic_exporter(metric_exporter)
        .with_resource(resource)
        .build();

    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().json().with_target(true).with_env_filter(env_filter).init();

    opentelemetry::global::set_meter_provider(meter_provider.clone());

    meter_provider
}

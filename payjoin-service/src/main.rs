use clap::Parser;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use payjoin_service::{cli, config};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let meter_provider = init_tracing();

    let args = cli::Args::parse();
    let config_path = args.config.unwrap_or_else(|| "config.toml".into());
    let config = config::Config::from_file(&config_path)?;

    #[cfg(feature = "acme")]
    if config.acme.is_some() {
        return payjoin_service::serve_acme(config, meter_provider).await;
    }

    payjoin_service::serve(config, meter_provider).await
}

#[cfg(not(feature = "telemetry"))]
fn init_tracing() -> Option<SdkMeterProvider> {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();
    None
}

#[cfg(feature = "telemetry")]
fn init_tracing() -> Option<SdkMeterProvider> {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry::KeyValue;
    use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
    use opentelemetry_otlp::WithHttpConfig;
    use opentelemetry_sdk::Resource;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let mut resource_builder = Resource::builder().with_service_name("payjoin-service");
    if let Ok(domain) = std::env::var("OPERATOR_DOMAIN") {
        resource_builder =
            resource_builder.with_attribute(KeyValue::new("operator.domain", domain));
    }
    let resource = resource_builder.build();

    let headers: std::collections::HashMap<String, String> =
        std::env::var("OTEL_EXPORTER_OTLP_TOKEN")
            .ok()
            .map(|token| [("Authorization".to_string(), format!("Basic {}", token))].into())
            .unwrap_or_default();

    // Initialize trace exporter and provider
    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_headers(headers.clone())
        .build()
        .expect("Failed to build OTLP span exporter");
    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter)
        .with_resource(resource.clone())
        .build();

    // Initialize log exporter and provider
    let log_exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_headers(headers.clone())
        .build()
        .expect("Failed to build OTLP log exporter");
    let logger_provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_batch_exporter(log_exporter)
        .with_resource(resource.clone())
        .build();

    // Initialize metric exporter and provider
    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_headers(headers)
        .build()
        .expect("Failed to build OTLP metric exporter");
    let meter_provider = SdkMeterProvider::builder()
        .with_periodic_exporter(metric_exporter)
        .with_resource(resource)
        .build();

    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().json().with_target(true))
        .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("payjoin-service")))
        .with(OpenTelemetryTracingBridge::new(&logger_provider))
        .init();

    opentelemetry::global::set_tracer_provider(tracer_provider);
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    Some(meter_provider)
}

use clap::Parser;
use payjoin_service::{cli, config};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let args = cli::Args::parse();
    let config_path = args.config.unwrap_or_else(|| "config.toml".into());
    let config = config::Config::from_file(&config_path)?;

    #[cfg(feature = "acme")]
    if config.acme.is_some() {
        return payjoin_service::serve_acme(config).await;
    }

    payjoin_service::serve(config).await
}

#[cfg(not(feature = "telemetry"))]
fn init_tracing() {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();
}

#[cfg(feature = "telemetry")]
fn init_tracing() {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // Initialize trace exporter and provider
    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
        .expect("Failed to build OTLP span exporter");
    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter)
        .build();

    // Initialize log exporter and provider
    let log_exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .build()
        .expect("Failed to build OTLP log exporter");
    let logger_provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_batch_exporter(log_exporter)
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
}

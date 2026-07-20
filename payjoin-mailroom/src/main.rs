use clap::Parser;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use payjoin_mailroom::{cli, config};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    let config_path = args.config.unwrap_or_else(|| "config.toml".into());
    let config = config::Config::from_file(&config_path)?;

    #[cfg(feature = "telemetry")]
    let meter_provider = match &config.telemetry {
        Some(telemetry) => init_tracing_with_telemetry(telemetry),
        None => init_tracing(),
    };
    #[cfg(not(feature = "telemetry"))]
    let meter_provider = init_tracing();

    #[cfg(feature = "acme")]
    if config.acme.is_some() {
        return payjoin_mailroom::serve_acme(config, meter_provider).await;
    }

    payjoin_mailroom::serve(config, meter_provider).await
}

fn init_tracing() -> Option<SdkMeterProvider> {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();
    None
}

#[cfg(feature = "telemetry")]
fn init_tracing_with_telemetry(telemetry: &config::TelemetryConfig) -> Option<SdkMeterProvider> {
    // export_enabled = false keeps this section's structured logging but
    // builds no exporter at all: metrics stay local to the operator.
    let meter_provider = telemetry.export_enabled.then(|| {
        payjoin_mailroom::telemetry::build_otlp_meter_provider(
            &telemetry.endpoint,
            &telemetry.auth_token,
            &telemetry.reporter_id,
        )
    });

    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().json().with_target(true).with_env_filter(env_filter).init();

    if let Some(meter_provider) = &meter_provider {
        opentelemetry::global::set_meter_provider(meter_provider.clone());
    }

    meter_provider
}

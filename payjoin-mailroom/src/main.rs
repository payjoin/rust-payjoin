use clap::Parser;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use payjoin_mailroom::config::LogFormat;
use payjoin_mailroom::{cli, config};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();
    let config_path = args.config.unwrap_or_else(|| "config.toml".into());
    let config = config::Config::from_file(&config_path)?;

    init_tracing(config.log_format);

    #[cfg(feature = "telemetry")]
    let meter_provider = config.telemetry.as_ref().map(init_telemetry);
    #[cfg(not(feature = "telemetry"))]
    let meter_provider: Option<SdkMeterProvider> = None;

    #[cfg(feature = "acme")]
    if config.acme.is_some() {
        return payjoin_mailroom::serve_acme(config, meter_provider).await;
    }

    payjoin_mailroom::serve(config, meter_provider).await
}

fn init_tracing(format: LogFormat) {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();
    let subscriber =
        tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter);
    match format {
        LogFormat::Text => subscriber.init(),
        LogFormat::Json => subscriber.json().init(),
    }
}

#[cfg(feature = "telemetry")]
fn init_telemetry(telemetry: &config::TelemetryConfig) -> SdkMeterProvider {
    let meter_provider = payjoin_mailroom::telemetry::build_otlp_meter_provider(
        &telemetry.endpoint,
        &telemetry.auth_token,
        &telemetry.operator_domain,
    );

    opentelemetry::global::set_meter_provider(meter_provider.clone());

    meter_provider
}

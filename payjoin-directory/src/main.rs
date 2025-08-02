use clap::Parser;
use payjoin_directory::metrics::Metrics;
use payjoin_directory::*;
use tokio::net::TcpListener;
use tracing::error;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    init_logging();

    let cli = cli::Cli::parse();
    let config = config::Config::new(&cli)?;

    let key_dir = config.ohttp_keys;
    std::fs::create_dir_all(&key_dir).expect("Failed to create key directory");

    let ohttp = match key_config::read_server_config(&key_dir) {
        Ok(config) => config,
        Err(_) => {
            let ohttp_config = key_config::gen_ohttp_server_config()?;
            let path = key_config::persist_new_key_config(ohttp_config, &key_dir)?;
            println!("Generated new key configuration at {}", path.display());
            key_config::read_server_config(&key_dir).expect("Failed to read newly generated config")
        }
    };

    let db = RedisDb::new(config.timeout, config.db_host).await?;
    let metrics = Metrics::new();
    let service = Service::new(db, ohttp.into(), metrics);

    // Start metrics server in the background
    let metrics_listener = TcpListener::bind(config.metrics_listen_addr).await?;
    {
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(e) = service.serve_metrics_tcp(metrics_listener).await {
                error!("Metrics server error: {e}");
            }
        });
    }

    let listener = TcpListener::bind(config.listen_addr).await?;
    service.serve_tcp(listener).await
}

fn init_logging() {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();

    println!("Logging initialized");
}

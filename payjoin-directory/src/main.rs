use std::env;

use payjoin_directory::*;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let dir_port =
        env::var("PJ_DIR_PORT").map_or(DEFAULT_DIR_PORT, |s| s.parse().expect("Invalid port"));

    let timeout_env = env::var("PJ_DIR_TIMEOUT_SECS")
        .map_or(DEFAULT_TIMEOUT_SECS, |s| s.parse().expect("Invalid timeout"));
    let timeout = std::time::Duration::from_secs(timeout_env);

    let db_host = env::var("PJ_DB_HOST").unwrap_or_else(|_| DEFAULT_DB_HOST.to_string());

    payjoin_directory::listen_tcp(dir_port, db_host, timeout).await
}

fn init_logging() {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();

    println!("Logging initialized");
}

use std::env;

use payjoin_directory::*;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

const DEFAULT_KEY_CONFIG_DIR: &str = "ohttp_keys";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let dir_port =
        env::var("PJ_DIR_PORT").map_or(DEFAULT_DIR_PORT, |s| s.parse().expect("Invalid port"));

    let timeout_env = env::var("PJ_DIR_TIMEOUT_SECS")
        .map_or(DEFAULT_TIMEOUT_SECS, |s| s.parse().expect("Invalid timeout"));
    let timeout = std::time::Duration::from_secs(timeout_env);

    let db_host = env::var("PJ_DB_HOST").unwrap_or_else(|_| DEFAULT_DB_HOST.to_string());

    let key_dir =
        std::env::var("PJ_OHTTP_KEY_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| {
            let key_dir = std::path::PathBuf::from(DEFAULT_KEY_CONFIG_DIR);
            std::fs::create_dir_all(&key_dir).expect("Failed to create key directory");
            key_dir
        });

    let ohttp = match key_config::read_server_config(&key_dir) {
        Ok(config) => config,
        Err(_) => {
            let ohttp_config = key_config::gen_ohttp_server_config()?;
            let path = key_config::persist_new_key_config(ohttp_config, &key_dir)?;
            println!("Generated new key configuration at {}", path.display());
            key_config::read_server_config(&key_dir).expect("Failed to read newly generated config")
        }
    };

    payjoin_directory::listen_tcp(dir_port, db_host, timeout, ohttp.into()).await
}

fn init_logging() {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();

    println!("Logging initialized");
}

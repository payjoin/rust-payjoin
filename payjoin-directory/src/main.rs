use std::env;

use payjoin_directory::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir_port =
        env::var("PJ_DIR_PORT").map_or(DEFAULT_DIR_PORT, |s| s.parse().expect("Invalid port"));

    let timeout_env = env::var("PJ_DIR_TIMEOUT_SECS")
        .map_or(DEFAULT_TIMEOUT_SECS, |s| s.parse().expect("Invalid timeout"));
    let timeout = std::time::Duration::from_secs(timeout_env);

    let db_host = env::var("PJ_DB_HOST").unwrap_or_else(|_| DEFAULT_DB_HOST.to_string());

    payjoin_directory::listen_tcp(dir_port, db_host, timeout).await
}

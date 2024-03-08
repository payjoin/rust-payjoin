use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use payjoin_directory::*;
use tracing::info;
use tokio::sync::Mutex;

use payjoin_directory::db::DbPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let dir_port = env::var("PJ_DIR_PORT").unwrap_or_else(|_| DEFAULT_DIR_PORT.to_string());
    let timeout_secs = env::var("PJ_DIR_TIMEOUT_SECS")
        .map(|s| s.parse().expect("Invalid timeout"))
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let db_host = env::var("PJ_DB_HOST").unwrap_or_else(|_| DEFAULT_DB_HOST.to_string());

    let pool = DbPool::new(timeout, db_host).await?;
    let ohttp = Arc::new(Mutex::new(init_ohttp()?));
    let make_svc = make_service_fn(|_| {
        let pool = pool.clone();
        let ohttp = ohttp.clone();
        async move {
            let handler = move |req| handle_ohttp_gateway(req, pool.clone(), ohttp.clone());
            Ok::<_, hyper::Error>(service_fn(handler))
        }
    });

    // Parse the bind address using the provided port
    let bind_addr_str = format!("0.0.0.0:{}", dir_port);
    let bind_addr: SocketAddr = bind_addr_str.parse()?;
    let server = payjoin_directory::init_server(&bind_addr)?.serve(make_svc);
    info!("Payjoin Directory awaiting HTTP connection at {}", bind_addr_str);
    Ok(server.await?)
}
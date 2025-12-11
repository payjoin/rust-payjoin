use std::net::{Ipv6Addr, SocketAddr};

use axum::extract::State;
use axum::http::Method;
use axum::response::{IntoResponse, Response};
use axum::Router;
use config::Config;
use tower::Service;
use tracing::info;

pub mod cli;
pub mod config;

#[derive(Clone)]
struct Services {
    directory: payjoin_directory::Service<payjoin_directory::FilesDb>,
    relay: ohttp_relay::Service,
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let services = Services {
        directory: init_directory(&config).await?,
        relay: ohttp_relay::Service::new().await,
    };
    let app = Router::new().fallback(route_request).with_state(services);

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, config.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Payjoin service listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn init_directory(
    config: &Config,
) -> anyhow::Result<payjoin_directory::Service<payjoin_directory::FilesDb>> {
    let db = payjoin_directory::FilesDb::init(config.timeout, config.storage_dir.clone()).await?;
    db.spawn_background_prune().await;

    let ohttp_keys_dir = config.storage_dir.join("ohttp-keys");
    let ohttp_config = init_ohttp_config(&ohttp_keys_dir)?;
    let metrics = payjoin_directory::metrics::Metrics::new();

    Ok(payjoin_directory::Service::new(db, ohttp_config.into(), metrics))
}

fn init_ohttp_config(
    ohttp_keys_dir: &std::path::Path,
) -> anyhow::Result<payjoin_directory::ServerKeyConfig> {
    std::fs::create_dir_all(ohttp_keys_dir)?;
    match payjoin_directory::read_server_config(ohttp_keys_dir) {
        Ok(config) => Ok(config),
        Err(_) => {
            let config = payjoin_directory::gen_ohttp_server_config()?;
            payjoin_directory::persist_new_key_config(config.clone(), ohttp_keys_dir)?;
            Ok(config)
        }
    }
}

async fn route_request(
    State(mut services): State<Services>,
    req: axum::extract::Request,
) -> Response {
    if is_relay_request(&req) {
        match services.relay.call(req).await {
            Ok(res) => res.into_response(),
            Err(e) => (axum::http::StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
        }
    } else {
        // The directory service handles all other requests (including 404)
        match services.directory.call(req).await {
            Ok(res) => res.into_response(),
            Err(e) =>
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

/// Determines if a request should be routed to the OHTTP relay service.
///
/// Routing rules:
/// - `(OPTIONS, _)` => CORS preflight handling
/// - `(CONNECT, _)` => OHTTP bootstrap tunneling
/// - `(POST, "/")` => relay to default gateway (needed for backwards-compatibility only)
/// - `(POST, /http(s)://...)` => RFC 9540 opt-in gateway specified in path
/// - `(GET, /http(s)://...)` => OHTTP bootstrap via WebSocket with opt-in gateway
fn is_relay_request(req: &axum::extract::Request) -> bool {
    let method = req.method();
    let path = req.uri().path();

    match (method, path) {
        (&Method::OPTIONS, _) | (&Method::CONNECT, _) | (&Method::POST, "/") => true,
        (&Method::POST, p) | (&Method::GET, p)
            if p.starts_with("/http://") || p.starts_with("/https://") =>
            true,
        _ => false,
    }
}

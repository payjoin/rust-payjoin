use std::net::{Ipv6Addr, SocketAddr};

use axum::extract::State;
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
    let db = payjoin_directory::FilesDb::init(config.timeout, config.storage_dir.clone()).await?;
    db.spawn_background_prune().await;

    let ohttp_keys_dir = config.storage_dir.join("ohttp-keys");
    let ohttp_config = init_ohttp_config(&ohttp_keys_dir)?;
    let metrics = payjoin_directory::metrics::Metrics::new();

    let directory = payjoin_directory::Service::new(db, ohttp_config.into(), metrics);

    // TODO: A gateway should no longer need to be specified, but ohttp-relay currently requires it.
    // See https://github.com/payjoin/ohttp-relay/issues/73
    let gateway =
        config.gateway_origin.parse::<ohttp_relay::GatewayUri>().map_err(|e| anyhow::anyhow!(e))?;
    let relay = ohttp_relay::Service::new_with_gateway(gateway).await;

    let services = Services { directory, relay };
    let app = Router::new().fallback(route_request).with_state(services);

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, config.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Payjoin service listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
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

/// Routes incoming requests to ohttp-relay or payjoin-directory based on the path.
/// OHTTP Gateway authorities are either hostnames (fully qualified, so containing a `.`) or IP
/// addresses (containing `.` or `:`). Directory mailboxes are 13 bech32 characters, so there is no
/// ambiguity.
///
/// Additionally, any request that doesn't match the authority pattern can simply be routed to the
/// directory since it already handles other useful paths (e.g. /health, /metrics, /ohttp-keys).
///
/// HTTP CONNECT requests are routed to the relay for OHTTP bootstrap tunneling.
async fn route_request(
    State(mut services): State<Services>,
    req: axum::extract::Request,
) -> Response {
    if req.method() == axum::http::Method::CONNECT {
        return match services.relay.call(req).await {
            Ok(res) => res.into_response(),
            Err(e) => (axum::http::StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
        };
    }

    let path = req.uri().path().to_string();

    if let Some(segment) = path.strip_prefix('/').and_then(|p| p.split('/').next()) {
        // .well-known requests contain a period but are handled by the directory service.
        if segment != ".well-known" && (segment.contains('.') || segment.contains(':')) {
            return match services.relay.call(req).await {
                Ok(res) => res.into_response(),
                Err(e) => (axum::http::StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
            };
        }
    }

    match services.directory.call(req).await {
        Ok(res) => res.into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

use std::net::SocketAddr;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::Method;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use config::Config;
use ohttp_relay::SentinelTag;
use rand::Rng;
use tokio_listener::{Listener, SystemOptions, UserOptions};
use tower::{Service, ServiceBuilder};
use tracing::info;
pub mod ohttp;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use ohttp::{OhttpGatewayConfig, OhttpGatewayLayer};
use tower::ServiceExt;

pub mod cli;
pub mod config;
pub mod metrics;
pub mod middleware;

use crate::metrics::MetricsService;
use crate::middleware::{track_connections, track_metrics};

#[derive(Clone)]
struct Services {
    directory: payjoin_directory::Service<payjoin_directory::FilesDb>,
    relay: ohttp_relay::Service,
    sentinel_tag: SentinelTag,
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let sentinel_tag = generate_sentinel_tag();
    let metrics = MetricsService::new()?;

    let services = Services {
        directory: init_directory(&config, sentinel_tag).await?,
        relay: ohttp_relay::Service::new(sentinel_tag).await,
        sentinel_tag,
    };

    let app = build_app(services, metrics.clone());
    let _ = spawn_metrics_server(config.metrics.listener.clone(), metrics).await?;

    let listener =
        Listener::bind(&config.listener, &SystemOptions::default(), &UserOptions::default())
            .await?;
    info!("Payjoin service listening on {:?}", listener.local_addr());
    axum::serve(listener, app).await?;

    Ok(())
}

/// Serves payjoin-service with manual TLS configuration.
///
/// Binds to `config.listener` (use port 0 to let the OS assign a free port) and returns
/// the actual bound port, the metrics port, and a task handle.
///
/// If `tls_config` is provided, the server will use TLS for incoming connections.
/// The `root_store` is used for outgoing relay connections to the gateway.
#[cfg(feature = "_manual-tls")]
pub async fn serve_manual_tls(
    config: Config,
    tls_config: Option<axum_server::tls_rustls::RustlsConfig>,
    root_store: rustls::RootCertStore,
) -> anyhow::Result<(u16, u16, tokio::task::JoinHandle<anyhow::Result<()>>)> {
    use std::net::SocketAddr;

    let sentinel_tag = generate_sentinel_tag();
    let metrics = MetricsService::new()?;

    let services = Services {
        directory: init_directory(&config, sentinel_tag).await?,
        relay: ohttp_relay::Service::new_with_roots(root_store, sentinel_tag).await,
        sentinel_tag,
    };
    let app = build_app(services, metrics.clone());
    let metrics_port = spawn_metrics_server(config.metrics.listener.clone(), metrics).await?;

    let addr: SocketAddr = config
        .listener
        .to_string()
        .parse()
        .map_err(|_| anyhow::anyhow!("TLS mode requires a TCP address (e.g., '[::]:8080')"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();

    let handle = match tls_config {
        Some(tls) => {
            info!("Payjoin service listening on port {} with TLS", port);
            tokio::spawn(async move {
                axum_server::from_tcp_rustls(listener.into_std()?, tls)?
                    .serve(app.into_make_service())
                    .await
                    .map_err(Into::into)
            })
        }
        None => {
            info!("Payjoin service listening on port {} without TLS", port);
            tokio::spawn(async move { axum::serve(listener, app).await.map_err(Into::into) })
        }
    };

    Ok((port, metrics_port, handle))
}

/// Serves payjoin-service with ACME-managed TLS certificates.
///
/// Uses `tokio-rustls-acme` to automatically obtain and renew TLS
/// certificates from Let's Encrypt via the TLS-ALPN-01 challenge.
#[cfg(feature = "acme")]
pub async fn serve_acme(config: Config) -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;

    let acme_config = config
        .acme
        .clone()
        .ok_or_else(|| anyhow::anyhow!("ACME configuration is required for serve_acme"))?;

    let sentinel_tag = generate_sentinel_tag();
    let metrics = MetricsService::new()?;

    let services = Services {
        directory: init_directory(&config, sentinel_tag).await?,
        relay: ohttp_relay::Service::new(sentinel_tag).await,
    };
    let app = build_app(services, metrics.clone());
    let _ = spawn_metrics_server(config.metrics.listener.clone(), metrics).await?;

    let addr: SocketAddr = config
        .listener
        .to_string()
        .parse()
        .map_err(|_| anyhow::anyhow!("ACME mode requires a TCP address (e.g., '[::]:443')"))?;

    let acme = acme_config.into_rustls_config(&config.storage_dir);
    let mut state = acme.state();
    let rustls_config = Arc::new(
        rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(state.resolver()),
    );
    let acceptor = state.axum_acceptor(rustls_config);

    // Drive ACME cert renewal in background
    tokio::spawn(async move {
        use tokio_stream::StreamExt;
        loop {
            match state.next().await {
                Some(Ok(ok)) => info!("ACME event: {:?}", ok),
                Some(Err(err)) => tracing::error!("ACME error: {:?}", err),
                None => break,
            }
        }
    });

    info!("Payjoin service listening on {} with ACME TLS", addr);
    axum_server::bind(addr).acceptor(acceptor).serve(app.into_make_service()).await?;
    Ok(())
}

/// Generate random sentinel tag at startup.
/// The relay and directory share this tag in a best-effort attempt
/// at detecting self loops.
fn generate_sentinel_tag() -> SentinelTag { SentinelTag::new(rand::thread_rng().gen()) }

async fn init_directory(
    config: &Config,
    sentinel_tag: SentinelTag,
) -> anyhow::Result<payjoin_directory::Service<payjoin_directory::FilesDb>> {
    let db = payjoin_directory::FilesDb::init(config.timeout, config.storage_dir.clone()).await?;
    db.spawn_background_prune().await;

    let ohttp_keys_dir = config.storage_dir.join("ohttp-keys");
    let ohttp_config = init_ohttp_config(&ohttp_keys_dir)?;

    Ok(payjoin_directory::Service::new(db, ohttp_config.into(), sentinel_tag))
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

fn build_app(services: Services, metrics: MetricsService) -> Router {
    Router::new()
        .fallback(route_request)
        .layer(
            ServiceBuilder::new()
                .layer(axum::middleware::from_fn_with_state(metrics.clone(), track_metrics))
                .layer(axum::middleware::from_fn_with_state(metrics, track_connections)),
        )
        .with_state(services)
}

fn build_metrics_app(metrics: MetricsService) -> Router {
    Router::new().route("/metrics", get(metrics_handler)).with_state(metrics)
}

async fn metrics_handler(State(metrics): State<MetricsService>) -> impl IntoResponse {
    match metrics.encode_metrics() {
        Ok(body) => (
            axum::http::StatusCode::OK,
            [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to encode metrics: {}", e),
        )
            .into_response(),
    }
}

async fn spawn_metrics_server(
    metrics_listener: tokio_listener::ListenerAddress,
    metrics: MetricsService,
) -> anyhow::Result<u16> {
    let addr: SocketAddr = metrics_listener.to_string().parse().map_err(|_| {
        anyhow::anyhow!("Metrics listener must be a TCP address (e.g., '[::]:9090')")
    })?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual_port = listener.local_addr()?.port();
    info!("Metrics server listening on [::]:{actual_port}");
    tokio::spawn(async move {
        let app = build_metrics_app(metrics);
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Metrics server error: {e}");
        }
    });
    Ok(actual_port)
}

async fn route_request(
    State(services): State<Services>,
    req: axum::extract::Request,
) -> Response {
    if is_relay_request(&req) {
        let mut relay = services.relay.clone();
        match relay.call(req).await {
            Ok(res) => res.into_response(),
            Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
        }
    } else {
        handle_directory_request(services, req).await
    }
}

async fn handle_directory_request(services: Services, req: axum::extract::Request) -> Response {
    let ohttp_server = services.directory.ohttp.clone();

    let ohttp_config = OhttpGatewayConfig::new(ohttp_server, services.sentinel_tag);

    let (parts, body) = req.into_parts();

    use http_body_util::BodyExt as _;

    let body_bytes = body
        .collect()
        .await
        .map_err(|_| "Failed to collect body")
        .expect("Failed to collect body")
        .to_bytes();

    let boxed_body = BoxBody::new(http_body_util::Full::new(body_bytes));

    let hyper_req = Request::from_parts(parts, boxed_body);

    let directory_service = tower::service_fn({
        let directory = services.directory.clone();
        move |req: Request<BoxBody<Bytes, hyper::Error>>| {
            let mut dir = directory.clone();
            async move {
                dir.call(req).await.map_err(|e| {
                    Box::new(std::io::Error::other(e.to_string()))
                        as Box<dyn std::error::Error + Send + Sync>
                })
            }
        }
    });

    let mut service_with_ohttp = ServiceBuilder::new()
        .layer(OhttpGatewayLayer::new(ohttp_config))
        .service(directory_service)
        .boxed_clone();

    match service_with_ohttp.ready().await {
        Ok(ready_service) => match ready_service.call(hyper_req).await {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                let axum_body = axum::body::Body::new(body);
                Response::from_parts(parts, axum_body).into_response()
            }
            Err(e) =>
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Service error: {}", e)).into_response(),
        },
        Err(e) =>
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Service not ready: {}", e)).into_response(),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum_server::tls_rustls::RustlsConfig;
    use payjoin_test_utils::{http_agent, local_cert_key, wait_for_service_ready};
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;
    use tempfile::tempdir;

    use super::*;

    async fn start_service(
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> (u16, u16, tokio::task::JoinHandle<anyhow::Result<()>>, tempfile::TempDir) {
        let tempdir = tempdir().unwrap();
        let config = Config::new(
            "[::]:0".parse().expect("valid listener address"),
            tempdir.path().to_path_buf(),
            Duration::from_secs(2),
            "[::]:0".parse().expect("valid metrics listener address"),
        );

        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der.clone())).unwrap();
        let tls_config = RustlsConfig::from_der(vec![cert_der], key_der).await.unwrap();

        let (port, metrics_port, handle) =
            serve_manual_tls(config, Some(tls_config), root_store).await.unwrap();
        (port, metrics_port, handle, tempdir)
    }

    #[tokio::test]
    async fn self_loop_request_is_rejected() {
        let cert = local_cert_key();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let (port, _metrics_port, _handle, _tempdir) =
            start_service(cert_der.clone(), key_der).await;

        let client = Arc::new(http_agent(cert_der.clone()).unwrap());
        let base_url = format!("https://localhost:{}", port);
        wait_for_service_ready(&base_url, client.clone()).await.unwrap();

        // Make a request through the relay that targets this same instance's directory.
        // The path format is /{gateway_url} where gateway_url points back to ourselves.
        let ohttp_req_url = format!("{}/{}", base_url, base_url);

        let response = client
            .post(&ohttp_req_url)
            .header("Content-Type", "message/ohttp-req")
            .body(vec![0u8; 100])
            .send()
            .await
            .expect("request should complete");

        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "self-loop request should be rejected with 403 Forbidden"
        );
    }

    #[tokio::test]
    async fn cross_instance_request_is_accepted() {
        let cert = local_cert_key();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let (relay_port, _relay_metrics, _relay_handle, _relay_tempdir) =
            start_service(cert_der.clone(), key_der.clone()).await;
        let (directory_port, _directory_metrics, _directory_handle, _directory_tempdir) =
            start_service(cert_der.clone(), key_der).await;

        let client = Arc::new(http_agent(cert_der).unwrap());
        let relay_url = format!("https://localhost:{}", relay_port);
        let directory_url = format!("https://localhost:{}", directory_port);

        wait_for_service_ready(&relay_url, client.clone()).await.unwrap();
        wait_for_service_ready(&directory_url, client.clone()).await.unwrap();

        // Make a request through the relay instance to the directory instance.
        // Since they're different instances with different sentinel tags, this should work.
        let ohttp_req_url = format!("{}/{}", relay_url, directory_url);

        let response = client
            .post(&ohttp_req_url)
            .header("Content-Type", "message/ohttp-req")
            .body(vec![0u8; 100])
            .send()
            .await
            .expect("request should complete");

        // The request may fail for other reasons (invalid OHTTP body), but not due to self-loop.
        assert_ne!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "cross-instance request should not be rejected as forbidden"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_works() {
        let cert = local_cert_key();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let (port, metrics_port, _handle, _tempdir) =
            start_service(cert_der.clone(), key_der).await;

        let client = Arc::new(http_agent(cert_der).unwrap());
        let base_url = format!("https://localhost:{}", port);
        wait_for_service_ready(&base_url, client.clone()).await.unwrap();

        let metrics_url = format!("http://localhost:{}/metrics", metrics_port);
        let http_client = reqwest::Client::new();
        let response =
            http_client.get(&metrics_url).send().await.expect("metrics request should work");

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(body.contains("http_request_total"));
        assert!(body.contains("active_connections"));
    }
}

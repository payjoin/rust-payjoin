#[cfg(feature = "access-control")]
use axum::extract::connect_info::Connected;
use axum::extract::State;
use axum::http::Method;
use axum::response::{IntoResponse, Response};
#[cfg(feature = "access-control")]
use axum::serve::IncomingStream;
use axum::Router;
use config::Config;
use ohttp_relay::SentinelTag;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use rand::Rng;
use tokio_listener::{Listener, SystemOptions, UserOptions};
use tower::{Service, ServiceBuilder};
use tracing::info;

#[cfg(feature = "access-control")]
pub mod access_control;
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
    metrics: MetricsService,
    #[cfg(feature = "access-control")]
    access_control: Option<std::sync::Arc<access_control::AccessControl>>,
}

pub async fn serve(config: Config, meter_provider: Option<SdkMeterProvider>) -> anyhow::Result<()> {
    let sentinel_tag = generate_sentinel_tag();

    #[cfg(feature = "access-control")]
    let access_control = init_access_control(&config).await?;
    #[cfg(feature = "access-control")]
    let blocked_addresses = init_blocked_addresses(&config)?;
    #[cfg(not(feature = "access-control"))]
    let blocked_addresses = None;

    let services = Services {
        directory: init_directory(&config, sentinel_tag, blocked_addresses, false).await?,
        relay: ohttp_relay::Service::new(sentinel_tag).await,
        metrics: MetricsService::new(meter_provider),
        #[cfg(feature = "access-control")]
        access_control,
    };

    let app = build_app(services);
    #[cfg(feature = "access-control")]
    let app = app.into_make_service_with_connect_info::<middleware::MaybePeerIp>();

    let listener =
        Listener::bind(&config.listener, &SystemOptions::default(), &UserOptions::default())
            .await?;
    info!("Payjoin service listening on {:?}", listener.local_addr());
    axum::serve(listener, app).await?;

    Ok(())
}

/// Serves payjoin-mailroom with manual TLS configuration.
///
/// Binds to `config.listener` (use port 0 to let the OS assign a free port) and returns
/// the actual bound port and a task handle.
///
/// If `tls_config` is provided, the server will use TLS for incoming connections.
/// The `root_store` is used for outgoing relay connections to the gateway.
#[cfg(feature = "_manual-tls")]
pub async fn serve_manual_tls(
    config: Config,
    tls_config: Option<axum_server::tls_rustls::RustlsConfig>,
    root_store: rustls::RootCertStore,
) -> anyhow::Result<(u16, tokio::task::JoinHandle<anyhow::Result<()>>)> {
    use std::net::SocketAddr;

    let sentinel_tag = generate_sentinel_tag();

    #[cfg(feature = "access-control")]
    let blocked_addresses = init_blocked_addresses(&config)?;
    #[cfg(not(feature = "access-control"))]
    let blocked_addresses = None;

    let services = Services {
        directory: init_directory(&config, sentinel_tag, blocked_addresses, false).await?,
        relay: ohttp_relay::Service::new_with_roots(root_store, sentinel_tag).await,
        metrics: MetricsService::new(None),
        #[cfg(feature = "access-control")]
        access_control: init_access_control(&config).await?,
    };
    let app = build_app(services);

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
                    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                    .map_err(Into::into)
            })
        }
        None => {
            info!("Payjoin service listening on port {} without TLS", port);
            tokio::spawn(async move {
                axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                    .map_err(Into::into)
            })
        }
    };

    Ok((port, handle))
}

/// Serves payjoin-mailroom with ACME-managed TLS certificates.
///
/// Uses `tokio-rustls-acme` to automatically obtain and renew TLS
/// certificates from Let's Encrypt via the TLS-ALPN-01 challenge.
#[cfg(feature = "acme")]
pub async fn serve_acme(
    config: Config,
    meter_provider: Option<SdkMeterProvider>,
) -> anyhow::Result<()> {
    use std::net::SocketAddr;
    use std::sync::Arc;

    let acme_config = config
        .acme
        .clone()
        .ok_or_else(|| anyhow::anyhow!("ACME configuration is required for serve_acme"))?;

    let sentinel_tag = generate_sentinel_tag();

    #[cfg(feature = "access-control")]
    let blocked_addresses = init_blocked_addresses(&config)?;
    #[cfg(not(feature = "access-control"))]
    let blocked_addresses = None;

    let services = Services {
        directory: init_directory(&config, sentinel_tag, blocked_addresses, false).await?,
        relay: ohttp_relay::Service::new(sentinel_tag).await,
        metrics: MetricsService::new(meter_provider),
        #[cfg(feature = "access-control")]
        access_control: init_access_control(&config).await?,
    };
    let app = build_app(services);

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
    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

/// Generate random sentinel tag at startup.
/// The relay and directory share this tag in a best-effort attempt
/// at detecting self loops.
fn generate_sentinel_tag() -> SentinelTag { SentinelTag::new(rand::thread_rng().gen()) }

#[cfg(feature = "access-control")]
impl Connected<IncomingStream<'_, Listener>> for middleware::MaybePeerIp {
    fn connect_info(stream: IncomingStream<'_, Listener>) -> Self {
        let ip = match stream.remote_addr() {
            tokio_listener::SomeSocketAddr::Tcp(addr) => Some(addr.ip()),
            _ => None,
        };
        Self(ip)
    }
}

async fn init_directory(
    config: &Config,
    sentinel_tag: SentinelTag,
    blocked_addresses: Option<
        std::sync::Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>,
    >,
    v1_disabled: bool,
) -> anyhow::Result<payjoin_directory::Service<payjoin_directory::FilesDb>> {
    let db = payjoin_directory::FilesDb::init(config.timeout, config.storage_dir.clone()).await?;
    db.spawn_background_prune().await;

    let ohttp_keys_dir = config.storage_dir.join("ohttp-keys");
    let ohttp_config = init_ohttp_config(&ohttp_keys_dir)?;

    Ok(payjoin_directory::Service::new(
        db,
        ohttp_config.into(),
        sentinel_tag,
        blocked_addresses,
        v1_disabled,
    ))
}

#[cfg(feature = "access-control")]
async fn init_access_control(
    config: &Config,
) -> anyhow::Result<Option<std::sync::Arc<access_control::AccessControl>>> {
    match &config.access_control {
        Some(ac_config) => {
            let ac =
                access_control::AccessControl::from_config(ac_config, &config.storage_dir).await?;
            info!("Access control enabled");
            Ok(Some(std::sync::Arc::new(ac)))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "access-control")]
fn init_blocked_addresses(
    config: &Config,
) -> anyhow::Result<Option<std::sync::Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>>>
{
    if let Some(ac_config) = &config.access_control {
        if let Some(path) = &ac_config.blocked_addresses_path {
            let addresses = access_control::load_blocked_addresses(path)?;
            info!("Loaded {} blocked addresses from {}", addresses.len(), path.display());
            return Ok(Some(std::sync::Arc::new(tokio::sync::RwLock::new(addresses))));
        }
    }
    Ok(None)
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

fn build_app(services: Services) -> Router {
    let metrics = services.metrics.clone();

    #[cfg(feature = "access-control")]
    let acaccess_control = services.access_control.clone();

    #[allow(unused_mut)]
    let mut router = Router::new()
        .fallback(route_request)
        .layer(
            ServiceBuilder::new()
                .layer(axum::middleware::from_fn_with_state(metrics.clone(), track_metrics))
                .layer(axum::middleware::from_fn_with_state(metrics, track_connections)),
        )
        .with_state(services);

    #[cfg(feature = "access-control")]
    {
        router = router
            .layer(axum::middleware::from_fn(middleware::check_access_control))
            .layer(axum::Extension(acaccess_control));
    }

    router
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum_server::tls_rustls::RustlsConfig;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use payjoin_test_utils::{http_agent, local_cert_key, wait_for_service_ready};
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;
    use tempfile::tempdir;

    use super::*;
    use crate::metrics::{ACTIVE_CONNECTIONS, HTTP_REQUESTS, TOTAL_CONNECTIONS};

    async fn start_service(
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> (u16, tokio::task::JoinHandle<anyhow::Result<()>>, tempfile::TempDir) {
        let tempdir = tempdir().unwrap();
        let config = Config::new(
            "[::]:0".parse().expect("valid listener address"),
            tempdir.path().to_path_buf(),
            Duration::from_secs(2),
        );

        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der.clone())).unwrap();
        let tls_config = RustlsConfig::from_der(vec![cert_der], key_der).await.unwrap();

        let (port, handle) = serve_manual_tls(config, Some(tls_config), root_store).await.unwrap();
        (port, handle, tempdir)
    }

    #[tokio::test]
    async fn self_loop_request_is_rejected() {
        let cert = local_cert_key();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let (port, _handle, _tempdir) = start_service(cert_der.clone(), key_der).await;

        let client = Arc::new(http_agent(cert_der.clone()).unwrap());
        let base_url = format!("https://localhost:{}", port);
        wait_for_service_ready(&base_url, client.clone()).await.unwrap();

        // Make a request through the relay that targets this same instance's directory.
        // The path format is /{gateway_url} where gateway_url points back to ourselves.
        let ohttp_req_url = format!("{base_url}/{base_url}");

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

        let (relay_port, _relay_handle, _relay_tempdir) =
            start_service(cert_der.clone(), key_der.clone()).await;
        let (directory_port, _directory_handle, _directory_tempdir) =
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
    async fn middleware_records_metrics() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();

        let tempdir = tempdir().unwrap();
        let config = Config::new(
            "[::]:0".parse().expect("valid listener address"),
            tempdir.path().to_path_buf(),
            Duration::from_secs(2),
        );

        let sentinel_tag = generate_sentinel_tag();
        let services = Services {
            directory: init_directory(&config, sentinel_tag, None, false).await.unwrap(),
            relay: ohttp_relay::Service::new(sentinel_tag).await,
            metrics: MetricsService::new(Some(provider.clone())),
            #[cfg(feature = "access-control")]
            access_control: None,
        };

        let app = build_app(services);

        let request = Request::builder().method("GET").uri("/health").body(Body::empty()).unwrap();
        let response = ServiceExt::<Request<Body>>::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), 200);

        provider.force_flush().expect("flush failed");

        let finished = exporter.get_finished_metrics().expect("metrics");
        let metric_names: Vec<&str> = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .map(|m| m.name())
            .collect();
        assert!(metric_names.contains(&HTTP_REQUESTS), "missing http_request_total");
        assert!(metric_names.contains(&TOTAL_CONNECTIONS), "missing total_connections");
        assert!(metric_names.contains(&ACTIVE_CONNECTIONS), "missing active_connections");
    }
}

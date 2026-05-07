#[cfg(feature = "access-control")]
use axum::extract::connect_info::Connected;
use axum::extract::State;
use axum::http::Method;
use axum::response::{IntoResponse, Response};
#[cfg(feature = "access-control")]
use axum::serve::IncomingStream;
use axum::Router;
use config::Config;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use rand::Rng;
use tokio_listener::{Listener, SystemOptions, UserOptions};
use tower::{Service, ServiceBuilder};
use tracing::info;

use crate::ohttp_relay::SentinelTag;

#[cfg(feature = "access-control")]
pub mod access_control;
pub mod cli;
pub mod config;
pub mod db;
pub mod directory;
pub mod key_config;
pub mod metrics;
pub mod middleware;
pub mod ohttp_relay;

use crate::metrics::MetricsService;
use crate::middleware::{track_connections, track_metrics};

type DirectoryService =
    crate::directory::Service<crate::db::MetricsDb<crate::db::DbServiceAdapter>>;

#[derive(Clone)]
struct Services {
    directory: DirectoryService,
    relay: crate::ohttp_relay::Service,
    metrics: MetricsService,
    #[cfg(feature = "access-control")]
    geoip: Option<std::sync::Arc<access_control::IpFilter>>,
}

pub async fn serve(config: Config, meter_provider: Option<SdkMeterProvider>) -> anyhow::Result<()> {
    let sentinel_tag = generate_sentinel_tag();
    let metrics = MetricsService::new(meter_provider);

    #[cfg(feature = "access-control")]
    let geoip = init_geoip(&config).await?;

    let directory = init_directory(&config, sentinel_tag, &metrics).await?;

    let services = Services {
        directory,
        relay: crate::ohttp_relay::Service::new(sentinel_tag).await,
        metrics,
        #[cfg(feature = "access-control")]
        geoip,
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
    default_gateway: Option<crate::ohttp_relay::GatewayUri>,
) -> anyhow::Result<(u16, tokio::task::JoinHandle<anyhow::Result<()>>)> {
    use std::net::SocketAddr;

    let sentinel_tag = generate_sentinel_tag();
    let metrics = MetricsService::new(None);

    #[cfg(feature = "access-control")]
    let geoip = init_geoip(&config).await?;

    let directory = init_directory(&config, sentinel_tag, &metrics).await?;

    let services = Services {
        directory,
        relay: crate::ohttp_relay::Service::new_with_roots(
            sentinel_tag,
            root_store,
            default_gateway,
        )
        .await,
        metrics,
        #[cfg(feature = "access-control")]
        geoip,
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
    let metrics = MetricsService::new(meter_provider);

    #[cfg(feature = "access-control")]
    let geoip = init_geoip(&config).await?;

    let directory = init_directory(&config, sentinel_tag, &metrics).await?;

    let services = Services {
        directory,
        relay: crate::ohttp_relay::Service::new(sentinel_tag).await,
        metrics,
        #[cfg(feature = "access-control")]
        geoip,
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
    metrics: &MetricsService,
) -> anyhow::Result<DirectoryService> {
    let files_db =
        crate::db::FilesDb::init(config.timeout, config.storage_dir.clone(), config.mailbox_ttl)
            .await?;
    files_db.spawn_background_prune().await;
    let db = crate::db::MetricsDb::new(crate::db::DbServiceAdapter::new(files_db), metrics.clone());

    let ohttp_keys_dir = config.storage_dir.join("ohttp-keys");
    let keyset = init_ohttp_keyset(&ohttp_keys_dir, config.ohttp_keys_max_age).await?;

    let v1 = if config.v1.is_some() {
        #[cfg(feature = "access-control")]
        let blocked = init_blocked_addresses(config).await?;
        #[cfg(not(feature = "access-control"))]
        let blocked = None;
        Some(crate::directory::V1::new(blocked))
    } else {
        None
    };
    let service =
        crate::directory::Service::new(db, keyset, config.ohttp_keys_max_age, sentinel_tag, v1);

    if let Some(max_age) = config.ohttp_keys_max_age {
        crate::directory::spawn_key_rotation(
            service.ohttp_key_set().clone(),
            ohttp_keys_dir,
            max_age,
        );
        info!("OHTTP key rotation enabled: interval={}s", max_age.as_secs());
    }

    Ok(service)
}

#[cfg(feature = "access-control")]
async fn init_geoip(
    config: &Config,
) -> anyhow::Result<Option<std::sync::Arc<access_control::IpFilter>>> {
    match &config.access_control {
        Some(ac_config) => {
            let gi = access_control::IpFilter::from_config(ac_config, &config.storage_dir).await?;
            info!("GeoIP access control enabled");
            Ok(Some(std::sync::Arc::new(gi)))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "access-control")]
async fn init_blocked_addresses(
    config: &Config,
) -> anyhow::Result<Option<crate::directory::BlockedAddresses>> {
    let v1_config = match &config.v1 {
        Some(c) => c,
        None => return Ok(None),
    };

    // Neither file nor URL configured
    if v1_config.blocked_addresses_path.is_none() && v1_config.blocked_addresses_url.is_none() {
        return Ok(None);
    }

    // Load initial addresses from file if available
    let blocked = match &v1_config.blocked_addresses_path {
        Some(path) => {
            let text = access_control::load_blocked_address_text(path)?;
            let ba = crate::directory::BlockedAddresses::from_address_lines(&text);
            info!("Loaded blocked addresses from {}", path.display());
            ba
        }
        None => crate::directory::BlockedAddresses::empty(),
    };

    // If URL configured, try initial fetch and spawn background updater
    if let Some(url) = &v1_config.blocked_addresses_url {
        let cache_path = config.storage_dir.join("blocked_addresses_cache.txt");
        let refresh = std::time::Duration::from_secs(
            v1_config.blocked_addresses_refresh_secs.unwrap_or(86400),
        );

        // Try initial fetch; fall back to cache on failure
        match reqwest::get(url).await.and_then(|r| r.error_for_status()) {
            Ok(resp) => match resp.text().await {
                Ok(body) => {
                    if let Err(e) = std::fs::write(&cache_path, &body) {
                        tracing::warn!("Failed to write address cache: {e}");
                    }
                    let count = blocked.update_from_lines(&body).await;
                    info!("Fetched {count} blocked addresses from URL");
                }
                Err(e) => {
                    tracing::warn!("Failed to read address list response: {e}");
                    load_address_cache(&cache_path, &blocked).await;
                }
            },
            Err(e) => {
                tracing::warn!("Failed to fetch address list: {e}");
                load_address_cache(&cache_path, &blocked).await;
            }
        }

        access_control::spawn_address_list_updater(
            url.clone(),
            refresh,
            cache_path,
            blocked.clone(),
        );
    }

    Ok(Some(blocked))
}

#[cfg(feature = "access-control")]
async fn load_address_cache(
    cache_path: &std::path::Path,
    blocked: &crate::directory::BlockedAddresses,
) {
    if cache_path.exists() {
        match access_control::load_blocked_address_text(cache_path) {
            Ok(text) => {
                let count = blocked.update_from_lines(&text).await;
                info!("Loaded {count} blocked addresses from cache");
            }
            Err(e) => tracing::warn!("Failed to load address cache: {e}"),
        }
    }
}

async fn init_ohttp_keyset(
    ohttp_keys_dir: &std::path::Path,
    interval: Option<std::time::Duration>,
) -> anyhow::Result<std::sync::Arc<crate::directory::KeyRotatingServer>> {
    tokio::fs::create_dir_all(ohttp_keys_dir).await?;

    // Ensure both key files exist, generating any that are missing.
    for key_id in [0u8, 1] {
        let path = crate::key_config::key_path_for_id(ohttp_keys_dir, key_id);
        if !path.exists() {
            let config = crate::key_config::gen_ohttp_server_config_with_id(key_id)?;
            crate::key_config::persist_key_config(&config, ohttp_keys_dir).await?;
            info!("Generated missing OHTTP key_id {key_id}");
        }
    }

    // Read both keys with their mtimes.
    let sys_now = std::time::SystemTime::now();
    let mut candidates: Vec<(crate::key_config::ServerKeyConfig, std::time::Duration)> =
        Vec::with_capacity(2);

    for key_id in [0u8, 1] {
        let path = crate::key_config::key_path_for_id(ohttp_keys_dir, key_id);
        let mtime = std::fs::metadata(&path)?.modified()?;
        let age = sys_now.duration_since(mtime).expect("mtime is in the future");
        let config = crate::key_config::read_server_config_for_id(ohttp_keys_dir, key_id)?;
        candidates.push((config, age));
    }

    // Oldest mtime (largest age) first — the active key is always the older one.
    candidates.sort_by_key(|(_, age)| std::cmp::Reverse(*age));

    let now = std::time::Instant::now();
    let (current_key_id, current_age) = if let Some(ivl) = interval {
        // Walk oldest-first, take the first key that hasn't expired.
        match candidates.iter().find(|(_, age)| *age < ivl) {
            Some((cfg, age)) => (cfg.key_id(), *age),
            None => {
                // Both expired — regenerate both and start fresh with key_id=0.
                candidates.clear();
                for key_id in [0u8, 1] {
                    let path = crate::key_config::key_path_for_id(ohttp_keys_dir, key_id);
                    let _ = tokio::fs::remove_file(&path).await;
                    let config = crate::key_config::gen_ohttp_server_config_with_id(key_id)?;
                    crate::key_config::persist_key_config(&config, ohttp_keys_dir).await?;
                    candidates.push((config, std::time::Duration::ZERO));
                    info!("Regenerated expired OHTTP key_id {key_id}");
                }
                (0u8, std::time::Duration::ZERO)
            }
        }
    } else {
        // No interval — oldest key is always current, never expires.
        (candidates[0].0.key_id(), candidates[0].1)
    };

    info!("Active OHTTP key_id={current_key_id}, age={current_age:?}");

    let mut slots: [Option<ohttp::Server>; 2] = [None, None];
    for (cfg, _) in candidates {
        let key_id = cfg.key_id();
        slots[key_id as usize] = Some(cfg.into_server());
    }

    let slot0 = slots[0].take().expect("slot 0 missing after init");
    let slot1 = slots[1].take().expect("slot 1 missing after init");
    let valid_until = match interval {
        Some(ivl) => now + ivl.saturating_sub(current_age),
        None => now + std::time::Duration::from_secs(60 * 60 * 24 * 365 * 10),
    };

    let keyset =
        crate::directory::KeyRotatingServer::new(slot0, slot1, current_key_id, valid_until);
    Ok(std::sync::Arc::new(keyset))
}

fn build_app(services: Services) -> Router {
    let metrics = services.metrics.clone();

    #[cfg(feature = "access-control")]
    let geoip = services.geoip.clone();

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
            .layer(axum::middleware::from_fn(middleware::check_geoip))
            .layer(axum::Extension(geoip));
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
    use std::time::{Duration, SystemTime};

    use axum_server::tls_rustls::RustlsConfig;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use payjoin_test_utils::{http_agent, local_cert_key, wait_for_service_ready};
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;
    use tempfile::tempdir;

    use super::*;
    use crate::metrics::{ACTIVE_CONNECTIONS, HTTP_REQUESTS, TOTAL_CONNECTIONS};

    /// Helper to set the mtime of a key file to a specific SystemTime.
    fn set_mtime(path: &std::path::Path, time: SystemTime) {
        let file = std::fs::File::open(path).expect("open file");
        let times = std::fs::FileTimes::new().set_modified(time);
        file.set_times(times).expect("set mtime");
    }

    /// Helper to create both key files in a directory.
    async fn create_both_keys(dir: &std::path::Path) {
        for key_id in [0u8, 1] {
            let config =
                crate::key_config::gen_ohttp_server_config_with_id(key_id).expect("gen config");
            crate::key_config::persist_key_config(&config, dir).await.expect("persist");
        }
    }

    async fn start_service(
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> (u16, tokio::task::JoinHandle<anyhow::Result<()>>, tempfile::TempDir) {
        let tempdir = tempdir().unwrap();
        let config = Config::new(
            "[::]:0".parse().expect("valid listener address"),
            tempdir.path().to_path_buf(),
            Duration::from_secs(2),
            None,
            None,
        );

        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der.clone())).unwrap();
        let tls_config = RustlsConfig::from_der(vec![cert_der], key_der).await.unwrap();

        let (port, handle) =
            serve_manual_tls(config, Some(tls_config), root_store, None).await.unwrap();
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
            None,
            None,
        );

        let sentinel_tag = generate_sentinel_tag();
        let metrics = MetricsService::new(Some(provider.clone()));
        let services = Services {
            directory: init_directory(&config, sentinel_tag, &metrics).await.unwrap(),
            relay: crate::ohttp_relay::Service::new(sentinel_tag).await,
            metrics,
            #[cfg(feature = "access-control")]
            geoip: None,
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

    #[tokio::test]
    async fn middleware_sanitizes_short_id_in_metrics() {
        use axum::body::Body;
        use axum::http::Request;
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
        use tower::ServiceExt;

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();

        let tempdir = tempdir().unwrap();
        let config = Config::new(
            "[::]:0".parse().expect("valid listener address"),
            tempdir.path().to_path_buf(),
            Duration::from_secs(2),
            None,
            None,
        );

        let sentinel_tag = generate_sentinel_tag();
        let metrics = MetricsService::new(Some(provider.clone()));
        let services = Services {
            directory: init_directory(&config, sentinel_tag, &metrics).await.unwrap(),
            relay: crate::ohttp_relay::Service::new(sentinel_tag).await,
            metrics,
            #[cfg(feature = "access-control")]
            geoip: None,
        };

        let app = build_app(services);

        let short_id = payjoin::directory::ShortId([0u8; 8]).to_string();
        let uri = format!("/{short_id}");
        let request = Request::builder().method("GET").uri(&uri).body(Body::empty()).unwrap();
        let _response = ServiceExt::<Request<Body>>::oneshot(app, request).await.unwrap();

        provider.force_flush().expect("flush failed");

        let finished = exporter.get_finished_metrics().expect("metrics");
        println!("finished: {:?}", finished);
        let endpoint_attrs: Vec<String> = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .filter(|m| m.name() == HTTP_REQUESTS)
            .flat_map(|m| match m.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                    .data_points()
                    .flat_map(|dp| dp.attributes())
                    .filter_map(|kv| {
                        if kv.key.as_str() == "endpoint" {
                            Some(kv.value.to_string())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
                _ => vec![],
            })
            .collect();

        println!("endpoint_attrs: {:?}", endpoint_attrs);

        assert!(
            endpoint_attrs.iter().all(|ep| ep == "/{mailbox}"),
            "short ID must be sanitized in metrics, got: {endpoint_attrs:?}"
        );
        assert!(
            endpoint_attrs.iter().all(|ep| !ep.contains(&short_id)),
            "actual short ID value must not appear in metrics"
        );
    }

    #[tokio::test]
    async fn both_keys_expired_regenerates_and_uses_key_id_0() {
        let dir = tempdir().expect("tempdir");
        let interval = Duration::from_secs(7 * 24 * 3600); // 7 days

        create_both_keys(dir.path()).await;

        // Set both mtimes to 8 days ago — both expired.
        let eight_days_ago = SystemTime::now() - Duration::from_secs(8 * 24 * 3600);
        set_mtime(&crate::key_config::key_path_for_id(dir.path(), 0), eight_days_ago);
        set_mtime(&crate::key_config::key_path_for_id(dir.path(), 1), eight_days_ago);

        let keyset = init_ohttp_keyset(dir.path(), Some(interval)).await.expect("init keyset");

        assert_eq!(keyset.current_key_id().await, 0);
        // valid_until should be ~7 days from now
        let remaining =
            keyset.valid_until().await.saturating_duration_since(std::time::Instant::now());
        assert!(remaining > Duration::from_secs(6 * 24 * 3600), "remaining={remaining:?}");
        assert!(remaining <= interval, "remaining={remaining:?}");
    }

    #[tokio::test]
    async fn one_valid_one_expired_uses_valid_key() {
        let dir = tempdir().expect("tempdir");
        let interval = Duration::from_secs(7 * 24 * 3600);

        create_both_keys(dir.path()).await;

        // key_id=0: 3 days old — valid, should be selected (older mtime).
        // key_id=1: 8 days old — expired.
        // After sort by age descending: key_id=1 (8d) is index 0, key_id=0 (3d) is index 1.
        // key_id=1 is checked first, expired, then key_id=0 is checked, valid — selected.
        let three_days_ago = SystemTime::now() - Duration::from_secs(3 * 24 * 3600);
        let eight_days_ago = SystemTime::now() - Duration::from_secs(8 * 24 * 3600);
        set_mtime(&crate::key_config::key_path_for_id(dir.path(), 0), three_days_ago);
        set_mtime(&crate::key_config::key_path_for_id(dir.path(), 1), eight_days_ago);

        let keyset = init_ohttp_keyset(dir.path(), Some(interval)).await.expect("init keyset");

        assert_eq!(keyset.current_key_id().await, 0);
        // ~4 days remaining
        let remaining =
            keyset.valid_until().await.saturating_duration_since(std::time::Instant::now());
        assert!(remaining > Duration::from_secs(3 * 24 * 3600), "remaining={remaining:?}");
        assert!(remaining < interval, "remaining={remaining:?}");
    }

    #[tokio::test]
    async fn two_valid_keys_uses_older_mtime() {
        let dir = tempdir().expect("tempdir");
        let interval = Duration::from_secs(7 * 24 * 3600);

        create_both_keys(dir.path()).await;

        // key_id=0: 5 days old — valid, older mtime -> should be selected as active.
        // key_id=1: 1 day old  — valid, newer mtime -> standby.
        let five_days_ago = SystemTime::now() - Duration::from_secs(5 * 24 * 3600);
        let one_day_ago = SystemTime::now() - Duration::from_secs(24 * 3600);
        set_mtime(&crate::key_config::key_path_for_id(dir.path(), 0), five_days_ago);
        set_mtime(&crate::key_config::key_path_for_id(dir.path(), 1), one_day_ago);

        let keyset = init_ohttp_keyset(dir.path(), Some(interval)).await.expect("init keyset");

        assert_eq!(keyset.current_key_id().await, 0);
        // ~2 days remaining
        let remaining =
            keyset.valid_until().await.saturating_duration_since(std::time::Instant::now());
        assert!(remaining > Duration::from_secs(24 * 3600), "remaining={remaining:?}");
        assert!(remaining < Duration::from_secs(3 * 24 * 3600), "remaining={remaining:?}");
    }

    #[tokio::test]
    async fn no_interval_uses_oldest_key_never_expires() {
        let dir = tempdir().expect("tempdir");

        create_both_keys(dir.path()).await;

        let five_days_ago = SystemTime::now() - Duration::from_secs(5 * 24 * 3600);
        let one_day_ago = SystemTime::now() - Duration::from_secs(24 * 3600);
        set_mtime(&crate::key_config::key_path_for_id(dir.path(), 0), five_days_ago);
        set_mtime(&crate::key_config::key_path_for_id(dir.path(), 1), one_day_ago);

        let keyset = init_ohttp_keyset(dir.path(), None).await.expect("init keyset");

        assert_eq!(keyset.current_key_id().await, 0);
        // valid_until should be ~10 years out
        let remaining =
            keyset.valid_until().await.saturating_duration_since(std::time::Instant::now());
        assert!(remaining > Duration::from_secs(365 * 24 * 3600), "should be far future");
    }

    #[tokio::test]
    async fn missing_keys_are_generated_on_init() {
        let dir = tempdir().expect("tempdir");
        let interval = Duration::from_secs(7 * 24 * 3600);

        // Don't create any keys — init should generate them.
        let keyset = init_ohttp_keyset(dir.path(), Some(interval)).await.expect("init keyset");

        assert_eq!(keyset.current_key_id().await, 0);
        let remaining =
            keyset.valid_until().await.saturating_duration_since(std::time::Instant::now());
        assert!(remaining > Duration::from_secs(6 * 24 * 3600), "remaining={remaining:?}");
    }
}

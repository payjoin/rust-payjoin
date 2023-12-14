use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use bitcoin::{self, base64};
use hyper::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use hyper::server::conn::AddrIncoming;
use hyper::server::Builder;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode, Uri};
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

const DEFAULT_RELAY_PORT: &str = "8080";
const DEFAULT_DB_HOST: &str = "redis://127.0.0.1/";
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_BUFFER_SIZE: usize = 65536;
const V1_REJECT_RES_JSON: &str =
    r#"{{"errorCode": "original-psbt-rejected ", "message": "Body is not a string"}}"#;
const V1_UNAVAILABLE_RES_JSON: &str = r#"{{"errorCode": "unavailable", "message": "V2 receiver offline. V1 sends require synchronous communications."}}"#;

mod db;
use crate::db::DbPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let relay_port = env::var("PJ_RELAY_PORT").unwrap_or_else(|_| DEFAULT_RELAY_PORT.to_string());
    let timeout_secs = env::var("PJ_RELAY_TIMEOUT_SECS")
        .map(|s| s.parse().expect("Invalid timeout"))
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let db_host = env::var("PJ_DB_HOST").unwrap_or_else(|_| DEFAULT_DB_HOST.to_string());
    let ohttp = Arc::new(Mutex::new(init_ohttp()?));
    let pool = Arc::new(Mutex::new(DbPool::new(db_host)?));
    let make_svc = make_service_fn(|_| {
        let pool = pool.clone();
        let ohttp = ohttp.clone();
        async move {
            let handler = move |req| handle_ohttp_gateway(req, pool.clone(), ohttp.clone());
            Ok::<_, hyper::Error>(service_fn(handler))
        }
    });

    // Parse the bind address using the provided port
    let bind_addr_str = format!("0.0.0.0:{}", relay_port);
    let bind_addr: SocketAddr = bind_addr_str.parse()?;
    let server = init_server(&bind_addr)?.serve(make_svc);
    info!("Serverless payjoin relay awaiting HTTP connection at {}", bind_addr_str);
    Ok(server.await?)
}

fn init_logging() {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();

    println!("Logging initialized");
}

#[cfg(not(feature = "danger-local-https"))]
fn init_server(bind_addr: &SocketAddr) -> Result<Builder<AddrIncoming>> {
    Ok(Server::bind(bind_addr))
}

#[cfg(feature = "danger-local-https")]
fn init_server(bind_addr: &SocketAddr) -> Result<Builder<hyper_rustls::TlsAcceptor>> {
    const LOCAL_CERT_FILE: &str = "localhost.der";

    use std::io::Write;

    use rustls::{Certificate, PrivateKey};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.serialize_der()?;
    let mut local_cert_path = std::env::temp_dir();
    local_cert_path.push(LOCAL_CERT_FILE);
    println!("RELAY CERT PATH {:?}", &local_cert_path);
    let mut file = std::fs::File::create(local_cert_path)?;
    file.write_all(&cert_der)?;
    let key = PrivateKey(cert.serialize_private_key_der());
    let certs = vec![Certificate(cert.serialize_der()?)];
    let incoming = AddrIncoming::bind(bind_addr)?;
    let acceptor = hyper_rustls::TlsAcceptor::builder()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?
        .with_all_versions_alpn()
        .with_incoming(incoming);
    Ok(Server::builder(acceptor))
}

fn init_ohttp() -> Result<ohttp::Server> {
    use ohttp::hpke::{Aead, Kdf, Kem};
    use ohttp::{KeyId, SymmetricSuite};

    const KEY_ID: KeyId = 1;
    const KEM: Kem = Kem::X25519Sha256;
    const SYMMETRIC: &[SymmetricSuite] =
        &[SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

    // create or read from file
    let server_config = ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC))?;
    let encoded_config = server_config.encode()?;
    let b64_config = base64::encode_config(
        encoded_config,
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
    );
    info!("ohttp-keys server config base64 UrlSafe: {:?}", b64_config);
    Ok(ohttp::Server::new(server_config)?)
}

async fn handle_ohttp_gateway(
    req: Request<Body>,
    pool: Arc<Mutex<DbPool>>,
    ohttp: Arc<Mutex<ohttp::Server>>,
) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or_default().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    debug!("handle_ohttp_gateway: {:?}", &path_segments);
    let mut response = match (parts.method, path_segments.as_slice()) {
        (Method::POST, ["", ""]) => handle_ohttp(body, pool, ohttp).await,
        (Method::GET, ["", "ohttp-keys"]) => get_ohttp_keys(&ohttp).await,
        (Method::POST, ["", id]) => post_fallback_v1(id, query, body, pool).await,
        _ => Ok(not_found()),
    }
    .unwrap_or_else(|e| e.to_response());

    // Allow CORS for third-party access
    response.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));

    Ok(response)
}

async fn handle_ohttp(
    body: Body,
    pool: Arc<Mutex<DbPool>>,
    ohttp: Arc<Mutex<ohttp::Server>>,
) -> Result<Response<Body>, HandlerError> {
    // decapsulate
    let ohttp_body =
        hyper::body::to_bytes(body).await.map_err(|e| HandlerError::BadRequest(e.into()))?;
    let mut ohttp_locked = ohttp.lock().await;
    let (bhttp_req, res_ctx) = ohttp_locked
        .decapsulate(&ohttp_body)
        .map_err(|e| HandlerError::OhttpKeyRejection(e.into()))?;
    drop(ohttp_locked);
    let mut cursor = std::io::Cursor::new(bhttp_req);
    let req =
        bhttp::Message::read_bhttp(&mut cursor).map_err(|e| HandlerError::BadRequest(e.into()))?;
    let uri = Uri::builder()
        .scheme(req.control().scheme().unwrap_or_default())
        .authority(req.control().authority().unwrap_or_default())
        .path_and_query(req.control().path().unwrap_or_default())
        .build()?;
    let body = req.content().to_vec();
    let mut http_req =
        Request::builder().uri(uri).method(req.control().method().unwrap_or_default());
    for header in req.header().fields() {
        http_req = http_req.header(header.name(), header.value())
    }
    let request = http_req.body(Body::from(body))?;

    let response = handle_v2(pool, request).await?;

    let (parts, body) = response.into_parts();
    let mut bhttp_res = bhttp::Message::response(parts.status.as_u16());
    let full_body = hyper::body::to_bytes(body)
        .await
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    bhttp_res.write_content(&full_body);
    let mut bhttp_bytes = Vec::new();
    bhttp_res
        .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes)
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    let ohttp_res = res_ctx
        .encapsulate(&bhttp_bytes)
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    Ok(Response::new(Body::from(ohttp_res)))
}

async fn handle_v2(
    pool: Arc<Mutex<DbPool>>,
    req: Request<Body>,
) -> Result<Response<Body>, HandlerError> {
    let path = req.uri().path().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    debug!("handle_v2: {:?}", &path_segments);
    match (parts.method, path_segments.as_slice()) {
        (Method::POST, &["", ""]) => post_enroll(body).await,
        (Method::POST, &["", id]) => post_fallback_v2(id, body, pool).await,
        (Method::GET, &["", id]) => get_fallback(id, pool).await,
        (Method::POST, &["", id, "payjoin"]) => post_payjoin(id, body, pool).await,
        _ => Ok(not_found()),
    }
}

enum HandlerError {
    PayloadTooLarge,
    InternalServerError(anyhow::Error),
    OhttpKeyRejection(anyhow::Error),
    BadRequest(anyhow::Error),
}

impl HandlerError {
    fn to_response(&self) -> Response<Body> {
        let mut res = Response::default();
        match self {
            HandlerError::PayloadTooLarge => *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE,
            HandlerError::InternalServerError(e) => {
                error!("Internal server error: {}", e);
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR
            }
            HandlerError::OhttpKeyRejection(e) => {
                const OHTTP_KEY_REJECTION_RES_JSON: &str = r#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key", "title": "key identifier unknown"}"#;

                error!("Bad request: Key configuration rejected: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST;
                res.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
                *res.body_mut() = Body::from(OHTTP_KEY_REJECTION_RES_JSON);
            }
            HandlerError::BadRequest(e) => {
                error!("Bad request: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST
            }
        };

        res
    }
}

impl From<hyper::http::Error> for HandlerError {
    fn from(e: hyper::http::Error) -> Self { HandlerError::InternalServerError(e.into()) }
}

async fn post_enroll(body: Body) -> Result<Response<Body>, HandlerError> {
    let b64_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
    let bytes =
        hyper::body::to_bytes(body).await.map_err(|e| HandlerError::BadRequest(e.into()))?;
    let base64_id =
        String::from_utf8(bytes.to_vec()).map_err(|e| HandlerError::BadRequest(e.into()))?;
    let pubkey_bytes: Vec<u8> = base64::decode_config(base64_id, b64_config)
        .map_err(|e| HandlerError::BadRequest(e.into()))?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| HandlerError::BadRequest(e.into()))?;
    tracing::info!("Enrolled valid pubkey: {:?}", pubkey);
    Ok(Response::builder().status(StatusCode::NO_CONTENT).body(Body::empty())?)
}

async fn post_fallback_v1(
    id: &str,
    query: String,
    body: Body,
    pool: Arc<Mutex<DbPool>>,
) -> Result<Response<Body>, HandlerError> {
    trace!("Post fallback v1");
    let none_response = Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(Body::from(V1_UNAVAILABLE_RES_JSON))?;
    let bad_request_body_res =
        Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from(V1_REJECT_RES_JSON))?;

    let body_bytes = match hyper::body::to_bytes(body).await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => return Ok(bad_request_body_res),
    };

    let body_str = match String::from_utf8(body_bytes) {
        Ok(body_str) => body_str,
        Err(_) => return Ok(bad_request_body_res),
    };

    let v2_compat_body = Body::from(format!("{}\n{}", body_str, query));
    post_fallback(id, v2_compat_body, pool, none_response).await
}

async fn post_fallback_v2(
    id: &str,
    body: Body,
    pool: Arc<Mutex<DbPool>>,
) -> Result<Response<Body>, HandlerError> {
    trace!("Post fallback v2");
    let none_response = Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?;
    post_fallback(id, body, pool, none_response).await
}

async fn post_fallback(
    id: &str,
    body: Body,
    pool: Arc<Mutex<DbPool>>,
    none_response: Response<Body>,
) -> Result<Response<Body>, HandlerError> {
    tracing::trace!("Post fallback");
    let id = shorten_string(id);
    let req = hyper::body::to_bytes(body)
        .await
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    if req.len() > MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    match pool.lock().await.push_req(&id, req.into()).await {
        Ok(_) => (),
        Err(e) => return Err(HandlerError::BadRequest(e.into())),
    };

    match pool.lock().await.clone().peek_res(&id).await {
        Ok(result) =>
            if result.is_empty() {
                Ok(none_response)
            } else {
                Ok(Response::new(Body::from(result)))
            },
        Err(_) => Ok(none_response),
    }
}

async fn get_fallback(id: &str, pool: Arc<Mutex<DbPool>>) -> Result<Response<Body>, HandlerError> {
    trace!("GET fallback");
    let id = shorten_string(id);
    match pool.lock().await.clone().peek_req(&id).await {
        Ok(result) => Ok(Response::new(Body::from(result))),
        Err(_) => Ok(Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?),
    }
}

async fn post_payjoin(
    id: &str,
    body: Body,
    pool: Arc<Mutex<DbPool>>,
) -> Result<Response<Body>, HandlerError> {
    trace!("POST payjoin");
    let id = shorten_string(id);
    let res = hyper::body::to_bytes(body)
        .await
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;

    let mut pool = pool.lock().await;
    match pool.push_res(&id, res.into()).await {
        Ok(_) => Ok(Response::builder().status(StatusCode::NO_CONTENT).body(Body::empty())?),
        Err(e) => Err(HandlerError::BadRequest(e.into())),
    }
}

fn not_found() -> Response<Body> {
    let mut res = Response::default();
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

async fn get_ohttp_keys(ohttp: &Arc<Mutex<ohttp::Server>>) -> Result<Response<Body>, HandlerError> {
    let mut res = Response::default();
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/ohttp-keys"));
    let ohttp_keys = ohttp
        .lock()
        .await
        .config()
        .encode()
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    *res.body_mut() = Body::from(ohttp_keys);
    Ok(res)
}

fn shorten_string(input: &str) -> String { input.chars().take(8).collect() }

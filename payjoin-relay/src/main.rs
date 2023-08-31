use std::env;
use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::Result;
use hyper::server::conn::AddrIncoming;
use hyper::server::Builder;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, HeaderMap, Method, Request, Response, Server, StatusCode};
use tracing::{debug, error, info};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

const DEFAULT_RELAY_PORT: &str = "8080";
const DEFAULT_DB_HOST: &str = "localhost:5432";
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_BUFFER_SIZE: usize = 65536;
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

    let pool = DbPool::new(timeout, db_host).await?;
    let make_svc = make_service_fn(|_| {
        let pool = pool.clone();
        async move {
            let handler = move |req| handle_web_req(pool.clone(), req);
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

async fn handle_web_req(pool: DbPool, req: Request<Body>) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    debug!("{:?}", &path_segments);
    let mut response = match (parts.method, path_segments.as_slice()) {
        (Method::POST, &["", ""]) => post_enroll(body).await,
        (Method::POST, &["", id]) => post_fallback(id, body, parts.headers, pool).await,
        (Method::GET, &["", id]) => get_fallback(id, pool).await,
        (Method::POST, &["", id, "payjoin"]) => post_payjoin(id, body, pool).await,
        _ => Ok(not_found()),
    }
    .unwrap_or_else(|e| e.to_response());

    // Allow CORS for third-party access
    response
        .headers_mut()
        .insert("Access-Control-Allow-Origin", hyper::header::HeaderValue::from_static("*"));

    Ok(response)
}

enum HandlerError {
    PayloadTooLarge,
    ReceiverOffline,
    InternalServerError(anyhow::Error),
    BadRequest(anyhow::Error),
}

impl HandlerError {
    fn to_response(&self) -> Response<Body> {
        let (status, body) = match self {
            HandlerError::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, Body::empty()),
            HandlerError::ReceiverOffline =>
                (StatusCode::SERVICE_UNAVAILABLE, Body::from(V1_UNAVAILABLE_RES_JSON)),
            HandlerError::BadRequest(e) => {
                error!("Bad request: {}", e);
                (StatusCode::BAD_REQUEST, Body::empty())
            }
            HandlerError::InternalServerError(e) => {
                error!("Internal server error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Body::empty())
            }
        };

        let mut res = Response::new(body);
        *res.status_mut() = status;
        res
    }
}

impl From<hyper::http::Error> for HandlerError {
    fn from(e: hyper::http::Error) -> Self { HandlerError::InternalServerError(e.into()) }
}

async fn post_enroll(body: Body) -> Result<Response<Body>, HandlerError> {
    use payjoin::{base64, bitcoin};
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

async fn post_fallback(
    id: &str,
    body: Body,
    headers: HeaderMap,
    pool: DbPool,
) -> Result<Response<Body>, HandlerError> {
    use hyper::header::HeaderValue;

    let id = shorten_string(id);
    let is_async = headers.get("Async") == Some(&HeaderValue::from_static("true"));
    let req = hyper::body::to_bytes(body)
        .await
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    if req.len() > MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    match pool.push_req(&id, req.into()).await {
        Ok(_) => (),
        Err(e) => return Err(HandlerError::BadRequest(e.into())),
    };

    match pool.peek_res(&id).await {
        Some(result) => match result {
            Ok(buffered_res) => Ok(Response::new(Body::from(buffered_res))),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        },
        None => fallback_timeout_response(is_async),
    }
}

fn fallback_timeout_response(is_req_async: bool) -> Result<Response<Body>, HandlerError> {
    if is_req_async {
        Ok(Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?)
    } else {
        Err(HandlerError::ReceiverOffline)
    }
}

async fn get_fallback(id: &str, pool: DbPool) -> Result<Response<Body>, HandlerError> {
    let id = shorten_string(id);
    match pool.peek_req(&id).await {
        Some(result) => match result {
            Ok(buffered_req) => Ok(Response::new(Body::from(buffered_req))),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        },
        None => Ok(Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?),
    }
}

async fn post_payjoin(id: &str, body: Body, pool: DbPool) -> Result<Response<Body>, HandlerError> {
    let id = shorten_string(id);
    let res = hyper::body::to_bytes(body)
        .await
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;

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

fn shorten_string(input: &str) -> String { input.chars().take(8).collect() }

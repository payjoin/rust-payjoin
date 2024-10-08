use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bitcoin::base64::prelude::BASE64_URL_SAFE_NO_PAD;
use bitcoin::base64::Engine;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, LOCATION};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace};

pub const DEFAULT_DIR_PORT: u16 = 8080;
pub const DEFAULT_DB_HOST: &str = "localhost:6379";
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_BASE_URL: &str = "https://localhost";

const MAX_BUFFER_SIZE: usize = 65536;

const V1_REJECT_RES_JSON: &str =
    r#"{{"errorCode": "original-psbt-rejected ", "message": "Body is not a string"}}"#;
const V1_UNAVAILABLE_RES_JSON: &str = r#"{{"errorCode": "unavailable", "message": "V2 receiver offline. V1 sends require synchronous communications."}}"#;

mod db;
use crate::db::DbPool;

pub async fn listen_tcp(
    base_url: String,
    port: u16,
    db_host: String,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = DbPool::new(timeout, db_host).await?;
    let ohttp = Arc::new(Mutex::new(init_ohttp()?));
    let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let listener = TcpListener::bind(bind_addr).await?;
    while let Ok((stream, _)) = listener.accept().await {
        let pool = pool.clone();
        let ohttp = ohttp.clone();
        let base_url = base_url.clone();
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        serve_payjoin_directory(req, pool.clone(), ohttp.clone(), base_url.clone())
                    }),
                )
                .with_upgrades()
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }

    Ok(())
}

#[cfg(feature = "danger-local-https")]
pub async fn listen_tcp_with_tls(
    base_url: String,
    port: u16,
    db_host: String,
    timeout: Duration,
    tls_config: (Vec<u8>, Vec<u8>),
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = DbPool::new(timeout, db_host).await?;
    let ohttp = Arc::new(Mutex::new(init_ohttp()?));
    let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let tls_acceptor = init_tls_acceptor(tls_config)?;
    let listener = TcpListener::bind(bind_addr).await?;
    while let Ok((stream, _)) = listener.accept().await {
        let pool = pool.clone();
        let ohttp = ohttp.clone();
        let base_url = base_url.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(e) => {
                    error!("TLS accept error: {}", e);
                    return;
                }
            };
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    TokioIo::new(tls_stream),
                    service_fn(move |req| {
                        serve_payjoin_directory(req, pool.clone(), ohttp.clone(), base_url.clone())
                    }),
                )
                .with_upgrades()
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }

    Ok(())
}

#[cfg(feature = "danger-local-https")]
fn init_tls_acceptor(cert_key: (Vec<u8>, Vec<u8>)) -> Result<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;
    let (cert, key) = cert_key;
    let cert = CertificateDer::from(cert);
    let key =
        PrivateKeyDer::try_from(key).map_err(|e| anyhow::anyhow!("Could not parse key: {}", e))?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn init_ohttp() -> Result<ohttp::Server> {
    use ohttp::hpke::{Aead, Kdf, Kem};
    use ohttp::{KeyId, SymmetricSuite};

    const KEY_ID: KeyId = 1;
    const KEM: Kem = Kem::K256Sha256;
    const SYMMETRIC: &[SymmetricSuite] =
        &[SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

    // create or read from file
    let server_config = ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC))?;
    info!("Initialized a new OHTTP Key Configuration. GET /ohttp-keys to fetch it.");
    Ok(ohttp::Server::new(server_config)?)
}

async fn serve_payjoin_directory(
    req: Request<Incoming>,
    pool: DbPool,
    ohttp: Arc<Mutex<ohttp::Server>>,
    base_url: String,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or_default().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    debug!("serve_payjoin_directory: {:?}", &path_segments);
    let mut response = match (parts.method, path_segments.as_slice()) {
        (Method::POST, ["", ""]) => handle_ohttp_gateway(body, pool, ohttp, base_url).await,
        (Method::GET, ["", "ohttp-keys"]) => get_ohttp_keys(&ohttp).await,
        (Method::POST, ["", id]) => post_fallback_v1(id, query, body, pool).await,
        (Method::GET, ["", "health"]) => health_check().await,
        _ => Ok(not_found()),
    }
    .unwrap_or_else(|e| e.to_response());

    // Allow CORS for third-party access
    response.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));

    Ok(response)
}

async fn handle_ohttp_gateway(
    body: Incoming,
    pool: DbPool,
    ohttp: Arc<Mutex<ohttp::Server>>,
    base_url: String,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    // decapsulate
    let ohttp_body =
        body.collect().await.map_err(|e| HandlerError::BadRequest(e.into()))?.to_bytes();
    let ohttp_locked = ohttp.lock().await;
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
    let request = http_req.body(full(body))?;

    let response = handle_v2(pool, base_url, request).await?;

    let (parts, body) = response.into_parts();
    let mut bhttp_res = bhttp::Message::response(parts.status.as_u16());
    for (name, value) in parts.headers.iter() {
        bhttp_res.put_header(name.as_str(), value.to_str().unwrap_or_default());
    }
    let full_body =
        body.collect().await.map_err(|e| HandlerError::InternalServerError(e.into()))?.to_bytes();
    bhttp_res.write_content(&full_body);
    let mut bhttp_bytes = Vec::new();
    bhttp_res
        .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes)
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    let ohttp_res = res_ctx
        .encapsulate(&bhttp_bytes)
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    Ok(Response::new(full(ohttp_res)))
}

async fn handle_v2(
    pool: DbPool,
    base_url: String,
    req: Request<BoxBody<Bytes, hyper::Error>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    let path = req.uri().path().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    debug!("handle_v2: {:?}", &path_segments);
    match (parts.method, path_segments.as_slice()) {
        (Method::POST, &["", ""]) => post_session(base_url, body).await,
        (Method::POST, &["", id]) => post_fallback_v2(id, body, pool).await,
        (Method::GET, &["", id]) => get_fallback(id, pool).await,
        (Method::PUT, &["", id]) => post_payjoin(id, body, pool).await,
        _ => Ok(not_found()),
    }
}

async fn health_check() -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    Ok(Response::new(empty()))
}

#[derive(Debug)]
enum HandlerError {
    PayloadTooLarge,
    InternalServerError(anyhow::Error),
    OhttpKeyRejection(anyhow::Error),
    BadRequest(anyhow::Error),
}

impl HandlerError {
    fn to_response(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        let mut res = Response::new(empty());
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
                *res.body_mut() = full(OHTTP_KEY_REJECTION_RES_JSON);
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

async fn post_session(
    base_url: String,
    body: BoxBody<Bytes, hyper::Error>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    let bytes = body.collect().await.map_err(|e| HandlerError::BadRequest(e.into()))?.to_bytes();
    let base64_id =
        String::from_utf8(bytes.to_vec()).map_err(|e| HandlerError::BadRequest(e.into()))?;
    let pubkey_bytes: Vec<u8> =
        BASE64_URL_SAFE_NO_PAD.decode(base64_id).map_err(|e| HandlerError::BadRequest(e.into()))?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| HandlerError::BadRequest(e.into()))?;
    tracing::info!("Initialized session with pubkey: {:?}", pubkey);
    Ok(Response::builder()
        .header(LOCATION, format!("{}/{}", base_url, pubkey))
        .status(StatusCode::CREATED)
        .body(empty())?)
}

async fn post_fallback_v1(
    id: &str,
    query: String,
    body: impl Body,
    pool: DbPool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    trace!("Post fallback v1");
    let none_response = Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(full(V1_UNAVAILABLE_RES_JSON))?;
    let bad_request_body_res =
        Response::builder().status(StatusCode::BAD_REQUEST).body(full(V1_REJECT_RES_JSON))?;

    let body_bytes = match body.collect().await {
        Ok(bytes) => bytes.to_bytes(),
        Err(_) => return Ok(bad_request_body_res),
    };

    let body_str = match String::from_utf8(body_bytes.to_vec()) {
        Ok(body_str) => body_str,
        Err(_) => return Ok(bad_request_body_res),
    };

    let v2_compat_body = full(format!("{}\n{}", body_str, query));
    post_fallback(id, v2_compat_body, pool, none_response).await
}

async fn post_fallback_v2(
    id: &str,
    body: BoxBody<Bytes, hyper::Error>,
    pool: DbPool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    trace!("Post fallback v2");
    let none_response = Response::builder().status(StatusCode::ACCEPTED).body(empty())?;
    post_fallback(id, body, pool, none_response).await
}

async fn post_fallback(
    id: &str,
    body: BoxBody<Bytes, hyper::Error>,
    pool: DbPool,
    none_response: Response<BoxBody<Bytes, hyper::Error>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    tracing::trace!("Post fallback");
    let id = shorten_string(id);
    let req =
        body.collect().await.map_err(|e| HandlerError::InternalServerError(e.into()))?.to_bytes();
    if req.len() > MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    match pool.push_req(&id, req.into()).await {
        Ok(_) => (),
        Err(e) => return Err(HandlerError::BadRequest(e.into())),
    };

    match pool.peek_res(&id).await {
        Some(result) => match result {
            Ok(buffered_res) => Ok(Response::new(full(buffered_res))),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        },
        None => Ok(none_response),
    }
}

async fn get_fallback(
    id: &str,
    pool: DbPool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    trace!("GET fallback");
    let id = shorten_string(id);
    match pool.peek_req(&id).await {
        Some(result) => match result {
            Ok(buffered_req) => Ok(Response::new(full(buffered_req))),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        },
        None => Ok(Response::builder().status(StatusCode::ACCEPTED).body(empty())?),
    }
}

async fn post_payjoin(
    id: &str,
    body: BoxBody<Bytes, hyper::Error>,
    pool: DbPool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    trace!("POST payjoin");
    let id = shorten_string(id);
    let res =
        body.collect().await.map_err(|e| HandlerError::InternalServerError(e.into()))?.to_bytes();

    match pool.push_res(&id, res.into()).await {
        Ok(_) => Ok(Response::builder().status(StatusCode::NO_CONTENT).body(empty())?),
        Err(e) => Err(HandlerError::BadRequest(e.into())),
    }
}

fn not_found() -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut res = Response::default();
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

async fn get_ohttp_keys(
    ohttp: &Arc<Mutex<ohttp::Server>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    let ohttp_keys = ohttp
        .lock()
        .await
        .config()
        .encode()
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    let mut res = Response::new(full(ohttp_keys));
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/ohttp-keys"));
    Ok(res)
}

fn shorten_string(input: &str) -> String { input.chars().take(8).collect() }

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

#[cfg(test)]
mod tests {
    use hyper::Request;

    use super::*;

    /// Ensure that the POST / endpoint returns a 201 Created with a Location header
    /// as is semantically correct when creating a resource.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9110#name-post
    #[tokio::test]
    async fn test_post_session() -> Result<(), Box<dyn std::error::Error>> {
        let base_url = "https://localhost".to_string();
        let body = full("A6z245ZfDfnlk7_HiAp6sPmNaVYwADih-vCGE3eysWp7");

        let request = Request::builder().method(Method::POST).uri("/").body(body)?;

        let response = post_session(base_url.clone(), request.into_body())
            .await
            .map_err(|e| format!("{:?}", e))?;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response.headers().contains_key(LOCATION));
        let location_header = response.headers().get(LOCATION).ok_or("Missing LOCATION header")?;
        assert!(location_header.to_str()?.starts_with(&base_url));
        Ok(())
    }
}

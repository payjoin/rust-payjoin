use std::pin::Pin;
use std::str::FromStr;

use anyhow::Result;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use payjoin::directory::{ShortId, ShortIdError, ENCAPSULATED_MESSAGE_BYTES};
use tracing::{debug, error, trace, warn};

pub use crate::db::DbPool;
pub mod key_config;
pub use crate::key_config::*;
use crate::metrics::Metrics;

const CHACHA20_POLY1305_NONCE_LEN: usize = 32; // chacha20poly1305 n_k
const POLY1305_TAG_SIZE: usize = 16;
pub const BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (CHACHA20_POLY1305_NONCE_LEN + POLY1305_TAG_SIZE);
const V1_MAX_BUFFER_SIZE: usize = 65536;

const V1_REJECT_RES_JSON: &str =
    r#"{{"errorCode": "original-psbt-rejected ", "message": "Body is not a string"}}"#;
const V1_UNAVAILABLE_RES_JSON: &str = r#"{{"errorCode": "unavailable", "message": "V2 receiver offline. V1 sends require synchronous communications."}}"#;

mod db;

pub mod cli;
pub mod config;
pub mod metrics;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(feature = "_manual-tls")]
fn init_tls_acceptor(cert_key: (Vec<u8>, Vec<u8>)) -> Result<tokio_rustls::TlsAcceptor> {
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::ServerConfig;
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
    Ok(TlsAcceptor::from(std::sync::Arc::new(server_config)))
}

#[derive(Clone)]
pub struct Service {
    pool: DbPool,
    ohttp: ohttp::Server,
    metrics: Metrics,
}

impl hyper::service::Service<Request<Incoming>> for Service {
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = anyhow::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.serve_request(req).await })
    }
}

impl Service {
    pub fn new(pool: DbPool, ohttp: ohttp::Server, metrics: Metrics) -> Self {
        Self { pool, ohttp, metrics }
    }

    #[cfg(feature = "_manual-tls")]
    pub async fn serve_tls(
        self,
        listener: tokio::net::TcpListener,
        tls_config: (Vec<u8>, Vec<u8>),
    ) -> Result<(), BoxError> {
        let tls_acceptor = init_tls_acceptor(tls_config)?;
        // Spawn the connection handling loop in a separate task

        while let Ok((stream, _)) = listener.accept().await {
            let tls_acceptor = tls_acceptor.clone();
            let service = self.clone();
            tokio::spawn(async move {
                service.metrics.record_connection();
                let tls_stream = match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(e) => {
                        error!("TLS accept error: {}", e);
                        return;
                    }
                };
                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .with_upgrades()
                    .await
                {
                    error!("Error serving connection: {:?}", err);
                }
            });
        }
        Ok(())
    }

    pub async fn serve_tcp(self, listener: tokio::net::TcpListener) -> Result<(), BoxError> {
        while let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let service = self.clone();
            tokio::spawn(async move {
                service.metrics.record_connection();
                if let Err(err) =
                    http1::Builder::new().serve_connection(io, service).with_upgrades().await
                {
                    error!("Error serving connection: {:?}", err);
                }
            });
        }

        Ok(())
    }

    async fn serve_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or_default().to_string();
        let (parts, body) = req.into_parts();

        let path_segments: Vec<&str> = path.split('/').collect();
        debug!("Service::serve_request: {:?}", &path_segments);
        let mut response = match (parts.method, path_segments.as_slice()) {
            (Method::POST, ["", ".well-known", "ohttp-gateway"]) =>
                self.handle_ohttp_gateway(body).await,
            (Method::GET, ["", ".well-known", "ohttp-gateway"]) =>
                self.handle_ohttp_gateway_get(&query).await,
            (Method::POST, ["", ""]) => self.handle_ohttp_gateway(body).await,
            (Method::GET, ["", "ohttp-keys"]) => self.get_ohttp_keys().await,
            (Method::POST, ["", id]) => self.post_fallback_v1(id, query, body).await,
            (Method::GET, ["", "health"]) => health_check().await,
            (Method::GET, ["", ""]) => handle_directory_home_path().await,
            (Method::GET, ["", "metrics"]) => Ok(self.handle_metrics().await),
            _ => Ok(not_found()),
        }
        .unwrap_or_else(|e| e.to_response());

        // Allow CORS for third-party access
        response.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));

        Ok(response)
    }

    async fn handle_ohttp_gateway(
        &self,
        body: Incoming,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
        // decapsulate
        let ohttp_body =
            body.collect().await.map_err(|e| HandlerError::BadRequest(e.into()))?.to_bytes();
        let (bhttp_req, res_ctx) = self
            .ohttp
            .decapsulate(&ohttp_body)
            .map_err(|e| HandlerError::OhttpKeyRejection(e.into()))?;
        let mut cursor = std::io::Cursor::new(bhttp_req);
        let req = bhttp::Message::read_bhttp(&mut cursor)
            .map_err(|e| HandlerError::BadRequest(e.into()))?;
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

        let response = self.handle_v2(request).await?;

        let (parts, body) = response.into_parts();
        let mut bhttp_res = bhttp::Message::response(
            bhttp::StatusCode::try_from(parts.status.as_u16())
                .map_err(|e| HandlerError::InternalServerError(e.into()))?,
        );
        for (name, value) in parts.headers.iter() {
            bhttp_res.put_header(name.as_str(), value.to_str().unwrap_or_default());
        }
        let full_body = body
            .collect()
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?
            .to_bytes();
        bhttp_res.write_content(&full_body);
        let mut bhttp_bytes = Vec::new();
        bhttp_res
            .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes)
            .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        bhttp_bytes.resize(BHTTP_REQ_BYTES, 0);
        let ohttp_res = res_ctx
            .encapsulate(&bhttp_bytes)
            .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        assert!(ohttp_res.len() == ENCAPSULATED_MESSAGE_BYTES, "Unexpected OHTTP response size");
        Ok(Response::new(full(ohttp_res)))
    }

    async fn handle_v2(
        &self,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
        let path = req.uri().path().to_string();
        let (parts, body) = req.into_parts();

        let path_segments: Vec<&str> = path.split('/').collect();
        debug!("handle_v2: {:?}", &path_segments);
        match (parts.method, path_segments.as_slice()) {
            (Method::POST, &["", id]) => self.post_mailbox(id, body).await,
            (Method::GET, &["", id]) => self.get_mailbox(id).await,
            (Method::PUT, &["", id]) => self.put_payjoin_v1(id, body).await,
            _ => Ok(not_found()),
        }
    }

    async fn post_mailbox(
        &self,
        id: &str,
        body: BoxBody<Bytes, hyper::Error>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
        let none_response = Response::builder().status(StatusCode::OK).body(empty())?;
        trace!("post_mailbox");

        let id = ShortId::from_str(id)?;

        let req = body
            .collect()
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?
            .to_bytes();
        if req.len() > V1_MAX_BUFFER_SIZE {
            return Err(HandlerError::PayloadTooLarge);
        }

        match self.pool.push_default(&id, req.into()).await {
            Ok(_) => Ok(none_response),
            Err(e) => Err(HandlerError::InternalServerError(e.into())),
        }
    }

    async fn get_mailbox(
        &self,
        id: &str,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
        trace!("get_mailbox");
        let id = ShortId::from_str(id)?;
        let timeout_response = Response::builder().status(StatusCode::ACCEPTED).body(empty())?;
        handle_peek(self.pool.peek_default(&id).await, timeout_response)
    }
    async fn put_payjoin_v1(
        &self,
        id: &str,
        body: BoxBody<Bytes, hyper::Error>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
        trace!("Put_payjoin_v1");
        let ok_response = Response::builder().status(StatusCode::OK).body(empty())?;

        let id = ShortId::from_str(id)?;
        let req = body
            .collect()
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?
            .to_bytes();
        if req.len() > V1_MAX_BUFFER_SIZE {
            return Err(HandlerError::PayloadTooLarge);
        }

        match self.pool.push_v1(&id, req.into()).await {
            Ok(_) => Ok(ok_response),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        }
    }

    async fn post_fallback_v1(
        &self,
        id: &str,
        query: String,
        body: impl Body,
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

        let v2_compat_body = format!("{body_str}\n{query}");
        let id = ShortId::from_str(id)?;
        self.pool
            .push_default(&id, v2_compat_body.into())
            .await
            .map_err(|e| HandlerError::BadRequest(e.into()))?;
        handle_peek(self.pool.peek_v1(&id).await, none_response)
    }

    async fn handle_ohttp_gateway_get(
        &self,
        query: &str,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
        match query {
            "allowed_purposes" => Ok(self.get_ohttp_allowed_purposes().await),
            _ => self.get_ohttp_keys().await,
        }
    }

    async fn get_ohttp_keys(&self) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
        let ohttp_keys = self
            .ohttp
            .config()
            .encode()
            .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        let mut res = Response::new(full(ohttp_keys));
        res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/ohttp-keys"));
        Ok(res)
    }

    async fn get_ohttp_allowed_purposes(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        // Encode the magic string in the same format as a TLS ALPN protocol list (a
        // U16BE length encoded list of U8 length encoded strings).
        //
        // The string is just "BIP77" followed by a UUID, that signals to relays
        // that this OHTTP gateway will accept any requests associated with this
        // purpose.
        let mut res = Response::new(full(Bytes::from_static(
            b"\x00\x01\x2aBIP77 454403bb-9f7b-4385-b31f-acd2dae20b7e",
        )));

        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/x-ohttp-allowed-purposes"));

        res
    }
    async fn handle_metrics(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        match self.metrics.generate_metrics() {
            Ok(metrics_data) => {
                let mut response = Response::new(full(metrics_data));
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                );
                response
            }
            Err(e) => {
                error!("failed to generate metrics: {}", e);
                let mut response = Response::new(full("Error generating metrics"));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                response
            }
        }
    }
}

fn handle_peek(
    result: db::Result<Vec<u8>>,
    timeout_response: Response<BoxBody<Bytes, hyper::Error>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    match result {
        Ok(buffered_req) => Ok(Response::new(full(buffered_req))),
        Err(e) => match e {
            db::Error::Redis(re) => {
                error!("Redis error: {}", re);
                Err(HandlerError::InternalServerError(anyhow::Error::msg("Internal server error")))
            }
            db::Error::Timeout(_) => Ok(timeout_response),
        },
    }
}

async fn health_check() -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    Ok(Response::new(empty()))
}

async fn handle_directory_home_path() -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError>
{
    let mut res = Response::new(empty());
    *res.status_mut() = StatusCode::OK;
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));

    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Payjoin Directory</title>
    <style>
        body {
            background-color: #0f0f0f;
            color: #eaeaea;
            font-family:  Manrope, sans-serif;
            padding: 2rem;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 0 10px rgba(0, 170, 255, 0.2);
            text-align: center;
        }
        h1 {
            color: black;
            background-color: #C71585;
            margin-bottom: 1rem;
            padding: 0.5rem;
            border-radius: 4px;
        }
        p {
            color: #ccc;
        }
        a{
            color: #F75394;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Payjoin Directory</h1>
        <p>The Payjoin Directory provides a rendezvous point for sender and receiver to meet. The directory stores Payjoin payloads to support asynchronous communication.</p>
        <p>Learn more about how asynchronous payjoin works here: <a href="https://payjoin.org/docs/how-it-works/payjoin-v2-bip-77">Payjoin V2</a></p>
    </div>
</body>
</html>
"#;

    *res.body_mut() = full(html);
    Ok(res)
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

                warn!("Bad request: Key configuration rejected: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST;
                res.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
                *res.body_mut() = full(OHTTP_KEY_REJECTION_RES_JSON);
            }
            HandlerError::BadRequest(e) => {
                warn!("Bad request: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST
            }
        };

        res
    }
}

impl From<hyper::http::Error> for HandlerError {
    fn from(e: hyper::http::Error) -> Self { HandlerError::InternalServerError(e.into()) }
}

impl From<ShortIdError> for HandlerError {
    fn from(_: ShortIdError) -> Self {
        HandlerError::BadRequest(anyhow::anyhow!("mailbox ID must be 13 bech32 characters"))
    }
}

fn not_found() -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut res = Response::default();
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

pub async fn serve_metrics_tcp(
    service: Service,
    listener: tokio::net::TcpListener,
) -> Result<(), BoxError> {
    while let Ok((stream, _)) = listener.accept().await {
        let io = TokioIo::new(stream);
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(err) =
                http1::Builder::new().serve_connection(io, service).with_upgrades().await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }

    Ok(())
}

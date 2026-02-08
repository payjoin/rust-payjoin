use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use futures::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Bytes};
use hyper::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use payjoin::directory::{ShortId, ShortIdError};
use tokio::net::TcpListener;
#[cfg(feature = "acme")]
use tokio_rustls_acme::AcmeConfig;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use tracing::{debug, error, warn};

pub use crate::db::files::Db as FilesDb;
use crate::db::Db;
pub mod key_config;
use ohttp_relay::SentinelTag;

pub use crate::key_config::*;

const V1_MAX_BUFFER_SIZE: usize = 65536;

const V1_UNAVAILABLE_RES_JSON: &str = r#"{{"errorCode": "unavailable", "message": "V2 receiver offline. V1 sends require synchronous communications."}}"#;

pub(crate) mod db;

pub mod cli;
pub mod config;

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
pub struct Service<D: Db> {
    db: D,
    pub ohttp: ohttp::Server,
    sentinel_tag: SentinelTag,
}

impl<D: Db, B> tower::Service<Request<B>> for Service<D>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = anyhow::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.serve_request(req).await })
    }
}

impl<D: Db> Service<D> {
    pub fn new(db: D, ohttp: ohttp::Server, sentinel_tag: SentinelTag) -> Self {
        Self { db, ohttp, sentinel_tag }
    }

    #[cfg(feature = "_manual-tls")]
    pub async fn serve_tls(
        self,
        listener: TcpListener,
        tls_config: (Vec<u8>, Vec<u8>),
    ) -> Result<(), BoxError> {
        let tls_acceptor = init_tls_acceptor(tls_config)?;
        // Spawn the connection handling loop in a separate task

        while let Ok((stream, _)) = listener.accept().await {
            let tls_acceptor = tls_acceptor.clone();
            let service = self.clone();
            tokio::spawn(async move {
                let tls_stream = match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(e) => {
                        error!("TLS accept error: {}", e);
                        return;
                    }
                };
                let hyper_service = TowerToHyperService::new(service);
                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls_stream), hyper_service)
                    .with_upgrades()
                    .await
                {
                    error!("Error serving connection: {:?}", err);
                }
            });
        }
        Ok(())
    }

    #[cfg(feature = "acme")]
    pub async fn serve_acme<EC, EA>(self, listener: TcpListener, acme_config: AcmeConfig<EC, EA>)
    where
        EC: 'static + std::fmt::Debug,
        EA: 'static + std::fmt::Debug,
    {
        let tcp_incoming = TcpListenerStream::new(listener);

        let tls_incoming = acme_config.incoming(tcp_incoming, Vec::new());

        self.serve_connections(tls_incoming).await;
    }

    pub async fn serve_tcp(self, listener: TcpListener) {
        let tcp_incoming = TcpListenerStream::new(listener);
        self.serve_connections(tcp_incoming).await;
    }

    async fn serve_connections<S, I>(self, mut incoming_connections: S)
    where
        S: Stream<Item = tokio::io::Result<I>> + Unpin,
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        while let Some(conn) = incoming_connections.next().await {
            match conn {
                Ok(stream) => {
                    let service = self.clone();
                    tokio::spawn(async move { service.serve_connection(stream).await });
                }
                Err(err) => {
                    error!("Accept error: {err}")
                }
            }
        }
    }

    async fn serve_connection<I>(&self, stream: I)
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let hyper_service = TowerToHyperService::new(self.clone());
        if let Err(err) = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), hyper_service)
            .with_upgrades()
            .await
        {
            error!("Error serving connection: {:?}", err);
        }
    }

    async fn serve_request<B>(
        &self,
        req: Request<B>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or_default().to_string();
        let (parts, body) = req.into_parts();

        let path_segments: Vec<&str> = path.split('/').collect();
        debug!("Service::serve_request: {:?}", &path_segments);

        // Best-effort validation that the relay and gateway aren't on the same
        // payjoin-service instance
        if let Some(header_value) =
            parts.headers.get(ohttp_relay::sentinel::HEADER_NAME).and_then(|v| v.to_str().ok())
        {
            if ohttp_relay::sentinel::is_self_loop(&self.sentinel_tag, header_value) {
                warn!("Rejected OHTTP request from same-instance relay");
                return Ok(HandlerError::Forbidden(anyhow::anyhow!(
                    "Relay and gateway must be operated by different entities"
                ))
                .to_response());
            }
        }

        let mut response = match (parts.method, path_segments.as_slice()) {
            (Method::GET, ["", ".well-known", "ohttp-gateway"]) =>
                self.handle_ohttp_gateway_get(&query).await,
            (Method::GET, ["", "ohttp-keys"]) => self.get_ohttp_keys().await,
            (Method::GET, ["", "health"]) => health_check().await,
            (Method::GET, ["", ""]) => handle_directory_home_path().await,
            (Method::POST, ["", id]) => self.post_mailbox_or_v1(id, query, body).await,
            (Method::GET, ["", id]) => self.get_mailbox(id).await,
            (Method::PUT, ["", id]) => self.put_payjoin_v1(id, body).await,
            _ => Ok(not_found()),
        }
        .unwrap_or_else(|e| e.to_response());

        // Allow CORS for third-party access
        response.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));

        Ok(response)
    }

    async fn post_mailbox_or_v1<B>(
        &self,
        id: &str,
        query: String,
        body: B,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| HandlerError::BadRequest(anyhow::anyhow!(e.into())))?
            .to_bytes();

        if body_bytes.len() > V1_MAX_BUFFER_SIZE {
            return Err(HandlerError::PayloadTooLarge);
        }

        let id = ShortId::from_str(id)?;

        if let Ok(body_str) = String::from_utf8(body_bytes.to_vec()) {
            let v2_compat_body = format!("{body_str}\n{query}");
            let none_response = Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(full(V1_UNAVAILABLE_RES_JSON))?;
            handle_peek(
                self.db.post_v1_request_and_wait_for_response(&id, v2_compat_body.into()).await,
                none_response,
            )
        } else {
            let none_response = Response::builder().status(StatusCode::OK).body(empty())?;
            match self.db.post_v2_payload(&id, body_bytes.into()).await {
                Ok(_) => Ok(none_response),
                Err(e) => Err(HandlerError::InternalServerError(e.into())),
            }
        }
    }

    async fn get_mailbox(
        &self,
        id: &str,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
        let id = ShortId::from_str(id)?;
        let timeout_response = Response::builder().status(StatusCode::ACCEPTED).body(empty())?;
        handle_peek(self.db.wait_for_v2_payload(&id).await, timeout_response)
    }

    async fn put_payjoin_v1<B>(
        &self,
        id: &str,
        body: B,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let ok_response = Response::builder().status(StatusCode::OK).body(empty())?;

        let id = ShortId::from_str(id)?;
        let req = body
            .collect()
            .await
            .map_err(|e| {
                HandlerError::InternalServerError(anyhow::anyhow!(
                    "Failed to read body: {}",
                    e.into()
                ))
            })?
            .to_bytes();
        if req.len() > V1_MAX_BUFFER_SIZE {
            return Err(HandlerError::PayloadTooLarge);
        }

        match self.db.post_v1_response(&id, req.into()).await {
            Ok(_) => Ok(ok_response),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        }
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
}

fn handle_peek<Error: db::SendableError>(
    result: Result<Arc<Vec<u8>>, db::Error<Error>>,
    timeout_response: Response<BoxBody<Bytes, hyper::Error>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    match result {
        Ok(payload) => Ok(Response::new(full((*payload).clone()))), // TODO Bytes instead of Arc<Vec<u8>>
        Err(e) => match e {
            db::Error::Operational(err) => {
                error!("Storage error: {err}");
                Err(HandlerError::InternalServerError(anyhow::Error::msg("Internal server error")))
            }
            db::Error::Timeout(_) => Ok(timeout_response),
            db::Error::OverCapacity => Err(HandlerError::ServiceUnavailable(anyhow::Error::msg(
                "mailbox storage at capacity",
            ))),
            db::Error::V1SenderUnavailable => Err(HandlerError::SenderGone(anyhow::Error::msg(
                "Sender is unavailable try a new request",
            ))),
        },
    }
}

async fn health_check() -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
    Ok(Response::new(empty()))
}

async fn handle_directory_home_path() -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError>
{
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

    let mut res = Response::new(full(html));
    *res.status_mut() = StatusCode::OK;
    res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
    Ok(res)
}

#[derive(Debug)]
enum HandlerError {
    PayloadTooLarge,
    InternalServerError(anyhow::Error),
    ServiceUnavailable(anyhow::Error),
    SenderGone(anyhow::Error),
    BadRequest(anyhow::Error),
    Forbidden(anyhow::Error),
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
            HandlerError::ServiceUnavailable(e) => {
                error!("Service temporarily unavailable: {}", e);
                *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE
            }
            HandlerError::SenderGone(e) => {
                error!("Sender gone: {}", e);
                *res.status_mut() = StatusCode::GONE
            }
            HandlerError::BadRequest(e) => {
                warn!("Bad request: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST
            }
            HandlerError::Forbidden(e) => {
                warn!("Forbidden: {}", e);
                *res.status_mut() = StatusCode::FORBIDDEN
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

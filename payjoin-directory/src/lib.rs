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
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use payjoin::directory::{ShortId, ShortIdError, ENCAPSULATED_MESSAGE_BYTES};
use tokio::net::TcpListener;
#[cfg(feature = "acme")]
use tokio_rustls_acme::AcmeConfig;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use tracing::{debug, error, trace, warn};

pub use crate::db::files::Db as FilesDb;
use crate::db::Db;
pub mod key_config;
use ohttp_relay::SentinelTag;

pub use crate::key_config::*;

const CHACHA20_POLY1305_NONCE_LEN: usize = 32; // chacha20poly1305 n_k
const POLY1305_TAG_SIZE: usize = 16;
pub const BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (CHACHA20_POLY1305_NONCE_LEN + POLY1305_TAG_SIZE);
const V1_MAX_BUFFER_SIZE: usize = 65536;

const V1_REJECT_RES_JSON: &str =
    r#"{{"errorCode": "original-psbt-rejected ", "message": "Body is not a string"}}"#;
const V1_UNAVAILABLE_RES_JSON: &str = r#"{{"errorCode": "unavailable", "message": "V2 receiver offline. V1 sends require synchronous communications."}}"#;
const V1_VERSION_UNSUPPORTED_RES_JSON: &str =
    r#"{"errorCode": "version-unsupported", "supported": [2], "message": "V1 is not supported"}"#;

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

/// Opaque blocklist of Bitcoin addresses stored as script pubkeys.
///
/// Addresses are converted to `ScriptBuf` at parse time so that
/// screening only requires a `HashSet::contains` on raw scripts,
/// avoiding address-encoding round-trips and bech32 case issues.
#[derive(Clone)]
pub struct BlockedAddresses(
    Arc<tokio::sync::RwLock<std::collections::HashSet<bitcoin::ScriptBuf>>>,
);

impl BlockedAddresses {
    pub fn empty() -> Self {
        Self(Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())))
    }

    pub fn from_address_lines(text: &str) -> Self {
        Self(Arc::new(tokio::sync::RwLock::new(parse_address_lines(text))))
    }

    /// Replace the contents with scripts parsed from newline-delimited
    /// address text.  Returns the number of entries after update.
    pub async fn update_from_lines(&self, text: &str) -> usize {
        let scripts = parse_address_lines(text);
        let count = scripts.len();
        *self.0.write().await = scripts;
        count
    }
}

/// V1 protocol configuration.
///
/// Its presence in [`Service`] enables the V1 fallback path;
/// its contents carry optional blocklist screening.
#[derive(Clone, Default)]
pub struct V1 {
    blocked_addresses: Option<BlockedAddresses>,
}

impl V1 {
    pub fn new(blocked_addresses: Option<BlockedAddresses>) -> Self { Self { blocked_addresses } }
}

fn parse_address_lines(text: &str) -> std::collections::HashSet<bitcoin::ScriptBuf> {
    text.lines()
        .filter_map(|l| {
            let trimmed = l.trim();
            if trimmed.is_empty() {
                return None;
            }
            match trimmed.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
                Ok(addr) => Some(addr.assume_checked().script_pubkey()),
                Err(e) => {
                    tracing::warn!("Skipping unparsable blocked address {trimmed:?}: {e}");
                    None
                }
            }
        })
        .collect()
}

#[derive(Clone)]
pub struct Service<D: Db> {
    db: D,
    ohttp: ohttp::Server,
    sentinel_tag: SentinelTag,
    v1: Option<V1>,
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
    pub fn new(db: D, ohttp: ohttp::Server, sentinel_tag: SentinelTag, v1: Option<V1>) -> Self {
        Self { db, ohttp, sentinel_tag, v1 }
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
        // payjoin-mailroom instance
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
            (Method::POST, ["", ".well-known", "ohttp-gateway"]) =>
                self.handle_ohttp_gateway(body).await,
            (Method::GET, ["", ".well-known", "ohttp-gateway"]) =>
                self.handle_ohttp_gateway_get(&query).await,
            (Method::POST, ["", ""]) => self.handle_ohttp_gateway(body).await,
            (Method::GET, ["", "ohttp-keys"]) => self.get_ohttp_keys().await,
            (Method::POST, ["", id]) => self.handle_post_v1(id, query, body).await,
            (Method::GET, ["", "health"]) => self.health_check().await,
            (Method::GET, ["", ""]) => handle_directory_home_path().await,
            _ => Ok(not_found()),
        }
        .unwrap_or_else(|e| e.to_response());

        // Allow CORS for third-party access
        response.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));

        Ok(response)
    }

    /// Route POST /{id}: forward to V1 fallback when enabled, otherwise reject.
    async fn handle_post_v1<B>(
        &self,
        id: &str,
        query: String,
        body: B,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        if self.v1.is_some() {
            self.post_fallback_v1(id, query, body).await
        } else {
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(CONTENT_TYPE, "application/json")
                .body(full(V1_VERSION_UNSUPPORTED_RES_JSON))?)
        }
    }

    /// Handle an encapsulated OHTTP request and return an encapsulated response
    async fn handle_ohttp_gateway<B>(
        &self,
        body: B,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        // Decapsulate OHTTP request
        let ohttp_body = body
            .collect()
            .await
            .map_err(|e| HandlerError::BadRequest(anyhow::anyhow!(e.into())))?
            .to_bytes();
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

        // Handle decapsulated request
        let response = self.handle_decapsulated_request(request).await?;

        // Encapsulate OHTTP response
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

    async fn handle_decapsulated_request(
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
            (Method::PUT, &["", id]) if self.v1.is_some() => self.put_payjoin_v1(id, body).await,
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

        match self.db.post_v2_payload(&id, req.into()).await {
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
        handle_peek(self.db.wait_for_v2_payload(&id).await, timeout_response)
    }

    /// Screen a V1 PSBT body against the address blocklist.
    ///
    /// Returns `Ok(())` if screening passes or is not configured.
    async fn check_v1_blocklist(&self, body_str: &str) -> Result<(), HandlerError> {
        if let Some(blocked) = self.v1.as_ref().and_then(|v| v.blocked_addresses.as_ref()) {
            let scripts = blocked.0.read().await;
            if !scripts.is_empty() {
                match screen_v1_addresses(body_str, &scripts) {
                    ScreenResult::Blocked => {
                        return Err(HandlerError::V1PsbtRejected(anyhow::anyhow!(
                            "blocked address in V1 PSBT"
                        )));
                    }
                    ScreenResult::Clean => {}
                    ScreenResult::ParseError(e) => {
                        warn!("Could not parse V1 PSBT: {e}");
                    }
                }
            }
        }
        Ok(())
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

        let body_str = std::str::from_utf8(&req).map_err(|e| HandlerError::BadRequest(e.into()))?;
        self.check_v1_blocklist(body_str).await?;

        match self.db.post_v1_response(&id, req.into()).await {
            Ok(_) => Ok(ok_response),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        }
    }

    async fn post_fallback_v1<B>(
        &self,
        id: &str,
        query: String,
        body: B,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
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

        self.check_v1_blocklist(&body_str).await?;

        let v2_compat_body = format!("{body_str}\n{query}");
        let id = ShortId::from_str(id)?;
        handle_peek(
            self.db.post_v1_request_and_wait_for_response(&id, v2_compat_body.into()).await,
            none_response,
        )
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
            db::Error::AlreadyRead => Ok(timeout_response),
            db::Error::V1SenderUnavailable => Err(HandlerError::SenderGone(anyhow::Error::msg(
                "Sender is unavailable try a new request",
            ))),
        },
    }
}

impl<D: Db> Service<D> {
    async fn health_check(&self) -> Result<Response<BoxBody<Bytes, hyper::Error>>, HandlerError> {
        let versions = if self.v1.is_some() { "[1,2]" } else { "[2]" };
        let body = format!(r#"{{"versions":{versions}}}"#);
        let mut res = Response::new(full(body));
        res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(res)
    }
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
    ServiceUnavailable(anyhow::Error),
    SenderGone(anyhow::Error),
    OhttpKeyRejection(anyhow::Error),
    BadRequest(anyhow::Error),
    /// V1 PSBT rejected — returns the BIP78 `original-psbt-rejected` error.
    V1PsbtRejected(anyhow::Error),
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
            HandlerError::V1PsbtRejected(e) => {
                warn!("PSBT rejected: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST;
                *res.body_mut() = full(V1_REJECT_RES_JSON);
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

enum ScreenResult {
    Blocked,
    Clean,
    ParseError(String),
}

fn screen_v1_addresses(
    body: &str,
    blocked: &std::collections::HashSet<bitcoin::ScriptBuf>,
) -> ScreenResult {
    use bitcoin::base64::prelude::{Engine, BASE64_STANDARD};
    use bitcoin::psbt::Psbt;

    let psbt_bytes = match BASE64_STANDARD.decode(body) {
        Ok(b) => b,
        Err(e) => return ScreenResult::ParseError(format!("base64 decode: {e}")),
    };

    let psbt = match Psbt::deserialize(&psbt_bytes) {
        Ok(p) => p,
        Err(e) => return ScreenResult::ParseError(format!("PSBT deserialize: {e}")),
    };

    // Check output scripts
    for txout in &psbt.unsigned_tx.output {
        if blocked.contains(&txout.script_pubkey) {
            return ScreenResult::Blocked;
        }
    }

    // Check input scripts from witness_utxo and non_witness_utxo
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(ref utxo) = input.witness_utxo {
            if blocked.contains(&utxo.script_pubkey) {
                return ScreenResult::Blocked;
            }
        }
        if let Some(ref tx) = input.non_witness_utxo {
            if let Some(prev_out) = psbt.unsigned_tx.input.get(i) {
                if let Some(txout) = tx.output.get(prev_out.previous_output.vout as usize) {
                    if blocked.contains(&txout.script_pubkey) {
                        return ScreenResult::Blocked;
                    }
                }
            }
        }
    }

    ScreenResult::Clean
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http_body_util::BodyExt;
    use hyper::body::Bytes;
    use hyper::{Method, Request, StatusCode};
    use ohttp_relay::SentinelTag;
    use payjoin::directory::ShortId;

    use super::*;

    async fn test_service(v1: Option<V1>) -> Service<FilesDb> {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = FilesDb::init(Duration::from_millis(100), dir.keep()).await.expect("db init");
        let ohttp: ohttp::Server =
            key_config::gen_ohttp_server_config().expect("ohttp config").into();
        Service::new(db, ohttp, SentinelTag::new([0u8; 32]), v1)
    }

    /// A valid ShortId encoded as bech32 for use in URL paths.
    fn valid_short_id_path() -> String {
        let id = ShortId([0u8; 8]);
        id.to_string()
    }

    async fn collect_body(res: Response<BoxBody<Bytes, hyper::Error>>) -> (StatusCode, String) {
        let (parts, body) = res.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        (parts.status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    // V1 routing

    #[tokio::test]
    async fn post_v1_when_disabled_returns_version_unsupported() {
        let mut svc = test_service(None).await;
        let id = valid_short_id_path();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://localhost/{id}"))
            .body(Full::new(Bytes::from("base64-psbt")))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        let (status, body) = collect_body(res).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, V1_VERSION_UNSUPPORTED_RES_JSON);
    }

    #[tokio::test]
    async fn post_v1_with_invalid_body_returns_reject() {
        let mut svc = test_service(Some(V1::new(None))).await;
        let id = valid_short_id_path();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://localhost/{id}"))
            .body(Full::new(Bytes::from(vec![0xFF, 0xFE])))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        let (status, body) = collect_body(res).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, V1_REJECT_RES_JSON);
    }

    #[tokio::test]
    async fn post_v1_with_no_receiver_returns_unavailable() {
        let mut svc = test_service(Some(V1::new(None))).await;
        let id = valid_short_id_path();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://localhost/{id}"))
            .body(Full::new(Bytes::from("base64-psbt")))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        let (status, body) = collect_body(res).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, V1_UNAVAILABLE_RES_JSON);
    }

    // Address screening

    fn make_test_psbt_base64(output_address: &str) -> String {
        use bitcoin::base64::prelude::{Engine, BASE64_STANDARD};
        use bitcoin::psbt::Psbt;
        use bitcoin::{Amount, Transaction, TxIn, TxOut};

        let addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            output_address.parse().expect("valid address");
        let script_pubkey = addr.assume_checked().script_pubkey();

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut { value: Amount::from_sat(50_000), script_pubkey }],
        };

        let psbt = Psbt::from_unsigned_tx(tx).expect("valid psbt");
        BASE64_STANDARD.encode(psbt.serialize())
    }

    fn addr_to_script(address: &str) -> bitcoin::ScriptBuf {
        let addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            address.parse().expect("valid address");
        addr.assume_checked().script_pubkey()
    }

    #[tokio::test]
    async fn post_v1_with_blocked_address_returns_bad_request() {
        let blocked_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let blocked = BlockedAddresses::from_address_lines(blocked_addr);
        let mut svc = test_service(Some(V1::new(Some(blocked)))).await;
        let id = valid_short_id_path();
        let psbt_b64 = make_test_psbt_base64(blocked_addr);
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://localhost/{id}"))
            .body(Full::new(Bytes::from(psbt_b64)))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        let (status, body) = collect_body(res).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, V1_REJECT_RES_JSON);
    }

    #[test]
    fn screen_blocks_blocked_output_address() {
        let blocked_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let blocked = std::collections::HashSet::from([addr_to_script(blocked_addr)]);

        let psbt_b64 = make_test_psbt_base64(blocked_addr);
        assert!(matches!(screen_v1_addresses(&psbt_b64, &blocked), ScreenResult::Blocked));
    }

    #[test]
    fn screen_allows_clean_psbt() {
        let clean_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let blocked = std::collections::HashSet::new(); // empty
        let psbt_b64 = make_test_psbt_base64(clean_addr);
        assert!(matches!(screen_v1_addresses(&psbt_b64, &blocked), ScreenResult::Clean));
    }

    #[test]
    fn screen_allows_non_blocked_address() {
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let blocked =
            std::collections::HashSet::from([addr_to_script("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")]);

        let psbt_b64 = make_test_psbt_base64(addr);
        assert!(matches!(screen_v1_addresses(&psbt_b64, &blocked), ScreenResult::Clean));
    }

    #[test]
    fn screen_parse_error_on_invalid_base64() {
        let blocked =
            std::collections::HashSet::from([addr_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")]);
        assert!(matches!(
            screen_v1_addresses("not-valid-base64!!!", &blocked),
            ScreenResult::ParseError(_)
        ));
    }

    #[test]
    fn screen_parse_error_on_invalid_psbt() {
        use bitcoin::base64::prelude::{Engine, BASE64_STANDARD};
        let blocked =
            std::collections::HashSet::from([addr_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")]);
        let bad_psbt = BASE64_STANDARD.encode(b"not a psbt");
        assert!(matches!(screen_v1_addresses(&bad_psbt, &blocked), ScreenResult::ParseError(_)));
    }

    #[test]
    fn screen_blocks_bech32_address() {
        let addr = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
        let blocked = std::collections::HashSet::from([addr_to_script(addr)]);

        let psbt_b64 = make_test_psbt_base64(addr);
        assert!(matches!(screen_v1_addresses(&psbt_b64, &blocked), ScreenResult::Blocked));
    }

    // Health check

    #[tokio::test]
    async fn health_check_without_v1() {
        let mut svc = test_service(None).await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://localhost/health")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        assert_eq!(res.headers().get(CONTENT_TYPE).unwrap(), "application/json");
        let (status, body) = collect_body(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"versions":[2]}"#);
    }

    #[tokio::test]
    async fn health_check_with_v1() {
        let mut svc = test_service(Some(V1::new(None))).await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://localhost/health")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        assert_eq!(res.headers().get(CONTENT_TYPE).unwrap(), "application/json");
        let (status, body) = collect_body(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"versions":[1,2]}"#);
    }
}

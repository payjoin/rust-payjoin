use std::fmt::Debug;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

pub(crate) use gateway_prober::Prober;
pub use gateway_uri::GatewayUri;
use http::uri::Authority;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    HeaderValue, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_LENGTH, CONTENT_TYPE,
};
use hyper::{Method, Request, Response};
use hyper_rustls::builderstates::WantsSchemes;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::instrument;

pub mod error;
mod gateway_prober;
mod gateway_uri;
pub mod sentinel;
pub use sentinel::SentinelTag;

use self::error::{BoxError, Error};

#[cfg(any(feature = "connect-bootstrap", feature = "ws-bootstrap"))]
pub mod bootstrap;

pub const EXPECTED_MEDIA_TYPE: HeaderValue = HeaderValue::from_static("message/ohttp-req");
pub const DEFAULT_GATEWAY: &str = "https://payjo.in";

#[derive(Debug)]
struct RelayConfig {
    default_gateway: GatewayUri,
    client: HttpClient,
    prober: Prober,
    sentinel_tag: SentinelTag,
}

impl RelayConfig {
    fn new_with_default_client(default_gateway: GatewayUri, sentinel_tag: SentinelTag) -> Self {
        Self::new(default_gateway, HttpClient::default(), sentinel_tag)
    }

    fn new(
        default_gateway: GatewayUri,
        into_client: impl Into<HttpClient>,
        sentinel_tag: SentinelTag,
    ) -> Self {
        let client = into_client.into();
        let prober = Prober::new_with_client(client.clone());
        RelayConfig { default_gateway, client, prober, sentinel_tag }
    }
}

#[derive(Clone)]
pub struct Service {
    config: Arc<RelayConfig>,
}

impl Service {
    pub async fn new(sentinel_tag: SentinelTag) -> Self {
        // The default gateway is hardcoded because it is obsolete and required only for backwards
        // compatibility.
        // The new mechanism for specifying a custom gateway is via RFC 9540 using
        // `/.well-known/ohttp-gateway` request paths.
        let gateway_origin = GatewayUri::from_str(DEFAULT_GATEWAY).expect("valid gateway uri");
        let config = RelayConfig::new_with_default_client(gateway_origin, sentinel_tag);
        config.prober.assert_opt_in(&config.default_gateway).await;
        Self { config: Arc::new(config) }
    }

    #[cfg(feature = "_manual-tls")]
    pub async fn new_with_roots(
        sentinel_tag: SentinelTag,
        root_store: rustls::RootCertStore,
        default_gateway: Option<GatewayUri>,
    ) -> Self {
        let gateway_origin = default_gateway
            .unwrap_or_else(|| GatewayUri::from_str(DEFAULT_GATEWAY).expect("valid gateway uri"));
        let config = RelayConfig::new(gateway_origin, root_store, sentinel_tag);
        config.prober.assert_opt_in(&config.default_gateway).await;
        Self { config: Arc::new(config) }
    }
}

impl<B> tower::Service<Request<B>> for Service
where
    B: hyper::body::Body<Data = Bytes> + Send + Debug + 'static,
    B::Error: Into<BoxError>,
{
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = hyper::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let config = self.config.clone();
        Box::pin(async move { serve_ohttp_relay(req, &config).await })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HttpClient(
    hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, hyper::Error>>,
);

impl std::ops::Deref for HttpClient {
    type Target = hyper_util::client::legacy::Client<
        HttpsConnector<HttpConnector>,
        BoxBody<Bytes, hyper::Error>,
    >;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<HttpsConnectorBuilder<WantsSchemes>> for HttpClient {
    fn from(builder: HttpsConnectorBuilder<WantsSchemes>) -> Self {
        let https = builder.https_or_http().enable_http1().build();
        Self(Client::builder(TokioExecutor::new()).build(https))
    }
}

impl Default for HttpClient {
    fn default() -> Self { HttpsConnectorBuilder::new().with_webpki_roots().into() }
}

impl From<rustls::RootCertStore> for HttpClient {
    fn from(root_store: rustls::RootCertStore) -> Self {
        HttpsConnectorBuilder::new()
            .with_tls_config(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            )
            .into()
    }
}

#[instrument]
async fn serve_ohttp_relay<B>(
    req: Request<B>,
    config: &RelayConfig,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
where
    B: hyper::body::Body<Data = Bytes> + Send + Debug + 'static,
    B::Error: Into<BoxError>,
{
    let method = req.method().clone();
    let path = req.uri().path();
    let authority = req.uri().authority().cloned();

    let mut res = match (&method, path) {
        (&Method::OPTIONS, _) => Ok(handle_preflight()),
        (&Method::GET, "/health") => Ok(health_check().await),
        (&Method::POST, _) => match parse_gateway_uri(&method, path, authority, config).await {
            Ok(gateway_uri) => handle_ohttp_relay(req, config, gateway_uri).await,
            Err(e) => Err(e),
        },
        #[cfg(any(feature = "connect-bootstrap", feature = "ws-bootstrap"))]
        (&Method::GET, _) | (&Method::CONNECT, _) => {
            match parse_gateway_uri(&method, path, authority, config).await {
                Ok(gateway_uri) =>
                    crate::ohttp_relay::bootstrap::handle_ohttp_keys(req, gateway_uri).await,
                Err(e) => Err(e),
            }
        }
        _ => Err(Error::NotFound),
    }
    .unwrap_or_else(|e| e.to_response());
    res.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    Ok(res)
}

async fn parse_gateway_uri(
    method: &Method,
    path: &str,
    authority: Option<Authority>,
    config: &RelayConfig,
) -> Result<GatewayUri, Error> {
    // for POST and GET (websockets), the gateway URI is provided in the path
    // for CONNECT requests, just an authority is provided, and we assume HTTPS
    let gateway_uri = match method {
        &Method::CONNECT => authority.map(GatewayUri::from),
        _ => parse_gateway_uri_from_path(path, &config.default_gateway).ok(),
    }
    .ok_or_else(|| Error::BadRequest("Invalid gateway".to_string()))?;

    let policy = match config.prober.check_opt_in(&gateway_uri).await {
        Some(policy) => Ok(policy),
        None => Err(Error::Unavailable(config.prober.unavailable_for().await)),
    }?;

    if policy.bip77_allowed {
        Ok(gateway_uri)
    } else {
        // TODO Cache-Control header for error based on policy.expires
        // is not found the right error? maybe forbidden or bad gateway?
        // prober policy judgement can be an enum instead of a bool to
        // distinguish 4xx vs. 5xx failures, 4xx being an explicit opt out and
        // 5xx for IO errors etc
        Err(Error::NotFound)
    }
}

fn parse_gateway_uri_from_path(path: &str, default: &GatewayUri) -> Result<GatewayUri, BoxError> {
    if path.is_empty() || path == "/" {
        return Ok(default.clone());
    }

    let path = &path[1..];

    if "http://" == &path[..7] || "https://" == &path[..8] {
        GatewayUri::from_str(path)
    } else {
        Ok(Authority::from_str(path)?.into())
    }
}

fn handle_preflight() -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut res = Response::new(empty());
    *res.status_mut() = hyper::StatusCode::NO_CONTENT;
    res.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    res.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("CONNECT, GET, OPTIONS, POST"),
    );
    res.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Content-Length"),
    );
    res
}

async fn health_check() -> Response<BoxBody<Bytes, hyper::Error>> { Response::new(empty()) }

#[instrument]
async fn handle_ohttp_relay<B>(
    req: Request<B>,
    config: &RelayConfig,
    gateway: GatewayUri,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: hyper::body::Body<Data = Bytes> + Send + Debug + 'static,
    B::Error: Into<BoxError>,
{
    let fwd_req = into_forward_req(req, gateway, &config.sentinel_tag).await?;

    forward_request(fwd_req, config).await.map(|res| {
        let (parts, body) = res.into_parts();
        let boxed_body = BoxBody::new(body);
        Response::from_parts(parts, boxed_body)
    })
}

/// Convert an incoming request into a request to forward to the target gateway server.
#[instrument]
async fn into_forward_req<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
    sentinel_tag: &SentinelTag,
) -> Result<Request<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: hyper::body::Body<Data = Bytes> + Send + Debug + 'static,
    B::Error: Into<BoxError>,
{
    let (head, body) = req.into_parts();

    if head.method != hyper::Method::POST {
        return Err(Error::MethodNotAllowed);
    }

    if head.headers.get(CONTENT_TYPE) != Some(&EXPECTED_MEDIA_TYPE) {
        return Err(Error::UnsupportedMediaType);
    }

    let mut builder = Request::builder()
        .method(hyper::Method::POST)
        .uri(gateway_origin.rfc_9540_url())
        .header(CONTENT_TYPE, EXPECTED_MEDIA_TYPE);

    if let Some(content_length) = head.headers.get(CONTENT_LENGTH) {
        builder = builder.header(CONTENT_LENGTH, content_length);
    }

    let bytes =
        body.collect().await.map_err(|e| Error::BadRequest(e.into().to_string()))?.to_bytes();

    builder = builder.header(sentinel::HEADER_NAME, sentinel_tag.to_header_value());

    builder.body(full(bytes)).map_err(|e| Error::InternalServerError(Box::new(e)))
}

#[instrument]
async fn forward_request(
    req: Request<BoxBody<Bytes, hyper::Error>>,
    config: &RelayConfig,
) -> Result<Response<Incoming>, Error> {
    config.client.request(req).await.map_err(|_| Error::BadGateway)
}

pub(crate) fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

pub(crate) fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

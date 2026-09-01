//! A `tower` middleware that terminates the OHTTP gateway boundary.
//!
//! [`OhttpGatewayLayer`] handles all cryptographic OHTTP operations and the key
//! material associated with them. It wraps an inner [`tower::Service`] that only
//! ever sees plaintext [`Request`]/[`Response`] pairs:
//!
//!  Decapsulated requests are tagged with the [`Decapsulated`] extension so the
//! inner service can distinguish encapsulated (v2) traffic from plaintext
//! transport requests that share the same method and path.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody};
use axum::http::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use axum::http::{Method, Request, Response, Uri};
use http_body_util::BodyExt;
use payjoin::directory::ENCAPSULATED_MESSAGE_BYTES;
use tower::{Layer, Service};

mod error;
use error::GatewayError;

use crate::ohttp_relay::sentinel::{self, SentinelTag};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

const CHACHA20_POLY1305_NONCE_LEN: usize = 32; // chacha20poly1305 n_k
const POLY1305_TAG_SIZE: usize = 16;

/// The maximum BHTTP payload that fits inside a single OHTTP message once the
/// AEAD nonce and authentication tag overhead is accounted for. Responses are
/// padded up to this length so every OHTTP response is a constant size.
pub const BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (CHACHA20_POLY1305_NONCE_LEN + POLY1305_TAG_SIZE);

const OHTTP_RES_MEDIA_TYPE: HeaderValue = HeaderValue::from_static("message/ohttp-res");
const OHTTP_KEYS_MEDIA_TYPE: HeaderValue = HeaderValue::from_static("application/ohttp-keys");

const RFC_9540_GATEWAY_SEGMENTS: [&str; 3] = ["", ".well-known", "ohttp-gateway"];

/// Marker extension inserted on requests the gateway has decapsulated.
///
/// The wrapped service inspects this to distinguish encapsulated (v2) requests
/// from plaintext transport requests sharing the same method and path
/// (e.g. an encapsulated v2 `POST /{id}` vs. a plaintext v1 `POST /{id}`).
#[derive(Clone, Copy, Debug)]
pub struct Decapsulated;

/// Shared, immutable gateway state. Holds the private key material.
struct GatewayState {
    server: ohttp::Server,
    sentinel_tag: SentinelTag,
    response_capacity: usize,
}

/// A [`tower::Layer`] that wraps a plaintext service with OHTTP gateway
/// termination.
#[derive(Clone)]
pub struct OhttpGatewayLayer {
    state: Arc<GatewayState>,
}

impl OhttpGatewayLayer {
    pub fn new(server: ohttp::Server, sentinel_tag: SentinelTag) -> Self {
        Self {
            state: Arc::new(GatewayState {
                server,
                sentinel_tag,
                response_capacity: BHTTP_REQ_BYTES,
            }),
        }
    }
}

impl<S> Layer<S> for OhttpGatewayLayer {
    type Service = OhttpGateway<S>;

    fn layer(&self, inner: S) -> Self::Service { OhttpGateway { inner, state: self.state.clone() } }
}

/// The service produced by [`OhttpGatewayLayer`].
#[derive(Clone)]
pub struct OhttpGateway<S> {
    inner: S,
    state: Arc<GatewayState>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for OhttpGateway<S>
where
    S: Service<Request<Body>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError>,
    ReqBody: HttpBody<Data = Bytes> + Send + 'static,
    ReqBody::Error: Into<BoxError>,
    ResBody: HttpBody<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let inner = self.inner.clone();
        let state = self.state.clone();
        Box::pin(async move { Ok(serve(req, inner, &state).await) })
    }
}

async fn serve<S, ReqBody, ResBody>(
    req: Request<ReqBody>,
    inner: S,
    state: &GatewayState,
) -> Response<Body>
where
    S: Service<Request<Body>, Response = Response<ResBody>> + Send,
    S::Future: Send,
    S::Error: Into<BoxError>,
    ReqBody: HttpBody<Data = Bytes> + Send + 'static,
    ReqBody::Error: Into<BoxError>,
    ResBody: HttpBody<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_owned);
    let segments: Vec<&str> = path.split('/').collect();

    let mut response = match (&method, segments.as_slice()) {
        (&Method::POST, seg) if seg == RFC_9540_GATEWAY_SEGMENTS || seg == ["", ""] =>
            handle_encapsulated(req, inner, state).await.unwrap_or_else(GatewayError::into_response),
        (&Method::GET, ["", "ohttp-keys"]) =>
            serve_keys(state).unwrap_or_else(GatewayError::into_response),
        // `?allowed_purposes` is a policy probe handled by the inner service;
        // every other GET of the gateway path returns the key configuration.
        (&Method::GET, seg)
            if seg == RFC_9540_GATEWAY_SEGMENTS && query.as_deref() != Some("allowed_purposes") =>
            serve_keys(state).unwrap_or_else(GatewayError::into_response),
        _ => passthrough(req, inner).await,
    };

    // CORS for third-party (browser) access to the gateway.
    response.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    response
}

/// Forward a non-OHTTP request to the inner service unchanged.
async fn passthrough<S, ReqBody, ResBody>(req: Request<ReqBody>, mut inner: S) -> Response<Body>
where
    S: Service<Request<Body>, Response = Response<ResBody>> + Send,
    S::Error: Into<BoxError>,
    ReqBody: HttpBody<Data = Bytes> + Send + 'static,
    ReqBody::Error: Into<BoxError>,
    ResBody: HttpBody<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    match inner.call(req.map(Body::new)).await {
        Ok(res) => res.map(Body::new),
        Err(e) => GatewayError::Internal(e.into()).into_response(),
    }
}

/// Decapsulate an OHTTP request, and route the plaintext request to the inner
/// service, and encapsulate the response.
async fn handle_encapsulated<S, ReqBody, ResBody>(
    req: Request<ReqBody>,
    mut inner: S,
    state: &GatewayState,
) -> Result<Response<Body>, GatewayError>
where
    S: Service<Request<Body>, Response = Response<ResBody>> + Send,
    S::Error: Into<BoxError>,
    ReqBody: HttpBody<Data = Bytes> + Send + 'static,
    ReqBody::Error: Into<BoxError>,
    ResBody: HttpBody<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    let (parts, body) = req.into_parts();

    // Best-effort detection that the relay and gateway are not the same
    // deployment: the relay stamps every forwarded request with our tag.
    if let Some(header_value) =
        parts.headers.get(sentinel::HEADER_NAME).and_then(|v| v.to_str().ok())
    {
        if sentinel::is_self_loop(&state.sentinel_tag, header_value) {
            return Err(GatewayError::SelfLoop);
        }
    }

    let ohttp_body =
        body.collect().await.map_err(|e| GatewayError::BadRequest(e.into()))?.to_bytes();

    // Decapsulate the OHTTP request into a BHTTP message plus the context
    // needed to encapsulate the matching response.
    let (bhttp_req, res_ctx) = state
        .server
        .decapsulate(&ohttp_body)
        .map_err(|e| GatewayError::OhttpKeyRejection(e.into()))?;
    let mut cursor = std::io::Cursor::new(bhttp_req);
    let bhttp_msg =
        bhttp::Message::read_bhttp(&mut cursor).map_err(|e| GatewayError::BadRequest(e.into()))?;

    let uri = Uri::builder()
        .scheme(bhttp_msg.control().scheme().unwrap_or_default())
        .authority(bhttp_msg.control().authority().unwrap_or_default())
        .path_and_query(bhttp_msg.control().path().unwrap_or_default())
        .build()
        .map_err(|e| GatewayError::BadRequest(e.into()))?;
    let inner_body = bhttp_msg.content().to_vec();
    let mut builder =
        Request::builder().uri(uri).method(bhttp_msg.control().method().unwrap_or_default());
    for header in bhttp_msg.header().fields() {
        builder = builder.header(header.name(), header.value());
    }
    let mut inner_req =
        builder.body(Body::from(inner_body)).map_err(|e| GatewayError::BadRequest(e.into()))?;
    inner_req.extensions_mut().insert(Decapsulated);

    let inner_res = inner.call(inner_req).await.map_err(|e| GatewayError::Internal(e.into()))?;

    encapsulate_response(inner_res, res_ctx, state.response_capacity).await
}

/// Serialize a plaintext response into BHTTP, pad it to the constant OHTTP
/// payload size, and encapsulate it.
async fn encapsulate_response<ResBody>(
    response: Response<ResBody>,
    res_ctx: ohttp::ServerResponse,
    capacity: usize,
) -> Result<Response<Body>, GatewayError>
where
    ResBody: HttpBody<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    let (parts, body) = response.into_parts();
    let mut bhttp_res = bhttp::Message::response(
        bhttp::StatusCode::try_from(parts.status.as_u16())
            .map_err(|e| GatewayError::Internal(e.into()))?,
    );
    for (name, value) in parts.headers.iter() {
        bhttp_res.put_header(name.as_str(), value.to_str().unwrap_or_default());
    }
    let full_body = body.collect().await.map_err(|e| GatewayError::Internal(e.into()))?.to_bytes();
    bhttp_res.write_content(&full_body);

    let mut bhttp_bytes = Vec::new();
    bhttp_res
        .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes)
        .map_err(|e| GatewayError::Internal(e.into()))?;

    if bhttp_bytes.len() > capacity {
        return Err(GatewayError::ResponseTooLarge);
    }
    bhttp_bytes.resize(capacity, 0);

    let ohttp_res =
        res_ctx.encapsulate(&bhttp_bytes).map_err(|e| GatewayError::Internal(e.into()))?;
    debug_assert_eq!(ohttp_res.len(), ENCAPSULATED_MESSAGE_BYTES, "unexpected OHTTP response size");

    let mut response = Response::new(Body::from(ohttp_res));
    response.headers_mut().insert(CONTENT_TYPE, OHTTP_RES_MEDIA_TYPE);
    Ok(response)
}

/// Serve the gateway's encoded OHTTP key configuration (RFC 9540).
fn serve_keys(state: &GatewayState) -> Result<Response<Body>, GatewayError> {
    let ohttp_keys =
        state.server.config().encode().map_err(|e| GatewayError::Internal(e.into()))?;
    let mut res = Response::new(Body::from(ohttp_keys));
    res.headers_mut().insert(CONTENT_TYPE, OHTTP_KEYS_MEDIA_TYPE);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use axum::http::StatusCode;
    use tower::{service_fn, ServiceExt};

    use super::*;

    /// Inner echo service: reports whether it was reached with the
    /// [`Decapsulated`] marker (via the `x-decap` header) and echoes the body.
    macro_rules! echo_inner {
        () => {
            service_fn(|req: Request<Body>| async move {
                let decapsulated = req.extensions().get::<Decapsulated>().is_some();
                let (_, body) = req.into_parts();
                let bytes = body.collect().await.unwrap().to_bytes();
                let res = Response::builder()
                    .status(StatusCode::OK)
                    .header("x-decap", if decapsulated { "1" } else { "0" })
                    .body(Body::from(bytes))
                    .expect("valid response");
                Ok::<_, Infallible>(res)
            })
        };
    }

    fn test_server() -> ohttp::Server {
        crate::key_config::gen_ohttp_server_config().expect("server config").into()
    }

    async fn body_bytes(res: Response<Body>) -> Bytes {
        res.into_body().collect().await.unwrap().to_bytes()
    }

    #[tokio::test]
    async fn round_trip_decapsulates_dispatches_and_encapsulates() {
        let server = test_server();
        let mut key_config = server.config().clone();
        let svc = OhttpGatewayLayer::new(server, SentinelTag::new([7u8; 32])).layer(echo_inner!());

        // Encapsulate a plaintext request as an OHTTP client would.
        let mut bhttp_req_msg = bhttp::Message::request(
            b"POST".to_vec(),
            b"https".to_vec(),
            b"example.com".to_vec(),
            b"/mailbox".to_vec(),
        );
        bhttp_req_msg.write_content(b"ping");
        let mut bhttp_req = Vec::new();
        bhttp_req_msg.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_req).unwrap();

        let ctx = ohttp::ClientRequest::from_config(&mut key_config).unwrap();
        let (encapsulated, client_response) = ctx.encapsulate(&bhttp_req).unwrap();

        let req = Request::builder()
            .method(Method::POST)
            .uri("/.well-known/ohttp-gateway")
            .body(Body::from(encapsulated))
            .unwrap();
        let res = svc.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(CONTENT_TYPE).unwrap(), "message/ohttp-res");

        // Decapsulate the response and confirm the inner service saw a marked
        // request and echoed the body.
        let ohttp_res = body_bytes(res).await;
        let bhttp_res = client_response.decapsulate(&ohttp_res).unwrap();
        let msg = bhttp::Message::read_bhttp(&mut Cursor::new(bhttp_res)).unwrap();
        assert!(msg.control().status() == Some(bhttp::StatusCode::OK));
        assert_eq!(
            msg.header()
                .fields()
                .iter()
                .find(|f| f.name() == b"x-decap".as_slice())
                .map(|f| f.value()),
            Some(b"1".as_slice()),
            "inner service must observe the Decapsulated marker"
        );
        assert_eq!(msg.content(), b"ping");
    }

    #[tokio::test]
    async fn self_loop_request_is_forbidden() {
        let tag = SentinelTag::new([9u8; 32]);
        let svc = OhttpGatewayLayer::new(test_server(), tag).layer(echo_inner!());

        let req = Request::builder()
            .method(Method::POST)
            .uri("/.well-known/ohttp-gateway")
            .header(sentinel::HEADER_NAME, tag.to_header_value())
            .body(Body::from(vec![0u8; 64]))
            .unwrap();
        let res = svc.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn serves_encoded_key_config() {
        let server = test_server();
        let expected = server.config().encode().unwrap();
        let svc = OhttpGatewayLayer::new(server, SentinelTag::new([0u8; 32])).layer(echo_inner!());

        for path in ["/ohttp-keys", "/.well-known/ohttp-gateway"] {
            let req = Request::builder().method(Method::GET).uri(path).body(Body::empty()).unwrap();
            let res = svc.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            assert_eq!(res.headers().get(CONTENT_TYPE).unwrap(), "application/ohttp-keys");
            assert_eq!(body_bytes(res).await.as_ref(), expected.as_slice());
        }
    }

    #[tokio::test]
    async fn allowed_purposes_probe_passes_through() {
        let svc =
            OhttpGatewayLayer::new(test_server(), SentinelTag::new([0u8; 32])).layer(echo_inner!());
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/ohttp-gateway?allowed_purposes")
            .body(Body::empty())
            .unwrap();
        let res = svc.oneshot(req).await.unwrap();

        // Reaches the inner service (unmarked), rather than returning key config.
        assert_eq!(res.headers().get("x-decap").unwrap(), "0");
    }

    #[tokio::test]
    async fn non_ohttp_request_passes_through_unmarked() {
        let svc =
            OhttpGatewayLayer::new(test_server(), SentinelTag::new([0u8; 32])).layer(echo_inner!());
        let req =
            Request::builder().method(Method::GET).uri("/health").body(Body::empty()).unwrap();
        let res = svc.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("x-decap").unwrap(),
            "0",
            "pass-through requests must not carry the Decapsulated marker"
        );
        assert_eq!(res.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
    }
}

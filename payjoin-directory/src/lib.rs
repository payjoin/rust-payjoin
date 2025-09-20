use std::str::FromStr;

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use payjoin::directory::{ShortId, ShortIdError, ENCAPSULATED_MESSAGE_BYTES};
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
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

#[derive(Clone)]
pub struct AppState {
    pool: DbPool,
    ohttp: ohttp::Server,
    metrics: Metrics,
}

impl AppState {
    pub fn new(pool: DbPool, ohttp: ohttp::Server, metrics: Metrics) -> Self {
        Self { pool, ohttp, metrics }
    }

    pub fn main_router(self) -> Router {
        Router::new()
            .route("/.well-known/ohttp-gateway", post(handle_ohttp_gateway))
            .route("/.well-known/ohttp-gateway", get(handle_ohttp_gateway_get))
            .route("/", post(handle_ohttp_gateway))
            .route("/ohttp-keys", get(get_ohttp_keys))
            .route("/{id}", post(post_fallback_v1))
            .route("/health", get(health_check))
            .route("/", get(handle_directory_home_path))
            .layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
            .with_state(self)
    }

    pub async fn serve_tcp(self, listener: tokio::net::TcpListener) -> Result<(), BoxError> {
        let router = self.main_router();
        axum::serve(listener, router).await?;
        Ok(())
    }

    #[cfg(feature = "_manual-tls")]
    pub async fn serve_tls(
        self,
        listener: tokio::net::TcpListener,
        cert_key: (Vec<u8>, Vec<u8>),
    ) -> Result<(), BoxError> {
        let (cert, key) = cert_key;
        let config = RustlsConfig::from_der(vec![cert], key).await?;

        let router = self.main_router();
        axum_server::from_tcp_rustls(listener.into_std()?, config)
            .serve(router.into_make_service())
            .await?;

        Ok(())
    }
}
async fn handle_ohttp_gateway(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Response, HandlerError> {
    let (bhttp_req, res_ctx) =
        state.ohttp.decapsulate(&body).map_err(|e| HandlerError::OhttpKeyRejection(e.into()))?;

    let mut cursor = std::io::Cursor::new(bhttp_req);
    let req =
        bhttp::Message::read_bhttp(&mut cursor).map_err(|e| HandlerError::BadRequest(e.into()))?;

    let uri = Uri::builder()
        .scheme(req.control().scheme().unwrap_or_default())
        .authority(req.control().authority().unwrap_or_default())
        .path_and_query(req.control().path().unwrap_or_default())
        .build()
        .map_err(|e| HandlerError::BadRequest(e.into()))?;

    let body_content = req.content().to_vec();
    let req_method = std::str::from_utf8(req.control().method().unwrap_or_default())?;

    let response = handle_v2_request(&state, &uri, req_method, Bytes::from(body_content)).await?;

    let mut bhttp_res = bhttp::Message::response(
        bhttp::StatusCode::try_from(response.status().as_u16())
            .map_err(|e| HandlerError::InternalServerError(e.into()))?,
    );

    for (name, value) in response.headers().iter() {
        bhttp_res.put_header(name.as_str(), value.to_str().unwrap_or_default());
    }

    let (_, body) = response.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;

    bhttp_res.write_content(&body_bytes);
    let mut bhttp_bytes = Vec::new();
    bhttp_res
        .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes)
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;

    bhttp_bytes.resize(BHTTP_REQ_BYTES, 0);
    let ohttp_res = res_ctx
        .encapsulate(&bhttp_bytes)
        .map_err(|e| HandlerError::InternalServerError(e.into()))?;
    assert!(ohttp_res.len() == ENCAPSULATED_MESSAGE_BYTES, "Unexpected OHTTP response size");
    Ok((StatusCode::OK, ohttp_res).into_response())
}

async fn handle_v2_request(
    state: &AppState,
    uri: &Uri,
    method: &str,
    body: Bytes,
) -> Result<Response, HandlerError> {
    let path = uri.path();
    let path_segments = path.split('/').collect::<Vec<&str>>();
    debug!("path_segments: {:?}", path_segments);

    match (method, path_segments.as_slice()) {
        ("POST", &["", id]) => post_mailbox(state, id, body).await,
        ("GET", &["", id]) => get_mailbox(state, id).await,
        ("PUT", &["", id]) => put_payjoin_v1(state, id, body).await,
        _ => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn get_mailbox(state: &AppState, mailbox_id: &str) -> Result<Response, HandlerError> {
    trace!("get_mailbox");
    let mailbox_id = ShortId::from_str(&mailbox_id)?;

    match state.pool.peek_default(&mailbox_id).await {
        Ok(buffered_req) => Ok((StatusCode::OK, buffered_req).into_response()),
        Err(e) => match e {
            db::Error::Redis(re) => {
                error!("Redis error: {}", re);
                Err(HandlerError::InternalServerError(anyhow::Error::msg("Internal server error")))
            }
            db::Error::Timeout(_) => Ok(StatusCode::ACCEPTED.into_response()),
        },
    }
}

async fn post_mailbox(
    state: &AppState,
    mailbox_id: &str,
    body: Bytes,
) -> Result<Response, HandlerError> {
    let none_response = StatusCode::OK.into_response();
    trace!("post_mailbox");

    let mailbox_id = ShortId::from_str(&mailbox_id)?;

    if body.len() > V1_MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    match state.pool.push_default(&mailbox_id, body.to_vec()).await {
        Ok(_) => Ok(none_response),
        Err(e) => Err(HandlerError::InternalServerError(e.into())),
    }
}

async fn put_payjoin_v1(
    state: &AppState,
    mailbox_id: &str,
    body: Bytes,
) -> Result<Response, HandlerError> {
    trace!("put_payjoin_v1");
    let none_response = StatusCode::OK.into_response();

    let mailbox_id = ShortId::from_str(&mailbox_id)?;

    if body.len() > V1_MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    match state.pool.push_v1(&mailbox_id, body.to_vec()).await {
        Ok(_) => Ok(none_response),
        Err(e) => Err(HandlerError::InternalServerError(e.into())),
    }
}

async fn post_fallback_v1(
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    uri: Uri,
    body: Bytes,
) -> Result<Response, HandlerError> {
    trace!("post_fallback_v1");

    let none_response = (StatusCode::SERVICE_UNAVAILABLE, V1_UNAVAILABLE_RES_JSON);
    let bad_request_body_res = (StatusCode::BAD_REQUEST, V1_REJECT_RES_JSON);

    let body_str = match String::from_utf8(body.to_vec()) {
        Ok(body_str) => body_str,
        Err(_) => return Ok(bad_request_body_res.into_response()),
    };

    let query = uri.query().unwrap_or_default();

    let v2_compact_body = format!("{body_str}\n{query}");
    let id = ShortId::from_str(&mailbox_id)?;

    state
        .pool
        .push_default(&id, v2_compact_body.clone().into_bytes())
        .await
        .map_err(|e| HandlerError::BadRequest(e.into()))?;

    match state.pool.peek_v1(&id).await {
        Ok(buffered_req) => Ok((StatusCode::OK, buffered_req).into_response()),
        Err(e) => match e {
            db::Error::Redis(re) => {
                error!("Redis error: {}", re);
                Err(HandlerError::InternalServerError(anyhow::Error::msg("Internal server error")))
            }
            db::Error::Timeout(_) => Ok(none_response.into_response()),
        },
    }
}
async fn get_ohttp_keys(State(state): State<AppState>) -> Result<Response, HandlerError> {
    get_ohttp_keys_func(&state).await
}

// Since only routers can inject state , only handlers that are called by the router can access the state
// This is both called  by router and in another handler . So we need to pass the state as a parameter to the handler
async fn get_ohttp_keys_func(state: &AppState) -> Result<Response, HandlerError> {
    let ohttp_keys =
        state.ohttp.config().encode().map_err(|e| HandlerError::InternalServerError(e.into()))?;

    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/ohttp-keys"));
    Ok((StatusCode::OK, headers, ohttp_keys).into_response())
}

async fn get_ohttp_allowed_purposes() -> Response {
    // Encode the magic string in the same format as a TLS ALPN protocol list (a
    // U16BE length encoded list of U8 length encoded strings).
    //
    // The string is just "BIP77" followed by a UUID, that signals to relays
    // that this OHTTP gateway will accept any requests associated with this
    // purpose.
    let body = Bytes::from_static(b"\x00\x01\x2aBIP77 454403bb-9f7b-4385-b31f-acd2dae20b7e");
    let mut headers = HeaderMap::new();
    headers
        .insert("content-type", HeaderValue::from_static("application/x-ohttp-allowed-purposes"));
    (StatusCode::OK, headers, body).into_response()
}

async fn handle_ohttp_gateway_get(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Response, HandlerError> {
    match params.get("allowed_purposes") {
        Some(_) => Ok(get_ohttp_allowed_purposes().await),
        None => get_ohttp_keys_func(&state).await,
    }
}

async fn handle_metrics(State(state): State<AppState>) -> Response {
    match state.metrics.generate_metrics() {
        Ok(metrics_data) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-type",
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            (StatusCode::OK, headers, metrics_data).into_response()
        }
        Err(e) => {
            error!("failed to generate metrics: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Error generating metrics").into_response()
        }
    }
}

async fn health_check() -> Response { StatusCode::OK.into_response() }

async fn handle_directory_home_path() -> Response {
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

    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("text/html"));
    (StatusCode::OK, headers, html).into_response()
}

#[derive(Debug)]
enum HandlerError {
    PayloadTooLarge,
    InternalServerError(anyhow::Error),
    //ServiceUnavailable(anyhow::Error),
    // SenderGone(anyhow::Error),
    OhttpKeyRejection(anyhow::Error),
    BadRequest(anyhow::Error),
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
        match self {
            HandlerError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
            HandlerError::InternalServerError(e) => {
                error!("Internal server error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            /* *
            HandlerError::ServiceUnavailable(e) => {
                error!("Service unavailable: {}", e);
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
            HandlerError::SenderGone(e) => {
                warn!("Sender gone: {}", e);
                StatusCode::GONE.into_response()
            }
            */
            HandlerError::OhttpKeyRejection(e) => {
                const OHTTP_KEY_REJECTION_RES_JSON: &str = r#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key", "title": "key identifier unknown"}"#;
                warn!("Bad request: Key configuration rejected: {}", e);

                let mut headers = HeaderMap::new();
                headers
                    .insert("content-type", HeaderValue::from_static("application/problem+json"));
                (StatusCode::BAD_REQUEST, headers, OHTTP_KEY_REJECTION_RES_JSON).into_response()
            }

            HandlerError::BadRequest(e) => {
                warn!("Bad request: {}", e);
                StatusCode::BAD_REQUEST.into_response()
            }
        }
    }
}

impl From<axum::http::Error> for HandlerError {
    fn from(e: axum::http::Error) -> Self { HandlerError::InternalServerError(e.into()) }
}

impl From<ShortIdError> for HandlerError {
    fn from(_: ShortIdError) -> Self {
        HandlerError::BadRequest(anyhow::anyhow!("mailbox ID must be 13 bech32 characters"))
    }
}
impl From<std::str::Utf8Error> for HandlerError {
    fn from(e: std::str::Utf8Error) -> Self {
        HandlerError::BadRequest(anyhow::anyhow!("Invalid UTF-8 in request method: {}", e))
    }
}

pub async fn serve_metrics_tcp(
    service: AppState,
    listener: tokio::net::TcpListener,
) -> Result<(), BoxError> {
    let router = Router::new().route("/metrics", get(handle_metrics)).with_state(service);

    axum::serve(listener, router).await?;
    Ok(())
}

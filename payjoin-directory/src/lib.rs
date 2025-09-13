use std::pin::Pin;
use std::str::FromStr;

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
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
            .route("/health", get(health_check))
            .route("/", get(handle_directory_home_path))
            .layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
            .with_state(self)
    }
}


async fn get_ohttp_allowed_purposes() -> Response {
        // Encode the magic string in the same format as a TLS ALPN protocol list (a
        // U16BE length encoded list of U8 length encoded strings).
        //
        // The string is just "BIP77" followed by a UUID, that signals to relays
        // that this OHTTP gateway will accept any requests associated with this
        // purpose.
        let body  = Bytes::from_static(b"\x00\x01\x2aBIP77 454403bb-9f7b-4385-b31f-acd2dae20b7e");
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/x-ohttp-allowed-purposes"));
        (StatusCode::OK, headers,body).into_response()
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

pub async fn serve_metrics_tcp(
    service: AppState,
    listener: tokio::net::TcpListener,
) -> Result<(), BoxError> {
    let router = Router::new().route("/metrics", get(handle_metrics)).with_state(service);

    axum::serve(listener, router).await?;
    Ok(())
}

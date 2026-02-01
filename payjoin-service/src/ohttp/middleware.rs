use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode, Uri};
use ohttp_relay::SentinelTag;
use tower::{Layer, Service};
use tracing::{debug, warn};

const CHACHA20_POLY1305_NONCE_LEN: usize = 32;
const POLY1305_TAG_SIZE: usize = 16;
const ENCAPSULATED_MESSAGE_BYTES: usize = 65536;
const BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (CHACHA20_POLY1305_NONCE_LEN + POLY1305_TAG_SIZE);

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct OhttpGatewayConfig {
    pub ohttp_server: ohttp::Server,
    pub sentinel_tag: SentinelTag,
}

impl OhttpGatewayConfig {
    pub fn new(ohttp_server: ohttp::Server, sentinel_tag: SentinelTag) -> Self {
        Self { ohttp_server, sentinel_tag }
    }
}

#[derive(Clone)]
pub struct OhttpGatewayLayer {
    config: OhttpGatewayConfig,
}

impl OhttpGatewayLayer {
    pub fn new(config: OhttpGatewayConfig) -> Self { Self { config } }
}

impl<S> Layer<S> for OhttpGatewayLayer {
    type Service = OhttpGatewayMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OhttpGatewayMiddleware { inner, config: self.config.clone() }
    }
}

#[derive(Clone)]
pub struct OhttpGatewayMiddleware<S> {
    inner: S,
    config: OhttpGatewayConfig,
}

type OhttpFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = Result<Response<BoxBody<Bytes, hyper::Error>>, OhttpGatewayError>,
            > + Send,
    >,
>;

impl<S, B> Service<Request<B>> for OhttpGatewayMiddleware<S>
where
    S: Service<
            Request<BoxBody<Bytes, hyper::Error>>,
            Response = Response<BoxBody<Bytes, hyper::Error>>,
        > + Clone
        + Send
        + 'static,
    S::Error: Into<BoxError> + 'static,
    S::Future: Send + 'static,
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = Response<BoxBody<Bytes, hyper::Error>>;
    type Error = OhttpGatewayError;
    type Future = OhttpFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|e| OhttpGatewayError::InnerService(e.into()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        let config = self.config.clone();

        Box::pin(async move {
            if let Some(header_value) =
                req.headers().get(ohttp_relay::sentinel::HEADER_NAME).and_then(|v| v.to_str().ok())
            {
                if ohttp_relay::sentinel::is_self_loop(&config.sentinel_tag, header_value) {
                    warn!("Rejected OHTTP request from same-instance relay");
                    return Ok(error_response(
                        StatusCode::FORBIDDEN,
                        "Relay and gateway must be operated by different entities",
                    ));
                }
            }

            let (decapsulated_req, res_ctx) =
                match decapsulate_ohttp_request(req, &config.ohttp_server).await {
                    Ok(result) => result,
                    Err(e) => {
                        debug!("OHTTP decapsulation failed: {}", e);
                        return Ok(e.to_response());
                    }
                };

            let response = inner
                .call(decapsulated_req)
                .await
                .map_err(|e| OhttpGatewayError::InnerService(e.into()))?;

            match encapsulate_ohttp_response(response, res_ctx).await {
                Ok(encapsulated_response) => Ok(encapsulated_response),
                Err(e) => {
                    debug!("OHTTP encapsulation failed: {}", e);
                    Ok(e.to_response())
                }
            }
        })
    }
}

async fn decapsulate_ohttp_request<B>(
    req: Request<B>,
    ohttp_server: &ohttp::Server,
) -> Result<(Request<BoxBody<Bytes, hyper::Error>>, ohttp::ServerResponse), OhttpGatewayError>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    let ohttp_body = req
        .into_body()
        .collect()
        .await
        .map_err(|e| OhttpGatewayError::BadRequest(format!("Failed to read body: {}", e.into())))?
        .to_bytes();

    let (bhttp_req, res_ctx) = ohttp_server.decapsulate(&ohttp_body).map_err(|e| {
        OhttpGatewayError::OhttpKeyRejection(format!("OHTTP decapsulation failed: {}", e))
    })?;

    let mut cursor = std::io::Cursor::new(bhttp_req);
    let bhttp_msg = bhttp::Message::read_bhttp(&mut cursor)
        .map_err(|e| OhttpGatewayError::BadRequest(format!("Invalid BHTTP: {}", e)))?;

    let uri = Uri::builder()
        .scheme(bhttp_msg.control().scheme().unwrap_or_default())
        .authority(bhttp_msg.control().authority().unwrap_or_default())
        .path_and_query(bhttp_msg.control().path().unwrap_or_default())
        .build()
        .map_err(|e| OhttpGatewayError::BadRequest(format!("Invalid URI: {}", e)))?;

    let body = bhttp_msg.content().to_vec();
    let mut http_req =
        Request::builder().uri(uri).method(bhttp_msg.control().method().unwrap_or_default());

    for header in bhttp_msg.header().fields() {
        http_req = http_req.header(header.name(), header.value());
    }

    let request = http_req.body(full(body)).map_err(|e| {
        OhttpGatewayError::InternalServerError(format!("Failed to build request: {}", e))
    })?;

    Ok((request, res_ctx))
}

async fn encapsulate_ohttp_response(
    response: Response<BoxBody<Bytes, hyper::Error>>,
    res_ctx: ohttp::ServerResponse,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, OhttpGatewayError> {
    let (parts, body) = response.into_parts();

    let mut bhttp_res =
        bhttp::Message::response(bhttp::StatusCode::try_from(parts.status.as_u16()).map_err(
            |e| OhttpGatewayError::InternalServerError(format!("Invalid status code: {}", e)),
        )?);

    for (name, value) in parts.headers.iter() {
        bhttp_res.put_header(name.as_str(), value.to_str().unwrap_or_default());
    }

    let full_body = body
        .collect()
        .await
        .map_err(|e| {
            OhttpGatewayError::InternalServerError(format!("Failed to collect body: {}", e))
        })?
        .to_bytes();
    bhttp_res.write_content(&full_body);

    let mut bhttp_bytes = Vec::new();
    bhttp_res.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes).map_err(|e| {
        OhttpGatewayError::InternalServerError(format!("BHTTP serialization failed: {}", e))
    })?;

    bhttp_bytes.resize(BHTTP_REQ_BYTES, 0);

    let ohttp_res = res_ctx.encapsulate(&bhttp_bytes).map_err(|e| {
        OhttpGatewayError::InternalServerError(format!("OHTTP encapsulation failed: {}", e))
    })?;

    assert!(
        ohttp_res.len() == ENCAPSULATED_MESSAGE_BYTES,
        "Unexpected OHTTP response size: {} != {}",
        ohttp_res.len(),
        ENCAPSULATED_MESSAGE_BYTES
    );

    Ok(Response::new(full(ohttp_res)))
}

#[derive(Debug)]
pub enum OhttpGatewayError {
    BadRequest(String),
    OhttpKeyRejection(String),
    InternalServerError(String),
    InnerService(BoxError),
}

impl OhttpGatewayError {
    fn to_response(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        let (status, message) = match self {
            OhttpGatewayError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            OhttpGatewayError::OhttpKeyRejection(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            OhttpGatewayError::InternalServerError(msg) =>
                (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str()),
            OhttpGatewayError::InnerService(_) =>
                (StatusCode::INTERNAL_SERVER_ERROR, "Inner service error"),
        };

        error_response(status, message)
    }
}

impl std::fmt::Display for OhttpGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OhttpGatewayError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            OhttpGatewayError::OhttpKeyRejection(msg) => write!(f, "OHTTP key rejection: {}", msg),
            OhttpGatewayError::InternalServerError(msg) => {
                write!(f, "Internal server error: {}", msg)
            }
            OhttpGatewayError::InnerService(e) => write!(f, "Inner service error: {}", e),
        }
    }
}

impl std::error::Error for OhttpGatewayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OhttpGatewayError::InnerService(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

fn error_response(status: StatusCode, message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder().status(status).body(full(Bytes::from(message.to_string()))).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ohttp_keys() -> (ohttp::KeyConfig, ohttp::Server) {
        use payjoin_test_utils::{KEM, KEY_ID, SYMMETRIC};

        let server_config = ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC))
            .expect("Failed to create test OHTTP config");

        let server =
            ohttp::Server::new(server_config.clone()).expect("Failed to create OHTTP server");

        (server_config, server)
    }

    #[test]
    fn test_middleware_layer_creation() {
        let (_config, server) = create_test_ohttp_keys();
        let sentinel_tag = SentinelTag::new([0u8; 32]);

        let ohttp_config = OhttpGatewayConfig::new(server, sentinel_tag);
        let layer = OhttpGatewayLayer::new(ohttp_config);

        assert!(std::mem::size_of_val(&layer) > 0);
    }

    #[test]
    fn test_config_clone() {
        let (_config, server) = create_test_ohttp_keys();
        let sentinel_tag = SentinelTag::new([0u8; 32]);

        let config1 = OhttpGatewayConfig::new(server.clone(), sentinel_tag);
        let config2 = config1.clone();

        assert!(std::mem::size_of_val(&config2) > 0);
    }

    #[test]
    fn test_error_types() {
        let err = OhttpGatewayError::BadRequest("test".to_string());
        assert!(err.to_string().contains("Bad request"));

        let err = OhttpGatewayError::OhttpKeyRejection("test".to_string());
        assert!(err.to_string().contains("OHTTP key rejection"));

        let err = OhttpGatewayError::InternalServerError("test".to_string());
        assert!(err.to_string().contains("Internal server error"));
    }
}

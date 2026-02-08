use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ohttp_relay::gateway_helpers::{decapsulate_ohttp_request, encapsulate_ohttp_response};
use ohttp_relay::sentinel::{self, SentinelTag};
use tracing::{debug, warn};

/// Configuration for the OHTTP gateway middleware
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

pub async fn ohttp_gateway(
    State(config): State<OhttpGatewayConfig>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(header_value) =
        req.headers().get(sentinel::HEADER_NAME).and_then(|v| v.to_str().ok())
    {
        if sentinel::is_self_loop(&config.sentinel_tag, header_value) {
            warn!("Rejected OHTTP request from same-instance relay");
            return (
                StatusCode::FORBIDDEN,
                "Relay and gateway must be operated by different entities",
            )
                .into_response();
        }
    }

    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };

    let (decapsulated_req, res_ctx) =
        match decapsulate_ohttp_request(&body_bytes, &config.ohttp_server) {
            Ok(result) => result,
            Err(e) => {
                debug!("OHTTP decapsulation failed: {}", e);
                return match e {
                    ohttp_relay::gateway_helpers::GatewayError::OhttpKeyRejection(_) =>
                        ohttp_key_rejection_response(),
                    ohttp_relay::gateway_helpers::GatewayError::BadRequest(msg) =>
                        (StatusCode::BAD_REQUEST, msg).into_response(),
                    ohttp_relay::gateway_helpers::GatewayError::InternalServerError(msg) =>
                        (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
                };
            }
        };

    let uri = match decapsulated_req.uri.parse::<axum::http::Uri>() {
        Ok(uri) => uri,
        Err(e) => {
            debug!("Invalid URI in BHTTP: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid URI").into_response();
        }
    };

    let method =
        decapsulated_req.method.parse::<axum::http::Method>().unwrap_or(axum::http::Method::GET);

    let mut new_parts = parts;
    new_parts.uri = uri;
    new_parts.method = method;

    for (name, value) in decapsulated_req.headers {
        if let Ok(header_name) = name.parse::<axum::http::HeaderName>() {
            if let Ok(header_value) = value.parse::<axum::http::HeaderValue>() {
                new_parts.headers.insert(header_name, header_value);
            }
        }
    }

    let inner_request = Request::from_parts(new_parts, Body::from(decapsulated_req.body));

    let response = next.run(inner_request).await;

    let (parts, body) = response.into_parts();
    let response_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read response body")
                .into_response();
        }
    };

    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (name.as_str().to_string(), value.to_str().unwrap_or_default().to_string())
        })
        .collect();

    let ohttp_response =
        match encapsulate_ohttp_response(parts.status.as_u16(), headers, response_bytes, res_ctx) {
            Ok(bytes) => bytes,
            Err(e) => {
                debug!("OHTTP encapsulation failed: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to encapsulate response")
                    .into_response();
            }
        };

    (StatusCode::OK, ohttp_response).into_response()
}

fn ohttp_key_rejection_response() -> Response {
    const OHTTP_KEY_REJECTION_JSON: &str = r#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key", "title": "key identifier unknown"}"#;

    (
        StatusCode::BAD_REQUEST,
        [("content-type", "application/problem+json")],
        OHTTP_KEY_REJECTION_JSON,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ohttp_server() -> ohttp::Server {
        use payjoin_test_utils::{KEM, KEY_ID, SYMMETRIC};

        let server_config = ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC))
            .expect("Failed to create test OHTTP config");

        ohttp::Server::new(server_config).expect("Failed to create OHTTP server")
    }

    #[test]
    fn test_config_creation() {
        let server = create_test_ohttp_server();
        let sentinel_tag = SentinelTag::new([0u8; 32]);

        let config = OhttpGatewayConfig::new(server, sentinel_tag);
        assert!(std::mem::size_of_val(&config) > 0);
    }

    #[test]
    fn test_config_clone() {
        let server = create_test_ohttp_server();
        let sentinel_tag = SentinelTag::new([0u8; 32]);

        let config1 = OhttpGatewayConfig::new(server, sentinel_tag);
        let config2 = config1.clone();

        assert!(std::mem::size_of_val(&config2) > 0);
    }
}

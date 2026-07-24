use axum::body::Body;
use axum::http::header::{HeaderValue, CONTENT_TYPE};
use axum::http::{Response, StatusCode};
use tracing::{error, warn};

use super::BoxError;

/// RFC 9540 problem document returned when the client encapsulated under a key
/// configuration this gateway does not recognize.
const OHTTP_KEY_REJECTION_RES_JSON: &str = r#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key", "title": "key identifier unknown"}"#;

/// Transport-level failures of the OHTTP gateway boundary.
///
/// These describe problems decapsulating, dispatching, or encapsulating an
/// OHTTP exchange. They are always rendered into an HTTP response; the
/// gateway never surfaces an error to the connection.
#[derive(Debug)]
pub(crate) enum GatewayError {
    /// The request carried this instance's sentinel tag, meaning the relay and
    /// gateway are the same deployment. Rejected to preserve the trust split.
    SelfLoop,
    /// The encapsulated request could not be read or parsed.
    BadRequest(BoxError),
    /// The key identifier in the encapsulated request is unknown to this gateway.
    OhttpKeyRejection(BoxError),
    /// The decapsulated response is larger than a single OHTTP message can carry.
    ResponseTooLarge,
    /// An unexpected failure while (de)serializing or encapsulating.
    Internal(BoxError),
}

impl GatewayError {
    pub(crate) fn into_response(self) -> Response<Body> {
        let mut res = Response::new(Body::empty());
        match self {
            GatewayError::SelfLoop => {
                warn!("Forbidden: relay and gateway must be operated by different entities");
                *res.status_mut() = StatusCode::FORBIDDEN;
            }
            GatewayError::BadRequest(e) => {
                warn!("Bad request: {e}");
                *res.status_mut() = StatusCode::BAD_REQUEST;
            }
            GatewayError::OhttpKeyRejection(e) => {
                warn!("Key configuration rejected: {e}");
                *res.status_mut() = StatusCode::BAD_REQUEST;
                res.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
                *res.body_mut() = Body::from(OHTTP_KEY_REJECTION_RES_JSON);
            }
            GatewayError::ResponseTooLarge => {
                error!("Decapsulated response exceeds OHTTP message capacity");
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            }
            GatewayError::Internal(e) => {
                error!("Internal server error: {e}");
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
        res
    }
}

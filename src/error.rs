use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::header::{HeaderValue, RETRY_AFTER};
use hyper::{Response, StatusCode};
use tracing::error;

use crate::{empty, full};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Error {
    BadGateway,
    MethodNotAllowed,
    UnsupportedMediaType,
    BadRequest(String),
    NotFound,
    InternalServerError(BoxError),
    Unavailable(Duration),
}

impl Error {
    pub fn to_response(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        let mut res = Response::new(empty());
        match self {
            Self::UnsupportedMediaType => *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::BadGateway => *res.status_mut() = StatusCode::BAD_GATEWAY,
            Self::MethodNotAllowed => *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED,
            Self::BadRequest(e) => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                *res.body_mut() = full(e.to_string()).boxed();
            }
            Self::NotFound => *res.status_mut() = StatusCode::NOT_FOUND,
            Self::InternalServerError(internal_error) => {
                error!("Internal server error: {}", internal_error);
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            }
            Self::Unavailable(max_age) => {
                *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                res.headers_mut().append(
                    RETRY_AFTER,
                    HeaderValue::from_str(&max_age.as_secs().to_string())
                        .expect("header value should always be valid"),
                );
            }
        };
        res
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnsupportedMediaType => write!(f, "Unsupported media type"),
            Self::BadGateway => write!(f, "Bad gateway"),
            Self::MethodNotAllowed => write!(f, "Method not allowed"),
            Self::BadRequest(e) => write!(f, "Bad request: {}", e),
            Self::NotFound => write!(f, "Not found"),
            Self::InternalServerError(e) => write!(f, "Internal server error: {}", e),
            Self::Unavailable(_) => write!(f, "Service unavailable"),
        }
    }
}

impl std::error::Error for Error {}

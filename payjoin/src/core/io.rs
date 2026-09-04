//! IO-related types and functions. Specifically, fetching OHTTP keys from a payjoin directory.
use std::time::Duration;

use http::header::ACCEPT;
use reqwest::{Client, Proxy};

use crate::into_url::IntoUrl;
use crate::OhttpKeys;

/// Upper bound on the size of an OHTTP key configuration response body.
///
/// Derived from the Ohttp Key Config (RFC 9458) wire format: `key_id(1) + kem_id(2) +
/// K-256 public key(65) + cipher suite vector length(2) + cipher suites` where
/// the suite vector is u16-length-bounded (at most 65532 bytes of suites). Any
/// larger response cannot decode and is rejected before being fully buffered
/// to prevent memory exhaustion from a hostile payjoin directory.
pub(crate) const MAX_OHTTP_KEYS_BODY_LEN: usize = 1 + 2 + 65 + 2 + u16::MAX as usize - 3;

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNECT method proxy to request the ohttp keys from a payjoin
///   directory.  Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
pub async fn fetch_ohttp_keys(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
) -> Result<OhttpKeys, Error> {
    let ohttp_keys_url = payjoin_directory.into_url()?.join("/.well-known/ohttp-gateway")?;
    let proxy = Proxy::all(ohttp_relay.into_url()?.as_str())?;
    let client = Client::builder().proxy(proxy).http1_only().build()?;
    let res = client
        .get(ohttp_keys_url.as_str())
        .timeout(Duration::from_secs(10))
        .header(ACCEPT, "application/ohttp-keys")
        .send()
        .await?;
    parse_ohttp_keys_response(res).await
}

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNECT method proxy to request the ohttp keys from a payjoin
///   directory.  Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
///
/// * `cert_der`: The DER-encoded certificate to use for local HTTPS connections.
#[cfg(feature = "_manual-tls")]
pub async fn fetch_ohttp_keys_with_cert(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
    cert_der: &[u8],
) -> Result<OhttpKeys, Error> {
    let ohttp_keys_url = payjoin_directory.into_url()?.join("/.well-known/ohttp-gateway")?;
    let proxy = Proxy::all(ohttp_relay.into_url()?.as_str())?;
    let client = Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der)?)
        .proxy(proxy)
        .http1_only()
        .build()?;
    let res = client
        .get(ohttp_keys_url.as_str())
        .timeout(Duration::from_secs(10))
        .header(ACCEPT, "application/ohttp-keys")
        .send()
        .await?;
    parse_ohttp_keys_response(res).await
}

async fn parse_ohttp_keys_response(res: reqwest::Response) -> Result<OhttpKeys, Error> {
    if !res.status().is_success() {
        return Err(Error::UnexpectedStatusCode(res.status()));
    }

    if let Some(len) = res.content_length() {
        if len > MAX_OHTTP_KEYS_BODY_LEN as u64 {
            return Err(Error::OhttpKeysBodyTooLarge(len));
        }
    }

    let mut body = Vec::new();
    let mut res = res;
    while let Some(chunk) = res.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_OHTTP_KEYS_BODY_LEN {
            return Err(Error::OhttpKeysBodyTooLarge(body.len() as u64));
        }
    }

    OhttpKeys::decode(&body).map_err(|e| {
        Error::Internal(InternalError(InternalErrorInner::InvalidOhttpKeys(e.to_string())))
    })
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// When the payjoin directory returns an unexpected status code
    UnexpectedStatusCode(http::StatusCode),
    /// When the payjoin directory returns an OHTTP key configuration body
    /// larger than `MAX_OHTTP_KEYS_BODY_LEN`
    OhttpKeysBodyTooLarge(u64),
    /// Internal errors that should not be pattern matched by users
    #[doc(hidden)]
    Internal(InternalError),
}

#[derive(Debug)]
pub struct InternalError(InternalErrorInner);

#[derive(Debug)]
enum InternalErrorInner {
    ParseUrl(crate::into_url::Error),
    Reqwest(reqwest::Error),
    Io(std::io::Error),
    #[cfg(feature = "_manual-tls")]
    Rustls(rustls::Error),
    InvalidOhttpKeys(String),
}

impl From<crate::core::UrlParseError> for Error {
    fn from(value: crate::core::UrlParseError) -> Self {
        Self::Internal(InternalError(InternalErrorInner::ParseUrl(value.into())))
    }
}

macro_rules! impl_from_error {
    ($from:ty, $to:ident) => {
        impl From<$from> for Error {
            fn from(value: $from) -> Self {
                Self::Internal(InternalError(InternalErrorInner::$to(value)))
            }
        }
    };
}

impl_from_error!(crate::into_url::Error, ParseUrl);
impl_from_error!(reqwest::Error, Reqwest);
impl_from_error!(std::io::Error, Io);
#[cfg(feature = "_manual-tls")]
impl_from_error!(rustls::Error, Rustls);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnexpectedStatusCode(code) => {
                write!(f, "Unexpected status code from payjoin directory: {code}")
            }
            Self::OhttpKeysBodyTooLarge(len) => write!(
                f,
                "OHTTP keys body of {len} bytes exceeds the maximum of {MAX_OHTTP_KEYS_BODY_LEN} bytes"
            ),
            Self::Internal(InternalError(e)) => e.fmt(f),
        }
    }
}

impl std::fmt::Display for InternalErrorInner {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use InternalErrorInner::*;

        match &self {
            Reqwest(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
            Io(e) => e.fmt(f),
            InvalidOhttpKeys(e) => {
                write!(f, "Invalid ohttp keys returned from payjoin directory: {e}")
            }
            #[cfg(feature = "_manual-tls")]
            Rustls(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(InternalError(e)) => e.source(),
            Self::UnexpectedStatusCode(_) => None,
            Self::OhttpKeysBodyTooLarge(_) => None,
        }
    }
}

impl std::error::Error for InternalErrorInner {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalErrorInner::*;

        match self {
            Reqwest(e) => Some(e),
            ParseUrl(e) => Some(e),
            Io(e) => Some(e),
            InvalidOhttpKeys(_) => None,
            #[cfg(feature = "_manual-tls")]
            Rustls(e) => Some(e),
        }
    }
}

impl From<InternalError> for Error {
    fn from(value: InternalError) -> Self { Self::Internal(value) }
}

impl From<InternalErrorInner> for Error {
    fn from(value: InternalErrorInner) -> Self { Self::Internal(InternalError(value)) }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use http::StatusCode;
    use reqwest::Response;

    use super::*;

    fn mock_response(status: StatusCode, body: Vec<u8>) -> Response {
        Response::from(http::response::Response::builder().status(status).body(body).unwrap())
    }

    /// Wraps a body so it reports no exact size, the way a `Transfer-Encoding:
    /// chunked` response does. `reqwest::Response::content_length` reads the
    /// body's size hint rather than a header, so a plain `Vec<u8>` body always
    /// has a known length and never reaches the streaming size check.
    struct UnknownLengthBody(reqwest::Body);

    impl http_body::Body for UnknownLengthBody {
        type Data = <reqwest::Body as http_body::Body>::Data;
        type Error = <reqwest::Body as http_body::Body>::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            Pin::new(&mut self.0).poll_frame(cx)
        }
    }

    /// Builds a 200 response whose body length is unknown up front, forcing
    /// `parse_ohttp_keys_response` through its streaming size check.
    fn mock_chunked_response(body: Vec<u8>) -> Response {
        let body = reqwest::Body::wrap(UnknownLengthBody(reqwest::Body::from(body)));
        let response = Response::from(
            http::response::Response::builder().status(StatusCode::OK).body(body).unwrap(),
        );
        assert_eq!(
            response.content_length(),
            None,
            "chunked mock must have no known length, or the streaming check is never exercised"
        );
        response
    }

    #[tokio::test]
    async fn test_parse_success_response() {
        let valid_keys = payjoin_test_utils::ohttp_key_config_bytes();

        let response = mock_response(StatusCode::OK, valid_keys);
        assert!(parse_ohttp_keys_response(response).await.is_ok(), "expected valid keys response");
    }

    #[tokio::test]
    async fn test_parse_error_status_codes() {
        let error_codes = [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ];

        for status in error_codes {
            let response = mock_response(status, vec![]);
            match parse_ohttp_keys_response(response).await {
                Err(Error::UnexpectedStatusCode(code)) => assert_eq!(code, status),
                result => panic!(
                    "Expected UnexpectedStatusCode error for status code: {status}, got: {result:?}"
                ),
            }
        }
    }

    #[tokio::test]
    async fn test_parse_invalid_keys() {
        // Invalid OHTTP keys (not properly encoded)
        let invalid_keys = vec![1, 2, 3, 4];

        let response = mock_response(StatusCode::OK, invalid_keys);

        assert!(
            matches!(
                parse_ohttp_keys_response(response).await,
                Err(Error::Internal(InternalError(InternalErrorInner::InvalidOhttpKeys(_))))
            ),
            "expected InvalidOhttpKeys error"
        );
    }

    #[tokio::test]
    async fn test_max_body_len_boundary() {
        // number is literal pin of MAX_OHTTP_KEYS_BODY_LEN
        let response = mock_response(StatusCode::OK, vec![0u8; 65602]);
        assert!(
            matches!(
                parse_ohttp_keys_response(response).await,
                Err(Error::Internal(InternalError(InternalErrorInner::InvalidOhttpKeys(_))))
            ),
            "body of exactly MAX_OHTTP_KEYS_BODY_LEN must not be rejected as oversized"
        );
    }

    #[tokio::test]
    async fn test_parse_oversized_body_with_content_length() {
        // number is literal pin of MAX_OHTTP_KEYS_BODY_LEN
        let response = mock_response(StatusCode::OK, vec![0u8; 65602 + 1]);
        assert_eq!(response.content_length(), Some(65602 + 1));

        assert!(
            matches!(
                parse_ohttp_keys_response(response).await,
                Err(Error::OhttpKeysBodyTooLarge(len)) if len == 65602 + 1
            ),
            "expected OhttpKeysBodyTooLarge from the declared length"
        );
    }

    #[tokio::test]
    async fn test_parse_oversized_body_without_content_length() {
        // number is literal pin of MAX_OHTTP_KEYS_BODY_LEN
        let response = mock_chunked_response(vec![0u8; 65602 + 1]);

        assert!(
            matches!(
                parse_ohttp_keys_response(response).await,
                Err(Error::OhttpKeysBodyTooLarge(_))
            ),
            "expected OhttpKeysBodyTooLarge from the streaming check"
        );
    }

    #[tokio::test]
    async fn test_parse_body_without_content_length_at_boundary() {
        // number is literal pin of MAX_OHTTP_KEYS_BODY_LEN
        let response = mock_chunked_response(vec![0u8; 65602]);

        assert!(
            matches!(
                parse_ohttp_keys_response(response).await,
                Err(Error::Internal(InternalError(InternalErrorInner::InvalidOhttpKeys(_))))
            ),
            "streamed body of exactly MAX_OHTTP_KEYS_BODY_LEN must not be rejected as oversized"
        );
    }
}

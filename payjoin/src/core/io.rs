//! IO-related types and functions. Specifically, fetching OHTTP keys from a payjoin directory.
use std::net::SocketAddr;
use std::time::Duration;

use http::header::ACCEPT;
use reqwest::{Client, ClientBuilder, Proxy};

use crate::into_url::IntoUrl;
use crate::{OhttpKeys, Url};

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
    fetch_ohttp_keys_inner(
        ohttp_relay.into_url()?,
        payjoin_directory.into_url()?,
        Client::builder(),
        None,
    )
    .await
}

/// Fetch OHTTP keys through a relay using previously resolved relay addresses.
///
/// The relay URL remains unchanged for proxy and TLS hostname validation while
/// its DNS resolution is overridden with `relay_addresses`.
pub async fn fetch_ohttp_keys_with_relay_addresses(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
    relay_addresses: &[SocketAddr],
) -> Result<OhttpKeys, Error> {
    fetch_ohttp_keys_inner(
        ohttp_relay.into_url()?,
        payjoin_directory.into_url()?,
        Client::builder(),
        Some(relay_addresses),
    )
    .await
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
    fetch_ohttp_keys_inner(
        ohttp_relay.into_url()?,
        payjoin_directory.into_url()?,
        Client::builder()
            .use_rustls_tls()
            .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der)?),
        None,
    )
    .await
}

/// Fetch OHTTP keys through a resolved relay using a custom TLS certificate.
#[cfg(feature = "_manual-tls")]
pub async fn fetch_ohttp_keys_with_cert_and_relay_addresses(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
    cert_der: &[u8],
    relay_addresses: &[SocketAddr],
) -> Result<OhttpKeys, Error> {
    fetch_ohttp_keys_inner(
        ohttp_relay.into_url()?,
        payjoin_directory.into_url()?,
        Client::builder()
            .use_rustls_tls()
            .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der)?),
        Some(relay_addresses),
    )
    .await
}

async fn fetch_ohttp_keys_inner(
    ohttp_relay: Url,
    payjoin_directory: Url,
    mut builder: ClientBuilder,
    relay_addresses: Option<&[SocketAddr]>,
) -> Result<OhttpKeys, Error> {
    let ohttp_keys_url = payjoin_directory.join("/.well-known/ohttp-gateway")?;
    let proxy = Proxy::all(ohttp_relay.as_str())?;
    builder = builder.proxy(proxy).http1_only();
    if let (Some(domain), Some(addresses)) = (ohttp_relay.domain(), relay_addresses) {
        builder = builder.resolve_to_addrs(domain, addresses);
    }
    let client = builder.build()?;
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

    let body = res.bytes().await?.to_vec();
    OhttpKeys::decode(&body).map_err(|e| {
        Error::Internal(InternalError(InternalErrorInner::InvalidOhttpKeys(e.to_string())))
    })
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// When the payjoin directory returns an unexpected status code
    UnexpectedStatusCode(http::StatusCode),
    /// Internal errors that should not be pattern matched by users
    #[doc(hidden)]
    Internal(InternalError),
}

impl Error {
    /// Whether retrying the request through another relay may succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Internal(InternalError(InternalErrorInner::Reqwest(error)))
                if error.is_timeout() || error.is_connect() || error.is_request()
        )
    }
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
    use http::StatusCode;
    use reqwest::Response;

    use super::*;

    fn mock_response(status: StatusCode, body: Vec<u8>) -> Response {
        Response::from(http::response::Response::builder().status(status).body(body).unwrap())
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
}

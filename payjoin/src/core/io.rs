//! IO-related types and functions. Specifically, fetching OHTTP keys from a payjoin directory.
use std::time::Duration;

use bitcoin::secp256k1::rand;
use http::header::ACCEPT;
use reqwest::{Client, Proxy};

use crate::into_url::IntoUrl;
use crate::relay::{RelaySelector, SelectContext};
use crate::{OhttpKeys, Url};

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `relays`: The http CONNECT method proxies to request the ohttp keys from a payjoin
///   directory, tried in random order until one succeeds.  Proxying requests for ohttp keys
///   ensures a client IP address is never revealed to the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
///
/// Returns the ohttp keys and the relay that served them.
pub async fn fetch_ohttp_keys(
    relays: &[Url],
    payjoin_directory: impl IntoUrl,
) -> Result<(OhttpKeys, Url), Error> {
    fetch_ohttp_keys_inner(relays, payjoin_directory.into_url()?, None).await
}

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `relays`: The http CONNECT method proxies to request the ohttp keys from a payjoin
///   directory, tried in random order until one succeeds.  Proxying requests for ohttp keys
///   ensures a client IP address is never revealed to the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
///
/// * `cert_der`: The DER-encoded certificate to use for local HTTPS connections.
///
/// Returns the ohttp keys and the relay that served them.
#[cfg(feature = "_manual-tls")]
pub async fn fetch_ohttp_keys_with_cert(
    relays: &[Url],
    payjoin_directory: impl IntoUrl,
    cert_der: &[u8],
) -> Result<(OhttpKeys, Url), Error> {
    fetch_ohttp_keys_inner(relays, payjoin_directory.into_url()?, Some(cert_der)).await
}

async fn fetch_ohttp_keys_inner(
    relays: &[Url],
    payjoin_directory: Url,
    cert_der: Option<&[u8]>,
) -> Result<(OhttpKeys, Url), Error> {
    let ohttp_keys_url = payjoin_directory.join("/.well-known/ohttp-gateway")?;
    let mut selector = RelaySelector::new(relays.to_vec());
    let ctx = SelectContext::random();
    let mut last_err: Option<Error> = None;
    loop {
        let relay = match selector.select(&ctx, &mut rand::thread_rng()) {
            Some(relay) => relay,
            None => return Err(last_err.unwrap_or(Error::NoRelaysAvailable)),
        };
        match fetch_keys_once(&relay, &ohttp_keys_url, cert_der).await {
            Ok(keys) => return Ok((keys, relay)),
            Err(e @ Error::UnexpectedStatusCode(_)) => return Err(e),
            Err(e) => {
                selector.mark_failed(&relay);
                last_err = Some(e);
            }
        }
    }
}

async fn fetch_keys_once(
    relay: &Url,
    ohttp_keys_url: &Url,
    cert_der: Option<&[u8]>,
) -> Result<OhttpKeys, Error> {
    #[cfg(not(feature = "_manual-tls"))]
    let _ = cert_der;
    let proxy = Proxy::all(relay.as_str())?;
    let builder = Client::builder().proxy(proxy).http1_only();
    #[cfg(feature = "_manual-tls")]
    let builder = match cert_der {
        Some(cert_der) => builder
            .use_rustls_tls()
            .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der)?),
        None => builder,
    };
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
    /// No relay was available to reach the payjoin directory.
    NoRelaysAvailable,
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
            Self::NoRelaysAvailable => write!(f, "No relay was available to fetch ohttp keys"),
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
            Self::NoRelaysAvailable => None,
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
    use std::str::FromStr;

    use http::StatusCode;
    use reqwest::Response;

    use super::*;

    fn mock_response(status: StatusCode, body: Vec<u8>) -> Response {
        Response::from(http::response::Response::builder().status(status).body(body).unwrap())
    }

    #[tokio::test]
    async fn test_parse_success_response() {
        let valid_keys =
            OhttpKeys::from_str("OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC")
                .expect("valid keys")
                .encode()
                .expect("encodevalid keys");

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
    async fn fetch_with_no_relays_returns_no_relays_available() {
        assert!(matches!(
            fetch_ohttp_keys(&[], "https://directory.example").await,
            Err(Error::NoRelaysAvailable)
        ));
    }

    #[tokio::test]
    async fn fetch_exhausts_unreachable_relays_and_surfaces_last_error() {
        // Every relay fails to connect: the loop marks each failed and terminates
        // once none remain, surfacing the last transport error. NoRelaysAvailable
        // is reserved for an empty relay list, where no attempt was ever made.
        let relays = [
            Url::parse("http://127.0.0.1:1").expect("valid url"),
            Url::parse("http://127.0.0.1:2").expect("valid url"),
        ];
        assert!(matches!(
            fetch_ohttp_keys(&relays, "https://directory.example").await,
            Err(Error::Internal(_))
        ));
    }
}

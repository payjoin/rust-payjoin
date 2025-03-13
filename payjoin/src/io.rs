//! IO-related types and functions. Specifically, fetching OHTTP keys from a payjoin directory.

use http::header::ACCEPT;
use reqwest::{Client, Proxy};

use crate::into_url::IntoUrl;
use crate::OhttpKeys;

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
    let client = Client::builder().proxy(proxy).build()?;
    let res = client.get(ohttp_keys_url).header(ACCEPT, "application/ohttp-keys").send().await?;
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
#[cfg(feature = "_danger-local-https")]
pub async fn fetch_ohttp_keys_with_cert(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
    cert_der: Vec<u8>,
) -> Result<OhttpKeys, Error> {
    let ohttp_keys_url = payjoin_directory.into_url()?.join("/.well-known/ohttp-gateway")?;
    let proxy = Proxy::all(ohttp_relay.into_url()?.as_str())?;
    let client = Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_der(&cert_der)?)
        .proxy(proxy)
        .build()?;
    let res = client.get(ohttp_keys_url).header(ACCEPT, "application/ohttp-keys").send().await?;
    parse_ohttp_keys_response(res).await
}

async fn parse_ohttp_keys_response(res: reqwest::Response) -> Result<OhttpKeys, Error> {
    if !res.status().is_success() {
        return Err(Error(InternalError::UnexpectedStatusCode(res.status())));
    }

    let body = res.bytes().await?.to_vec();
    OhttpKeys::decode(&body).map_err(|e| Error(InternalError::InvalidOhttpKeys(e.to_string())))
}

#[derive(Debug)]
pub struct Error(InternalError);

#[derive(Debug)]
enum InternalError {
    ParseUrl(crate::into_url::Error),
    Reqwest(reqwest::Error),
    Io(std::io::Error),
    #[cfg(feature = "_danger-local-https")]
    Rustls(rustls::Error),
    InvalidOhttpKeys(String),
    UnexpectedStatusCode(http::StatusCode),
}

impl From<url::ParseError> for Error {
    fn from(value: url::ParseError) -> Self { Self(InternalError::ParseUrl(value.into())) }
}

macro_rules! impl_from_error {
    ($from:ty, $to:ident) => {
        impl From<$from> for Error {
            fn from(value: $from) -> Self { Self(InternalError::$to(value)) }
        }
    };
}

impl_from_error!(crate::into_url::Error, ParseUrl);
impl_from_error!(reqwest::Error, Reqwest);
impl_from_error!(std::io::Error, Io);
#[cfg(feature = "_danger-local-https")]
impl_from_error!(rustls::Error, Rustls);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use InternalError::*;

        match &self.0 {
            Reqwest(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
            Io(e) => e.fmt(f),
            InvalidOhttpKeys(e) => {
                write!(f, "Invalid ohttp keys returned from payjoin directory: {}", e)
            }
            UnexpectedStatusCode(code) => {
                write!(f, "Unexpected status code from payjoin directory: {}", code)
            }
            #[cfg(feature = "_danger-local-https")]
            Rustls(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalError::*;

        match &self.0 {
            Reqwest(e) => Some(e),
            ParseUrl(e) => Some(e),
            Io(e) => Some(e),
            InvalidOhttpKeys(_) => None,
            UnexpectedStatusCode(_) => None,
            #[cfg(feature = "_danger-local-https")]
            Rustls(e) => Some(e),
        }
    }
}

impl From<InternalError> for Error {
    fn from(value: InternalError) -> Self { Self(value) }
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
                Err(Error(InternalError::UnexpectedStatusCode(code))) => assert_eq!(code, status),
                result => panic!(
                    "Expected UnexpectedStatusCode error for status code: {}, got: {:?}",
                    status, result
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
                Err(Error(InternalError::InvalidOhttpKeys(_)))
            ),
            "expected InvalidOhttpKeys error"
        );
    }
}

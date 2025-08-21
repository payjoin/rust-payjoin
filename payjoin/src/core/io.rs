//! IO-related types and functions. Specifically, fetching OHTTP keys from a payjoin directory.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "io")]
use dashmap::DashMap;
use http::header::ACCEPT;
use reqwest::{Client, Proxy};
#[cfg(feature = "io")]
use thiserror::Error;
use url::Url;
#[cfg(feature = "io")]
use urlencoding;

use crate::into_url::IntoUrl;
use crate::OhttpKeys;

#[cfg(feature = "io")]
#[derive(Debug, Clone, Copy)]
pub struct FetchOptions {
    pub timeout: Duration,
    pub max_retries: usize,
    pub cache_ttl: Duration,
}

#[cfg(feature = "io")]
impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_retries: 3,
            cache_ttl: Duration::from_secs(300),
        }
    }
}

#[cfg(feature = "io")]
impl FetchOptions {
    pub fn mobile() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_retries: 2,
            cache_ttl: Duration::from_secs(600),
        }
    }
}

#[cfg(feature = "io")]
pub type Cache = Arc<DashMap<String, (OhttpKeys, Instant)>>;
#[cfg(feature = "io")]
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("All {count} relays timed out after {timeout:?}")]
    AllTimedOut { count: usize, timeout: Duration },

    #[error("All {count} relays failed: {errors:?}")]
    AllFailed { count: usize, errors: Vec<String> },

    #[error("No relays provided")]
    NoRelays,

    #[error("BIP21 parsing failed: {0}")]
    Bip21Parse(String),

    #[error("URL parsing failed: {0}")]
    UrlParse(String),
}

#[cfg(feature = "io")]
async fn fetch_single_relay(
    relay: &Url,
    directory: &Url,
    timeout: Duration,
) -> Result<OhttpKeys, Box<dyn std::error::Error + Send + Sync>> {
    let proxy = Proxy::all(relay.as_str())?;

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(timeout)
        .proxy(proxy)
        .build()?;

    let url = directory.join("/.well-known/ohttp-gateway")?;
    let res = client.get(url).header(ACCEPT, "application/ohttp-keys").send().await?;
    parse_ohttp_keys_response(res).await.map_err(Into::into)
}

#[cfg(feature = "io")]
async fn fetch_from_relays_impl(
    relays: &[Url],
    directory: &Url,
    options: FetchOptions,
) -> Result<(OhttpKeys, Url), FetchError> {
    if relays.is_empty() {
        return Err(FetchError::NoRelays);
    }

    let mut errors = Vec::new();
    let mut timeout_count = 0;

    for relay in relays.iter().take(options.max_retries) {
        match fetch_single_relay(relay, directory, options.timeout).await {
            Ok(keys) => {
                log::info!("Fetched OHTTP keys via {}", relay);
                return Ok((keys, relay.clone()));
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("timeout") || error_str.contains("timed out") {
                    timeout_count += 1;
                }
                errors.push(format!("{}: {}", relay, error_str));
                log::warn!("Relay {} failed: {}", relay, e);
            }
        }
    }

    if timeout_count == errors.len() {
        Err(FetchError::AllTimedOut { count: errors.len(), timeout: options.timeout })
    } else {
        Err(FetchError::AllFailed { count: errors.len(), errors })
    }
}

#[cfg(feature = "io")]
pub async fn fetch_ohttp_keys_robust(
    relays: Vec<Url>,
    directory: Url,
    options: FetchOptions,
    cache: Option<Cache>,
) -> Result<(OhttpKeys, Url), FetchError> {
    let cache_key = directory.to_string();

    if let Some(ref cache) = cache {
        if let Some(entry) = cache.get(&cache_key) {
            let (keys, timestamp) = entry.value();
            if timestamp.elapsed() < options.cache_ttl {
                log::debug!("Cache hit for {}", directory);
                return Ok((keys.clone(), relays[0].clone()));
            } else {
                drop(entry);
                cache.remove(&cache_key);
            }
        }
    }

    let result = fetch_from_relays_impl(&relays, &directory, options).await?;

    if let Some(ref cache) = cache {
        cache.insert(cache_key, (result.0.clone(), Instant::now()));

        if cache.len() > 100 {
            cache.retain(|_, (_, timestamp)| timestamp.elapsed() < options.cache_ttl);
        }
    }

    Ok(result)
}

#[cfg(feature = "io")]
fn extract_ohttp_from_bip21(uri: &str) -> Result<OhttpKeys, FetchError> {
    let query = uri
        .split('?')
        .nth(1)
        .ok_or_else(|| FetchError::Bip21Parse("No query parameters".to_string()))?;

    for param in query.split('&') {
        if let Some(encoded_value) = param.strip_prefix("ohttp=") {
            let value = urlencoding::decode(encoded_value)
                .map_err(|e| FetchError::Bip21Parse(format!("URL decode failed: {}", e)))?;

            return OhttpKeys::from_str(&value)
                .map_err(|e| FetchError::Bip21Parse(format!("Invalid OHTTP keys: {}", e)));
        }
    }

    Err(FetchError::Bip21Parse("No ohttp parameter found".to_string()))
}

#[cfg(feature = "io")]
pub async fn fetch_ohttp_keys_enhanced(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
) -> Result<OhttpKeys, FetchError> {
    let relays = vec![ohttp_relay
        .into_url()
        .map_err(|e| FetchError::UrlParse(format!("Invalid relay URL: {}", e)))?];
    let directory = payjoin_directory
        .into_url()
        .map_err(|e| FetchError::UrlParse(format!("Invalid directory URL: {}", e)))?;

    let (keys, _) =
        fetch_ohttp_keys_robust(relays, directory, FetchOptions::default(), None).await?;

    Ok(keys)
}

#[cfg(feature = "io")]
pub async fn fetch_ohttp_keys_bull_bitcoin(
    bip21_uri: Option<&str>,
    relays: Vec<Url>,
    directory: Url,
    cache: Cache,
) -> Result<OhttpKeys, FetchError> {
    if let Some(uri) = bip21_uri {
        match extract_ohttp_from_bip21(uri) {
            Ok(keys) => {
                log::info!("Using OHTTP keys from BIP21 URI");
                return Ok(keys);
            }
            Err(e) => {
                log::debug!("BIP21 extraction failed: {}, falling back to network", e);
            }
        }
    }

    let (keys, _) =
        fetch_ohttp_keys_robust(relays, directory, FetchOptions::mobile(), Some(cache)).await?;

    Ok(keys)
}

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

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .proxy(proxy)
        .build()?;

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
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_der(&cert_der)?)
        .proxy(proxy)
        .build()?;

    let res = client.get(ohttp_keys_url).header(ACCEPT, "application/ohttp-keys").send().await?;
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

#[derive(Debug)]
pub struct InternalError(InternalErrorInner);

#[derive(Debug)]
enum InternalErrorInner {
    ParseUrl(crate::into_url::Error),
    Reqwest(reqwest::Error),
    Io(std::io::Error),
    #[cfg(feature = "_danger-local-https")]
    Rustls(rustls::Error),
    InvalidOhttpKeys(String),
}

impl From<url::ParseError> for Error {
    fn from(value: url::ParseError) -> Self {
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
#[cfg(feature = "_danger-local-https")]
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
            #[cfg(feature = "_danger-local-https")]
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
            #[cfg(feature = "_danger-local-https")]
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
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use http::StatusCode;
    use reqwest::Response;
    use url::Url;

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

    #[cfg(feature = "io")]
    mod timeout_and_cache_tests {
        use super::*;

        const TEST_TIMEOUT_SECS: u64 = 2;
        const TEST_RETRY_TIMEOUT_SECS: u64 = 1;
        const TEST_CACHE_TTL_SECS: u64 = 300;
        const TEST_STALE_OFFSET_SECS: u64 = 400;
        const TEST_MAX_TIMEOUT_SECS: u64 = 10;
        const TEST_MIN_TIMEOUT_SECS: u64 = 1;
        const TEST_MAX_RETRY_TIME_SECS: u64 = 5;

        const TEST_OHTTP_KEYS_STR: &str =
            "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        const TEST_BIP21_ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        const TEST_UNREACHABLE_IP_1: &str = "http://192.0.2.1:1";
        const TEST_UNREACHABLE_IP_2: &str = "http://192.0.2.2:1";
        const TEST_DIRECTORY_URL: &str = "https://directory.test";

        fn test_ohttp_keys() -> OhttpKeys {
            OhttpKeys::from_str(TEST_OHTTP_KEYS_STR).expect("valid test keys")
        }

        fn test_cache() -> Cache { Arc::new(DashMap::new()) }

        fn test_fetch_options() -> FetchOptions {
            FetchOptions {
                timeout: Duration::from_secs(TEST_RETRY_TIMEOUT_SECS),
                max_retries: 2,
                cache_ttl: Duration::from_secs(TEST_CACHE_TTL_SECS),
            }
        }

        fn test_bip21_uri_with_ohttp() -> String {
            format!("bitcoin:{}?amount=0.01&ohttp={}", TEST_BIP21_ADDRESS, TEST_OHTTP_KEYS_STR)
        }

        fn test_bip21_uri_without_ohttp() -> String {
            format!("bitcoin:{}?amount=0.01", TEST_BIP21_ADDRESS)
        }

        #[tokio::test]
        async fn test_timeout_enforcement() {
            let start_time = Instant::now();
            let unreachable_relay = Url::parse(TEST_UNREACHABLE_IP_1).expect("valid test URL");
            let directory = Url::parse(TEST_DIRECTORY_URL).expect("valid test URL");
            let timeout = Duration::from_secs(TEST_TIMEOUT_SECS);

            let result = fetch_single_relay(&unreachable_relay, &directory, timeout).await;
            let elapsed = start_time.elapsed();

            assert!(result.is_err(), "unreachable relay should timeout");
            assert!(
                elapsed < Duration::from_secs(TEST_MAX_TIMEOUT_SECS),
                "timeout should be enforced quickly, got {:?}",
                elapsed
            );
            assert!(
                elapsed >= Duration::from_secs(TEST_MIN_TIMEOUT_SECS),
                "should actually attempt connection, got {:?}",
                elapsed
            );
        }

        #[tokio::test]
        async fn test_retry_with_multiple_relays() {
            let relay1 = Url::parse(TEST_UNREACHABLE_IP_1).expect("valid test URL");
            let relay2 = Url::parse(TEST_UNREACHABLE_IP_2).expect("valid test URL");
            let directory = Url::parse(TEST_DIRECTORY_URL).expect("valid test URL");
            let relays = vec![relay1, relay2];
            let options = test_fetch_options();

            let start_time = Instant::now();
            let result = fetch_from_relays_impl(&relays, &directory, options).await;
            let elapsed = start_time.elapsed();

            match result {
                Err(FetchError::AllTimedOut { count, .. })
                | Err(FetchError::AllFailed { count, .. }) => {
                    assert_eq!(count, 2, "should attempt both relays");
                    assert!(
                        elapsed < Duration::from_secs(TEST_MAX_RETRY_TIME_SECS),
                        "should fail quickly with retries, got {:?}",
                        elapsed
                    );
                }
                other => panic!("expected AllTimedOut or AllFailed, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn test_cache_storage_and_retrieval() {
            let cache = test_cache();
            let directory = Url::parse(TEST_DIRECTORY_URL).expect("valid test URL");
            let cache_key = directory.to_string();
            let keys = test_ohttp_keys();

            cache.insert(cache_key.clone(), (keys.clone(), Instant::now()));

            let cached_entry = cache.get(&cache_key).expect("cache should contain inserted entry");
            let (cached_keys, _) = cached_entry.value();

            assert_eq!(
                cached_keys.encode().unwrap(),
                keys.encode().unwrap(),
                "cached keys should match original keys"
            );
        }

        #[tokio::test]
        async fn test_cache_expiry_detection() {
            let cache = test_cache();
            let directory = Url::parse(TEST_DIRECTORY_URL).expect("valid test URL");
            let cache_key = directory.to_string();
            let keys = test_ohttp_keys();
            let options = test_fetch_options();

            let expired_timestamp = Instant::now() - Duration::from_secs(TEST_STALE_OFFSET_SECS);
            cache.insert(cache_key.clone(), (keys, expired_timestamp));

            let entry = cache.get(&cache_key).expect("cache should contain entry");
            let (_, timestamp) = entry.value();

            assert!(
                timestamp.elapsed() > options.cache_ttl,
                "entry should be detected as expired: elapsed={:?}, ttl={:?}",
                timestamp.elapsed(),
                options.cache_ttl
            );
        }

        #[tokio::test]
        async fn test_cache_cleanup_boundary_conditions() {
            let cache = test_cache();
            let keys = test_ohttp_keys();
            let now = Instant::now();
            let ttl = Duration::from_secs(TEST_CACHE_TTL_SECS);

            cache.insert("fresh_entry".to_string(), (keys.clone(), now));
            cache.insert(
                "stale_entry".to_string(),
                (keys, now - Duration::from_secs(TEST_STALE_OFFSET_SECS)),
            );

            cache.retain(|_, (_, timestamp)| timestamp.elapsed() < ttl);

            assert_eq!(cache.len(), 1, "only fresh entry should remain after cleanup");
            assert!(cache.contains_key("fresh_entry"), "fresh entry should be retained");
            assert!(!cache.contains_key("stale_entry"), "stale entry should be removed");
        }

        #[tokio::test]
        async fn test_bip21_ohttp_extraction_success() {
            let bip21_uri = test_bip21_uri_with_ohttp();
            let expected_keys = test_ohttp_keys();

            let result = extract_ohttp_from_bip21(&bip21_uri);

            assert!(result.is_ok(), "should successfully extract OHTTP keys from valid BIP21 URI");

            let extracted_keys = result.unwrap();
            assert_eq!(
                extracted_keys.encode().unwrap(),
                expected_keys.encode().unwrap(),
                "extracted keys should match expected test keys"
            );
        }

        #[tokio::test]
        async fn test_bip21_ohttp_extraction_failure() {
            let bip21_uri_without_ohttp = test_bip21_uri_without_ohttp();

            let result = extract_ohttp_from_bip21(&bip21_uri_without_ohttp);

            assert!(
                matches!(result, Err(FetchError::Bip21Parse(_))),
                "should fail to extract OHTTP keys from URI without ohttp parameter"
            );
        }

        #[test]
        fn test_fetch_options_default_configuration() {
            let default_opts = FetchOptions::default();

            assert_eq!(
                default_opts.timeout,
                Duration::from_secs(5),
                "default timeout should be 5 seconds"
            );
            assert_eq!(default_opts.max_retries, 3, "default max_retries should be 3");
            assert_eq!(
                default_opts.cache_ttl,
                Duration::from_secs(300),
                "default cache TTL should be 300 seconds"
            );
        }

        #[test]
        fn test_fetch_options_mobile_configuration() {
            let mobile_opts = FetchOptions::mobile();

            assert_eq!(
                mobile_opts.timeout,
                Duration::from_secs(5),
                "mobile timeout should be 5 seconds"
            );
            assert_eq!(
                mobile_opts.max_retries, 2,
                "mobile max_retries should be 2 (optimized for mobile)"
            );
            assert_eq!(
                mobile_opts.cache_ttl,
                Duration::from_secs(600),
                "mobile cache TTL should be 600 seconds (longer for mobile)"
            );
        }
    }
}

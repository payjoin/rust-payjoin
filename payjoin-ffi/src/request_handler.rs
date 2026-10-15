use std::sync::{Arc, Mutex};

use payjoin::bitcoin::secp256k1::rand::rngs::OsRng;
use payjoin::request_handler;

use crate::ohttp::{ClientResponse, OhttpKeys};
pub use crate::uri::error::UrlParseError;
use crate::Url;

/// Errors returned by [`RequestHandler`] key fetching.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum RequestHandlerError {
    /// Every configured directory has been marked failed. Carries the last
    /// fetch failure observed while trying them, when there was one.
    #[error("No valid directories available")]
    NoDirectoriesAvailable {
        /// The most recent failure seen while exhausting the directories.
        last_error: Option<String>,
    },
    /// Catch-all for unhandled error variants
    #[error("An unexpected error occurred")]
    Unexpected,
}

impl From<request_handler::Error> for RequestHandlerError {
    fn from(value: request_handler::Error) -> Self {
        match value {
            request_handler::Error::NoDirectoriesAvailable =>
                Self::NoDirectoriesAvailable { last_error: None },
            _ => Self::Unexpected,
        }
    }
}

/// The result of a successful [`RequestHandler::fetch_ohttp_keys`].
#[derive(Debug, uniffi::Record)]
pub struct FetchedOhttpKeys {
    /// The directory the keys belong to. Pin this in the BIP21 URI when
    /// creating a session, since a session's directory must not change.
    pub directory: Arc<Url>,
    /// The directory's OHTTP keys.
    pub ohttp_keys: Arc<OhttpKeys>,
}

/// Why a single attempt to fetch a directory's OHTTP keys failed.
///
/// The variant an [`OhttpKeysFetcher`] returns tells [`RequestHandler`] how to
/// fail over: a `Transient` failure retires the relay and retries the same
/// directory over another relay, while a `Directory` failure retires the
/// directory and moves on to another directory.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum DirectoryFetchError {
    /// The relay (or the connection through it) is at fault; retry over
    /// another relay.
    #[error("relay transport failure: {detail}")]
    Transient {
        /// Human-readable detail.
        detail: String,
    },
    /// The directory itself is at fault (for example a non-2xx status); do not
    /// retry it over another relay.
    #[error("directory failure: {detail}")]
    Directory {
        /// Human-readable detail.
        detail: String,
    },
}

impl request_handler::DirectoryFatal for DirectoryFetchError {
    fn is_directory_fatal(&self) -> bool { matches!(self, DirectoryFetchError::Directory { .. }) }
}

/// Fetches a payjoin directory's OHTTP keys through an OHTTP relay.
///
/// Implemented by the binding, which owns the HTTP transport and any proxy or
/// TLS configuration. [`RequestHandler::fetch_ohttp_keys`] selects the relay
/// and directory, drives failover, and tracks failures; the fetcher performs a
/// single HTTP attempt per call.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait OhttpKeysFetcher: Send + Sync {
    /// Fetch OHTTP keys from `directory` tunnelled through `relay`.
    ///
    /// Return [`DirectoryFetchError::Transient`] when the relay is at fault so
    /// the handler retries over another relay, and
    /// [`DirectoryFetchError::Directory`] when the directory itself is at
    /// fault so the handler retries over another directory.
    async fn fetch(
        &self,
        relay: Arc<Url>,
        directory: Arc<Url>,
    ) -> Result<Arc<OhttpKeys>, DirectoryFetchError>;
}

/// A posted request and the OHTTP context needed to process its response.
#[derive(uniffi::Record)]
pub struct RelayedResponse {
    /// The response body returned through the relay.
    pub body: Vec<u8>,
    /// The OHTTP context to pass to the session's `process_response`.
    pub ohttp_context: Arc<ClientResponse>,
}

/// A request built for a specific relay, ready to POST.
#[derive(uniffi::Record)]
pub struct BuiltRequest {
    /// The request to POST to the relay.
    pub request: crate::Request,
    /// The OHTTP context needed to process the eventual response.
    pub ohttp_context: Arc<ClientResponse>,
}

/// Why building a request for a relay failed.
///
/// [`RequestHandler::post_via_relay`] stops failover on either variant and
/// surfaces it to the caller: `Expired` as [`RelayPostError::Expired`] and
/// `Fatal` as [`RelayPostError::Fatal`].
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum RelayBuildError {
    /// The session expired while building the request; stop failover.
    #[error("session expired")]
    Expired,
    /// The request could not be built for another reason; stop failover.
    #[error("could not build request: {detail}")]
    Fatal {
        /// Human-readable detail.
        detail: String,
    },
}

impl request_handler::RequestExpiry for RelayBuildError {
    fn expired(&self) -> bool { matches!(self, RelayBuildError::Expired) }
}

/// Why a single attempt to POST a request over a relay failed.
///
/// The variant a [`RelayTransport`] returns tells [`RequestHandler`] how to
/// fail over: a `Transient` failure retires the relay and retries over another
/// relay. Build-time failures (expiry, fatal) are reported by
/// [`RelayTransport::build`], not here.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum RelayTransportError {
    /// The relay could not be reached; retire it and retry over another relay.
    #[error("relay transport failure: {detail}")]
    Transient {
        /// Human-readable detail.
        detail: String,
    },
}

/// Errors from [`RequestHandler::post_via_relay`].
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum RelayPostError {
    /// Every configured relay has been marked failed or excluded. Carries the
    /// last transport failure observed while trying them, when there was one.
    #[error("No valid relays available")]
    NoRelaysAvailable {
        /// The most recent transport failure seen while exhausting the relays.
        last_error: Option<String>,
    },
    /// The session expired while building the request.
    #[error("session expired")]
    Expired,
    /// The request could not be built for another reason.
    #[error("could not build request: {detail}")]
    Fatal {
        /// Human-readable detail.
        detail: String,
    },
}

/// Builds and posts a request through a relay, implemented by the binding.
///
/// [`RequestHandler::post_via_relay`] selects the relay, drives failover, and
/// tracks failures; the transport builds a fresh request for the selected
/// relay and performs the HTTP request.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait RelayTransport: Send + Sync {
    /// Build a fresh OHTTP request addressed to `relay`.
    ///
    /// Build a new request (and OHTTP context) on every call: reusing or
    /// retransmitting identical ciphertext breaks OHTTP privacy, since a relay
    /// could observe that a request is being retried. Return
    /// [`RelayBuildError::Expired`] if the session expired while building.
    fn build(&self, relay: Arc<Url>) -> Result<BuiltRequest, RelayBuildError>;

    /// POST a request produced by [`RelayTransport::build`], returning the
    /// response body. Return [`RelayTransportError::Transient`] to retire the
    /// relay and retry over another.
    async fn post(&self, request: crate::Request) -> Result<Vec<u8>, RelayTransportError>;
}

/// Selects OHTTP relays and payjoin directories, excluding endpoints marked
/// failed, and drives failover over a caller-supplied transport.
///
/// Endpoints are configured as URL strings and deduplicated. Failures are
/// scoped to a single failover loop: `post_via_relay` and `fetch_ohttp_keys`
/// clear recorded relay failures on entry, and `fetch_ohttp_keys` clears
/// directory failures on entry, so a transient outage that retires every
/// endpoint does not persist to the next call.
///
/// Failure state is synchronized internally, so the handler is safe to share
/// across tasks.
///
/// A directory chosen for a session must not change: select one when creating
/// a new session and keep it for the session's lifetime. Resuming a session
/// does not consult this handler.
#[derive(Debug, uniffi::Object)]
pub struct RequestHandler {
    inner: request_handler::RequestHandler,
}

fn parse_urls(urls: Vec<String>) -> Result<Vec<payjoin::Url>, UrlParseError> {
    urls.into_iter().map(|url| payjoin::Url::parse(&url).map_err(Into::into)).collect()
}

#[uniffi::export]
impl RequestHandler {
    /// Create a `RequestHandler` from relay and directory URL strings.
    ///
    /// Duplicates are removed so uniform selection isn't skewed by an
    /// endpoint listed more than once.
    #[uniffi::constructor]
    pub fn new(relays: Vec<String>, directories: Vec<String>) -> Result<Self, UrlParseError> {
        Ok(Self {
            inner: request_handler::RequestHandler::new(
                parse_urls(relays)?,
                parse_urls(directories)?,
            ),
        })
    }

    /// Pin user-supplied OHTTP keys so a key fetch never contacts a
    /// directory.
    ///
    /// Observed by every reference to this handler rather than creating a
    /// forked copy with separate failure tracking.
    pub fn set_ohttp_keys(&self, ohttp_keys: Arc<OhttpKeys>) {
        let keys: payjoin::OhttpKeys = Arc::unwrap_or_clone(ohttp_keys).into();
        self.inner.set_ohttp_keys(keys);
    }

    /// Return the pinned OHTTP keys, or fetch them with automatic failover.
    ///
    /// Relay transport failures retry over another relay. A directory failure
    /// retires that directory and retries over another, giving the next
    /// directory a clean relay set. Failures are scoped to this call: the
    /// failed-directory and failed-relay sets are cleared on entry, so an
    /// endpoint that failed a previous call is tried again.
    ///
    /// Returns the directory alongside the keys: a receiver pins the directory
    /// in the BIP21 URI at session creation, so the directory is reported even
    /// when the keys are pinned and no fetch happened.
    pub async fn fetch_ohttp_keys(
        &self,
        fetcher: Arc<dyn OhttpKeysFetcher>,
    ) -> Result<FetchedOhttpKeys, RequestHandlerError> {
        // Core drives the directory/relay failover loop; the closure records
        // the last attempt's failure so it can be reported once every
        // directory is exhausted.
        let last_error = Arc::new(Mutex::new(None::<String>));
        let fetch = {
            let fetcher = fetcher.clone();
            let last_error = last_error.clone();
            move |relay: payjoin::Url, directory: payjoin::Url| {
                let fetcher = fetcher.clone();
                let last_error = last_error.clone();
                async move {
                    let result =
                        fetcher.fetch(Arc::new(relay.into()), Arc::new(directory.into())).await;
                    match result {
                        Ok(ohttp_keys) => Ok(Arc::unwrap_or_clone(ohttp_keys).into()),
                        Err(e) => {
                            *last_error.lock().unwrap() = Some(e.to_string());
                            Err(e)
                        }
                    }
                }
            }
        };
        match self.inner.fetch_ohttp_keys_with(&mut OsRng, fetch).await {
            Ok((directory, ohttp_keys)) => Ok(FetchedOhttpKeys {
                directory: Arc::new(directory.into()),
                ohttp_keys: Arc::new(ohttp_keys.into()),
            }),
            Err(request_handler::Error::NoDirectoriesAvailable) =>
                Err(RequestHandlerError::NoDirectoriesAvailable {
                    last_error: last_error.lock().unwrap().clone(),
                }),
            Err(e) => Err(e.into()),
        }
    }

    /// Build and POST a request over a relay, failing over to another relay on
    /// transport error.
    ///
    /// `exclude` is the target the request ultimately reaches — for Payjoin v2
    /// the session directory. A relay equal to it is never selected: a server
    /// serving as both relay and directory rejects the resulting self-loop
    /// request.
    ///
    /// `transport` builds and POSTs the request, letting callers keep their own
    /// proxy and TLS client configuration while this method owns relay
    /// selection and failover. `build` runs once per relay attempt and a
    /// transport error marks that relay failed and retries over another.
    ///
    /// Returns [`RelayPostError::NoRelaysAvailable`] once every configured
    /// relay has been marked failed or excluded. Relay failures are scoped to
    /// this call: the failed-relay set is cleared on entry, so an outage that
    /// retires every relay in one call leaves the next call free to try them
    /// again.
    pub async fn post_via_relay(
        &self,
        exclude: Arc<Url>,
        transport: Arc<dyn RelayTransport>,
    ) -> Result<RelayedResponse, RelayPostError> {
        let exclude: payjoin::Url = Arc::unwrap_or_clone(exclude).into();
        struct CoreRelayTransport {
            inner: Arc<dyn RelayTransport>,
        }
        impl payjoin::request_handler::RelayTransport for CoreRelayTransport {
            type Request = crate::Request;
            type Context = Arc<ClientResponse>;
            type Response = Vec<u8>;
            type BuildError = RelayBuildError;
            type Error = RelayTransportError;
            fn build(
                &mut self,
                relay: &payjoin::Url,
            ) -> Result<(crate::Request, Arc<ClientResponse>), RelayBuildError> {
                let built = self.inner.build(Arc::new(relay.clone().into()))?;
                Ok((built.request, built.ohttp_context))
            }
            async fn post(
                &mut self,
                request: crate::Request,
            ) -> Result<Vec<u8>, RelayTransportError> {
                self.inner.post(request).await
            }
        }
        let transport = CoreRelayTransport { inner: transport };
        match self.inner.post_via_relay(&mut OsRng, &exclude, transport).await {
            Ok(request_handler::RelayPost::Posted(body, ohttp_context)) =>
                Ok(RelayedResponse { body, ohttp_context }),
            Ok(request_handler::RelayPost::Expired) => Err(RelayPostError::Expired),
            Err(request_handler::PostError::NoRelaysAvailable { last_error }) =>
                Err(RelayPostError::NoRelaysAvailable { last_error }),
            Err(request_handler::PostError::Build(RelayBuildError::Expired)) =>
                Err(RelayPostError::Expired),
            Err(request_handler::PostError::Build(RelayBuildError::Fatal { detail })) =>
                Err(RelayPostError::Fatal { detail }),
        }
    }
}

#[cfg(feature = "_manual-tls")]
#[uniffi::export]
impl RequestHandler {
    /// Use a DER-encoded certificate for local HTTPS connections when
    /// fetching OHTTP keys.
    ///
    /// Observed by every reference to this handler rather than creating a
    /// forked copy with separate failure tracking.
    pub fn set_cert_der(&self, cert_der: Vec<u8>) { self.inner.set_cert_der(cert_der); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls() -> Vec<String> {
        vec![
            "https://a.example".to_string(),
            "https://b.example".to_string(),
            "https://c.example".to_string(),
        ]
    }

    fn canonical_urls() -> Vec<String> {
        urls().into_iter().map(|url| Url::parse(url).unwrap().as_string()).collect()
    }

    #[test]
    fn new_rejects_invalid_url() {
        let err = RequestHandler::new(vec!["not a url".to_string()], urls()).unwrap_err();
        assert_eq!(err.to_string(), "invalid scheme");
    }

    // Failover loops are async and need a runtime; they run under the
    // `_test-utils` feature, which enables tokio.
    #[cfg(feature = "_test-utils")]
    mod failover {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;

        use super::*;

        fn unconfigured() -> Arc<Url> {
            Arc::new(Url::parse("https://unconfigured.example".to_string()).unwrap())
        }

        fn test_keys() -> Arc<OhttpKeys> {
            Arc::new(OhttpKeys::decode(payjoin_test_utils::ohttp_key_config_bytes()).unwrap())
        }

        fn post_request() -> crate::Request {
            crate::Request {
                url: "https://relay.example".to_string(),
                content_type: "message/ohttp-req".to_string(),
                body: vec![1, 2, 3],
            }
        }

        fn built() -> BuiltRequest {
            BuiltRequest {
                request: post_request(),
                ohttp_context: Arc::new(ClientResponse::dangling()),
            }
        }

        struct AlwaysTransient {
            calls: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl RelayTransport for AlwaysTransient {
            fn build(&self, _relay: Arc<Url>) -> Result<BuiltRequest, RelayBuildError> {
                Ok(built())
            }

            async fn post(&self, _request: crate::Request) -> Result<Vec<u8>, RelayTransportError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(RelayTransportError::Transient { detail: "down".to_string() })
            }
        }

        #[tokio::test]
        async fn post_via_relay_retires_relay_and_exhausts() {
            let mailroom = RequestHandler::new(urls(), Vec::new()).unwrap();
            let transport = Arc::new(AlwaysTransient { calls: AtomicUsize::new(0) });
            let result = mailroom.post_via_relay(unconfigured(), transport.clone()).await;
            match result {
                Err(RelayPostError::NoRelaysAvailable { last_error }) =>
                    assert_eq!(last_error.as_deref(), Some("relay transport failure: down")),
                Err(other) => panic!("expected relays to be exhausted, got {other:?}"),
                Ok(_) => panic!("expected relays to be exhausted, got a response"),
            }
            assert_eq!(transport.calls.load(Ordering::SeqCst), 3);
        }

        struct FixedBuildError {
            calls: AtomicUsize,
            error: fn() -> RelayBuildError,
        }

        #[async_trait::async_trait]
        impl RelayTransport for FixedBuildError {
            fn build(&self, _relay: Arc<Url>) -> Result<BuiltRequest, RelayBuildError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err((self.error)())
            }

            async fn post(&self, _request: crate::Request) -> Result<Vec<u8>, RelayTransportError> {
                unreachable!("post must not run when build fails")
            }
        }

        #[tokio::test]
        async fn post_via_relay_stops_on_expiry() {
            let mailroom = RequestHandler::new(urls(), Vec::new()).unwrap();
            let transport = Arc::new(FixedBuildError {
                calls: AtomicUsize::new(0),
                error: || RelayBuildError::Expired,
            });
            let result = mailroom.post_via_relay(unconfigured(), transport.clone()).await;
            assert!(matches!(result, Err(RelayPostError::Expired)));
            assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn post_via_relay_stops_on_fatal_build_error() {
            let mailroom = RequestHandler::new(urls(), Vec::new()).unwrap();
            let transport = Arc::new(FixedBuildError {
                calls: AtomicUsize::new(0),
                error: || RelayBuildError::Fatal { detail: "bad".to_string() },
            });
            let result = mailroom.post_via_relay(unconfigured(), transport.clone()).await;
            match result {
                Err(RelayPostError::Fatal { detail }) => assert_eq!(detail, "bad"),
                Err(other) => panic!("expected a fatal build error, got {other:?}"),
                Ok(_) => panic!("expected a fatal build error, got a response"),
            }
            assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn post_via_relay_never_selects_excluded_relay() {
            // The only relay is the excluded directory, so no relay is
            // selectable and the transport must never be called.
            let mailroom = RequestHandler::new(vec![urls()[0].clone()], Vec::new()).unwrap();
            let transport = Arc::new(AlwaysTransient { calls: AtomicUsize::new(0) });
            let exclude = Arc::new(Url::parse(urls()[0].clone()).unwrap());
            let result = mailroom.post_via_relay(exclude, transport.clone()).await;
            match result {
                Err(RelayPostError::NoRelaysAvailable { last_error }) =>
                    assert_eq!(last_error, None),
                Err(other) => panic!("expected relays to be exhausted, got {other:?}"),
                Ok(_) => panic!("expected relays to be exhausted, got a response"),
            }
            assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
        }

        struct TransientThenKeys {
            calls: AtomicUsize,
            keys: Arc<OhttpKeys>,
        }

        #[async_trait::async_trait]
        impl OhttpKeysFetcher for TransientThenKeys {
            async fn fetch(
                &self,
                _relay: Arc<Url>,
                _directory: Arc<Url>,
            ) -> Result<Arc<OhttpKeys>, DirectoryFetchError> {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(DirectoryFetchError::Transient { detail: "down".to_string() });
                }
                Ok(self.keys.clone())
            }
        }

        #[tokio::test]
        async fn fetch_retries_over_another_relay() {
            let mailroom = RequestHandler::new(urls(), urls()).unwrap();
            let fetcher =
                Arc::new(TransientThenKeys { calls: AtomicUsize::new(0), keys: test_keys() });
            let result = mailroom.fetch_ohttp_keys(fetcher.clone()).await.unwrap();
            assert!(canonical_urls().contains(&result.directory.as_string()));
            // One transient failure, then a success.
            assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
        }

        struct AlwaysDirectoryFails {
            calls: AtomicUsize,
            directories: Mutex<Vec<String>>,
        }

        #[async_trait::async_trait]
        impl OhttpKeysFetcher for AlwaysDirectoryFails {
            async fn fetch(
                &self,
                _relay: Arc<Url>,
                directory: Arc<Url>,
            ) -> Result<Arc<OhttpKeys>, DirectoryFetchError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.directories.lock().unwrap().push(directory.as_string());
                Err(DirectoryFetchError::Directory { detail: "404".to_string() })
            }
        }

        #[tokio::test]
        async fn fetch_retires_directory_and_gives_up() {
            let mailroom = RequestHandler::new(urls(), urls()).unwrap();
            let fetcher = Arc::new(AlwaysDirectoryFails {
                calls: AtomicUsize::new(0),
                directories: Mutex::new(Vec::new()),
            });
            let result = mailroom.fetch_ohttp_keys(fetcher.clone()).await;
            match result {
                Err(RequestHandlerError::NoDirectoriesAvailable { last_error }) => {
                    let last_error = last_error.expect("a directory failure should be reported");
                    assert!(last_error.contains("404"), "unexpected detail: {last_error}");
                }
                Err(other) => panic!("expected directories to be exhausted, got {other:?}"),
                Ok(_) => panic!("expected directories to be exhausted, got keys"),
            }
            // Every directory is attempted exactly once.
            assert_eq!(fetcher.calls.load(Ordering::SeqCst), 3);
            let mut tried = fetcher.directories.lock().unwrap().clone();
            tried.sort();
            tried.dedup();
            assert_eq!(tried.len(), 3);
        }

        struct NeverCalled {
            calls: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl OhttpKeysFetcher for NeverCalled {
            async fn fetch(
                &self,
                _relay: Arc<Url>,
                _directory: Arc<Url>,
            ) -> Result<Arc<OhttpKeys>, DirectoryFetchError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                unreachable!("pinned keys must not be fetched")
            }
        }

        #[tokio::test]
        async fn pinned_ohttp_keys_short_circuit_fetch() {
            let mailroom = RequestHandler::new(Vec::new(), urls()).unwrap();
            mailroom.set_ohttp_keys(test_keys());
            let fetcher = Arc::new(NeverCalled { calls: AtomicUsize::new(0) });
            let result = mailroom.fetch_ohttp_keys(fetcher.clone()).await.unwrap();
            assert!(canonical_urls().contains(&result.directory.as_string()));
            assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn fetch_resets_directory_failures() {
            // The first fetch retires every directory (each reports a
            // directory-fatal 404); the second starts from a clean directory
            // set and succeeds rather than reporting every directory retired
            // for the handler's lifetime.
            let mailroom = RequestHandler::new(urls(), urls()).unwrap();
            let fetcher = Arc::new(AlwaysDirectoryFails {
                calls: AtomicUsize::new(0),
                directories: Mutex::new(Vec::new()),
            });
            assert!(matches!(
                mailroom.fetch_ohttp_keys(fetcher).await,
                Err(RequestHandlerError::NoDirectoriesAvailable { .. })
            ));
            let fetcher =
                Arc::new(TransientThenKeys { calls: AtomicUsize::new(0), keys: test_keys() });
            let result = mailroom.fetch_ohttp_keys(fetcher).await.unwrap();
            assert!(canonical_urls().contains(&result.directory.as_string()));
        }
    }
}

//! Failover-aware OHTTP relay and payjoin directory management.
//!
//! [`RequestHandler`] owns the selection policy for OHTTP relays and payjoin
//! directories, tracks which endpoints have failed, and drives failover:
//! [`RequestHandler::post_via_relay`] retries a caller-supplied transport
//! ([`RelayTransport`], or [`FnRelayTransport`]) over another relay, and —
//! with the `io` feature — [`RequestHandler::fetch_ohttp_keys`] fetches
//! OHTTP keys with automatic failover, retrying relay failures over another
//! relay and moving directory failures on to another directory.
//!
//! A directory chosen for a session must not change: it is embedded in the
//! BIP21 URI at session creation and recovered from the session event log
//! on resume. [`RequestHandler`] selects a directory only when a new session is
//! created; resumption does not consult it.
//!
//! All selection goes through one internal `UrlSelector` path, so policy
//! stays uniform across integrators and topology-aware ordering (for example
//! AS-aware relay selection) can be introduced later in that one place rather
//! than forked per implementation.
//!
//! A relay equal to the directory it is reaching is never selected: a server
//! serving as both rejects the self-loop request. Exclusion is a filter on
//! candidates, so it composes with any future ordering policy.
//!
//! The `io` feature gates only the network-touching OHTTP key fetch; it is
//! opt-in. [`RequestHandler::post_via_relay`] takes the transport as a
//! [`RelayTransport`], so integrators that already have an HTTP client get
//! relay failover and selection without `io` — closure-based transports can
//! use [`FnRelayTransport`] — while those that enable it also get the OHTTP
//! key fetch with automatic failover.
use bitcoin::secp256k1::rand::Rng;

use crate::selector::UrlSelector;
use crate::Url;

/// Selects OHTTP relays and payjoin directories, excluding endpoints marked
/// failed. Failures are scoped to a single failover loop: both
/// [`RequestHandler::post_via_relay`] and
/// [`RequestHandler::fetch_ohttp_keys`] clear recorded relay failures on
/// entry, and the key fetch clears directory failures on entry, so a
/// transient outage that retires every endpoint does not persist to the next
/// call.
///
/// Methods take `&self`: failure state and pinned configuration are behind
/// `Mutex`es held only for synchronous accesses and never across `.await`, so
/// a `RequestHandler` can be shared across tasks (for example via `Arc`)
/// without an external async lock and without serializing concurrent relay
/// posts. It is not `Clone`: a clone would fork the tracked failure state,
/// so sharing goes through `Arc` and configuration through the setters, which
/// every holder observes.
#[derive(Debug)]
pub struct RequestHandler {
    relays: UrlSelector,
    directories: UrlSelector,
    ohttp_keys: std::sync::Mutex<Option<crate::OhttpKeys>>,
    #[cfg(feature = "_manual-tls")]
    cert_der: std::sync::Mutex<Option<Vec<u8>>>,
}

impl RequestHandler {
    /// Deduplicates `relays` and `directories` (preserving order) so uniform
    /// selection isn't skewed by an endpoint listed more than once.
    pub fn new(relays: Vec<Url>, directories: Vec<Url>) -> Self {
        Self {
            relays: UrlSelector::new(relays),
            directories: UrlSelector::new(directories),
            ohttp_keys: std::sync::Mutex::new(None),
            #[cfg(feature = "_manual-tls")]
            cert_der: std::sync::Mutex::new(None),
        }
    }

    /// Pin user-supplied OHTTP keys so [`RequestHandler::fetch_ohttp_keys`] returns
    /// them without contacting a directory.
    ///
    /// Takes `&self`: the pinned keys are observed by every holder of this
    /// handler rather than by a forked copy.
    pub fn set_ohttp_keys(&self, ohttp_keys: crate::OhttpKeys) {
        *self.lock_ohttp_keys() = Some(ohttp_keys);
    }

    /// Lock the pinned OHTTP keys, recovering from a poisoned lock rather
    /// than panicking: a panic in another thread should not take down
    /// selection.
    fn lock_ohttp_keys(&self) -> std::sync::MutexGuard<'_, Option<crate::OhttpKeys>> {
        self.ohttp_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Lock the pinned certificate, recovering from a poisoned lock rather
    /// than panicking.
    #[cfg(feature = "_manual-tls")]
    fn lock_cert_der(&self) -> std::sync::MutexGuard<'_, Option<Vec<u8>>> {
        self.cert_der.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Use a DER-encoded certificate for local HTTPS connections when
    /// fetching OHTTP keys.
    ///
    /// Takes `&self`: the certificate is observed by every holder of this
    /// handler rather than by a forked copy.
    #[cfg(feature = "_manual-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "_manual-tls")))]
    pub fn set_cert_der(&self, cert_der: Vec<u8>) { *self.lock_cert_der() = Some(cert_der); }

    /// Pick a relay, never one marked failed and never `exclude`.
    ///
    /// Pass the session directory so a directory is never reached through
    /// itself: a server serving as both relay and directory rejects the
    /// self-loop request.
    pub(crate) fn select_relay_excluding<R: Rng>(
        &self,
        rng: &mut R,
        exclude: &Url,
    ) -> Result<Url, Error> {
        self.relays.select_excluding(rng, exclude).ok_or(Error::NoRelaysAvailable)
    }

    /// Pick a payjoin directory, never one marked failed.
    pub(crate) fn select_directory<R: Rng>(&self, rng: &mut R) -> Result<Url, Error> {
        self.directories.select(rng).ok_or(Error::NoDirectoriesAvailable)
    }

    /// Record a relay transport failure so subsequent selections avoid it.
    pub(crate) fn mark_relay_failed(&self, relay: &Url) { self.relays.mark_failed(relay); }

    /// Record a directory failure so subsequent selections avoid it.
    #[cfg(test)]
    pub(crate) fn mark_directory_failed(&self, directory: &Url) {
        self.directories.mark_failed(directory);
    }

    /// Clear all recorded relay failures so every configured relay is
    /// selectable again.
    ///
    /// [`RequestHandler::post_via_relay`] and [`RequestHandler::fetch_ohttp_keys`]
    /// call this at the start of each call, scoping relay failures to one
    /// failover loop: an outage that retires every relay does not persist to
    /// the next call.
    pub(crate) fn clear_failed_relays(&self) { self.relays.clear_failed(); }

    /// Clear all recorded directory failures so every configured directory is
    /// selectable again.
    ///
    /// [`RequestHandler::fetch_ohttp_keys`] calls this at the start of each
    /// fetch, scoping directory failures to one session: a transient outage
    /// that retires every directory does not persist to the next session.
    pub(crate) fn clear_failed_directories(&self) { self.directories.clear_failed(); }

    /// Return the pinned OHTTP keys, or fetch them through `fetch`, with
    /// automatic failover.
    ///
    /// The transport-generic form of [`RequestHandler::fetch_ohttp_keys`]:
    /// `fetch` performs a single attempt per call against a `(relay,
    /// directory)` pair, returning the keys or an error implementing
    /// [`DirectoryFatal`] so this loop can attribute the failure to the relay
    /// or the directory. Relay failures retry over another relay; a
    /// directory-fatal failure retires the directory and moves on.
    ///
    /// Directory failures are scoped to this call: the failed-directory set is
    /// cleared on entry, so a directory that failed a previous session is
    /// tried again. Relay failures are scoped the same way: the failed-relay
    /// set is cleared on entry and after each directory failure, so every
    /// directory is attempted with a clean relay set.
    ///
    /// Returns the directory alongside the keys: a receiver pins the directory
    /// in the BIP21 URI at session creation, so the directory is reported even
    /// when the keys are pinned and no fetch happened.
    #[cfg(feature = "v2")]
    #[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
    pub async fn fetch_ohttp_keys_with<R, F, Fut, E>(
        &self,
        rng: &mut R,
        fetch: F,
    ) -> Result<(Url, crate::OhttpKeys), Error>
    where
        R: Rng,
        F: Fn(Url, Url) -> Fut,
        Fut: std::future::Future<Output = Result<crate::OhttpKeys, E>>,
        E: DirectoryFatal + std::fmt::Display,
    {
        self.clear_failed_directories();
        self.clear_failed_relays();
        loop {
            let directory = self.select_directory(rng)?;
            if let Some(ohttp_keys) = self.lock_ohttp_keys().clone() {
                return Ok((directory, ohttp_keys));
            }
            if let Ok(keys) =
                fetch_keys_via_relay_with(&self.relays, &self.directories, &directory, rng, &fetch)
                    .await
            {
                return Ok((directory, keys));
            }
            // The directory was marked failed (directly, or by exhausting
            // every relay against it). Give the next directory a clean set
            // of relays to fail over through.
            self.clear_failed_relays();
        }
    }

    /// Return the pinned OHTTP keys, or fetch them over the network with
    /// automatic failover.
    ///
    /// Relay transport failures retry over another relay. A directory failure
    /// (unexpected status or oversized key body) marks that directory failed,
    /// resets the relay failure list, and retries over another directory.
    /// Returns an error only once every configured endpoint has been marked
    /// failed within this call.
    ///
    /// Directory failures are scoped to this call: the failed-directory set is
    /// cleared on entry, so a directory that failed a previous session is
    /// tried again rather than staying retired for the handler's lifetime.
    #[cfg(feature = "io")]
    #[cfg_attr(docsrs, doc(cfg(feature = "io")))]
    pub async fn fetch_ohttp_keys<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Url, crate::OhttpKeys), Error> {
        #[cfg(feature = "_manual-tls")]
        let cert_der = self.lock_cert_der().clone();
        #[cfg(not(feature = "_manual-tls"))]
        let cert_der: Option<Vec<u8>> = None;
        self.fetch_ohttp_keys_with(rng, move |relay, directory| {
            let cert_der = cert_der.clone();
            async move { fetch_via_relay_impl(cert_der.as_deref(), &relay, &directory).await }
        })
        .await
    }
}

/// Relay failover loop behind [`RequestHandler::fetch_ohttp_keys_with`],
/// factored out so tests can drive it with a synthetic `fetch` without touching
/// the network.
///
/// On return the directory has been marked failed: either the directory itself
/// misbehaved, or every relay failed to reach it.
#[cfg(feature = "v2")]
async fn fetch_keys_via_relay_with<R, F, Fut, E>(
    relays: &UrlSelector,
    directories: &UrlSelector,
    directory: &Url,
    rng: &mut R,
    fetch: F,
) -> Result<crate::OhttpKeys, DirectoryAttemptFailure>
where
    R: Rng,
    F: Fn(Url, Url) -> Fut,
    Fut: std::future::Future<Output = Result<crate::OhttpKeys, E>>,
    E: DirectoryFatal + std::fmt::Display,
{
    loop {
        // A relay equal to the directory would loop back to itself and be
        // rejected as a self-loop, so it is excluded up front. When every
        // relay is either failed or equal to the directory, selection
        // returns `None` and the directory is marked failed below: it
        // cannot be reached through a relay at all.
        let relay = match relays.select_excluding(rng, directory) {
            Some(relay) => relay,
            None => {
                // A directory that exhausted every relay is marked failed so
                // selection moves on instead of retrying it forever.
                directories.mark_failed(directory);
                return Err(DirectoryAttemptFailure::RelaysExhausted);
            }
        };
        match fetch(relay.clone(), directory.clone()).await {
            Ok(keys) => return Ok(keys),
            Err(e) if e.is_directory_fatal() => {
                tracing::debug!("Directory {directory} failed via relay {relay}: {e}");
                directories.mark_failed(directory);
                return Err(DirectoryAttemptFailure::Directory);
            }
            Err(e) => {
                tracing::debug!("Relay {relay} failed: {e}");
                relays.mark_failed(&relay);
            }
        }
    }
}

#[cfg(feature = "io")]
async fn fetch_via_relay_impl(
    cert_der: Option<&[u8]>,
    relay: &Url,
    directory: &Url,
) -> Result<crate::OhttpKeys, crate::io::Error> {
    #[cfg(feature = "_manual-tls")]
    if let Some(cert_der) = cert_der {
        return crate::io::fetch_ohttp_keys_with_cert(relay.as_str(), directory.as_str(), cert_der)
            .await;
    }
    #[cfg(not(feature = "_manual-tls"))]
    let _ = cert_der;
    crate::io::fetch_ohttp_keys(relay.as_str(), directory.as_str()).await
}

/// Errors returned by [`RequestHandler`] relay and directory selection.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Every configured relay has been marked failed.
    NoRelaysAvailable,
    /// Every configured directory has been marked failed.
    NoDirectoriesAvailable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoRelaysAvailable => write!(f, "No valid relays available"),
            Error::NoDirectoriesAvailable => write!(f, "No valid directories available"),
        }
    }
}

impl std::error::Error for Error {}

/// Whether an OHTTP keys fetch error should be attributed to the directory
/// rather than the relay transporting the request.
///
/// The classification policy lives here so it is owned by the library: the
/// networked [`RequestHandler::fetch_ohttp_keys`] path implements it for its
/// transport error, and a caller supplying its own transport through
/// [`RequestHandler::fetch_ohttp_keys_with`] implements it over its own error
/// type instead of re-deciding the policy.
#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub trait DirectoryFatal {
    /// Returns `true` when the error is the directory's fault (for example a
    /// non-2xx status), so retrying over another relay would not help.
    fn is_directory_fatal(&self) -> bool;
}

#[cfg(feature = "io")]
impl DirectoryFatal for crate::io::Error {
    fn is_directory_fatal(&self) -> bool {
        matches!(
            self,
            crate::io::Error::UnexpectedStatusCode(_) | crate::io::Error::OhttpKeysBodyTooLarge(_)
        )
    }
}

/// Whether a request-construction error was caused by session expiry.
///
/// Implemented for the send and receive v2 `CreateRequestError` types so
/// [`RequestHandler::post_via_relay`] can hand expiry back to the caller (which owns
/// the typestate needed to react) instead of flattening it into this loop.
#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub trait RequestExpiry {
    /// Returns `true` when the request failed because the session expired.
    fn expired(&self) -> bool;
}

#[cfg(feature = "v2")]
impl RequestExpiry for crate::send::v2::CreateRequestError {
    fn expired(&self) -> bool { self.is_expired() }
}

#[cfg(feature = "v2")]
impl RequestExpiry for crate::receive::v2::CreateRequestError {
    fn expired(&self) -> bool { self.is_expired() }
}

/// Outcome of [`RequestHandler::post_via_relay`].
#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub enum RelayPost<P, T> {
    /// The request was posted; carries the transport response and the caller
    /// context returned by the request builder.
    Posted(P, T),
    /// The request could not be built because the session had expired.
    Expired,
}

/// Errors from [`RequestHandler::post_via_relay`].
#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
#[derive(Debug)]
pub enum PostError<E> {
    /// Every configured relay has been marked failed or excluded. Carries the
    /// most recent transport failure observed while trying them, when there was
    /// one.
    NoRelaysAvailable {
        /// The most recent transport failure seen while exhausting the relays.
        last_error: Option<String>,
    },
    /// The request could not be built for a reason other than expiry.
    Build(E),
}

#[cfg(feature = "v2")]
impl<E: std::fmt::Display> std::fmt::Display for PostError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PostError::NoRelaysAvailable { .. } => write!(f, "No valid relays available"),
            PostError::Build(e) => write!(f, "Could not build request: {e}"),
        }
    }
}

#[cfg(feature = "v2")]
impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for PostError<E> {}

/// Builds and POSTs a request through a relay, implemented by the caller.
///
/// [`RequestHandler::post_via_relay`] selects the relay, drives failover, and
/// tracks failures; a `RelayTransport` builds a fresh request for the selected
/// relay and performs the HTTP request, so callers keep their own HTTP
/// client, proxy, and TLS configuration while the loop owns the retry policy.
#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub trait RelayTransport {
    /// The request to POST to the relay. Generic so a caller whose request is
    /// not [`crate::Request`] (for example an FFI binding with its own
    /// request type) passes it through unchanged rather than reconstructing
    /// one.
    type Request;
    /// Caller context produced by [`RelayTransport::build`] and threaded back
    /// on success, so the caller can process the response (for example an
    /// OHTTP context).
    type Context;
    /// The response produced by a successful POST.
    type Response;
    /// Why building a request failed. Must implement [`RequestExpiry`] so the
    /// loop can report session expiry as [`RelayPost::Expired`] instead of a
    /// build failure.
    type BuildError: RequestExpiry;
    /// Why a POST failed. Display-only: a transport error retires the relay
    /// and the loop retries over another, so the loop never branches on its
    /// structure.
    type Error: std::fmt::Display;

    /// Build a fresh request (and its context) addressed to `relay`.
    ///
    /// Build a new request on every call: reusing or retransmitting
    /// identical ciphertext breaks OHTTP privacy, since a relay could observe
    /// that a request is being retried.
    fn build(&mut self, relay: &Url) -> Result<(Self::Request, Self::Context), Self::BuildError>;

    /// POST a request produced by [`RelayTransport::build`].
    fn post(
        &mut self,
        request: Self::Request,
    ) -> impl std::future::Future<Output = Result<Self::Response, Self::Error>>;
}

/// [`RelayTransport`] over a pair of closures, for callers that already have
/// a build closure and a post closure.
#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub struct FnRelayTransport<B, P> {
    build: B,
    post: P,
}

#[cfg(feature = "v2")]
impl<B, P> FnRelayTransport<B, P> {
    /// Adapt a `build` closure (relay URL to request plus context) and a
    /// `post` closure (request to response) into a [`RelayTransport`].
    pub fn new(build: B, post: P) -> Self { Self { build, post } }
}

#[cfg(feature = "v2")]
impl<B, P, Rq, T, E, Fut, Resp, TransportError> RelayTransport for FnRelayTransport<B, P>
where
    B: FnMut(&Url) -> Result<(Rq, T), E>,
    E: RequestExpiry,
    P: Fn(Rq) -> Fut,
    Fut: std::future::Future<Output = Result<Resp, TransportError>>,
    TransportError: std::fmt::Display,
{
    type Request = Rq;
    type Context = T;
    type Response = Resp;
    type BuildError = E;
    type Error = TransportError;

    fn build(&mut self, relay: &Url) -> Result<(Rq, T), E> { (self.build)(relay) }

    fn post(
        &mut self,
        request: Rq,
    ) -> impl std::future::Future<Output = Result<Resp, TransportError>> {
        (self.post)(request)
    }
}

#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
impl RequestHandler {
    /// Build and POST a request over a relay, failing over to another relay on
    /// transport error.
    ///
    /// `exclude` names the target the request ultimately reaches — for
    /// Payjoin v2 the session directory, available from the session types
    /// (for example [`crate::receive::v2::Receiver::directory`]). A relay
    /// equal to it is never selected: a server serving as both relay and
    /// directory rejects the resulting self-loop request.
    ///
    /// `transport` builds a request per selected relay and performs the POST
    /// (see [`RelayTransport`]); the caller context from `build` is threaded
    /// back on success. When `build` reports [`RequestExpiry::expired`], the
    /// loop stops and returns [`RelayPost::Expired`] so the caller can react
    /// with its own typestate. A transport error marks the relay failed and
    /// retries over another relay.
    ///
    /// Returns [`PostError::NoRelaysAvailable`] once every configured relay has
    /// been marked failed or excluded, carrying the last transport failure.
    ///
    /// Relay failures are scoped to this call: the failed-relay set is cleared
    /// on entry, so an outage that retires every relay in one call leaves the
    /// next call free to try them again.
    pub async fn post_via_relay<R, X>(
        &self,
        rng: &mut R,
        exclude: &Url,
        mut transport: X,
    ) -> Result<RelayPost<X::Response, X::Context>, PostError<X::BuildError>>
    where
        R: Rng,
        X: RelayTransport,
    {
        self.clear_failed_relays();
        let mut last_error = None;
        loop {
            let relay = match self.select_relay_excluding(rng, exclude) {
                Ok(relay) => relay,
                Err(_) => return Err(PostError::NoRelaysAvailable { last_error }),
            };
            let (req, ctx) = match transport.build(&relay) {
                Ok(r) => r,
                Err(e) if e.expired() => return Ok(RelayPost::Expired),
                Err(e) => return Err(PostError::Build(e)),
            };
            match transport.post(req).await {
                Ok(resp) => return Ok(RelayPost::Posted(resp, ctx)),
                Err(e) => {
                    tracing::debug!("Request to relay {relay} failed: {e}");
                    last_error = Some(e.to_string());
                    self.mark_relay_failed(&relay);
                }
            }
        }
    }
}

/// Why an attempt against one directory ended in failure. The underlying
/// error is logged where the failure is observed, before this is returned.
#[cfg(feature = "v2")]
enum DirectoryAttemptFailure {
    /// Every relay failed to reach the directory.
    RelaysExhausted,
    /// The directory misbehaved; fetching over another relay would not help.
    Directory,
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::rand::rngs::StdRng;
    use bitcoin::secp256k1::rand::SeedableRng;

    use super::*;

    fn urls() -> Vec<Url> {
        ["https://a.example", "https://b.example", "https://c.example"]
            .iter()
            .map(|s| Url::parse(s).unwrap())
            .collect()
    }

    #[test]
    fn select_directory_fails_when_all_directories_marked_failed() {
        let mailroom = RequestHandler::new(urls(), urls());
        for directory in urls() {
            mailroom.mark_directory_failed(&directory);
        }
        let mut rng = StdRng::seed_from_u64(2);
        assert_eq!(mailroom.select_directory(&mut rng), Err(Error::NoDirectoriesAvailable));
    }

    #[test]
    fn clear_failed_directories_restores_selection() {
        let mailroom = RequestHandler::new(urls(), urls());
        for directory in urls() {
            mailroom.mark_directory_failed(&directory);
        }
        let mut rng = StdRng::seed_from_u64(10);
        assert!(mailroom.select_directory(&mut rng).is_err());
        mailroom.clear_failed_directories();
        assert!(mailroom.select_directory(&mut rng).is_ok());
    }

    #[test]
    fn error_displays_endpoint_kind() {
        assert_eq!(Error::NoRelaysAvailable.to_string(), "No valid relays available");
        assert_eq!(Error::NoDirectoriesAvailable.to_string(), "No valid directories available");
    }
    #[cfg(feature = "io")]
    #[tokio::test]
    async fn pinned_ohttp_keys_short_circuit_fetch() {
        let keys = crate::OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes()).unwrap();
        let directories = urls();
        let mailroom = RequestHandler::new(Vec::new(), directories.clone());
        mailroom.set_ohttp_keys(keys);
        let mut rng = StdRng::seed_from_u64(5);
        // No relays configured: only the pinned keys can satisfy the fetch.
        // The selected directory is still reported for BIP21 pinning.
        let (directory, _) = mailroom.fetch_ohttp_keys(&mut rng).await.unwrap();
        assert!(directories.contains(&directory));
    }

    #[cfg(feature = "io")]
    #[tokio::test]
    async fn fetch_fails_without_directories_even_with_pinned_keys() {
        let keys = crate::OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes()).unwrap();
        let mailroom = RequestHandler::new(Vec::new(), Vec::new());
        mailroom.set_ohttp_keys(keys);
        let mut rng = StdRng::seed_from_u64(8);
        assert!(matches!(
            mailroom.fetch_ohttp_keys(&mut rng).await,
            Err(Error::NoDirectoriesAvailable)
        ));
    }

    #[cfg(feature = "io")]
    #[tokio::test]
    async fn fetch_resets_directory_failures() {
        let keys = crate::OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes()).unwrap();
        let directories = urls();
        let mailroom = RequestHandler::new(Vec::new(), directories.clone());
        mailroom.set_ohttp_keys(keys);
        // Retire every directory, as a previous session's outage might have.
        for directory in &directories {
            mailroom.mark_directory_failed(directory);
        }
        let mut rng = StdRng::seed_from_u64(9);
        // A fresh fetch starts from a clean directory set rather than
        // reporting every directory retired for the handler's lifetime.
        let (directory, _) = mailroom.fetch_ohttp_keys(&mut rng).await.unwrap();
        assert!(directories.contains(&directory));
    }

    // The pinned certificate is stored behind `&self`, so a later fetch uses
    // it and an overwriting call replaces it rather than stacking or
    // forking per-caller state.
    #[cfg(feature = "_manual-tls")]
    #[test]
    fn set_cert_der_pins_certificate_for_every_holder() {
        let handler = RequestHandler::new(urls(), Vec::new());
        assert!(handler.lock_cert_der().is_none());
        handler.set_cert_der(b"first".to_vec());
        assert_eq!(handler.lock_cert_der().as_deref(), Some(b"first".as_slice()));
        handler.set_cert_der(b"second".to_vec());
        assert_eq!(handler.lock_cert_der().as_deref(), Some(b"second".as_slice()));
    }

    #[cfg(feature = "io")]
    #[test]
    fn unexpected_status_is_directory_fatal() {
        let err = crate::io::Error::UnexpectedStatusCode(http::StatusCode::NOT_FOUND);
        assert!(err.is_directory_fatal());
    }

    #[cfg(feature = "io")]
    #[test]
    fn oversized_keys_body_is_directory_fatal() {
        let err = crate::io::Error::OhttpKeysBodyTooLarge(65_603);
        assert!(err.is_directory_fatal());
    }

    #[cfg(feature = "io")]
    #[test]
    fn transport_error_is_not_directory_fatal() {
        // A URL parse error surfaces as an internal (transport-class) error.
        let parse_err = Url::parse("invalid url").unwrap_err();
        let err = crate::io::Error::from(parse_err);
        assert!(!err.is_directory_fatal());
    }

    #[cfg(feature = "io")]
    #[tokio::test]
    async fn directory_fatal_error_marks_directory_not_relay() {
        let relays = UrlSelector::new(urls());
        let directories = UrlSelector::new(urls());
        let directory = urls()[0].clone();
        let mut rng = StdRng::seed_from_u64(20);
        let calls = std::cell::Cell::new(0u32);
        let result = fetch_keys_via_relay_with(
            &relays,
            &directories,
            &directory,
            &mut rng,
            |_relay, _directory| {
                calls.set(calls.get() + 1);
                let n = calls.get();
                async move {
                    assert!(n <= 3, "a directory-fatal error must not be retried per relay");
                    Err::<crate::OhttpKeys, _>(crate::io::Error::UnexpectedStatusCode(
                        http::StatusCode::NOT_FOUND,
                    ))
                }
            },
        )
        .await;
        assert!(matches!(result, Err(DirectoryAttemptFailure::Directory)));
        // The directory is retired immediately; no relay is blamed for it.
        for _ in 0..50 {
            assert_ne!(directories.select(&mut rng), Some(directory.clone()));
        }
        assert!(relays.select(&mut rng).is_some());
    }

    #[cfg(feature = "io")]
    #[tokio::test]
    async fn transport_error_marks_relay_not_directory() {
        let relays = UrlSelector::new(urls());
        let directories = UrlSelector::new(urls());
        let directory = urls()[0].clone();
        let mut rng = StdRng::seed_from_u64(21);
        let calls = std::cell::Cell::new(0u32);
        let result = fetch_keys_via_relay_with(
            &relays,
            &directories,
            &directory,
            &mut rng,
            |_relay, _directory| {
                calls.set(calls.get() + 1);
                let n = calls.get();
                async move {
                    // The relay equal to the directory is excluded up front,
                    // so only the other two are attempted, once each.
                    assert!(n <= 2, "failover must retire a relay on every transport error");
                    Err::<crate::OhttpKeys, _>(crate::io::Error::from(
                        Url::parse("invalid url").unwrap_err(),
                    ))
                }
            },
        )
        .await;
        assert!(matches!(result, Err(DirectoryAttemptFailure::RelaysExhausted)));
        // Every relay other than the excluded one is retired; the directory
        // itself is left selectable. The excluded relay was never attempted,
        // so it remains selectable on its own — just not against this
        // directory.
        assert!(directories.select(&mut rng).is_some());
        assert_eq!(relays.select(&mut rng), Some(directory.clone()));
        assert_eq!(relays.select_excluding(&mut rng, &directory), None);
    }

    #[derive(Debug)]
    struct TestExpiry(bool);

    impl RequestExpiry for TestExpiry {
        fn expired(&self) -> bool { self.0 }
    }

    impl std::fmt::Display for TestExpiry {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "test expiry: {}", self.0)
        }
    }

    fn req() -> crate::Request {
        crate::Request {
            url: "https://relay.example".to_string(),
            content_type: "message/ohttp-req",
            body: Vec::new(),
        }
    }

    /// A URL absent from `urls()`, so exclusion does not shrink the
    /// selectable pool in tests that only exercise posting.
    fn unconfigured() -> Url { Url::parse("https://unconfigured.example").unwrap() }

    #[cfg(feature = "v2")]
    #[tokio::test]
    async fn post_via_relay_returns_response_and_context() {
        let mailroom = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(11);
        let result = mailroom
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(
                    |_relay: &Url| Ok::<_, TestExpiry>((req(), 42u8)),
                    |_req| async { Ok::<_, TestExpiry>("response") },
                ),
            )
            .await;
        match result {
            Ok(RelayPost::Posted(resp, ctx)) => {
                assert_eq!(resp, "response");
                assert_eq!(ctx, 42);
            }
            _ => panic!("expected a posted response"),
        }
    }

    #[cfg(feature = "v2")]
    #[tokio::test]
    async fn post_via_relay_reports_expiry() {
        let mailroom = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(12);
        let result = mailroom
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(
                    |_relay: &Url| Err::<(crate::Request, u8), _>(TestExpiry(true)),
                    |_req| async { Ok::<_, TestExpiry>("response") },
                ),
            )
            .await;
        assert!(matches!(result, Ok(RelayPost::Expired)));
    }

    #[cfg(feature = "v2")]
    #[tokio::test]
    async fn post_via_relay_surfaces_build_error() {
        let mailroom = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(13);
        let result = mailroom
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(
                    |_relay: &Url| Err::<(crate::Request, u8), _>(TestExpiry(false)),
                    |_req| async { Ok::<_, TestExpiry>("response") },
                ),
            )
            .await;
        assert!(matches!(result, Err(PostError::Build(TestExpiry(false)))));
    }

    #[cfg(feature = "v2")]
    #[tokio::test]
    async fn post_via_relay_fails_over_then_succeeds() {
        let mailroom = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(14);
        let attempts = std::cell::Cell::new(0u32);
        let post = |_req: crate::Request| {
            let attempt = attempts.get();
            attempts.set(attempt + 1);
            async move {
                if attempt == 0 {
                    Err("transport down")
                } else {
                    Ok("response")
                }
            }
        };
        let result = mailroom
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(|_relay: &Url| Ok::<_, TestExpiry>((req(), ())), post),
            )
            .await;
        assert!(matches!(result, Ok(RelayPost::Posted("response", ()))));
        assert_eq!(attempts.get(), 2);
    }

    #[cfg(feature = "v2")]
    #[tokio::test]
    async fn post_via_relay_exhausts_relays() {
        let mailroom = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(15);
        let attempts = std::cell::Cell::new(0u32);
        // Bail out if a no-op `mark_relay_failed` lets the failover loop spin
        // forever: failing the test beats hanging the suite.
        let post = |_req: crate::Request| {
            attempts.set(attempts.get() + 1);
            assert!(attempts.get() <= 4, "failover must stop once every relay is marked failed");
            async { Err::<&str, &str>("transport down") }
        };
        let result = mailroom
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(|_relay: &Url| Ok::<_, TestExpiry>((req(), ())), post),
            )
            .await;
        assert_eq!(attempts.get(), 3);
        match result {
            Err(PostError::NoRelaysAvailable { last_error }) =>
                assert_eq!(last_error.as_deref(), Some("transport down")),
            _ => panic!("expected relays to be exhausted"),
        }
    }

    // Relay failures are scoped to one `post_via_relay` call: an outage that
    // retires every relay does not persist to the next call.
    #[cfg(feature = "v2")]
    #[tokio::test]
    async fn post_via_relay_recovers_relays_on_next_call() {
        let mailroom = RequestHandler::new(urls(), Vec::new());
        let mut rng = StdRng::seed_from_u64(22);
        let attempts = std::cell::Cell::new(0u32);
        // Fail every relay attempt, then succeed from the next call on.
        let post = |_req: crate::Request| {
            let attempt = attempts.get();
            attempts.set(attempt + 1);
            async move {
                if attempt < 3 {
                    Err("outage")
                } else {
                    Ok("response")
                }
            }
        };
        let result = mailroom
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(|_relay: &Url| Ok::<_, TestExpiry>((req(), ())), post),
            )
            .await;
        // The first call exhausted all three relays...
        assert!(matches!(result, Err(PostError::NoRelaysAvailable { .. })));
        assert_eq!(attempts.get(), 3);
        // ...and the second call starts from a clean relay set rather than
        // failing without touching the network.
        let result = mailroom
            .post_via_relay(
                &mut rng,
                &unconfigured(),
                FnRelayTransport::new(|_relay: &Url| Ok::<_, TestExpiry>((req(), ())), post),
            )
            .await;
        assert!(matches!(result, Ok(RelayPost::Posted("response", ()))));
        assert_eq!(attempts.get(), 4);
    }

    #[test]
    fn select_relay_excluding_skips_excluded_relay() {
        let mailroom = RequestHandler::new(urls(), urls());
        let excluded = urls()[0].clone();
        // With the excluded relay also marked failed the outcome must not
        // change: exclusion and failure tracking are independent filters.
        mailroom.mark_relay_failed(&urls()[1]);
        let mut rng = StdRng::seed_from_u64(16);
        for _ in 0..50 {
            assert_ne!(mailroom.select_relay_excluding(&mut rng, &excluded), Ok(excluded.clone()));
        }
    }

    #[test]
    fn select_relay_excluding_fails_when_only_excluded_remains() {
        let mailroom = RequestHandler::new(vec![urls()[0].clone()], Vec::new());
        let mut rng = StdRng::seed_from_u64(17);
        assert_eq!(
            mailroom.select_relay_excluding(&mut rng, &urls()[0]),
            Err(Error::NoRelaysAvailable)
        );
    }

    #[cfg(feature = "v2")]
    #[tokio::test]
    async fn post_via_relay_never_selects_excluded_relay() {
        let mailroom = RequestHandler::new(urls(), Vec::new());
        let excluded = urls()[0].clone();
        let mut rng = StdRng::seed_from_u64(18);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_clone = seen.clone();
        let attempts = std::cell::Cell::new(0u32);
        // Bail out if a no-op `mark_relay_failed` lets the failover loop spin
        // forever: failing the test beats hanging the suite.
        let post = |_req: crate::Request| {
            attempts.set(attempts.get() + 1);
            assert!(attempts.get() <= 4, "failover must stop once every relay is marked failed");
            async { Err::<&str, &str>("transport down") }
        };
        let result = mailroom
            .post_via_relay(
                &mut rng,
                &excluded,
                FnRelayTransport::new(
                    |relay: &Url| {
                        seen_clone.lock().unwrap().push(relay.to_string());
                        Ok::<_, TestExpiry>((req(), ()))
                    },
                    post,
                ),
            )
            .await;
        assert!(matches!(result, Err(PostError::NoRelaysAvailable { .. })));
        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty());
        assert!(seen.iter().all(|r| r != excluded.as_str()), "excluded relay must never be built");
    }

    // Failure state is internally synchronized, so concurrent posts over a
    // shared `&RequestHandler` run at the same time rather than serializing on
    // an external lock held across the await.
    #[cfg(feature = "v2")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_via_relay_does_not_serialize_concurrent_posts() {
        use std::sync::Arc;

        use tokio::sync::Barrier;

        let mailroom = Arc::new(RequestHandler::new(urls(), Vec::new()));
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for seed in [31u64, 32u64] {
            let mailroom = mailroom.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let mut rng = StdRng::seed_from_u64(seed);
                mailroom
                    .post_via_relay(
                        &mut rng,
                        &unconfigured(),
                        FnRelayTransport::new(
                            |_relay: &Url| Ok::<_, TestExpiry>((req(), ())),
                            |_req| {
                                let barrier = barrier.clone();
                                async move {
                                    // Both posts must be in flight at once;
                                    // an external lock held across the await
                                    // would make the first wait on a barrier
                                    // the second can never reach.
                                    barrier.wait().await;
                                    Ok::<_, &str>("response")
                                }
                            },
                        ),
                    )
                    .await
            }));
        }
        for handle in handles {
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
                .await
                .expect("concurrent posts must not serialize")
                .unwrap();
            assert!(matches!(result, Ok(RelayPost::Posted("response", ()))));
        }
    }

    #[cfg(feature = "io")]
    #[tokio::test]
    async fn fetch_never_uses_relay_equal_to_directory() {
        let relays = UrlSelector::new(urls());
        let directories = UrlSelector::new(urls());
        let directory = urls()[0].clone();
        let mut rng = StdRng::seed_from_u64(19);
        let seen = std::cell::RefCell::new(Vec::new());
        let result = fetch_keys_via_relay_with(
            &relays,
            &directories,
            &directory,
            &mut rng,
            |relay, target| {
                // This covers a mutant as a no-op `mark_failed` lets the failover
                // loop spin forever: failing the test beats hanging the suite.
                assert!(
                    seen.borrow().len() < urls().len() - 1,
                    "failover must stop once every relay is marked failed"
                );
                seen.borrow_mut().push((relay, target));
                async {
                    Err::<crate::OhttpKeys, _>(crate::io::Error::from(
                        Url::parse("invalid url").unwrap_err(),
                    ))
                }
            },
        )
        .await;
        assert!(matches!(result, Err(DirectoryAttemptFailure::RelaysExhausted)));
        let seen = seen.borrow();
        assert!(!seen.is_empty());
        assert!(
            seen.iter().all(|(relay, target)| relay != target),
            "a relay equal to the directory must never be attempted"
        );
    }
}

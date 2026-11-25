//! OHTTP relay selection and failover.
//!
//! [`RequestHandler`] holds the configured OHTTP relays. It is immutable once
//! built, so one handler can be shared across every session of an
//! application, whatever directory each session uses.
//!
//! No failures are remembered: every failure is assumed transient. Each
//! operation tries relays in a fresh random order and gives up once all of
//! them have failed, so an outage seen by one operation never affects the
//! next one, and no failure state needs clearing or expiring.
//!
//! A session's directory is fixed: the receiver chooses it and embeds it in
//! the BIP21 URI at session creation, and both parties recover it from the
//! session on resume. Requests for a session go through a [`DirectoryHandle`]
//! obtained from [`RequestHandler::for_directory`], which binds that
//! directory once so relay selection can never be pointed at the wrong one.
//! With the `io` feature the handle also fetches OHTTP keys from its
//! directory, and [`RequestHandler::fetch_ohttp_keys_from`] falls back across
//! candidate directories when a receiver creates a new session.
use bitcoin::secp256k1::rand::seq::SliceRandom;
use bitcoin::secp256k1::rand::Rng;

use crate::Url;

/// The configured OHTTP relays, shared across sessions.
///
/// Holds no mutable state, so it can be shared across tasks (for example
/// via `Arc`) without locking.
#[derive(Debug, Clone)]
pub struct RequestHandler {
    relays: Vec<Url>,
    #[cfg(feature = "_manual-tls")]
    cert_der: Option<Vec<u8>>,
}

impl RequestHandler {
    /// Deduplicates `relays` (preserving order) so uniform selection isn't
    /// skewed by a relay listed more than once.
    pub fn new(relays: Vec<Url>) -> Self {
        let mut deduped: Vec<Url> = Vec::new();
        for relay in relays {
            if !deduped.contains(&relay) {
                deduped.push(relay);
            }
        }
        Self {
            relays: deduped,
            #[cfg(feature = "_manual-tls")]
            cert_der: None,
        }
    }

    /// Use a DER-encoded certificate for local HTTPS connections when
    /// fetching OHTTP keys.
    #[cfg(feature = "_manual-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "_manual-tls")))]
    pub fn with_cert_der(mut self, cert_der: Vec<u8>) -> Self {
        self.cert_der = Some(cert_der);
        self
    }

    /// Scope requests to the session directory `directory`.
    ///
    /// Take `directory` from the session itself
    /// ([`crate::uri::v2::PjParam::directory`],
    /// [`crate::send::v2::Sender::directory`] or
    /// [`crate::receive::v2::Receiver::directory`]), or, for a new receiver
    /// session, the directory the caller has chosen for it. It need not be
    /// known to this handler in advance.
    pub fn for_directory(&self, directory: Url) -> DirectoryHandle<'_> {
        DirectoryHandle { handler: self, directory, ohttp_keys: None }
    }

    /// Fetch OHTTP keys for a new receiver session, falling back across
    /// `directories`.
    ///
    /// Directories are tried in random order, each with its own relay
    /// failover, until one yields keys. Returns that directory alongside its
    /// keys: the receiver embeds it in the BIP21 URI, and it carries the
    /// session from then on.
    #[cfg(feature = "io")]
    #[cfg_attr(docsrs, doc(cfg(feature = "io")))]
    pub async fn fetch_ohttp_keys_from<R: Rng>(
        &self,
        directories: &[Url],
        rng: &mut R,
    ) -> Result<(Url, crate::OhttpKeys), Error> {
        let mut directories = directories.to_vec();
        directories.shuffle(rng);
        for directory in directories {
            match self.for_directory(directory.clone()).fetch_ohttp_keys(rng).await {
                Ok(keys) => return Ok((directory, keys)),
                Err(e) => tracing::debug!("Directory {directory} unavailable: {e}"),
            }
        }
        Err(Error::NoDirectoriesAvailable)
    }

    #[cfg(feature = "io")]
    async fn fetch_via_relay(
        &self,
        relay: &Url,
        directory: &Url,
    ) -> Result<crate::OhttpKeys, crate::io::Error> {
        #[cfg(feature = "_manual-tls")]
        if let Some(cert_der) = self.cert_der.as_ref() {
            return crate::io::fetch_ohttp_keys_with_cert(
                relay.as_str(),
                directory.as_str(),
                cert_der,
            )
            .await;
        }
        crate::io::fetch_ohttp_keys(relay.as_str(), directory.as_str()).await
    }
}

/// A [`RequestHandler`] scoped to one session directory.
///
/// Cheap to create: obtain one per session (or per request) with
/// [`RequestHandler::for_directory`].
#[derive(Debug)]
pub struct DirectoryHandle<'a> {
    handler: &'a RequestHandler,
    directory: Url,
    ohttp_keys: Option<crate::OhttpKeys>,
}

impl DirectoryHandle<'_> {
    /// The session directory this handle reaches.
    pub fn directory(&self) -> &Url { &self.directory }

    /// Pin user-supplied OHTTP keys for this directory so
    /// [`DirectoryHandle::fetch_ohttp_keys`] returns them without contacting
    /// the directory.
    pub fn with_ohttp_keys(mut self, ohttp_keys: crate::OhttpKeys) -> Self {
        self.ohttp_keys = Some(ohttp_keys);
        self
    }

    /// The order in which to try relays for one request to this directory.
    ///
    /// A fresh uniform-random order on every call: try each relay in turn,
    /// moving to the next on a transport failure, and give up once the
    /// order is exhausted. Nothing is remembered between calls, so a relay
    /// that failed once is tried again by the next request.
    ///
    /// A relay equal to the directory is never included, since a server
    /// serving as both relay and directory rejects the self-loop request.
    ///
    /// This is the single relay selection path, so a future topology-aware
    /// ordering (for example AS-aware relay selection) lands here once.
    pub fn relays<R: Rng>(&self, rng: &mut R) -> Vec<Url> {
        let mut relays: Vec<Url> =
            self.handler.relays.iter().filter(|r| **r != self.directory).cloned().collect();
        relays.shuffle(rng);
        relays
    }

    /// Return the pinned OHTTP keys, or fetch them from this directory,
    /// failing over to another relay on transport errors.
    ///
    /// Returns [`Error::Directory`] when the directory itself misbehaves
    /// (unexpected status or oversized key body); retrying over another
    /// relay would not help. Returns [`Error::NoRelaysAvailable`] once every
    /// relay has failed, which may equally mean the directory is
    /// unreachable.
    #[cfg(feature = "io")]
    #[cfg_attr(docsrs, doc(cfg(feature = "io")))]
    pub async fn fetch_ohttp_keys<R: Rng>(&self, rng: &mut R) -> Result<crate::OhttpKeys, Error> {
        if let Some(ohttp_keys) = &self.ohttp_keys {
            return Ok(ohttp_keys.clone());
        }
        for relay in self.relays(rng) {
            match self.handler.fetch_via_relay(&relay, &self.directory).await {
                Ok(keys) => return Ok(keys),
                Err(e) if is_directory_fatal(&e) => {
                    tracing::debug!("Directory {} failed via relay {relay}: {e}", self.directory);
                    return Err(Error::Directory(e));
                }
                Err(e) => tracing::debug!("Relay {relay} failed: {e}"),
            }
        }
        Err(Error::NoRelaysAvailable)
    }
}

/// Errors returned by [`RequestHandler`] and [`DirectoryHandle`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Every relay failed to reach the directory, or none are configured
    /// other than the directory itself.
    NoRelaysAvailable,
    /// Every candidate directory failed.
    NoDirectoriesAvailable,
    /// The directory misbehaved; the caller should choose another directory.
    #[cfg(feature = "io")]
    #[cfg_attr(docsrs, doc(cfg(feature = "io")))]
    Directory(crate::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoRelaysAvailable => write!(f, "No valid relays available"),
            Error::NoDirectoriesAvailable => write!(f, "No valid directories available"),
            #[cfg(feature = "io")]
            Error::Directory(e) => write!(f, "Payjoin directory failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::NoRelaysAvailable | Error::NoDirectoriesAvailable => None,
            #[cfg(feature = "io")]
            Error::Directory(e) => Some(e),
        }
    }
}

/// Whether an OHTTP keys fetch error should be attributed to the directory
/// rather than the relay transporting the request.
#[cfg(feature = "io")]
pub(crate) fn is_directory_fatal(err: &crate::io::Error) -> bool {
    matches!(
        err,
        crate::io::Error::UnexpectedStatusCode(_) | crate::io::Error::OhttpKeysBodyTooLarge(_)
    )
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

    fn unlisted() -> Url { Url::parse("https://receiver-chosen.example").unwrap() }

    #[test]
    fn error_display() {
        assert_eq!(Error::NoRelaysAvailable.to_string(), "No valid relays available");
        assert_eq!(Error::NoDirectoriesAvailable.to_string(), "No valid directories available");
    }

    #[test]
    fn new_dedups_relays_preserving_order() {
        let a = urls()[0].clone();
        let b = urls()[1].clone();
        let handler = RequestHandler::new(vec![a.clone(), a.clone(), b.clone()]);
        assert_eq!(handler.relays, vec![a, b]);
    }

    // A sender reaches the directory the receiver chose, which the handler
    // has never seen: every relay is a candidate.
    #[test]
    fn relays_for_unlisted_directory_include_every_relay() {
        let handler = RequestHandler::new(urls());
        let mut rng = StdRng::seed_from_u64(1);
        let relays = handler.for_directory(unlisted()).relays(&mut rng);
        assert_eq!(relays.len(), urls().len());
        assert!(urls().iter().all(|u| relays.contains(u)));
    }

    #[test]
    fn relays_never_include_the_directory() {
        let handler = RequestHandler::new(urls());
        let mailroom = handler.for_directory(urls()[0].clone());
        let mut rng = StdRng::seed_from_u64(2);
        for _ in 0..50 {
            let relays = mailroom.relays(&mut rng);
            assert_eq!(relays.len(), 2);
            assert!(!relays.contains(&urls()[0]));
        }
    }

    #[test]
    fn relays_are_empty_when_only_the_directory_is_configured() {
        let handler = RequestHandler::new(vec![urls()[0].clone()]);
        let mut rng = StdRng::seed_from_u64(3);
        assert!(handler.for_directory(urls()[0].clone()).relays(&mut rng).is_empty());
    }

    // Each call starts fresh, and every relay is reached first eventually.
    #[test]
    fn relays_order_is_uniform_across_calls() {
        let handler = RequestHandler::new(urls());
        let mailroom = handler.for_directory(unlisted());
        let mut rng = StdRng::seed_from_u64(4);
        let mut first = std::collections::BTreeSet::new();
        for _ in 0..200 {
            first.insert(mailroom.relays(&mut rng)[0].to_string());
        }
        assert_eq!(first.len(), urls().len(), "random must reach every relay");
    }

    #[cfg(feature = "_manual-tls")]
    #[test]
    fn with_cert_der_pins_certificate() {
        let handler = RequestHandler::new(urls());
        assert!(handler.cert_der.is_none());
        let handler = handler.with_cert_der(b"cert".to_vec());
        assert_eq!(handler.cert_der.as_deref(), Some(b"cert".as_slice()));
    }

    #[cfg(feature = "io")]
    #[tokio::test]
    async fn pinned_ohttp_keys_short_circuit_fetch() {
        let keys = crate::OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes()).unwrap();
        // No relays configured: only the pinned keys can satisfy the fetch.
        let handler = RequestHandler::new(Vec::new());
        let mailroom = handler.for_directory(unlisted()).with_ohttp_keys(keys.clone());
        let mut rng = StdRng::seed_from_u64(5);
        assert_eq!(mailroom.fetch_ohttp_keys(&mut rng).await.unwrap(), keys);
    }

    #[cfg(feature = "io")]
    #[tokio::test]
    async fn fetch_fails_without_relays() {
        let handler = RequestHandler::new(Vec::new());
        let mut rng = StdRng::seed_from_u64(6);
        assert!(matches!(
            handler.for_directory(unlisted()).fetch_ohttp_keys(&mut rng).await,
            Err(Error::NoRelaysAvailable)
        ));
    }

    #[cfg(feature = "io")]
    #[tokio::test]
    async fn fetch_from_fails_when_every_directory_fails() {
        // No relays: every directory fails, and the fallback reports it.
        let handler = RequestHandler::new(Vec::new());
        let mut rng = StdRng::seed_from_u64(7);
        assert!(matches!(
            handler.fetch_ohttp_keys_from(&urls(), &mut rng).await,
            Err(Error::NoDirectoriesAvailable)
        ));
        assert!(matches!(
            handler.fetch_ohttp_keys_from(&[], &mut rng).await,
            Err(Error::NoDirectoriesAvailable)
        ));
    }

    #[cfg(feature = "io")]
    #[test]
    fn unexpected_status_is_directory_fatal() {
        let err = crate::io::Error::UnexpectedStatusCode(http::StatusCode::NOT_FOUND);
        assert!(is_directory_fatal(&err));
    }

    #[cfg(feature = "io")]
    #[test]
    fn oversized_keys_body_is_directory_fatal() {
        let err = crate::io::Error::OhttpKeysBodyTooLarge(65_603);
        assert!(is_directory_fatal(&err));
    }

    #[cfg(feature = "io")]
    #[test]
    fn transport_error_is_not_directory_fatal() {
        // A URL parse error surfaces as an internal (transport-class) error.
        let parse_err = Url::parse("invalid url").unwrap_err();
        let err = crate::io::Error::from(parse_err);
        assert!(!is_directory_fatal(&err));
    }
}

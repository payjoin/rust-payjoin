//! Failover-aware OHTTP relay and payjoin directory management.
//!
//! [`RequestHandler`] owns the selection policy for OHTTP relays and payjoin
//! directories, tracks which endpoints have failed, and — with the `io`
//! feature — fetches OHTTP keys with automatic failover: relay failures
//! retry over another relay, directory failures move on to another
//! directory.
//!
//! A directory chosen for a session must not change: it is embedded in the
//! BIP21 URI at session creation and recovered from the session event log
//! on resume. [`RequestHandler`] selects a directory only when a new session is
//! created; resumption does not consult it.
use bitcoin::secp256k1::rand::Rng;

use crate::selector::UrlSelector;
use crate::Url;

/// Selects OHTTP relays and payjoin directories, excluding endpoints marked
/// failed for the lifetime of this `RequestHandler`.
///
/// Methods take `&self`: failure state and pinned configuration are behind
/// `Mutex`es held only for synchronous accesses and never across `.await`,
/// so a `RequestHandler` can be shared across tasks (for example via `Arc`)
/// without an external async lock. It is not `Clone`: a clone would fork the
/// tracked failure state, so sharing goes through `Arc` and configuration
/// through the setters, which every holder observes.
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
    pub fn select_relay_excluding<R: Rng>(&self, rng: &mut R, exclude: &Url) -> Result<Url, Error> {
        self.relays.select_excluding(rng, exclude).ok_or(Error::NoRelaysAvailable)
    }

    /// Pick a payjoin directory, never one marked failed.
    pub fn select_directory<R: Rng>(&self, rng: &mut R) -> Result<Url, Error> {
        self.directories.select(rng).ok_or(Error::NoDirectoriesAvailable)
    }

    /// Record a relay transport failure so subsequent selections avoid it.
    pub fn mark_relay_failed(&self, relay: &Url) { self.relays.mark_failed(relay); }

    /// Record a directory failure so subsequent selections avoid it.
    pub fn mark_directory_failed(&self, directory: &Url) {
        self.directories.mark_failed(directory);
    }

    /// Clear all recorded relay failures so every configured relay is
    /// selectable again.
    pub fn clear_failed_relays(&self) { self.relays.clear_failed(); }

    /// Return the pinned OHTTP keys, or fetch them with automatic failover.
    ///
    /// Relay transport failures retry over another relay. A directory
    /// failure (unexpected status or oversized key body) marks that
    /// directory failed, resets the relay failure list, and retries over
    /// another directory. Returns an error only once every configured
    /// endpoint has been marked failed.
    ///
    /// Returns the directory alongside the keys: a receiver pins the
    /// directory in the BIP21 URI at session creation, so the directory is
    /// reported even when the keys are pinned and no fetch happened.
    #[cfg(feature = "io")]
    #[cfg_attr(docsrs, doc(cfg(feature = "io")))]
    pub async fn fetch_ohttp_keys<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Url, crate::OhttpKeys), Error> {
        loop {
            let directory = self.select_directory(rng)?;
            if let Some(ohttp_keys) = self.lock_ohttp_keys().clone() {
                return Ok((directory, ohttp_keys));
            }
            if let Ok(keys) = self.fetch_keys_via_relay(&directory, rng).await {
                return Ok((directory, keys));
            }
            // The directory was marked failed (directly, or by exhausting
            // every relay against it). Give the next directory a clean set
            // of relays to fail over through.
            self.clear_failed_relays();
        }
    }

    /// Fetch keys from `directory`, failing over relays on transport errors.
    ///
    /// On return the directory has been marked failed: either the directory
    /// itself misbehaved, or every relay failed to reach it.
    #[cfg(feature = "io")]
    #[cfg_attr(docsrs, doc(cfg(feature = "io")))]
    async fn fetch_keys_via_relay<R: Rng>(
        &self,
        directory: &Url,
        rng: &mut R,
    ) -> Result<crate::OhttpKeys, DirectoryAttemptFailure> {
        loop {
            let relay = match self.relays.select(rng) {
                Some(relay) => relay,
                None => {
                    // A directory that exhausted every relay is marked
                    // failed so selection moves on instead of retrying it
                    // forever.
                    self.directories.mark_failed(directory);
                    return Err(DirectoryAttemptFailure::RelaysExhausted);
                }
            };
            let result = self.fetch_via_relay(&relay, directory).await;
            match result {
                Ok(keys) => return Ok(keys),
                Err(e) if is_directory_fatal(&e) => {
                    tracing::debug!("Directory {directory} failed via relay {relay}: {e}");
                    self.directories.mark_failed(directory);
                    return Err(DirectoryAttemptFailure::Directory);
                }
                Err(e) => {
                    tracing::debug!("Relay {relay} failed: {e}");
                    self.mark_relay_failed(&relay);
                }
            }
        }
    }

    #[cfg(feature = "io")]
    #[cfg_attr(docsrs, doc(cfg(feature = "io")))]
    async fn fetch_via_relay(
        &self,
        relay: &Url,
        directory: &Url,
    ) -> Result<crate::OhttpKeys, crate::io::Error> {
        #[cfg(feature = "_manual-tls")]
        let cert_der = self.lock_cert_der().clone();
        #[cfg(feature = "_manual-tls")]
        if let Some(cert_der) = cert_der.as_ref() {
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

/// Why an attempt against one directory ended in failure. The underlying
/// error is logged where the failure is observed, before this is returned.
#[cfg(feature = "io")]
enum DirectoryAttemptFailure {
    /// Every relay failed to reach the directory.
    RelaysExhausted,
    /// The directory misbehaved; fetching over another relay would not help.
    Directory,
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
    fn error_displays_endpoint_kind() {
        assert_eq!(Error::NoRelaysAvailable.to_string(), "No valid relays available");
        assert_eq!(Error::NoDirectoriesAvailable.to_string(), "No valid directories available");
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
}

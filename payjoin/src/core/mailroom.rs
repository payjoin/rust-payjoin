//! Failover-aware OHTTP relay and payjoin directory management.
//!
//! [`Mailroom`] owns the selection policy for OHTTP relays and payjoin
//! directories, tracks which endpoints have failed, and — with the `io`
//! feature — fetches OHTTP keys with automatic failover: relay failures
//! retry over another relay, directory failures move on to another
//! directory.
//!
//! A directory chosen for a session must not change: it is embedded in the
//! BIP21 URI at session creation and recovered from the session event log
//! on resume. [`Mailroom`] selects a directory only when a new session is
//! created; resumption does not consult it.
use bitcoin::secp256k1::rand::Rng;

use crate::selector::{DirectorySelector, RelaySelector};
use crate::Url;

/// Selects OHTTP relays and payjoin directories, excluding endpoints marked
/// failed for the lifetime of this `Mailroom`.
///
/// Because [`Mailroom::fetch_ohttp_keys`] holds `&mut self` across `.await`
/// points, share a `Mailroom` behind an async-aware lock such as
/// `tokio::sync::Mutex`, never `std::sync::Mutex`.
#[derive(Clone, Debug)]
pub struct Mailroom {
    relays: RelaySelector,
    directories: DirectorySelector,
    ohttp_keys: Option<crate::OhttpKeys>,
    #[cfg(feature = "_manual-tls")]
    cert_der: Option<Vec<u8>>,
}

impl Mailroom {
    /// Deduplicates `relays` and `directories` (preserving order) so uniform
    /// selection isn't skewed by an endpoint listed more than once.
    pub fn new(relays: Vec<Url>, directories: Vec<Url>) -> Self {
        Self {
            relays: RelaySelector::new(relays),
            directories: DirectorySelector::new(directories),
            ohttp_keys: None,
            #[cfg(feature = "_manual-tls")]
            cert_der: None,
        }
    }

    /// Pin user-supplied OHTTP keys so [`Mailroom::fetch_ohttp_keys`] returns
    /// them without contacting a directory.
    pub fn with_ohttp_keys(mut self, ohttp_keys: crate::OhttpKeys) -> Self {
        self.ohttp_keys = Some(ohttp_keys);
        self
    }

    /// Use a DER-encoded certificate for local HTTPS connections when
    /// fetching OHTTP keys.
    #[cfg(feature = "_manual-tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "_manual-tls")))]
    pub fn with_cert_der(mut self, cert_der: Vec<u8>) -> Self {
        self.cert_der = Some(cert_der);
        self
    }

    /// Pick a relay, never one marked failed.
    pub fn select_relay<R: Rng>(&self, rng: &mut R) -> Result<Url, Error> {
        self.relays.select(rng).ok_or(Error::NoRelaysAvailable)
    }

    /// Pick a payjoin directory, never one marked failed.
    pub fn select_directory<R: Rng>(&self, rng: &mut R) -> Result<Url, Error> {
        self.directories.select(rng).ok_or(Error::NoDirectoriesAvailable)
    }

    /// Record a relay transport failure so subsequent selections avoid it.
    pub fn mark_relay_failed(&mut self, relay: &Url) { self.relays.mark_failed(relay); }

    /// Record a directory failure so subsequent selections avoid it.
    pub fn mark_directory_failed(&mut self, directory: &Url) {
        self.directories.mark_failed(directory);
    }

    /// Clear all recorded relay failures so every configured relay is
    /// selectable again.
    pub fn clear_failed_relays(&mut self) { self.relays.clear_failed(); }

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
        &mut self,
        rng: &mut R,
    ) -> Result<(Url, crate::OhttpKeys), Error> {
        loop {
            let directory = self.select_directory(rng)?;
            if let Some(ohttp_keys) = self.ohttp_keys.clone() {
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
        &mut self,
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
                    self.mark_directory_failed(directory);
                    return Err(DirectoryAttemptFailure::RelaysExhausted);
                }
            };
            let result = self.fetch_via_relay(&relay, directory).await;
            match result {
                Ok(keys) => return Ok(keys),
                Err(e) if is_directory_fatal(&e) => {
                    tracing::debug!("Directory {directory} failed via relay {relay}: {e}");
                    self.mark_directory_failed(directory);
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

/// Errors returned by [`Mailroom`] relay and directory selection.
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
    fn select_relay_fails_when_all_relays_marked_failed() {
        let mut mailroom = Mailroom::new(urls(), urls());
        for relay in urls() {
            mailroom.mark_relay_failed(&relay);
        }
        let mut rng = StdRng::seed_from_u64(1);
        assert_eq!(mailroom.select_relay(&mut rng), Err(Error::NoRelaysAvailable));
    }

    #[test]
    fn select_directory_fails_when_all_directories_marked_failed() {
        let mut mailroom = Mailroom::new(urls(), urls());
        for directory in urls() {
            mailroom.mark_directory_failed(&directory);
        }
        let mut rng = StdRng::seed_from_u64(2);
        assert_eq!(mailroom.select_directory(&mut rng), Err(Error::NoDirectoriesAvailable));
    }

    #[test]
    fn marked_relay_is_not_selected() {
        let mut mailroom = Mailroom::new(urls(), urls());
        let failed = urls()[0].clone();
        mailroom.mark_relay_failed(&failed);
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..50 {
            assert_ne!(mailroom.select_relay(&mut rng), Ok(failed.clone()));
        }
    }

    #[test]
    fn clear_failed_relays_restores_selection() {
        let mut mailroom = Mailroom::new(urls(), urls());
        for relay in urls() {
            mailroom.mark_relay_failed(&relay);
        }
        let mut rng = StdRng::seed_from_u64(4);
        assert!(mailroom.select_relay(&mut rng).is_err());
        mailroom.clear_failed_relays();
        assert!(mailroom.select_relay(&mut rng).is_ok());
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
        let mut mailroom = Mailroom::new(Vec::new(), directories.clone()).with_ohttp_keys(keys);
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
        let mut mailroom = Mailroom::new(Vec::new(), Vec::new()).with_ohttp_keys(keys);
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
}

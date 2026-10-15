use std::sync::{Mutex, PoisonError};

use bitcoin::secp256k1::rand::seq::IteratorRandom;
use bitcoin::secp256k1::rand::{self};

use crate::Url;

/// Picks a URL, excluding any marked failed, so clients share one
/// selection policy instead of each diverging.
///
/// Failure state is behind a `Mutex` so selection and marking take `&self` and
/// can be shared across tasks without an external lock. The lock is only held
/// for the duration of a synchronous access, never across an `.await`, so the
/// selector can back an async failover loop without serializing it.
///
/// Kept as the single selection path so a future topology-aware ordering (for
/// example AS-aware relay selection) lands here once, without forking into a
/// separate API that integrators would have to opt into individually.
#[derive(Debug)]
pub struct UrlSelector {
    urls: Vec<Url>,
    failed: Mutex<Vec<Url>>,
}

impl UrlSelector {
    /// Deduplicates `urls` (preserving order) so uniform selection isn't
    /// skewed by a URL listed more than once.
    pub fn new(urls: Vec<Url>) -> Self {
        let mut deduped: Vec<Url> = Vec::new();
        for url in urls {
            if !deduped.contains(&url) {
                deduped.push(url);
            }
        }
        Self { urls: deduped, failed: Mutex::new(Vec::new()) }
    }

    /// Lock the failed list, recovering from a poisoned lock rather than
    /// panicking: a panic in another thread should not take down selection.
    fn failed(&self) -> std::sync::MutexGuard<'_, Vec<Url>> {
        self.failed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Pick a URL, never one marked failed, or `None` when none remain.
    pub fn select<R: rand::Rng>(&self, rng: &mut R) -> Option<Url> {
        let failed = self.failed();
        self.urls.iter().filter(|u| !failed.contains(u)).choose(rng).cloned()
    }

    /// Pick a URL, never one marked failed and never `exclude`, or `None`
    /// when none remain.
    ///
    /// A relay equal to the selection target would loop back to itself: a
    /// server serving as both relay and directory rejects such a request as
    /// a self-loop. Callers pass the target (for example the session
    /// directory) so that candidate is skipped rather than tried and
    /// rejected over the network. URL equality is a heuristic: the same
    /// server under a different URL still slips through, and the server's
    /// self-loop protection remains authoritative.
    pub fn select_excluding<R: rand::Rng>(&self, rng: &mut R, exclude: &Url) -> Option<Url> {
        let failed = self.failed();
        self.urls.iter().filter(|u| !failed.contains(u) && *u != exclude).choose(rng).cloned()
    }

    /// Record a transport failure so `select` avoids the URL.
    pub fn mark_failed(&self, url: &Url) {
        let mut failed = self.failed();
        if !failed.contains(url) {
            failed.push(url.clone());
        }
    }

    /// Clear all recorded failures so every configured URL is selectable
    /// again.
    pub fn clear_failed(&self) { self.failed().clear(); }
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
    fn select_returns_a_configured_url() {
        let selector = UrlSelector::new(urls());
        let mut rng = StdRng::seed_from_u64(1);
        let picked = selector.select(&mut rng).expect("a url");
        assert!(urls().contains(&picked));
    }

    #[test]
    fn select_never_returns_a_failed_relay() {
        let selector = UrlSelector::new(urls());
        let mut rng = StdRng::seed_from_u64(2);
        let failed = Url::parse("https://a.example").unwrap();
        selector.mark_failed(&failed);
        for _ in 0..50 {
            assert_ne!(selector.select(&mut rng), Some(failed.clone()));
        }
    }

    #[test]
    fn select_never_returns_a_failed_directory() {
        let selector = UrlSelector::new(urls());
        let mut rng = StdRng::seed_from_u64(7);
        let failed = Url::parse("https://b.example").unwrap();
        selector.mark_failed(&failed);
        for _ in 0..50 {
            assert_ne!(selector.select(&mut rng), Some(failed.clone()));
        }
    }

    #[test]
    fn select_is_none_when_all_failed() {
        let selector = UrlSelector::new(urls());
        for u in urls() {
            selector.mark_failed(&u);
        }
        let mut rng = StdRng::seed_from_u64(3);
        assert_eq!(selector.select(&mut rng), None);
    }

    #[test]
    fn clear_failed_restores_all_urls() {
        let selector = UrlSelector::new(urls());
        for u in urls() {
            selector.mark_failed(&u);
        }
        let mut rng = StdRng::seed_from_u64(6);
        assert_eq!(selector.select(&mut rng), None);
        selector.clear_failed();
        assert!(selector.select(&mut rng).is_some());
    }

    #[test]
    fn new_dedups_urls_preserving_order() {
        let a = Url::parse("https://a.example").unwrap();
        let b = Url::parse("https://b.example").unwrap();
        let selector = UrlSelector::new(vec![a.clone(), a.clone(), b.clone()]);
        assert_eq!(selector.urls, vec![a, b]);
    }

    #[test]
    fn select_is_none_when_empty() {
        let selector = UrlSelector::new(Vec::new());
        let mut rng = StdRng::seed_from_u64(4);
        assert_eq!(selector.select(&mut rng), None);
    }

    // Selection is uniform across all configured URLs.
    #[test]
    fn select_excluding_never_returns_the_excluded_url() {
        let selector = UrlSelector::new(urls());
        let excluded = urls()[1].clone();
        let mut rng = StdRng::seed_from_u64(8);
        for _ in 0..50 {
            assert_ne!(selector.select_excluding(&mut rng, &excluded), Some(excluded.clone()));
        }
    }

    #[test]
    fn select_excluding_is_none_when_only_the_excluded_url_remains() {
        let selector = UrlSelector::new(urls());
        let excluded = urls()[0].clone();
        let mut rng = StdRng::seed_from_u64(9);
        for url in urls().iter().skip(1) {
            selector.mark_failed(url);
        }
        assert_eq!(selector.select_excluding(&mut rng, &excluded), None);
    }

    #[test]
    fn select_excluding_still_skips_failed_urls() {
        let selector = UrlSelector::new(urls());
        let excluded = urls()[0].clone();
        let failed = urls()[1].clone();
        selector.mark_failed(&failed);
        let mut rng = StdRng::seed_from_u64(10);
        for _ in 0..50 {
            let picked = selector.select_excluding(&mut rng, &excluded).unwrap();
            assert_ne!(picked, excluded);
            assert_ne!(picked, failed);
        }
    }

    #[test]
    fn select_is_uniform_across_urls() {
        let selector = UrlSelector::new(urls());
        let mut seen = std::collections::BTreeSet::new();
        let mut rng = StdRng::seed_from_u64(5);
        for _ in 0..200 {
            if let Some(u) = selector.select(&mut rng) {
                seen.insert(u.to_string());
            }
        }
        assert_eq!(seen.len(), urls().len(), "random must reach every url");
    }
}

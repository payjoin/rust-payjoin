use bitcoin::secp256k1::rand::seq::IteratorRandom;
use bitcoin::secp256k1::rand::{self};

use crate::Url;

/// Picks a URL, excluding any marked failed, so clients share one
/// selection policy instead of each diverging.
///
/// Kept as the single selection path so a future topology-aware ordering (for
/// example AS-aware relay selection) lands here once, without forking into a
/// separate API that integrators would have to opt into individually.
#[derive(Clone, Debug)]
pub struct UrlSelector {
    urls: Vec<Url>,
    failed: Vec<Url>,
}

/// Selects an OHTTP relay from the configured list, excluding failed ones.
pub type RelaySelector = UrlSelector;

/// Selects a payjoin directory from the configured list, excluding failed
/// ones.
pub type DirectorySelector = UrlSelector;

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
        Self { urls: deduped, failed: Vec::new() }
    }

    /// Pick a URL, never one marked failed, or `None` when none remain.
    pub fn select<R: rand::Rng>(&self, rng: &mut R) -> Option<Url> {
        self.urls.iter().filter(|u| !self.failed.contains(u)).choose(rng).cloned()
    }

    /// Record a transport failure so `select` avoids the URL.
    pub fn mark_failed(&mut self, url: &Url) {
        if !self.failed.contains(url) {
            self.failed.push(url.clone());
        }
    }

    /// Clear all recorded failures so every configured URL is selectable
    /// again.
    pub fn clear_failed(&mut self) { self.failed.clear(); }
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
        let selector = RelaySelector::new(urls());
        let mut rng = StdRng::seed_from_u64(1);
        let picked = selector.select(&mut rng).expect("a url");
        assert!(urls().contains(&picked));
    }

    #[test]
    fn select_never_returns_a_failed_relay() {
        let mut selector = RelaySelector::new(urls());
        let mut rng = StdRng::seed_from_u64(2);
        let failed = Url::parse("https://a.example").unwrap();
        selector.mark_failed(&failed);
        for _ in 0..50 {
            assert_ne!(selector.select(&mut rng), Some(failed.clone()));
        }
    }

    #[test]
    fn select_never_returns_a_failed_directory() {
        let mut selector = DirectorySelector::new(urls());
        let mut rng = StdRng::seed_from_u64(7);
        let failed = Url::parse("https://b.example").unwrap();
        selector.mark_failed(&failed);
        for _ in 0..50 {
            assert_ne!(selector.select(&mut rng), Some(failed.clone()));
        }
    }

    #[test]
    fn select_is_none_when_all_failed() {
        let mut selector = RelaySelector::new(urls());
        for u in urls() {
            selector.mark_failed(&u);
        }
        let mut rng = StdRng::seed_from_u64(3);
        assert_eq!(selector.select(&mut rng), None);
    }

    #[test]
    fn clear_failed_restores_all_urls() {
        let mut selector = RelaySelector::new(urls());
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
        let selector = RelaySelector::new(Vec::new());
        let mut rng = StdRng::seed_from_u64(4);
        assert_eq!(selector.select(&mut rng), None);
    }

    // Selection is uniform across all configured URLs.
    #[test]
    fn select_is_uniform_across_urls() {
        let selector = RelaySelector::new(urls());
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

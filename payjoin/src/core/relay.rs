use bitcoin::secp256k1::rand::seq::IteratorRandom;
use bitcoin::secp256k1::rand::{self};

use crate::Url;

/// Picks an OHTTP relay, excluding relays marked failed, so clients share one
/// selection policy instead of each diverging.
#[derive(Clone, Debug)]
pub struct RelaySelector {
    relays: Vec<Url>,
    failed: Vec<Url>,
}

impl RelaySelector {
    /// Deduplicates `relays` (preserving order) so uniform selection isn't
    /// skewed by a relay listed more than once.
    pub fn new(relays: Vec<Url>) -> Self {
        let mut deduped: Vec<Url> = Vec::new();
        for relay in relays {
            if !deduped.contains(&relay) {
                deduped.push(relay);
            }
        }
        Self { relays: deduped, failed: Vec::new() }
    }

    /// Pick a relay, never one marked failed, or `None` when none remain.
    pub fn select<R: rand::Rng>(&self, rng: &mut R) -> Option<Url> {
        self.relays.iter().filter(|r| !self.failed.contains(r)).choose(rng).cloned()
    }

    /// Record a relay transport failure so `select` avoids it.
    pub fn mark_failed(&mut self, relay: &Url) {
        if !self.failed.contains(relay) {
            self.failed.push(relay.clone());
        }
    }

    /// Clear all recorded failures so every configured relay is selectable again.
    pub fn clear_failed(&mut self) { self.failed.clear(); }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::rand::rngs::StdRng;
    use bitcoin::secp256k1::rand::SeedableRng;

    use super::*;

    fn relays() -> Vec<Url> {
        ["https://a.example", "https://b.example", "https://c.example"]
            .iter()
            .map(|s| Url::parse(s).unwrap())
            .collect()
    }

    #[test]
    fn select_returns_a_configured_relay() {
        let selector = RelaySelector::new(relays());
        let mut rng = StdRng::seed_from_u64(1);
        let picked = selector.select(&mut rng).expect("a relay");
        assert!(relays().contains(&picked));
    }

    #[test]
    fn select_never_returns_a_failed_relay() {
        let mut selector = RelaySelector::new(relays());
        let mut rng = StdRng::seed_from_u64(2);
        let failed = Url::parse("https://a.example").unwrap();
        selector.mark_failed(&failed);
        for _ in 0..50 {
            assert_ne!(selector.select(&mut rng), Some(failed.clone()));
        }
    }

    #[test]
    fn select_is_none_when_all_failed() {
        let mut selector = RelaySelector::new(relays());
        for r in relays() {
            selector.mark_failed(&r);
        }
        let mut rng = StdRng::seed_from_u64(3);
        assert_eq!(selector.select(&mut rng), None);
    }

    #[test]
    fn clear_failed_restores_all_relays() {
        let mut selector = RelaySelector::new(relays());
        for r in relays() {
            selector.mark_failed(&r);
        }
        let mut rng = StdRng::seed_from_u64(6);
        assert_eq!(selector.select(&mut rng), None);
        selector.clear_failed();
        assert!(selector.select(&mut rng).is_some());
    }

    #[test]
    fn new_dedups_relays_preserving_order() {
        let a = Url::parse("https://a.example").unwrap();
        let b = Url::parse("https://b.example").unwrap();
        let selector = RelaySelector::new(vec![a.clone(), a.clone(), b.clone()]);
        assert_eq!(selector.relays, vec![a, b]);
    }

    #[test]
    fn select_is_none_when_empty() {
        let selector = RelaySelector::new(Vec::new());
        let mut rng = StdRng::seed_from_u64(4);
        assert_eq!(selector.select(&mut rng), None);
    }

    // Selection is uniform across all relays.
    #[test]
    fn select_is_uniform_across_relays() {
        let selector = RelaySelector::new(relays());
        let mut seen = std::collections::BTreeSet::new();
        let mut rng = StdRng::seed_from_u64(5);
        for _ in 0..200 {
            if let Some(r) = selector.select(&mut rng) {
                seen.insert(r.to_string());
            }
        }
        assert_eq!(seen.len(), relays().len(), "random must reach every relay");
    }
}

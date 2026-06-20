use bitcoin::secp256k1::rand::seq::IteratorRandom;
use bitcoin::secp256k1::rand::{self};

use crate::Url;

/// Picks an OHTTP relay at random, excluding relays marked failed, so clients
/// share one selection policy instead of each diverging.
#[derive(Clone, Debug)]
pub struct RelaySelector {
    relays: Vec<Url>,
    failed: Vec<Url>,
}

impl RelaySelector {
    pub fn new(relays: Vec<Url>) -> Self { Self { relays, failed: Vec::new() } }

    /// Pick a random relay not marked failed, or `None` when none remain.
    pub fn select<R: rand::Rng>(&self, rng: &mut R) -> Option<Url> {
        self.relays.iter().filter(|r| !self.failed.contains(r)).choose(rng).cloned()
    }

    pub fn mark_failed(&mut self, relay: &Url) {
        if !self.failed.contains(relay) {
            self.failed.push(relay.clone());
        }
    }
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
    fn select_is_none_when_empty() {
        let selector = RelaySelector::new(Vec::new());
        let mut rng = StdRng::seed_from_u64(4);
        assert_eq!(selector.select(&mut rng), None);
    }
}

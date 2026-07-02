use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::Duration;

/// Mean gap of the Poisson poll schedule. The directory learns only this rate,
/// so it must stay uniform across clients, not a per-user knob.
pub const POLL_MEAN: Duration = Duration::from_secs(5);

/// Samples inter-poll gaps from an Exp(1/mean) distribution. Emit polls on
/// this clock independently of responses (reset on fire, before awaiting the
/// poll) so the observed interval is the gap, not gap + round-trip.
#[derive(Debug)]
pub struct PollSchedule {
    state: u64,
    mean: Duration,
}

impl PollSchedule {
    /// Create a schedule seeded from OS entropy at the standard [`POLL_MEAN`] rate.
    pub fn new() -> Self {
        // Seed from OS entropy via the standard library's randomly-keyed hasher:
        // hashing a fixed value mixes those random keys into a u64.
        let mut h = RandomState::new().build_hasher();
        h.write_u64(0);
        Self { state: h.finish(), mean: POLL_MEAN }
    }

    /// Sample the next inter-poll gap.
    pub fn next_gap(&mut self) -> Duration {
        Duration::from_secs_f64(-self.mean.as_secs_f64() * self.next_uniform().ln())
    }

    /// Draw the next uniform sample in (0, 1) from the SplitMix64 state.
    fn next_uniform(&mut self) -> f64 {
        // SplitMix64 (reference constants: golden-ratio increment + two mixers)
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        ((z >> 11) as f64 + 1.0) / (1u64 << 53) as f64
    }
}

impl Default for PollSchedule {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_seed(seed: u64, mean: Duration) -> PollSchedule { PollSchedule { state: seed, mean } }

    #[test]
    fn uniform_sequence_is_pinned() {
        let mut s = from_seed(1, Duration::from_secs(5));
        assert_eq!(s.next_uniform(), 0.566561575172281);
        assert_eq!(s.next_uniform(), 0.7457817572627012);
        assert_eq!(s.next_uniform(), 0.9710027535867963);
    }

    #[test]
    fn same_seed_is_deterministic() {
        let mut a = from_seed(1, Duration::from_secs(5));
        let mut b = from_seed(1, Duration::from_secs(5));
        for _ in 0..100 {
            assert_eq!(a.next_gap(), b.next_gap());
        }
    }

    #[test]
    fn mean_is_near_lambda_inverse() {
        let mut s = from_seed(440, Duration::from_secs(5));
        let n = 20_000;
        let total: f64 = (0..n).map(|_| s.next_gap().as_secs_f64()).sum();
        let mean = total / n as f64;
        assert!((mean - 5.0).abs() < 0.2, "mean gap {mean} not ~5s");
    }
}

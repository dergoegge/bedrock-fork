// SPDX-License-Identifier: GPL-2.0

//! A small deterministic PRNG (splitmix64) used by the mutator, the corpus
//! scheduler, and the RNG-tape fresh-extension. Deterministic and seedable so a
//! whole campaign can be reproduced from its seed.

#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng { state: seed }
    }

    /// splitmix64 — a fast, well-distributed 64-bit generator.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish index in `[0, n)`. Returns 0 for `n == 0`.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// Uniform-ish value in `[lo, hi]` (inclusive). Returns `lo` if `hi <= lo`.
    pub fn range_u64(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            lo + self.next_u64() % (hi - lo + 1)
        }
    }

    pub fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_differ() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn below_in_range() {
        let mut r = Rng::new(7);
        for _ in 0..10_000 {
            assert!(r.below(13) < 13);
        }
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn range_inclusive_bounds() {
        let mut r = Rng::new(99);
        for _ in 0..10_000 {
            let v = r.range_u64(5, 9);
            assert!((5..=9).contains(&v));
        }
        assert_eq!(r.range_u64(3, 3), 3);
        assert_eq!(r.range_u64(9, 3), 9);
    }
}

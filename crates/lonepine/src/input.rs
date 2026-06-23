// SPDX-License-Identifier: GPL-2.0

//! The fuzzer's input: a typed [`Plan`] rather than an opaque byte buffer.
//!
//! A plan is a sequence of [`Step`]s; each step launches a concurrent batch of
//! drivers plus the RNG the guest consumed that step. A per-plan [`DriverMask`]
//! implements swarm testing (each plan is restricted to a random enabled-driver
//! subset). RNG is *consume-and-record*: a step's `rng` is exactly what the
//! guest pulled, captured from the lab's input recording after execution.

use crate::hash::fnv1a_128;
use crate::prng::Rng;

/// Swarm mask: which drivers are enabled for a given plan. Fixed within a plan,
/// changed only by deriving a new plan (the `FlipMask` mutation). Not part of
/// execution — it only constrains what the mutator may introduce — so it is
/// deliberately absent from the trie edge key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverMask {
    enabled: Vec<bool>,
}

impl DriverMask {
    pub fn all(n: usize) -> Self {
        DriverMask {
            enabled: vec![true; n],
        }
    }

    pub fn len(&self) -> usize {
        self.enabled.len()
    }

    pub fn is_empty(&self) -> bool {
        self.enabled.is_empty()
    }

    pub fn is_enabled(&self, i: usize) -> bool {
        self.enabled.get(i).copied().unwrap_or(false)
    }

    pub fn set(&mut self, i: usize, v: bool) {
        if i < self.enabled.len() {
            self.enabled[i] = v;
        }
    }

    pub fn toggle(&mut self, i: usize) {
        if i < self.enabled.len() {
            self.enabled[i] = !self.enabled[i];
        }
    }

    pub fn count_enabled(&self) -> usize {
        self.enabled.iter().filter(|&&e| e).count()
    }

    pub fn enabled_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.enabled
            .iter()
            .enumerate()
            .filter_map(|(i, &e)| if e { Some(i) } else { None })
    }

    /// Pick a uniformly-random enabled driver index, or `None` if none enabled.
    pub fn pick_enabled(&self, rng: &mut Rng) -> Option<usize> {
        let c = self.count_enabled();
        if c == 0 {
            return None;
        }
        self.enabled_indices().nth(rng.below(c))
    }

    /// Guarantee at least one driver is enabled (re-enable index 0 otherwise),
    /// so a plan can always make progress. No-op for an empty mask.
    pub fn ensure_nonempty(&mut self) {
        if self.count_enabled() == 0 && !self.enabled.is_empty() {
            self.enabled[0] = true;
        }
    }
}

/// One driver invocation within a batch: which `(container, driver)` rule, and
/// the virtual-time offset (TSC ticks) at which it launches relative to the
/// step's base time. The offset is the interleaving knob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub driver: usize,
    pub offset: i64,
}

/// One step: a concurrent batch of drivers plus the two randomness tapes the
/// guest consumed while running them (front-to-back, shared across the batch):
/// `rng` is the RDRAND/RDSEED stream; `rand` is the `HYPERCALL_GET_RANDOM`
/// (`/dev/urandom` / `getrandom()`) byte stream — the high-signal knob, since it
/// reaches driver/parser inputs verbatim with no CRNG laundering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub batch: Vec<Member>,
    pub rng: Vec<u8>,
    pub rand: Vec<u8>,
}

impl Step {
    /// The trie edge label for this step: a hash of the batch spec plus both
    /// consumed randomness tapes. The mask is intentionally excluded — it does
    /// not affect execution. Both tapes are included because they both determine
    /// the resulting guest state, so two steps that differ only in their
    /// `getrandom()` bytes must not collide to the same cached checkpoint.
    pub fn edge_hash(&self) -> u128 {
        let mut buf =
            Vec::with_capacity(self.batch.len() * 16 + self.rng.len() + self.rand.len() + 2);
        for m in &self.batch {
            buf.extend_from_slice(&(m.driver as u64).to_le_bytes());
            buf.extend_from_slice(&m.offset.to_le_bytes());
        }
        buf.push(0xff); // separate the batch spec from the rng bytes
        buf.extend_from_slice(&self.rng);
        buf.push(0xfe); // separate the rng tape from the rand tape
        buf.extend_from_slice(&self.rand);
        fnv1a_128(&buf)
    }
}

/// A complete fuzzer input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub mask: DriverMask,
    pub steps: Vec<Step>,
}

impl Plan {
    /// An empty plan with every driver enabled — the campaign's initial seed.
    pub fn empty(n_drivers: usize) -> Self {
        Plan {
            mask: DriverMask::all(n_drivers),
            steps: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Edge-hash sequence for trie lookup, one per step (using each step's
    /// current `rng`).
    pub fn edges(&self) -> Vec<u128> {
        self.steps.iter().map(|s| s.edge_hash()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_pick_only_enabled() {
        let mut m = DriverMask::all(4);
        m.set(1, false);
        m.set(3, false);
        let mut r = Rng::new(1);
        for _ in 0..1000 {
            let i = m.pick_enabled(&mut r).unwrap();
            assert!(i == 0 || i == 2);
        }
    }

    #[test]
    fn mask_ensure_nonempty() {
        let mut m = DriverMask::all(3);
        for i in 0..3 {
            m.set(i, false);
        }
        assert_eq!(m.count_enabled(), 0);
        m.ensure_nonempty();
        assert_eq!(m.count_enabled(), 1);
        assert!(m.is_enabled(0));
    }

    #[test]
    fn edge_hash_sensitive_to_batch_and_rng() {
        let s = Step {
            batch: vec![Member {
                driver: 1,
                offset: 0,
            }],
            rng: vec![1, 2, 3],
            rand: vec![],
        };
        let same = s.clone();
        assert_eq!(s.edge_hash(), same.edge_hash());

        let mut diff_driver = s.clone();
        diff_driver.batch[0].driver = 2;
        assert_ne!(s.edge_hash(), diff_driver.edge_hash());

        let mut diff_offset = s.clone();
        diff_offset.batch[0].offset = 7;
        assert_ne!(s.edge_hash(), diff_offset.edge_hash());

        let mut diff_rng = s.clone();
        diff_rng.rng.push(4);
        assert_ne!(s.edge_hash(), diff_rng.edge_hash());

        // The getrandom() tape is part of the edge key too.
        let mut diff_rand = s.clone();
        diff_rand.rand.push(9);
        assert_ne!(s.edge_hash(), diff_rand.edge_hash());
    }

    #[test]
    fn edge_hash_ignores_mask() {
        // Two plans, identical steps, different masks => identical edges.
        let step = Step {
            batch: vec![Member {
                driver: 0,
                offset: 0,
            }],
            rng: vec![],
            rand: vec![],
        };
        let mut a = Plan {
            mask: DriverMask::all(3),
            steps: vec![step.clone()],
        };
        let mut b = a.clone();
        a.mask.set(2, false);
        b.mask.set(1, false);
        assert_eq!(a.edges(), b.edges());
    }
}

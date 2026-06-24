// SPDX-License-Identifier: GPL-2.0

//! The randomness tapes fed to a step. Two independent streams replay the step's
//! recorded bytes, and when the guest consumes past them (a mutation pushed it
//! down a hungrier path) extend with fresh deterministic bytes:
//!
//! - `rng` — the RDRAND/RDSEED stream (`next_rng_u64`).
//! - `rand` — the `HYPERCALL_GET_RANDOM` (`/dev/urandom` / `getrandom()`) byte
//!   stream (`next_random`), served as one flat front-to-back tape shared across
//!   every request in the step.
//!
//! The lab records everything both return, so after the step the realized
//! consumption is captured back into the plan — no length cap, no exhaustion.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bedrock_lab::InputSource;

use crate::prng::Rng;

#[derive(Clone)]
pub struct ReplayThenFresh {
    rng_tape: Arc<Vec<u8>>,
    rng_pos: usize,
    rand_tape: Arc<Vec<u8>>,
    rand_pos: usize,
    fresh: Rng,
    /// Count of bytes served from the fresh PRNG past the end of either recorded
    /// tape. Shared across clones (see [`InputSource::clone_box`]) so the caller
    /// can read the total after the branch — and any of its forked sub-branches —
    /// has run. During a campaign, drawing fresh is the normal way exploration
    /// pushes past a recording; during reproduce it is a hard failure, because the
    /// saved recording is supposed to contain every byte the guest consumed.
    overrun: Arc<AtomicU64>,
}

impl ReplayThenFresh {
    /// `rng`/`rand` are the step's seed RDRAND and `getrandom()` tapes; `seed`
    /// seeds the fresh-extension PRNG (only reached past a recording, during
    /// exploration).
    pub fn new(rng: Vec<u8>, rand: Vec<u8>, seed: u64) -> Self {
        ReplayThenFresh {
            rng_tape: Arc::new(rng),
            rng_pos: 0,
            rand_tape: Arc::new(rand),
            rand_pos: 0,
            fresh: Rng::new(seed),
            overrun: Arc::new(AtomicU64::new(0)),
        }
    }

    /// A handle to this source's fresh-byte counter, shared with every clone.
    /// Read it after the branch has run to learn how many bytes were served past
    /// the recorded tapes (`0` == the recording covered every draw).
    pub fn overrun_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.overrun)
    }
}

impl InputSource for ReplayThenFresh {
    fn next_rng_u64(&mut self) -> Option<u64> {
        let end = self.rng_pos + 8;
        if let Some(chunk) = self.rng_tape.get(self.rng_pos..end) {
            self.rng_pos = end;
            let mut b = [0u8; 8];
            b.copy_from_slice(chunk);
            Some(u64::from_le_bytes(b))
        } else {
            // Past the recording: generate fresh. The lab records the value, so
            // a later replay reads it from the tape and never reaches here.
            self.overrun.fetch_add(8, Ordering::Relaxed);
            Some(self.fresh.next_u64())
        }
    }

    fn next_random(&mut self, len: usize, _pid: u32) -> Vec<u8> {
        // Serve `len` bytes from the recorded rand tape (front-to-back across all
        // requests in the step), topping up with fresh bytes past the recording.
        // Always returns exactly `len` bytes.
        let mut out = Vec::with_capacity(len);
        let end = self.rand_pos + len;
        if let Some(chunk) = self.rand_tape.get(self.rand_pos..end) {
            out.extend_from_slice(chunk);
            self.rand_pos = end;
        } else {
            // Take whatever recorded bytes remain, then extend fresh.
            let remaining = self.rand_tape.get(self.rand_pos..).unwrap_or(&[]);
            out.extend_from_slice(remaining);
            self.rand_pos = self.rand_tape.len();
            let fresh_start = out.len();
            while out.len() < len {
                out.extend_from_slice(&self.fresh.next_u64().to_le_bytes());
            }
            out.truncate(len);
            self.overrun
                .fetch_add((len - fresh_start) as u64, Ordering::Relaxed);
        }
        out
    }

    fn clone_box(&self) -> Box<dyn InputSource> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bedrock_lab::InputSource;

    #[test]
    fn replays_recorded_then_extends() {
        let recorded = [7u64.to_le_bytes(), 9u64.to_le_bytes()].concat();
        let mut t = ReplayThenFresh::new(recorded, vec![], 123);
        assert_eq!(t.next_rng_u64(), Some(7));
        assert_eq!(t.next_rng_u64(), Some(9));
        // past the recording -> fresh, never None
        assert!(t.next_rng_u64().is_some());
        assert!(t.next_rng_u64().is_some());
    }

    #[test]
    fn partial_trailing_bytes_go_fresh() {
        // 5 trailing bytes can't form a u64; the source falls through to fresh.
        let mut t = ReplayThenFresh::new(vec![1, 2, 3, 4, 5], vec![], 1);
        assert!(t.next_rng_u64().is_some());
    }

    #[test]
    fn rand_replays_recorded_then_extends() {
        let mut t = ReplayThenFresh::new(vec![], vec![1, 2, 3, 4], 7);
        // Exact recorded bytes for a request inside the recording.
        assert_eq!(t.next_random(3, 0), vec![1, 2, 3]);
        // Straddles the end: one recorded byte then fresh fill, exact length.
        let r = t.next_random(5, 0);
        assert_eq!(r.len(), 5);
        assert_eq!(r[0], 4);
        // Fully past the recording -> all fresh, exact length, never short.
        assert_eq!(t.next_random(16, 0).len(), 16);
    }

    #[test]
    fn clone_is_independent() {
        let mut a = ReplayThenFresh::new(vec![], vec![], 42);
        let mut b = a.clone();
        // Same seed => same fresh stream; independent cursors.
        assert_eq!(a.next_rng_u64(), b.next_rng_u64());
        assert_eq!(a.next_random(8, 0), b.next_random(8, 0));
    }

    #[test]
    fn overrun_counts_only_fresh_bytes() {
        // Draws fully inside the recorded tapes never touch the fresh PRNG.
        let mut t = ReplayThenFresh::new(7u64.to_le_bytes().to_vec(), vec![1, 2, 3, 4], 0);
        let overrun = t.overrun_handle();
        assert_eq!(t.next_rng_u64(), Some(7));
        assert_eq!(t.next_random(4, 0), vec![1, 2, 3, 4]);
        assert_eq!(overrun.load(Ordering::Relaxed), 0, "stayed within the tape");

        // Drawing past the rng tape adds 8 (one fresh u64); a 6-byte getrandom
        // request fully past its tape adds 6.
        t.next_rng_u64();
        t.next_random(6, 0);
        assert_eq!(overrun.load(Ordering::Relaxed), 8 + 6);
    }

    #[test]
    fn overrun_is_shared_across_clones() {
        let a = ReplayThenFresh::new(vec![], vec![], 1);
        let overrun = a.overrun_handle();
        let mut b = a.clone(); // a forked sub-branch
        b.next_rng_u64(); // fresh draw on the clone
        assert_eq!(
            overrun.load(Ordering::Relaxed),
            8,
            "a clone's overrun is visible through the original's handle"
        );
    }
}

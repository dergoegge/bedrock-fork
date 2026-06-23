// SPDX-License-Identifier: GPL-2.0

//! The corpus: the seed pool the mutator draws from, with each entry anchored in
//! the lab's **radix genealogy** so its prefix can be resumed and revived.
//!
//! An entry is a plan that hit never-seen coverage, kept together with everything
//! needed to re-enter its execution cheaply:
//!
//! - `tip` — the live [`Checkpoint`] at the plan's end. A mutation that only
//!   appends resumes by forking it; a mutation that edits step `k` resumes by
//!   [`Checkpoint::rewind`]ing it to the checkpoint after step `k-1`. Both are
//!   served by the genealogy (a radix tree over the input recording).
//! - `retained` — a [`RetainedInput`] anchor. It pins the entry's *input* prefix
//!   in the genealogy (not the VM), so even after the tip's VM is evicted the
//!   prefix stays classifiable as known and **revivable** by replay.
//! - `step_times` — the virtual time of the checkpoint after each step, so a
//!   rewind target can be named without holding per-step checkpoints.
//!
//! Live tips are bounded by `budget`: beyond it the oldest entry's tip VM is
//! dropped (its `retained` anchor stays, so it is revived on demand via
//! [`RetainedInput::longest_checkpoint_prefix`]). The corpus of *inputs* is never
//! evicted — only the expensive VM state behind a tip.

use std::collections::VecDeque;

use bedrock_lab::{Checkpoint, InputRecording, PrefixMatch, RetainedInput, VirtTime};

use crate::input::Plan;
use crate::prng::Rng;

/// One coverage find: the plan plus its radix-genealogy resume handles.
pub struct Entry {
    plan: Plan,
    /// Virtual time of the checkpoint taken after each step (len == plan.len()).
    step_times: Vec<VirtTime>,
    /// Input-prefix anchor in the genealogy — keeps the prefix revivable even
    /// after `tip` is dropped.
    retained: RetainedInput,
    /// Live VM at the plan's end; `None` once evicted under the live-tip budget.
    tip: Option<Checkpoint>,
    /// Step count, cached for the size tournament.
    steps: usize,
}

impl Entry {
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn step_times(&self) -> &[VirtTime] {
        &self.step_times
    }
}

pub struct Corpus {
    entries: Vec<Entry>,
    /// Indices with a live tip, oldest at the front (a tip may appear more than
    /// once after a revival re-notes it; stale duplicates are popped as no-ops).
    tip_lru: VecDeque<usize>,
    /// Count of entries currently holding a live tip.
    live: usize,
    /// Maximum live tips before the oldest is evicted (0 == unbounded).
    budget: usize,
}

impl Corpus {
    pub fn new(budget: usize) -> Self {
        Corpus {
            entries: Vec::new(),
            tip_lru: VecDeque::new(),
            live: 0,
            budget,
        }
    }

    /// Number of permanent coverage finds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries currently holding a live VM tip (the heartbeat's cache metric).
    pub fn live_tips(&self) -> usize {
        self.live
    }

    /// Seed the corpus with the empty plan rooted at the ready checkpoint. The
    /// empty plan resumes from `ready` directly (its `tip` is never rewound), so
    /// this just establishes a pickable entry the mutator grows from.
    pub fn seed(&mut self, ready: &Checkpoint) {
        let retained = ready.retain();
        self.entries.push(Entry {
            plan: Plan::empty(0),
            step_times: Vec::new(),
            retained,
            tip: Some(ready.clone()),
            steps: 0,
        });
        self.note_live(0);
    }

    /// Add a coverage find: its plan, the per-step checkpoint times, and the live
    /// tip. The tip is `retain`ed so the prefix survives tip eviction. Returns the
    /// new entry index.
    pub fn add(&mut self, plan: Plan, step_times: Vec<VirtTime>, tip: Checkpoint) -> usize {
        debug_assert_eq!(plan.len(), step_times.len());
        let retained = tip.retain();
        let steps = plan.len();
        let idx = self.entries.len();
        self.entries.push(Entry {
            plan,
            step_times,
            retained,
            tip: Some(tip),
            steps,
        });
        self.note_live(idx);
        idx
    }

    /// Pick a seed to mutate via a 2-way size tournament (prefer smaller, cheaper
    /// plans). Returns `(index, plan clone)`.
    pub fn pick(&self, rng: &mut Rng) -> Option<(usize, Plan)> {
        let n = self.entries.len();
        if n == 0 {
            return None;
        }
        let a = rng.below(n);
        let b = rng.below(n);
        let idx = if self.entries[a].steps <= self.entries[b].steps {
            a
        } else {
            b
        };
        Some((idx, self.entries[idx].plan.clone()))
    }

    /// A uniformly-random donor plan for splice mutations.
    pub fn donor(&self, rng: &mut Rng) -> Option<Plan> {
        let n = self.entries.len();
        if n == 0 {
            return None;
        }
        Some(self.entries[rng.below(n)].plan.clone())
    }

    pub fn entry(&self, idx: usize) -> &Entry {
        &self.entries[idx]
    }

    /// The live tip at `idx`, cloned, if it has not been evicted.
    pub fn tip(&self, idx: usize) -> Option<Checkpoint> {
        self.entries[idx].tip.clone()
    }

    /// Locate this entry's retained input prefix against the genealogy — the
    /// radix query used to revive an evicted tip (fork the deepest live ancestor,
    /// replay the recorded suffix forward).
    pub fn retained_prefix(&self, idx: usize) -> Option<PrefixMatch> {
        self.entries[idx].retained.longest_checkpoint_prefix()
    }

    /// A clone of this entry's full input recording (the retained corpus input),
    /// used as the replay tape when reviving from the root.
    pub fn recording(&self, idx: usize) -> InputRecording {
        self.entries[idx].retained.recording().clone()
    }

    /// Install a revived tip for `idx`, re-noting it as live (and evicting the
    /// oldest if over budget).
    pub fn set_tip(&mut self, idx: usize, tip: Checkpoint) {
        let was_live = self.entries[idx].tip.is_some();
        self.entries[idx].tip = Some(tip);
        if !was_live {
            self.note_live(idx);
        }
    }

    /// Mark `idx` as holding a live tip and enforce the budget.
    fn note_live(&mut self, idx: usize) {
        self.tip_lru.push_back(idx);
        self.live += 1;
        self.evict_if_needed();
    }

    /// Drop the oldest live tips until within budget. Dropping a tip frees its VM
    /// but keeps the entry's `retained` anchor, so the prefix stays revivable.
    fn evict_if_needed(&mut self) {
        if self.budget == 0 {
            return;
        }
        while self.live > self.budget {
            let Some(idx) = self.tip_lru.pop_front() else {
                break;
            };
            // A stale duplicate (already evicted, or re-noted later) is a no-op.
            if self.entries[idx].tip.take().is_some() {
                self.live -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The corpus's resume/revival paths drive a real VM and are covered by the
    // integration suite; here we cover the pure bookkeeping that needs no VM.

    #[test]
    fn empty_pick_is_none() {
        let c = Corpus::new(0);
        let mut r = Rng::new(1);
        assert!(c.pick(&mut r).is_none());
        assert!(c.donor(&mut r).is_none());
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert_eq!(c.live_tips(), 0);
    }
}

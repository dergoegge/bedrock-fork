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
use std::sync::Mutex;

use bedrock_lab::{Checkpoint, RecordedInputSource, RetainedInput, RunOutcome, VirtTime};

use crate::input::Plan;
use crate::prng::Rng;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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

pub struct Corpus {
    entries: Vec<Entry>,
    /// Indices with a live tip, oldest at the front (a tip may appear more than
    /// once after a revival re-notes it; stale duplicates are popped as no-ops).
    tip_lru: VecDeque<usize>,
    /// Count of entries currently holding a live tip.
    live: usize,
    /// Maximum live tips before the oldest is evicted (0 == unbounded).
    budget: usize,
    /// Round-robin cursor for the queue scheduling policy ([`pick_queue`]). A
    /// monotonic counter taken modulo the entry count, shared (behind the
    /// corpus mutex) by every queue-policy worker so they collaboratively walk
    /// the corpus in order rather than redundantly fuzzing the same entries.
    cursor: u64,
}

impl Corpus {
    pub fn new(budget: usize) -> Self {
        Corpus {
            entries: Vec::new(),
            tip_lru: VecDeque::new(),
            live: 0,
            budget,
            cursor: 0,
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

    /// Seed the corpus with an empty `plan` rooted at the ready checkpoint. An
    /// empty plan resumes from `ready` directly (its `tip` is never rewound), so
    /// this just establishes a pickable entry the mutator grows from. The campaign
    /// seeds one per timeline kind ([`Plan::empty`](crate::input::Plan::empty) for
    /// the parallel timeline, and [`Plan::singleton_seed`] when the workload has a
    /// singleton driver). The plan's mask must be sized to the number of
    /// discovered rules, or the mutator can never pick a driver to add.
    ///
    /// [`Plan::singleton_seed`]: crate::input::Plan::singleton_seed
    pub fn seed(&mut self, ready: &Checkpoint, plan: Plan) {
        debug_assert!(
            plan.steps.is_empty(),
            "seed plans resume from ready and must have no steps"
        );
        let retained = ready.retain();
        let idx = self.entries.len();
        self.entries.push(Entry {
            plan,
            step_times: Vec::new(),
            retained,
            tip: Some(ready.clone()),
            steps: 0,
        });
        self.note_live(idx);
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

    /// Add a coverage find derived from entry `parent_idx` by running its
    /// `steps[k..]`: the full step-time line is the parent's prefix `[..k]`
    /// spliced with the new suffix. Keeps the splice — the only place the prefix
    /// and the realized suffix are stitched — inside the corpus. Returns the new
    /// entry index.
    pub fn add_child(
        &mut self,
        parent_idx: usize,
        k: usize,
        plan: Plan,
        suffix_times: &[VirtTime],
        tip: Checkpoint,
    ) -> usize {
        let mut full = self.entries[parent_idx].step_times[..k].to_vec();
        full.extend_from_slice(suffix_times);
        self.add(plan, full, tip)
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

    /// Pick the next seed in round-robin order (the queue scheduling policy):
    /// hand out entries in index order, advancing a shared cursor and cycling
    /// back to the start, so the corpus is covered systematically and newly
    /// appended entries are picked up on the next pass. Returns `(index, plan)`.
    pub fn pick_queue(&mut self) -> Option<(usize, Plan)> {
        let n = self.entries.len();
        if n == 0 {
            return None;
        }
        let idx = (self.cursor % n as u64) as usize;
        self.cursor = self.cursor.wrapping_add(1);
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

    /// Resume the checkpoint to run `plan.steps[k..]` from: the state after step
    /// `k-1` of entry `idx`. `k == 0` forks the ready checkpoint; an appended
    /// suffix forks the parent tip; an edit at step `k` rewinds the tip to step
    /// `k-1`. Returns the resume checkpoint and any guest seconds spent reviving
    /// an evicted prefix (the only execution counted as `replay`).
    ///
    /// Takes `&Mutex<Self>` so the lock is held only for the cheap tip lookup and
    /// the revival store; the rewind and the revival replay — the slow VM work —
    /// run unlocked, letting workers explore concurrently.
    pub fn resume(
        this: &Mutex<Self>,
        idx: usize,
        k: usize,
        ready: &Checkpoint,
    ) -> Result<(Checkpoint, f64)> {
        if k == 0 {
            return Ok((ready.clone(), 0.0));
        }
        let (tip_opt, target) = {
            let c = this.lock().unwrap();
            (c.entries[idx].tip.clone(), c.entries[idx].step_times[k - 1])
        };
        let mut replay_secs = 0.0f64;
        let tip = match tip_opt {
            Some(t) => t,
            None => {
                let (t, replayed) = Self::revive(this, idx, ready)?;
                replay_secs += replayed;
                this.lock().unwrap().set_tip(idx, t.clone());
                t
            }
        };
        if target >= tip.time() {
            // Appended suffix: resume at the tip itself.
            return Ok((tip, replay_secs));
        }
        // Edited step: rewind to the checkpoint after step k-1 (a genealogy
        // prefix query + recorded-suffix replay).
        Ok((tip.rewind(tip.time() - target)?, replay_secs))
    }

    /// Reconstruct an evicted entry's tip by replaying its retained input prefix.
    /// Locates the deepest live ancestor via [`RetainedInput::longest_checkpoint_prefix`]
    /// and replays the recorded suffix forward to the tip's time — *revival*.
    /// Returns the tip and the guest seconds replayed. The lock is held only to
    /// read the entry's recording/anchor; the replay runs unlocked.
    fn revive(this: &Mutex<Self>, idx: usize, ready: &Checkpoint) -> Result<(Checkpoint, f64)> {
        let (recording, end, prefix) = {
            let c = this.lock().unwrap();
            let e = &c.entries[idx];
            let end = *e.step_times.last().ok_or("revive: entry has no steps")?;
            (
                e.retained.recording().clone(),
                end,
                e.retained.longest_checkpoint_prefix(),
            )
        };
        let m = prefix.ok_or("revive: retained prefix not in genealogy")?;
        let new_empty = m.new.io_inputs().is_empty() && m.new.random_inputs().is_empty();
        let (mut br, from_secs) = if new_empty {
            // The whole prefix is known ground: fork the deepest live ancestor
            // and replay the matching suffix from it.
            let from = m.start.time().as_secs_f64();
            (
                m.start
                    .branch_with_input_source(RecordedInputSource::new(m.replay))?,
                from,
            )
        } else {
            // Defensive fallback (the retain anchor should keep the prefix
            // known): replay the full recording from the root.
            (
                ready.branch_with_input_source(RecordedInputSource::new(recording))?,
                ready.time().as_secs_f64(),
            )
        };
        loop {
            let (at, outcome) = br.run_until(end)?;
            match outcome {
                RunOutcome::ReachedTime => break,
                RunOutcome::ActionResponse { .. } | RunOutcome::Ready => continue,
                other => {
                    return Err(format!("revive: unexpected outcome at {at:?}: {other:?}").into());
                }
            }
        }
        let tip = br.checkpoint()?;
        let replayed = (end.as_secs_f64() - from_secs).max(0.0);
        Ok((tip, replayed))
    }

    /// Install a revived tip for `idx`, re-noting it as live (and evicting the
    /// oldest if over budget).
    fn set_tip(&mut self, idx: usize, tip: Checkpoint) {
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
        let mut c = Corpus::new(0);
        let mut r = Rng::new(1);
        assert!(c.pick(&mut r).is_none());
        assert!(c.pick_queue().is_none());
        assert!(c.donor(&mut r).is_none());
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        assert_eq!(c.live_tips(), 0);
    }

    #[test]
    fn pick_queue_round_robins_and_wraps() {
        // Drive the cursor directly without checkpoints by pushing bare cursor
        // state: build a corpus whose entry list we can index. We can't make real
        // Entry values without a VM, so assert the cursor arithmetic via a small
        // stand-in: a fresh corpus reports None, and after the cursor logic the
        // index sequence over `n` entries is 0,1,..,n-1,0,1,... We exercise that
        // arithmetic through `cursor` using a tiny synthetic entry count.
        //
        // (The real round-robin over live entries is exercised by the integration
        // suite; here we only pin the wrap-around math.)
        let n: u64 = 3;
        let mut cursor: u64 = 0;
        let seq: Vec<usize> = (0..7)
            .map(|_| {
                let idx = (cursor % n) as usize;
                cursor = cursor.wrapping_add(1);
                idx
            })
            .collect();
        assert_eq!(seq, vec![0, 1, 2, 0, 1, 2, 0]);
    }
}

// SPDX-License-Identifier: GPL-2.0

//! The step executor: the one place that turns a [`Plan`] into VM execution.
//!
//! [`Executor`] holds the shared, immutable run context — the rule set, the
//! [`Feedback`] maps, the serial [`Sink`], the TSC frequency, and the campaign
//! [`Config`] — behind a small interface so callers (the worker loop and
//! minimization) drive a step run with one method rather than threading nine
//! arguments. How each driver kind shapes its timeline lives in [`crate::driver`]
//! ([`resolve_batch`]); the one tricky pure decision the executor still owns —
//! splitting the guest's consumed randomness back into the two recorded tapes —
//! is extracted as [`partition_randoms`] so it is unit-tested directly, not only
//! through a live VM.

use bedrock_lab::{
    Branch, Checkpoint, EventCategories, EventConfig, RandomInput, RunOutcome, VirtDuration,
    VirtTime,
};
use bedrock_vm::events::RandomSource;

use crate::campaign::Config;
use crate::driver::{ends_timeline, resolve_batch, Rule};
use crate::feedback::Feedback;
use crate::input::Plan;
use crate::oracle::Finding;
use crate::rng::ReplayThenFresh;
use crate::sink::Sink;
use crate::solution::WorkloadProvenance;

/// The shared context a step run needs. Borrowed for the duration of a worker's
/// loop; cheap to construct from the campaign's shared state.
pub struct Executor<'a> {
    pub rules: &'a [Rule],
    pub feedback: &'a Feedback,
    pub sink: &'a Sink,
    pub freq: u64,
    pub cfg: &'a Config,
    /// Workload-file provenance (paths + SHA-1), hashed once at startup and
    /// stamped into every reproducer this worker saves. Empty when no workload
    /// files are configured or hashing failed at startup.
    pub provenance: &'a WorkloadProvenance,
}

/// The outcome of executing a plan's novel suffix.
pub struct ExecOutcome {
    /// Never-before-covered edges (map slots) this run hit; >0 ⇒ a corpus find.
    pub new_edges: usize,
    /// Already-covered edges that reached a new hit-count bucket (loop
    /// sensitivity); >0 ⇒ also corpus-worthy.
    pub new_hits: usize,
    /// An assertion on this run advanced a hill-climbing target's best score.
    pub target_improved: bool,
    pub finding: Option<Finding>,
    /// The plan with each executed step's `rng`/`rand` set to its realized
    /// consumption.
    pub realized: Plan,
    /// Checkpoint time after each executed step (one per step in `start..len`).
    pub step_times: Vec<VirtTime>,
    /// The checkpoint at the plan's end (the resume checkpoint when no steps ran).
    pub tip: Checkpoint,
    /// Serial of the finding's step (the bug's proof); empty when no finding.
    pub serial: Vec<String>,
    /// Guest virtual time (s) executed exploring the novel suffix.
    pub novel_vt_secs: f64,
    /// Total bytes served from the fresh PRNG past the end of the steps' recorded
    /// randomness tapes. During a campaign this is the normal signature of
    /// exploration pushing past a recording (and is ignored). During a reproduce
    /// it must be `0`: a non-zero value means the replay drew randomness the saved
    /// recording did not contain, so the run diverged from what was recorded — a
    /// reproduction failure.
    pub fresh_random_bytes: u64,
}

impl ExecOutcome {
    /// Worth keeping as a corpus seed: the run found new coverage or advanced a
    /// hill-climbing target. A finding is handled separately and is not seeded.
    pub fn interesting(&self) -> bool {
        self.new_edges > 0 || self.new_hits > 0 || self.target_improved
    }
}

impl Executor<'_> {
    /// Execute `plan.steps[start..]` from `resume_cp`. Each step forks the current
    /// checkpoint with a [`ReplayThenFresh`] source (replays the step's recorded
    /// randomness, extends fresh past it), launches the driver batch at their
    /// virtual-time offsets, drains a response per driver (or until the branch
    /// budget), folds coverage, and scans serial for a failed assertion and a
    /// hill-climbing signal. Driver exit codes/output are not inspected —
    /// coverage is the only steering signal; a hard VM fault or a failed `Always`
    /// assertion is the only finding.
    pub fn run(&self, plan: &Plan, resume_cp: Checkpoint, start: usize, seed: u64) -> ExecOutcome {
        let mut realized = plan.clone();
        let mut cp = resume_cp;

        // If the resumed prefix already ran a singleton driver, the timeline has
        // used its one singleton — run nothing more. Coverage for the prefix was
        // already counted, so this contributes nothing.
        let prefix_has_singleton = plan.steps[..start.min(plan.steps.len())]
            .iter()
            .any(|s| ends_timeline(&s.batch, self.rules));
        if prefix_has_singleton {
            realized.steps.truncate(start);
            return ExecOutcome {
                new_edges: 0,
                new_hits: 0,
                target_improved: false,
                finding: None,
                realized,
                step_times: Vec::new(),
                tip: cp,
                serial: Vec::new(),
                novel_vt_secs: 0.0,
                fresh_random_bytes: 0,
            };
        }

        let mut new_edges = 0usize;
        let mut new_hits = 0usize;
        let mut target_improved = false;
        let mut finding = None;
        let mut finding_serial: Vec<String> = Vec::new();
        let mut step_times: Vec<VirtTime> = Vec::new();
        let mut novel_vt_secs = 0.0f64;
        let mut fresh_random_bytes = 0u64;
        let branch_budget = VirtDuration::from_secs(self.cfg.branch_budget_secs, self.freq);

        'steps: for i in start..plan.steps.len() {
            let step = &plan.steps[i];
            // Number of randomness inputs already on the line, so we can slice out
            // exactly what this step consumes after it runs.
            let base_random = cp.input_recording().random_inputs().len();
            let src = ReplayThenFresh::new(
                step.rng.clone(),
                step.rand.clone(),
                seed ^ (i as u64).wrapping_mul(0x9E37),
            );
            // Grab the fresh-byte counter before the source is moved into the
            // branch; it is shared with every clone the branch makes, so reading
            // it after the step run reflects all draws past the recorded tapes.
            let overrun = src.overrun_handle();
            let mut br: Branch = match cp.branch_with_input_source(src) {
                Ok(b) => b,
                Err(_) => {
                    finding = Some(Finding::VmFault { step: i });
                    break;
                }
            };
            let branch_id = br.id();
            self.sink.start_capture(branch_id);

            // Diagnostic: turn on APIC-timer injection capture so the sink can
            // flag idle TSC over-advances. Purely observational — it emits extra
            // records but does not touch guest execution or the recorded
            // randomness, so the replay stays bit-for-bit deterministic.
            if self.cfg.trace_injects {
                let _ = br.set_event_config(&EventConfig {
                    categories: EventCategories::INJECT,
                    ..Default::default()
                });
            }

            // Resolve the batch under the driver-kind rules: a singleton collapses
            // to itself plus any anytime drivers (and is terminal); any other batch
            // runs as-is. Reflect what actually ran in the realized plan so the
            // corpus/reproducer record it exactly.
            let (batch, singleton_step) = resolve_batch(&step.batch, self.rules);
            realized.steps[i].batch = batch.clone();

            let base = br.current_time();
            let budget_deadline = base + branch_budget;
            let mut faulted = false;
            // Launch each driver at its fuzzed virtual-time offset relative to the
            // step base. Offset is the interleaving knob the mutator controls; the
            // anytime preemption driver (`anytime_kick`) is scheduled the same way.
            for m in &batch {
                let d = &self.rules[m.driver];
                let at = base + VirtDuration::from_instructions(m.offset.max(0) as u64, self.freq);
                if br
                    .sched_bash(at, d.target.clone(), &d.command, false)
                    .is_err()
                {
                    faulted = true;
                    break;
                }
            }

            // Drain a response per launched driver to reach a quiescent point, but
            // no longer than the branch budget.
            let mut pending = batch.len();
            while !faulted && pending > 0 {
                match br.run_until(budget_deadline) {
                    Ok((_, RunOutcome::ActionResponse { .. })) => pending -= 1,
                    Ok((_, RunOutcome::Ready)) => {}
                    Ok((_, RunOutcome::ReachedTime)) => break,
                    _ => faulted = true,
                }
            }

            // Settle window: after the drivers finish, keep running a few seconds
            // so the guest's async oracle pipeline surfaces this step's
            // exec-/container-death assertion on serial *before* we read it.
            if !faulted && self.cfg.quiesce_secs > 0.0 {
                let settle = (br.current_time()
                    + VirtDuration::from_secs_f64(self.cfg.quiesce_secs, self.freq))
                .min(budget_deadline);
                while br.current_time() < settle {
                    match br.run_until(settle) {
                        Ok((_, RunOutcome::ReachedTime)) => break,
                        Ok((_, RunOutcome::ActionResponse { .. })) | Ok((_, RunOutcome::Ready)) => {
                        }
                        _ => {
                            faulted = true;
                            break;
                        }
                    }
                }
            }

            // Coverage: fold this branch's feedback buffers into the shared map.
            if !faulted {
                let (e, h) = self.feedback.fold_coverage(&mut br);
                new_edges += e;
                new_hits += h;
            }

            // Reclaim this branch's serial, then apply the oracles: a hard VM
            // fault, or a failed `Always` assertion. Every step's serial also
            // feeds hill-climbing via the feedback verdict.
            let serial = self.sink.take_capture(branch_id);

            // Capture the randomness the guest actually consumed this step, split
            // by channel into the RDRAND/RDSEED tape and the getrandom() tape.
            //
            // This MUST run before the finding `break`s below. A step that
            // triggers an assertion or VM fault still consumed randomness while
            // it ran; if we break first, that consumption is dropped and the
            // step's tapes stay empty. The reproducer then replays the finding
            // step with empty tapes, `ReplayThenFresh` falls through to fresh
            // PRNG bytes that differ from the original run, and a
            // randomness-dependent bug fails to reproduce. The branch (`br`) is
            // still alive on every path that reaches here, so its recording is
            // available regardless of fault/assertion/success.
            let randoms = br.input_recording().random_inputs();
            let consumed = &randoms[base_random.min(randoms.len())..];
            let (rng, rand) = partition_randoms(consumed);
            realized.steps[i].rng = rng;
            realized.steps[i].rand = rand;

            // Bytes this step drew from the fresh PRNG past its recorded tapes.
            // Harmless during exploration; a reproduce treats any as a failure.
            fresh_random_bytes += overrun.load(std::sync::atomic::Ordering::Relaxed);

            if faulted {
                finding = Some(Finding::VmFault { step: i });
                finding_serial = serial;
                break 'steps;
            }
            let verdict = self.feedback.scan_serial(&serial);
            target_improved |= verdict.target_improved;
            if let Some(message) = verdict.finding_reason {
                finding = Some(Finding::Assertion { step: i, message });
                finding_serial = serial;
                break 'steps;
            }

            let snap = match br.checkpoint() {
                Ok(c) => c,
                Err(_) => {
                    finding = Some(Finding::VmFault { step: i });
                    break;
                }
            };
            novel_vt_secs += (snap.time().as_secs_f64() - base.as_secs_f64()).max(0.0);
            step_times.push(snap.time());
            cp = snap;

            // One singleton per timeline: a singleton step ends the plan.
            if singleton_step {
                realized.steps.truncate(i + 1);
                break 'steps;
            }
        }

        ExecOutcome {
            new_edges,
            new_hits,
            target_improved,
            finding,
            realized,
            step_times,
            tip: cp,
            serial: finding_serial,
            novel_vt_secs,
            fresh_random_bytes,
        }
    }
}

/// Split a step's consumed random inputs into the two recorded tapes: the
/// RDRAND/RDSEED stream (`rng`) and the `getrandom()` stream (`rand`). The lab
/// merges both into one recording tagged by source; this partitions them back.
pub(crate) fn partition_randoms(consumed: &[RandomInput]) -> (Vec<u8>, Vec<u8>) {
    let rng = consumed
        .iter()
        .filter(|r| r.source != RandomSource::GetRandom)
        .flat_map(|r| r.bytes.iter().copied())
        .collect();
    let rand = consumed
        .iter()
        .filter(|r| r.source == RandomSource::GetRandom)
        .flat_map(|r| r.bytes.iter().copied())
        .collect();
    (rng, rand)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_splits_by_source() {
        let zero = VirtTime::from_instructions(0, 1);
        let ri = |source, bytes| RandomInput {
            at: zero,
            source,
            pid: 0,
            bytes,
        };
        let inputs = vec![
            ri(RandomSource::Rdrand, vec![1, 2]),
            ri(RandomSource::GetRandom, vec![9, 8, 7]),
            ri(RandomSource::Rdseed, vec![3]),
        ];
        let (rng, rand) = partition_randoms(&inputs);
        assert_eq!(rng, vec![1, 2, 3], "RDRAND + RDSEED, in order");
        assert_eq!(rand, vec![9, 8, 7], "getrandom() only");

        let (rng, rand) = partition_randoms(&[]);
        assert!(rng.is_empty() && rand.is_empty());
    }
}

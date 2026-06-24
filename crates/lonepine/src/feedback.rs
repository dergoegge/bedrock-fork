// SPDX-License-Identifier: GPL-2.0

//! The verdict seam: given one run's coverage and serial, decide whether it is
//! *interesting* (worth keeping as a corpus seed) and whether it is a *finding*.
//!
//! [`Feedback`] owns the campaign's two pure search signals — the multi-domain
//! [`CoverageMap`] and the per-assertion hill-climbing targets — behind one
//! interface, so the "is this run worth keeping?" rule lives in a single place
//! rather than smeared across the executor and the worker loop. It is the only
//! caller of the assertion hill-climbing
//! ([`assertion_observations`](crate::oracle::assertion_observations) →
//! [`observe_target`](CoverageMap::observe_target)): every assertion on every
//! step's serial is fed in, pulling the search toward reaching `Sometimes` goals
//! and breaking `Always` invariants.

use std::collections::HashSet;
use std::sync::Mutex;

use bedrock_lab::Branch;

use crate::coverage::CoverageMap;
use crate::oracle::{assertion_failure_reason, assertion_observations};

/// The campaign's shared search signals behind one lock. Workers fold coverage
/// and scan serial through it concurrently; the lock is held only for the cheap
/// map ops, never the VM run.
pub struct Feedback {
    map: Mutex<CoverageMap>,
    /// Feedback-buffer id prefix that scopes which buffers count as coverage.
    cov_prefix: Vec<u8>,
}

/// What scanning a step's serial told us: the bug oracle's verdict plus whether
/// the run advanced the hill-climbing frontier.
#[derive(Debug, Default, Clone)]
pub struct SerialVerdict {
    /// The first failed `Always` assertion's message — the assertion bug signal.
    pub finding_reason: Option<String>,
    /// Whether any assertion improved a hill-climbing target's best score.
    pub target_improved: bool,
}

/// A snapshot of the search signals for the campaign heartbeat.
#[derive(Debug, Clone, Copy)]
pub struct FeedbackStats {
    pub domains: usize,
    pub covered: usize,
    pub capacity: usize,
    pub targets: usize,
}

impl Feedback {
    pub fn new(cov_prefix: Vec<u8>) -> Self {
        Feedback {
            map: Mutex::new(CoverageMap::new()),
            cov_prefix,
        }
    }

    /// Fold a branch's coverage into the map. Each registered feedback buffer is
    /// a domain; ids are scoped by `cov_prefix` and deduped (same-id buffers are
    /// unioned and counted once). Returns `(new_edges, new_hits)`. The buffer
    /// reads happen on the caller's branch; the lock is taken only for the fold.
    pub fn fold_coverage(&self, br: &mut Branch) -> (usize, usize) {
        let ids = br.feedback_buffer_ids().unwrap_or_default();
        let mut new_edges = 0usize;
        let mut new_hits = 0usize;
        let mut seen = HashSet::new();
        for id in &ids {
            if !id.starts_with(&self.cov_prefix[..]) || !seen.insert(id.clone()) {
                continue;
            }
            if let Ok(bufs) = br.feedback_buffers(id) {
                let (e, h) = self.map.lock().unwrap().observe(id, &bufs);
                new_edges += e;
                new_hits += h;
            }
        }
        (new_edges, new_hits)
    }

    /// Scan one step's captured serial: detect a failed `Always` (the assertion
    /// bug oracle) and feed *every* assertion into hill-climbing. The only place
    /// the assertion search signal is wired in.
    pub fn scan_serial(&self, serial: &[String]) -> SerialVerdict {
        let finding_reason = assertion_failure_reason(serial);
        let observations = assertion_observations(serial);
        let mut target_improved = false;
        if !observations.is_empty() {
            let mut map = self.map.lock().unwrap();
            for (key, score) in observations {
                target_improved |= map.observe_target(&key, score);
            }
        }
        SerialVerdict {
            finding_reason,
            target_improved,
        }
    }

    /// Snapshot the search signals for the heartbeat.
    pub fn stats(&self) -> FeedbackStats {
        let map = self.map.lock().unwrap();
        FeedbackStats {
            domains: map.domains(),
            covered: map.covered(),
            capacity: map.capacity(),
            targets: map.targets(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // fold_coverage drives a real branch and is covered by the integration suite;
    // here we pin the serial scan — the previously-orphaned hill-climbing wiring.

    #[test]
    fn scan_detects_failed_always_and_feeds_hill_climb() {
        let fb = Feedback::new(b"go-".to_vec());
        let failed = r#"{"Always":{"condition":{"Eq":{"x":1,"y":0}},"result":false,"message":"boom","location":{"file":"m.rs","line":1,"column":1}}}"#.to_string();
        let v = fb.scan_serial(&[failed]);
        assert_eq!(v.finding_reason.as_deref(), Some("boom"));
        assert!(
            v.target_improved,
            "first sight of a target is an improvement"
        );
        assert_eq!(fb.stats().targets, 1);
    }

    #[test]
    fn scan_hill_climb_only_rewards_improvement() {
        let fb = Feedback::new(Vec::new());
        // Always x==y: closeness-to-true peaks at 0 when equal; Always negates,
        // so a holding case scores 0 and a nearer break scores higher.
        let hold = r#"{"Always":{"condition":{"Eq":{"x":5,"y":5}},"result":true,"message":"inv","location":{"file":"m.rs","line":1,"column":1}}}"#.to_string();
        let near = r#"{"Always":{"condition":{"Eq":{"x":5,"y":7}},"result":false,"message":"inv","location":{"file":"m.rs","line":1,"column":1}}}"#.to_string();
        assert!(fb.scan_serial(&[hold.clone()]).target_improved); // first sight
        assert!(!fb.scan_serial(&[hold]).target_improved); // no improvement
        assert!(fb.scan_serial(&[near]).target_improved); // closer to breaking
    }

    #[test]
    fn scan_ignores_non_assertion_serial() {
        let fb = Feedback::new(Vec::new());
        let v = fb.scan_serial(&["[podman] | btcd1 started".to_string()]);
        assert!(v.finding_reason.is_none());
        assert!(!v.target_improved);
        assert_eq!(fb.stats().targets, 0);
    }
}

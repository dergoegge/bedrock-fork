// SPDX-License-Identifier: GPL-2.0

//! Oracles and assertion-derived search signals.
//!
//! Bug signals:
//! - a **hard VM fault** — an unhandled/error VM exit while a step runs; and
//! - a **failed `Always` assertion** read off the guest's serial. Workloads (and
//!   the in-guest container monitor) emit [`bedrock_assertions::Assertion`]
//!   records on serial as `… {json}`; a container that dies with a nonzero exit,
//!   for example, trips an `Always` "exit code is zero" assertion. A single
//!   failed `Always` is a bug, reported by its message.
//!
//! Search signal:
//! - **every assertion** (both variants) feeds hill-climbing.
//!   [`assertion_observations`] turns each serial assertion into a `(key, score)`
//!   where the score is a *signed closeness* — `Sometimes` climbs toward holding
//!   (reach the objective), `Always` climbs toward failing (approach a
//!   violation). The coverage map keeps any input that improves a target's best
//!   score (see
//!   [`CoverageMap::observe_target`](crate::coverage::CoverageMap::observe_target)),
//!   so the search is pulled toward both reaching `Sometimes` goals and breaking
//!   `Always` invariants.

use bedrock_assertions::{Assertion, Condition};

use crate::shape::strip_ansi;

/// A detected violation, tagged with the step it occurred at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The VM exited for a reason the lab did not handle internally, or a lab
    /// operation failed mid-step — i.e. the guest faulted.
    VmFault { step: usize },
    /// A failed `Always` assertion was observed on the guest serial. `message`
    /// is the assertion's operator message (e.g. "container btcd1 exit code is
    /// zero"); findings dedup by it.
    Assertion { step: usize, message: String },
}

impl Finding {
    /// Stable identifier for the bug class — used as the failure `origin` and to
    /// keep minimization targeting the same kind of bug.
    pub fn kind(&self) -> &'static str {
        match self {
            Finding::VmFault { .. } => "vm-fault",
            Finding::Assertion { .. } => "assertion",
        }
    }
}

/// Parse the assertion record carried by one serial line, if any. The record is
/// the trailing JSON object; any formatter/branch prefix before it contains no
/// `{`. Returns `None` for lines without a parseable assertion.
fn parse_assertion(line: &str) -> Option<Assertion> {
    let stripped = strip_ansi(line);
    let json = stripped.get(stripped.find('{')?..)?;
    serde_json::from_str::<Assertion>(json).ok()
}

/// Inspect captured serial for a failed `Always` assertion — the assertion-based
/// bug signal. Returns the message of the first `Always` record whose `result`
/// is false. `Sometimes` records and passing records are not bugs. The message
/// is used verbatim as the finding reason, so findings dedup by message.
pub fn assertion_failure_reason(serial: &[String]) -> Option<String> {
    serial.iter().find_map(|line| match parse_assertion(line)? {
        Assertion::Always(data) if !data.result => Some(data.message),
        _ => None,
    })
}

/// Signed-closeness observations for hill-climbing, one per assertion on the
/// serial. The key is the assertion message; the score is how much an input
/// should be *rewarded*: `Sometimes` climbs toward the condition holding,
/// `Always` climbs toward it failing (approaching a violation). Higher is
/// better in both cases, so the coverage map's "improved a target" check is
/// uniform across variants.
pub fn assertion_observations(serial: &[String]) -> Vec<(String, i128)> {
    serial
        .iter()
        .filter_map(|line| {
            let a = parse_assertion(line)?;
            let toward_true = closeness(a.condition());
            let score = match a {
                // Reward getting closer to (or staying further into) holding.
                Assertion::Sometimes(_) => toward_true,
                // Reward getting closer to failing — the negative margin.
                Assertion::Always(_) => -toward_true,
            };
            Some((a.data().message.clone(), score))
        })
        .collect()
}

/// Closeness of a condition to being **true**: positive (and larger) the more
/// firmly it holds, negative the further it is from holding. The magnitude is
/// the comparison margin; for `Eq` it peaks at 0 when the operands are equal.
fn closeness(c: Condition) -> i128 {
    match c {
        Condition::Bool(b) => {
            if b {
                1
            } else {
                -1
            }
        }
        // x < y  and  x <= y  hold when y - x is (>0 / >=0); larger margin = deeper.
        Condition::Lt { x, y } | Condition::Lte { x, y } => y.saturating_sub(x),
        // x > y  and  x >= y  hold when x - y is (>0 / >=0).
        Condition::Gt { x, y } | Condition::Gte { x, y } => x.saturating_sub(y),
        // x == y  is closest at 0; further apart is more negative.
        Condition::Eq { x, y } => -(x - y).abs(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_distinct() {
        assert_eq!(Finding::VmFault { step: 0 }.kind(), "vm-fault");
        assert_eq!(
            Finding::Assertion {
                step: 0,
                message: "m".into()
            }
            .kind(),
            "assertion"
        );
    }

    const FAILED_CONTAINER: &str = r#"[br BranchId(7) vt 12.345] [assertions] | {"Always":{"condition":{"Eq":{"x":137,"y":0}},"result":false,"message":"container btcd1 exit code is zero","location":{"file":"m.rs","line":1,"column":1}}}"#;

    #[test]
    fn failed_always_is_detected_with_prefix_and_ansi() {
        let line = format!("\x1b[1;34m{FAILED_CONTAINER}\x1b[0m");
        assert_eq!(
            assertion_failure_reason(&[line]).as_deref(),
            Some("container btcd1 exit code is zero")
        );
    }

    #[test]
    fn passing_always_is_ignored() {
        let ok = r#"[assertions] | {"Always":{"condition":{"Eq":{"x":0,"y":0}},"result":true,"message":"ok","location":{"file":"m.rs","line":1,"column":1}}}"#;
        assert_eq!(assertion_failure_reason(&[ok.to_string()]), None);
    }

    #[test]
    fn sometimes_is_not_a_failure() {
        let s = r#"{"Sometimes":{"condition":{"Bool":false},"result":false,"message":"never","location":{"file":"m.rs","line":1,"column":1}}}"#;
        assert_eq!(assertion_failure_reason(&[s.to_string()]), None);
    }

    #[test]
    fn non_assertion_lines_are_ignored() {
        let serial = vec![
            "[podman] | btcd1 started".to_string(),
            "kernel: hello".to_string(),
        ];
        assert_eq!(assertion_failure_reason(&serial), None);
        assert!(assertion_observations(&serial).is_empty());
    }

    #[test]
    fn sometimes_score_climbs_toward_holding() {
        // Sometimes x < y: closer to holding as y - x grows.
        let near = r#"{"Sometimes":{"condition":{"Lt":{"x":9,"y":10}},"result":true,"message":"reach","location":{"file":"m.rs","line":1,"column":1}}}"#;
        let far = r#"{"Sometimes":{"condition":{"Lt":{"x":0,"y":10}},"result":true,"message":"reach","location":{"file":"m.rs","line":1,"column":1}}}"#;
        let near_score = assertion_observations(&[near.to_string()])[0].1;
        let far_score = assertion_observations(&[far.to_string()])[0].1;
        assert_eq!(near_score, 1);
        assert_eq!(far_score, 10);
        assert!(far_score > near_score, "deeper into holding scores higher");
    }

    #[test]
    fn always_score_climbs_toward_violation() {
        // Always x == y: a holding case (x==y) scores lower than a near-miss,
        // so the search is pulled toward breaking it.
        let holding = r#"{"Always":{"condition":{"Eq":{"x":5,"y":5}},"result":true,"message":"inv","location":{"file":"m.rs","line":1,"column":1}}}"#;
        let near_break = r#"{"Always":{"condition":{"Eq":{"x":5,"y":7}},"result":false,"message":"inv","location":{"file":"m.rs","line":1,"column":1}}}"#;
        let hold_score = assertion_observations(&[holding.to_string()])[0].1;
        let break_score = assertion_observations(&[near_break.to_string()])[0].1;
        // closeness-to-true: Eq{5,5}=0, Eq{5,7}=-2; Always negates => 0 and 2.
        assert_eq!(hold_score, 0);
        assert_eq!(break_score, 2);
        assert!(
            break_score > hold_score,
            "approaching violation scores higher"
        );
    }
}

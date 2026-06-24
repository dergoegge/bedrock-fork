// SPDX-License-Identifier: GPL-2.0

//! The driver taxonomy: what kinds of drivers exist and how a kind shapes the
//! timeline it runs on.
//!
//! A [`Rule`] is one enumerated `(container, driver)` the mutator can schedule.
//! Its [`DriverKind`] is the single knob that decides how it behaves on a
//! timeline; all the kind-specific rules live here rather than special-cased
//! through the executor, so adding a kind is a new variant plus its rule in
//! [`resolve_batch`], not an edit to the step loop.
//!
//! Kinds (detected from the driver's name at discovery, see [`classify`]):
//!
//! - [`Parallel`](DriverKind::Parallel) — the default. Runs at any offset,
//!   concurrently with other parallel (and anytime) drivers, across a sequence of
//!   steps that build up guest state and probe orderings.
//! - [`Singleton`](DriverKind::Singleton) — runs *alone* on its timeline (only
//!   anytime drivers may run alongside it) and is *terminal*: at most one per
//!   timeline. For porting existing unit/functional tests that must run isolated.
//! - [`Anytime`](DriverKind::Anytime) — may run at any point on *any* timeline,
//!   alongside a singleton or a parallel batch alike, because it does no test
//!   work of its own. The built-in `anytime_kick` preemption driver — a no-op
//!   shipped on the host in the initrd — is one; a workload can name its own with
//!   the [`ANYTIME_PREFIX`].

use bedrock_lab::BashTarget;

use crate::input::Member;

/// Driver-name prefix marking a [`Singleton`](DriverKind::Singleton) driver.
pub const SINGLETON_PREFIX: &str = "singleton_";

/// Driver-name prefix marking an [`Anytime`](DriverKind::Anytime) driver.
pub const ANYTIME_PREFIX: &str = "anytime_";

/// How a driver behaves on a timeline. See the module docs for the kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverKind {
    /// The default: concurrent, sequenced across steps.
    Parallel,
    /// Alone on its timeline (only anytime drivers alongside), terminal.
    Singleton,
    /// May run at any point on any timeline; does no test work of its own.
    Anytime,
}

impl DriverKind {
    pub fn is_singleton(self) -> bool {
        matches!(self, DriverKind::Singleton)
    }

    pub fn is_anytime(self) -> bool {
        matches!(self, DriverKind::Anytime)
    }
}

/// Classify a discovered driver by its name. The longest/most-specific prefixes
/// win; anything unprefixed is a plain [`Parallel`](DriverKind::Parallel) driver.
pub fn classify(name: &str) -> DriverKind {
    if name.starts_with(SINGLETON_PREFIX) {
        DriverKind::Singleton
    } else if name.starts_with(ANYTIME_PREFIX) {
        DriverKind::Anytime
    } else {
        DriverKind::Parallel
    }
}

/// One enumerated `(container, driver)` rule, discovered under the driver dir on
/// the host or in a container (see `campaign::discover_rules`). Every driver —
/// including the no-op `anytime_kick` preemption driver shipped on the host in
/// the initrd — is an ordinary discovered file; there are no synthetic rules.
#[derive(Debug, Clone)]
pub struct Rule {
    pub target: BashTarget,
    pub name: String,
    /// The exact command to run: `<driver_dir>/<name>`.
    pub command: String,
    /// How this driver behaves on a timeline.
    pub kind: DriverKind,
}

/// The batch a step actually runs, and whether the step ends the timeline.
///
/// A batch naming any [`Singleton`](DriverKind::Singleton) collapses to that lone
/// singleton plus any [`Anytime`](DriverKind::Anytime) members — the singleton
/// runs with no other *test* driver during its runtime, but anytime drivers
/// (which do no test work) are kept so they can perturb its interleaving — and is
/// terminal. Any other batch ([`Parallel`](DriverKind::Parallel) + anytime
/// members) runs as-is and is non-terminal.
pub fn resolve_batch(batch: &[Member], rules: &[Rule]) -> (Vec<Member>, bool) {
    match batch.iter().find(|m| rules[m.driver].kind.is_singleton()) {
        Some(s) => {
            let mut out = vec![s.clone()];
            out.extend(
                batch
                    .iter()
                    .filter(|m| rules[m.driver].kind.is_anytime())
                    .cloned(),
            );
            (out, true)
        }
        None => (batch.to_vec(), false),
    }
}

/// Whether this step's batch ends the timeline (names a singleton). Used to skip
/// execution once a resumed prefix has already spent its one singleton.
pub fn ends_timeline(batch: &[Member], rules: &[Rule]) -> bool {
    batch.iter().any(|m| rules[m.driver].kind.is_singleton())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str) -> Rule {
        Rule {
            target: BashTarget::host(),
            name: name.to_string(),
            command: format!("/opt/bedrock/drivers/{name}"),
            kind: classify(name),
        }
    }

    #[test]
    fn classify_by_prefix() {
        assert_eq!(classify("drv_a"), DriverKind::Parallel);
        assert_eq!(classify("singleton_mptest"), DriverKind::Singleton);
        assert_eq!(classify("anytime_reload"), DriverKind::Anytime);
    }

    #[test]
    fn singleton_batch_collapses_to_one_plus_anytime() {
        // idx 0 parallel, 1 singleton, 2 parallel, 3 anytime (the kick driver).
        let rules = vec![
            rule("drv_a"),
            rule("singleton_mptest"),
            rule("drv_b"),
            rule("anytime_kick"),
        ];

        // A batch naming a singleton drops other *test* drivers but keeps the lone
        // singleton, and is flagged terminal.
        let mixed = vec![
            Member {
                driver: 0,
                offset: 0,
            },
            Member {
                driver: 1,
                offset: 5,
            },
            Member {
                driver: 2,
                offset: 9,
            },
        ];
        assert!(ends_timeline(&mixed, &rules));
        let (eff, terminal) = resolve_batch(&mixed, &rules);
        assert!(terminal);
        assert_eq!(eff.len(), 1, "only the singleton runs (parallels dropped)");
        assert_eq!(eff[0].driver, 1);
        assert_eq!(eff[0].offset, 5, "the singleton's own offset is kept");

        // Anytime drivers survive the collapse: they perturb the singleton's
        // interleaving without being a competing test driver.
        let with_kicks = vec![
            Member {
                driver: 0,
                offset: 0,
            }, // drv_a (dropped)
            Member {
                driver: 1,
                offset: 5,
            }, // singleton (kept)
            Member {
                driver: 3,
                offset: 7,
            }, // anytime kick (kept)
            Member {
                driver: 3,
                offset: 9,
            }, // anytime kick (kept)
        ];
        let (eff, terminal) = resolve_batch(&with_kicks, &rules);
        assert!(terminal);
        assert_eq!(eff.len(), 3, "singleton + 2 anytime");
        assert_eq!(eff[0].driver, 1, "singleton first");
        assert!(eff[1..].iter().all(|m| m.driver == 3), "rest are anytime");

        // An all-parallel batch runs unchanged and is not terminal.
        let parallel = vec![
            Member {
                driver: 0,
                offset: 0,
            },
            Member {
                driver: 2,
                offset: 3,
            },
        ];
        assert!(!ends_timeline(&parallel, &rules));
        let (eff, terminal) = resolve_batch(&parallel, &rules);
        assert!(!terminal);
        assert_eq!(eff, parallel);
    }
}

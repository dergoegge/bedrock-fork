// SPDX-License-Identifier: GPL-2.0

//! lonepine — a coverage-guided driver fuzzer for the bedrock hypervisor.
//!
//! One loop does both jobs of a modern fuzzer: a coverage map steers *which*
//! inputs run, and on every execution the oracles (a hard VM fault, a failed
//! `Always` assertion) are checked. Findings are minimized to a small
//! reproducer. Re-execution and minimization are made cheap by **bedrock-lab's
//! radix genealogy** — a radix tree over the input recording — which resumes a
//! mutated plan's shared prefix (fork the parent tip, or [`rewind`] it to an
//! earlier step) and revives evicted prefixes by replay; bedrock's determinism
//! makes concurrency bugs reproducible.
//!
//! The design is documented under `docs/lonepine/`. The crate is split so the
//! pure search logic (input, mutator, coverage, oracle, prng, hash) is
//! unit-testable without a VM; [`feedback`] is the verdict seam over the
//! coverage/oracle signals; [`executor`] turns a plan into VM execution;
//! [`solution`] records a finding; [`corpus`] owns the radix-genealogy resume;
//! [`campaign`] is the integration layer that wires them across workers; and
//! [`reproduce`] is the read side — replaying a saved finding once to confirm it
//! still fires (the binary's `--reproduce`).
//!
//! [`rewind`]: bedrock_lab::Checkpoint::rewind

pub mod affinity;
pub mod campaign;
pub mod corpus;
pub mod coverage;
pub mod driver;
pub mod executor;
pub mod feedback;
pub mod hash;
pub mod input;
pub mod mutator;
pub mod oracle;
pub mod prng;
pub mod reproduce;
pub mod rng;
pub mod shape;
pub mod sink;
pub mod solution;
pub mod ui;

pub use campaign::{run_campaign, Config};
pub use corpus::Corpus;
pub use coverage::CoverageMap;
pub use driver::{DriverKind, Rule};
pub use executor::{ExecOutcome, Executor};
pub use feedback::Feedback;
pub use input::{DriverMask, Member, Plan, Step, TimelineKind};
pub use mutator::{mutate, Limits};
pub use oracle::Finding;
pub use prng::Rng;

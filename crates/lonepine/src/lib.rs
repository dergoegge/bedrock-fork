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
//! search logic (input, mutator, coverage, corpus, prng, hash, oracle) is pure
//! and unit-testable without a VM, while [`campaign`] is the integration layer
//! that drives `bedrock-lab`.
//!
//! [`rewind`]: bedrock_lab::Checkpoint::rewind

pub mod campaign;
pub mod corpus;
pub mod coverage;
pub mod hash;
pub mod input;
pub mod mutator;
pub mod oracle;
pub mod prng;
pub mod rng;
pub mod shape;
pub mod sink;
pub mod ui;

pub use campaign::{run_campaign, Config, Rule};
pub use corpus::Corpus;
pub use coverage::CoverageMap;
pub use input::{DriverMask, Member, Plan, Step};
pub use mutator::{mutate, Limits};
pub use oracle::Finding;
pub use prng::Rng;

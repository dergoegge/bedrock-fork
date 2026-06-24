// SPDX-License-Identifier: GPL-2.0

//! The integration layer: boot a workload guest, enumerate its drivers, then run
//! a coverage-guided loop on bedrock across one or more parallel workers. This
//! module wires the pieces together — picking, mutating, resuming, executing,
//! judging, recording — while the work itself lives in deeper modules: the
//! [`Executor`] runs a plan against the VM, the [`Feedback`] maps judge each run,
//! the [`Corpus`] owns the radix-genealogy resume, and [`solution`] records a
//! finding.
//!
//! ## Resuming via the radix genealogy
//!
//! bedrock-lab keys its checkpoint genealogy on a radix tree over the input
//! recording, so "B descends from A" is exactly "A's recording is a prefix of
//! B's". This fuzzer leans on that instead of carrying its own checkpoint trie:
//!
//! - every corpus entry holds the live [`Checkpoint`] at its plan's end and a
//!   [`RetainedInput`](bedrock_lab::RetainedInput) anchor for its prefix;
//! - a mutation that *appends* resumes by forking the parent tip; a mutation that
//!   *edits step k* resumes by [`Checkpoint::rewind`]ing the parent tip to the
//!   checkpoint after step `k-1` — a prefix query the genealogy answers by
//!   forking the deepest live ancestor and replaying the recorded suffix;
//! - when a tip's VM has been evicted under the live-tip budget, its prefix is
//!   *revived* by replay — re-deriving it from the deepest live ancestor. This
//!   revival is the only execution counted as `replay`. Resume and revival both
//!   live in [`Corpus`], which owns the genealogy handles.
//!
//! ## Parallelism
//!
//! `--cores` worker threads share one ready [`Checkpoint`], the [`Feedback`] maps,
//! and the [`Corpus`] (which owns the live checkpoints); only each worker's PRNG
//! is private (seeded by core index). Each worker is pinned to its own CPU
//! ([`affinity`]). The corpus and feedback locks are held only for the cheap map
//! ops (pick, add, coverage fold, fetching a resume tip); the slow VM run —
//! forking, replaying, rewinding — happens unlocked, so workers explore
//! concurrently. The genealogy itself is internally synchronized by the lab.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bedrock_lab::{BashTarget, Branch, Checkpoint, LabOpts, RngMode, VirtTime};
use bedrock_vm::{boot::defaults, load_kernel, LinuxBootConfig, VmBuilder};

use crate::affinity;
use crate::corpus::Corpus;
use crate::driver::{self, Rule};
use crate::executor::Executor;
use crate::feedback::Feedback;
use crate::input::Plan;
use crate::mutator::{mutate, Limits};
use crate::prng::Rng;
use crate::sink::Sink;
use crate::solution::{self, FoundAt, WorkloadProvenance};
use crate::ui;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;

/// Campaign configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub vmlinux: PathBuf,
    pub initramfs: PathBuf,
    /// Workload `compose.yaml`, served to the guest over the file-transmission
    /// hypercall during boot (the generic podman initrd downloads it).
    pub compose: PathBuf,
    /// Workload `images.tar` (the container archives `build.sh` produces),
    /// served the same way.
    pub images: PathBuf,
    pub memory_mb: usize,
    /// Virtual-time budget (seconds) for the one-time boot to the ready
    /// checkpoint. A container workload can take many emulated minutes to settle,
    /// so this is generous by default.
    pub ready_deadline_secs: u64,
    pub boot_rng_seed: u64,
    /// Feedback-buffer id prefix that marks a coverage map. Every buffer whose
    /// id starts with this is treated as a coverage domain.
    pub cov_prefix: Vec<u8>,
    pub driver_dir: String,
    /// Per-step branch budget: the maximum **virtual** time (seconds) a step's
    /// branch may run before lonepine stops waiting for its drivers and
    /// checkpoints where it is. Bounds a slow/hung driver without making it a
    /// finding.
    pub branch_budget_secs: u64,
    /// Settle window (virtual seconds) to keep running each step's branch after
    /// its drivers finish, so the guest's async assertion pipeline surfaces any
    /// failure on serial before the oracle reads it. `0` disables it.
    pub quiesce_secs: f64,
    /// Maximum live VM tips kept in the corpus (others are dropped and revived on
    /// demand). Bounds total cached VM memory regardless of `cores`.
    pub cache_budget: usize,
    /// Number of parallel fuzzing workers. All share one ready checkpoint, the
    /// coverage map, and the corpus; only the PRNG is per-worker.
    pub cores: usize,
    pub seed: u64,
    /// Iteration cap, per worker; `0` == run forever.
    pub max_iters: u64,
    /// Directory reproducers are written to. Each bug is named by a content hash
    /// of its inputs and gets `bug-<hash>.json` (the raw input, saved as soon as
    /// it is found), `bug-<hash>.serial.log` (the finding's console), and
    /// `bug-<hash>.min.json` (the minimized input).
    pub solutions_dir: String,
    /// Diagnostic: capture the [`INJECT`](bedrock_lab::EventCategories::INJECT)
    /// event category on every executed branch and report any large
    /// emulated-TSC gap between consecutive captured events. A timer injection
    /// records the deadline it fired for (`target_tsc`), so an idle over-advance
    /// (a `time.sleep(0.05)` whose APIC timer was armed seconds — or minutes —
    /// into the future) shows up as a single flagged gap. Intended for
    /// `--reproduce`; off by default.
    pub trace_injects: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            vmlinux: PathBuf::new(),
            initramfs: PathBuf::new(),
            compose: PathBuf::new(),
            images: PathBuf::new(),
            memory_mb: 10240,
            ready_deadline_secs: 3600,
            boot_rng_seed: 0xbed0_0001,
            cov_prefix: b"go-".to_vec(),
            driver_dir: "/opt/bedrock/drivers".to_string(),
            branch_budget_secs: 600,
            quiesce_secs: 5.0,
            cache_budget: 512,
            cores: 1,
            seed: 0x5ca1_ab1e,
            max_iters: 0,
            solutions_dir: "lonepine-solutions".to_string(),
            trace_injects: false,
        }
    }
}

/// How many mutations to try on a corpus entry once it's picked, before picking
/// again. Spending a burst of energy per seed (rather than re-picking every
/// exec) amortizes scheduling and explores the neighborhood of each seed.
const MUTATIONS_PER_PICK: u64 = 16;

/// Boot the guest once and return the ready checkpoint the workers fork from.
/// The workload's `compose.yaml` / `images.tar` are served over the
/// file-transmission hypercall during boot. Boot serial (and the container
/// monitor's `[podman]` lines) flows to `sink`, shown in the boot-log panel until
/// `enter_fuzz_mode`.
pub fn boot_ready(cfg: &Config, sink: Arc<Sink>) -> Result<Checkpoint> {
    let mut vm = VmBuilder::new().memory_mb(cfg.memory_mb).build()?;
    let kernel = std::fs::read(&cfg.vmlinux)?;
    let initramfs = std::fs::read(&cfg.initramfs)?;
    let (entry, end) = {
        let memory = vm.memory_mut()?;
        load_kernel(memory, &kernel)?
    };
    let boot = LinuxBootConfig::new(entry, end)
        .cmdline(defaults::CMDLINE)
        .initramfs(&initramfs);
    vm.setup_linux_boot(&boot)?;

    let freq = bedrock_vm::DEFAULT_TSC_FREQUENCY;
    let cp = Checkpoint::initial_when_ready_with(
        vm,
        VirtTime::from_secs(cfg.ready_deadline_secs, freq),
        LabOpts {
            rng: RngMode::Seeded(cfg.boot_rng_seed),
            sink,
            files: vec![
                (
                    "compose.yaml".to_string(),
                    cfg.compose.to_string_lossy().into_owned(),
                ),
                (
                    "images.tar".to_string(),
                    cfg.images.to_string_lossy().into_owned(),
                ),
            ],
            ..Default::default()
        },
    )?;
    Ok(cp)
}

/// List the running containers by asking podman on the host.
fn list_containers(b: &mut Branch) -> Result<Vec<String>> {
    let out = b.bash(BashTarget::host(), "podman ps --format '{{.Names}}'", true)?;
    Ok(out
        .output_lossy()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Enumerate `<driver_dir>` across the host and every running container once.
/// Containers are discovered by injecting a `podman ps` on the host — the fuzzer
/// is not told about them. The indexed order is frozen for the campaign (stable
/// rule indices) and shared across all workers.
pub fn discover_rules(ready: &Checkpoint, cfg: &Config) -> Result<Vec<Rule>> {
    let mut b = ready.branch()?;
    let containers = list_containers(&mut b)?;
    let mut targets = vec![BashTarget::host()];
    targets.extend(containers.into_iter().map(BashTarget::Container));

    let mut rules = Vec::new();
    for t in targets {
        let out = b.bash(
            t.clone(),
            &format!("ls {} 2>/dev/null", cfg.driver_dir),
            true,
        )?;
        for name in out.output_lossy().lines() {
            let name = name.trim();
            if !name.is_empty() {
                rules.push(Rule {
                    target: t.clone(),
                    name: name.to_string(),
                    command: format!("{}/{}", cfg.driver_dir, name),
                    kind: driver::classify(name),
                });
            }
        }
    }
    Ok(rules)
}

/// Longest common step prefix of two plans (by structural step equality). Steps
/// before this index execute identically, so a mutated plan resumes its parent's
/// state at this depth. The swarm mask is irrelevant to execution and ignored.
fn common_prefix(a: &Plan, b: &Plan) -> usize {
    let n = a.steps.len().min(b.steps.len());
    (0..n).take_while(|&i| a.steps[i] == b.steps[i]).count()
}

/// Campaign-wide counters the monitor reads; the rest of the heartbeat is read
/// live off the shared structures. `*_vt_us` are guest virtual microseconds:
/// `novel` explored new ground, `replay` revived evicted prefixes.
#[derive(Default)]
struct Stats {
    execs: AtomicU64,
    bugs: AtomicU64,
    novel_vt_us: AtomicU64,
    replay_vt_us: AtomicU64,
}

/// Format seconds as a compact `1d2h3m4s` (largest non-zero unit down to
/// seconds, seconds always shown).
fn fmt_hms(secs: f64) -> String {
    let t = secs.max(0.0) as u64;
    let (d, h, m, s) = (t / 86400, (t % 86400) / 3600, (t % 3600) / 60, t % 60);
    if d > 0 {
        format!("{d}d{h}h{m}m{s}s")
    } else if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// Print a campaign stats line on a fixed wall-clock cadence (not per-iteration:
/// iterations run the VM and are slow). Runs until `stop` is set, then prints one
/// final line.
fn monitor(
    stats: Arc<Stats>,
    feedback: Arc<Feedback>,
    corpus: Arc<Mutex<Corpus>>,
    seen_reasons: Arc<Mutex<HashSet<String>>>,
    stop: Arc<AtomicBool>,
) {
    let start = Instant::now();
    let interval = Duration::from_secs(10);
    loop {
        let mut waited = Duration::ZERO;
        while waited < interval && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
            waited += Duration::from_millis(200);
        }
        let done = stop.load(Ordering::Relaxed);

        let secs = start.elapsed().as_secs_f64().max(1e-3);
        let execs = stats.execs.load(Ordering::Relaxed);
        let bugs = stats.bugs.load(Ordering::Relaxed);
        let unique = seen_reasons.lock().unwrap().len();
        let novel_vt = stats.novel_vt_us.load(Ordering::Relaxed) as f64 / 1e6;
        let replay_vt = stats.replay_vt_us.load(Ordering::Relaxed) as f64 / 1e6;
        let fb = feedback.stats();
        let (domains, edges, edge_cap, targets) = (fb.domains, fb.covered, fb.capacity, fb.targets);
        let (ncorp, tnodes) = {
            let c = corpus.lock().unwrap();
            (c.len(), c.live_tips())
        };

        let edge_pct = if edge_cap > 0 {
            100.0 * edges as f64 / edge_cap as f64
        } else {
            0.0
        };
        let exec_vt = novel_vt + replay_vt;
        let vt_ratio = exec_vt / secs;
        let replay_pct = if exec_vt > 0.0 {
            100.0 * replay_vt / exec_vt
        } else {
            0.0
        };
        let wall = fmt_hms(secs);
        let vt = fmt_hms(exec_vt);
        ui::heartbeat(&format!(
            "wall {wall} · vt {vt} ({vt_ratio:.1}x) · replay {replay_pct:.0}% · {execs} execs ({:.0}/s) · corpus {ncorp} · domains {domains} · edges {edges}/{edge_cap} ({edge_pct:.2}%) · targets {targets} · trie {tnodes} · bugs {bugs} ({unique} unique)",
            execs as f64 / secs,
        ));
        ui::set_spinner_status(format!(
            "{edges} edges ({edge_pct:.1}%), {execs} execs, {vt_ratio:.0}x vt, {bugs} bugs ({unique} unique)"
        ));

        if done {
            return;
        }
    }
}

/// One fuzzing worker. All workers share the feedback maps and corpus (which owns
/// the live checkpoints); only the PRNG is per-worker (seeded by core).
#[allow(clippy::too_many_arguments)]
fn worker_loop(
    core: usize,
    ready: Checkpoint,
    rules: Arc<Vec<Rule>>,
    feedback: Arc<Feedback>,
    corpus: Arc<Mutex<Corpus>>,
    sink: Arc<Sink>,
    stats: Arc<Stats>,
    seen_reasons: Arc<Mutex<HashSet<String>>>,
    provenance: Arc<WorkloadProvenance>,
    cfg: Config,
    freq: u64,
    ready_vt_secs: f64,
) {
    // Pin this worker to its own core: workers are CPU-bound on VM execution, so
    // keeping each on one CPU avoids the scheduler bouncing them.
    affinity::pin_to_core(core);

    // The shared run context for every step this worker executes (and for
    // minimization). Borrows the worker's shared state for the campaign's life.
    let exec = Executor {
        rules: rules.as_slice(),
        feedback: &feedback,
        sink: &sink,
        freq,
        cfg: &cfg,
        provenance: &provenance,
    };

    let limits = Limits::with_kinds(rules.iter().map(|r| r.kind).collect());
    let mut rng = Rng::new(cfg.seed ^ (core as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut iters = 0u64;

    // Alternate scheduling policy by core: even cores draw seeds at random (a
    // size tournament), odd cores walk the corpus as a shared round-robin queue.
    let use_queue = core % 2 == 1;

    'campaign: while cfg.max_iters == 0 || iters < cfg.max_iters {
        // Pick one parent (and a donor), then spend a burst of mutations on it
        // before picking again — amortizes the pick and explores the seed's
        // neighborhood. Resuming the same parent repeatedly also keeps its tip
        // warm.
        let (parent_idx, parent_plan, donor) = {
            let mut c = corpus.lock().unwrap();
            let picked = if use_queue {
                c.pick_queue()
            } else {
                c.pick(&mut rng)
            };
            let (idx, plan) = picked.unwrap_or((0, Plan::empty(rules.len())));
            let donor = c.donor(&mut rng);
            (idx, plan, donor)
        };

        for _ in 0..MUTATIONS_PER_PICK {
            if cfg.max_iters != 0 && iters >= cfg.max_iters {
                break 'campaign;
            }
            iters += 1;
            stats.execs.fetch_add(1, Ordering::Relaxed);

            let plan = mutate(&parent_plan, donor.as_ref(), &limits, &mut rng);
            let k = common_prefix(&plan, &parent_plan);

            let (resume_cp, replay_secs) = match Corpus::resume(&corpus, parent_idx, k, &ready) {
                Ok(r) => r,
                Err(e) => {
                    ui::warn(&format!("resume failed (corpus #{parent_idx}): {e}"));
                    continue;
                }
            };

            let out = exec.run(&plan, resume_cp, k, rng.next_u64());
            stats
                .novel_vt_us
                .fetch_add((out.novel_vt_secs * 1e6) as u64, Ordering::Relaxed);
            stats
                .replay_vt_us
                .fetch_add((replay_secs * 1e6) as u64, Ordering::Relaxed);

            let vt_secs = (out.tip.time().as_secs_f64() - ready_vt_secs).max(0.0);

            if let Some(f) = out.finding.clone() {
                let id = stats.bugs.fetch_add(1, Ordering::Relaxed);
                // Only a new unique reason is recorded; recurrences are tallied
                // but otherwise dropped.
                let is_new = seen_reasons.lock().unwrap().insert(f.reason());
                if is_new {
                    let found = FoundAt {
                        id,
                        from: parent_idx,
                        core,
                        iter: iters,
                        vt_secs,
                    };
                    solution::record_finding(
                        &exec,
                        &found,
                        &f,
                        &out.realized,
                        &out.serial,
                        &ready,
                        &mut rng,
                    );
                }
            }

            // New coverage (a new edge, or an already-covered edge reaching a new
            // hit-count bucket), or a hill-climbing target improvement, is kept
            // permanently as a corpus entry — but only for a plan that ran to
            // completion. A plan that hit a finding stopped early, so its
            // tip/step_times cover only the steps before the fault and don't match
            // the full realized plan; its prefix coverage is already folded into the
            // map, so nothing is lost by not seeding it.
            if out.finding.is_none() && out.interesting() {
                let new_id = corpus.lock().unwrap().add_child(
                    parent_idx,
                    k,
                    out.realized.clone(),
                    &out.step_times,
                    out.tip.clone(),
                );
                let hits = if out.new_hits > 0 {
                    format!(", +{} hits", out.new_hits)
                } else {
                    String::new()
                };
                ui::good(&format!(
                    "corpus #{new_id} (+{} edges{hits}) · {vt_secs:.1}s vt · from #{parent_idx}",
                    out.new_edges,
                ));
            }
        }
    }
}

/// Run the coverage-guided campaign across `cfg.cores` parallel workers.
pub fn run_campaign(cfg: Config) -> Result<()> {
    ui::banner("coverage-guided driver fuzzer for bedrock");

    let sink = Arc::new(Sink::new());

    let ready = boot_ready(&cfg, Arc::clone(&sink))?;
    let freq = ready.tsc_frequency();
    let ready_vt_secs = ready.time().as_secs_f64();
    let rules = discover_rules(&ready, &cfg)?;
    sink.enter_fuzz_mode(); // seal the boot panel before any tagged output

    if rules.is_empty() {
        ui::err(&format!("no drivers found under {}", cfg.driver_dir));
        return Err(format!("no drivers found under {}", cfg.driver_dir).into());
    }
    let targets: HashSet<String> = rules.iter().map(|r| format!("{:?}", r.target)).collect();
    let cores = cfg.cores.max(1);
    let n_singleton = rules.iter().filter(|r| r.kind.is_singleton()).count();
    let n_anytime = rules.iter().filter(|r| r.kind.is_anytime()).count();
    let n_parallel = rules.len() - n_singleton - n_anytime;
    ui::good(&format!(
        "discovered {} drivers ({n_parallel} parallel, {n_singleton} singleton, {n_anytime} anytime) across {} target(s)",
        rules.len(),
        targets.len()
    ));
    // List each so its discovered kind/target is visible (e.g. the host's
    // built-in `anytime_kick` should read `[Anytime]`).
    for r in &rules {
        ui::detail(&format!("{} [{:?}] @ {:?}", r.name, r.kind, r.target));
    }
    // Anytime drivers (the host `anytime_kick`) do no test work of their own, so a
    // rule set with no parallel/singleton driver has nothing to actually fuzz —
    // usually the workload's container drivers weren't discovered (`podman ps`
    // found no containers, or they expose no `<driver_dir>`).
    if n_parallel + n_singleton == 0 {
        ui::warn(&format!(
            "only anytime drivers found ({} target(s)) — no test drivers to drive; \
             check the workload's containers and {}",
            targets.len(),
            cfg.driver_dir
        ));
    }
    let rules = Arc::new(rules);
    ui::info(&format!("fuzzing with {cores} core(s)"));
    if let Err(e) = std::fs::create_dir_all(&cfg.solutions_dir) {
        ui::warn(&format!(
            "could not create solutions dir {}: {e}",
            cfg.solutions_dir
        ));
    } else {
        ui::info(&format!("saving reproducers to {}", cfg.solutions_dir));
    }

    // Hash the workload files (kernel/initrd/compose/images) once, here at
    // startup — not per finding, where re-hashing a multi-hundred-MB images.tar
    // on every bug would be wasteful. Every reproducer this campaign writes
    // carries this provenance so a replay can confirm the same bytes.
    let provenance = Arc::new(match WorkloadProvenance::collect(&cfg) {
        Ok(p) => {
            for f in &p.files {
                ui::detail(&format!("{}: {} ({})", f.key, f.path, f.sha1));
            }
            p
        }
        Err(e) => {
            ui::warn(&format!(
                "could not hash workload files for provenance: {e}"
            ));
            WorkloadProvenance::default()
        }
    });

    let feedback = Arc::new(Feedback::new(cfg.cov_prefix.clone()));
    let corpus = Arc::new(Mutex::new(Corpus::new(cfg.cache_budget)));
    {
        // Seed one empty plan per timeline kind: the parallel timeline always, and
        // a singleton timeline when the workload has any singleton driver. The
        // mutator grows each while keeping it homogeneous.
        let mut c = corpus.lock().unwrap();
        c.seed(&ready, Plan::empty(rules.len()));
        if rules.iter().any(|r| r.kind.is_singleton()) {
            c.seed(&ready, Plan::singleton_seed(rules.len()));
        }
    }

    let stats = Arc::new(Stats::default());
    let seen_reasons = Arc::new(Mutex::new(HashSet::<String>::new()));
    let stop = Arc::new(AtomicBool::new(false));

    let monitor_handle = {
        let stats = Arc::clone(&stats);
        let feedback = Arc::clone(&feedback);
        let corpus = Arc::clone(&corpus);
        let seen_reasons = Arc::clone(&seen_reasons);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || monitor(stats, feedback, corpus, seen_reasons, stop))
    };

    ui::spinner_start();
    let mut handles = Vec::new();
    for core in 0..cores {
        let ready = ready.clone();
        let rules = Arc::clone(&rules);
        let feedback = Arc::clone(&feedback);
        let corpus = Arc::clone(&corpus);
        let sink = Arc::clone(&sink);
        let stats = Arc::clone(&stats);
        let seen_reasons = Arc::clone(&seen_reasons);
        let provenance = Arc::clone(&provenance);
        let cfg = cfg.clone();
        handles.push(std::thread::spawn(move || {
            worker_loop(
                core,
                ready,
                rules,
                feedback,
                corpus,
                sink,
                stats,
                seen_reasons,
                provenance,
                cfg,
                freq,
                ready_vt_secs,
            );
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    stop.store(true, Ordering::Relaxed);
    let _ = monitor_handle.join();
    ui::spinner_stop();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{Member, Step};

    fn step(driver: usize, offset: i64) -> Step {
        Step {
            batch: vec![Member { driver, offset }],
            rng: Vec::new(),
            rand: Vec::new(),
        }
    }

    #[test]
    fn fmt_hms_compact() {
        assert_eq!(fmt_hms(0.0), "0s");
        assert_eq!(fmt_hms(45.0), "45s");
        assert_eq!(fmt_hms(125.0), "2m5s");
        assert_eq!(fmt_hms(3700.0), "1h1m40s");
        assert_eq!(fmt_hms(90000.0), "1d1h0m0s");
        assert_eq!(fmt_hms(-5.0), "0s");
    }

    #[test]
    fn common_prefix_counts_shared_steps() {
        let mut a = Plan::empty(3);
        a.steps = vec![step(0, 0), step(1, 0), step(2, 0)];
        let mut b = a.clone();
        // Identical -> full prefix.
        assert_eq!(common_prefix(&a, &b), 3);
        // Diverge at step 1.
        b.steps[1] = step(2, 5);
        assert_eq!(common_prefix(&a, &b), 1);
        // A shorter plan that is a prefix matches up to its length.
        b.steps.truncate(1);
        assert_eq!(common_prefix(&a, &b), 1);
        // Empty parent shares nothing.
        assert_eq!(common_prefix(&a, &Plan::empty(3)), 0);
    }
}

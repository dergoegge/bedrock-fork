// SPDX-License-Identifier: GPL-2.0

//! The integration layer: boot a workload guest, enumerate its drivers, then run
//! a coverage-guided loop on bedrock. Everything that touches a real VM lives
//! here; the search logic in the sibling modules is pure and unit-tested.
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
//!   *revived* by [`RetainedInput::longest_checkpoint_prefix`] +
//!   [`RecordedInputSource`] replay — re-deriving it from the deepest live
//!   ancestor. This revival is the only execution counted as `replay`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bedrock_lab::{
    BashTarget, Branch, Checkpoint, LabOpts, RecordedInputSource, RngMode, RunOutcome,
    VirtDuration, VirtTime,
};
use bedrock_vm::events::RandomSource;
use bedrock_vm::{boot::defaults, load_kernel, LinuxBootConfig, VmBuilder};

use crate::corpus::Corpus;
use crate::coverage::CoverageMap;
use crate::input::{Member, Plan};
use crate::mutator::{mutate, Limits};
use crate::oracle::{assertion_failure_reason, Finding};
use crate::prng::Rng;
use crate::rng::ReplayThenFresh;
use crate::sink::Sink;
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
    /// Maximum live VM tips kept in the corpus (others are dropped and revived on
    /// demand). Bounds total cached VM memory.
    pub cache_budget: usize,
    pub seed: u64,
    /// Iteration cap; `0` == run forever.
    pub max_iters: u64,
    /// Directory reproducers are written to. Each bug gets `crash-<n>.json` (the
    /// raw input, saved as soon as it is found), `crash-<n>.serial.log` (the
    /// finding's console), and `crash-<n>.min.json` (the minimized input).
    pub solutions_dir: String,
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
            cache_budget: 512,
            seed: 0x5ca1_ab1e,
            max_iters: 0,
            solutions_dir: "lonepine-solutions".to_string(),
        }
    }
}

/// Driver-name prefix marking a *singleton* driver (see `workloads/README.md`):
/// on any timeline only one singleton runs, ever, and nothing runs alongside it.
/// Used to port existing unit/functional tests so they can be replayed across
/// deterministic schedules to surface intermittent failures.
const SINGLETON_PREFIX: &str = "singleton_";

/// One enumerated `(container, driver)` rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub target: BashTarget,
    pub name: String,
    /// A singleton driver (name starts with [`SINGLETON_PREFIX`]): runs alone,
    /// at most one per timeline.
    pub singleton: bool,
}

impl Rule {
    fn path(&self, dir: &str) -> String {
        format!("{dir}/{}", self.name)
    }
}

/// Boot the guest once and return the ready checkpoint the fuzzer forks from.
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
/// rule indices).
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
                    singleton: name.starts_with(SINGLETON_PREFIX),
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

/// Whether a step's batch names any singleton driver.
fn is_singleton_step(batch: &[Member], rules: &[Rule]) -> bool {
    batch.iter().any(|m| rules[m.driver].singleton)
}

/// The batch a step actually runs under singleton rules, and whether it is a
/// singleton step. A batch naming any singleton driver collapses to that lone
/// singleton — run alone, with no other driver during its runtime
/// ([`SINGLETON_PREFIX`]); any other batch runs as-is (concurrent).
fn effective_batch(batch: &[Member], rules: &[Rule]) -> (Vec<Member>, bool) {
    match batch.iter().find(|m| rules[m.driver].singleton) {
        Some(m) => (vec![m.clone()], true),
        None => (batch.to_vec(), false),
    }
}

/// The outcome of executing a plan's novel suffix.
struct ExecOutcome {
    /// Never-before-covered edges (map slots) this run hit; >0 ⇒ a corpus find.
    new_edges: usize,
    /// Already-covered edges that reached a new hit-count bucket (loop
    /// sensitivity); >0 ⇒ also corpus-worthy.
    new_hits: usize,
    finding: Option<Finding>,
    /// The plan with each executed step's `rng`/`rand` set to its realized
    /// consumption.
    realized: Plan,
    /// Checkpoint time after each executed step (one per step in `start..len`).
    step_times: Vec<VirtTime>,
    /// The checkpoint at the plan's end (the resume checkpoint when no steps ran).
    tip: Checkpoint,
    /// Serial of the finding's step (the bug's proof); empty when no finding.
    serial: Vec<String>,
    /// Guest virtual time (s) executed exploring the novel suffix.
    novel_vt_secs: f64,
}

/// Execute `plan.steps[start..]` from `resume_cp`, accumulating coverage. Each
/// step forks the current checkpoint with a [`ReplayThenFresh`] source (replays
/// the step's recorded randomness, extends fresh past it), launches the driver
/// batch at their virtual-time offsets, drains a response per driver (or until
/// the branch budget), reads coverage, and scans serial for a failed assertion.
/// Driver exit codes/output are not inspected — coverage is the only steering
/// signal; a hard VM fault or a failed `Always` assertion is the only finding.
#[allow(clippy::too_many_arguments)]
fn execute(
    plan: &Plan,
    resume_cp: Checkpoint,
    start: usize,
    rules: &[Rule],
    cov: &mut CoverageMap,
    sink: &Sink,
    freq: u64,
    cfg: &Config,
    seed: u64,
) -> ExecOutcome {
    let mut realized = plan.clone();
    let mut cp = resume_cp;

    // If the resumed prefix already ran a singleton driver, the timeline has used
    // its one singleton — run nothing more (steps a mutation appended past a
    // singleton don't execute). Coverage for the prefix was already counted, so
    // this contributes nothing and won't be added to the corpus.
    let prefix_has_singleton = plan.steps[..start.min(plan.steps.len())]
        .iter()
        .any(|s| is_singleton_step(&s.batch, rules));
    if prefix_has_singleton {
        realized.steps.truncate(start);
        return ExecOutcome {
            new_edges: 0,
            new_hits: 0,
            finding: None,
            realized,
            step_times: Vec::new(),
            tip: cp,
            serial: Vec::new(),
            novel_vt_secs: 0.0,
        };
    }

    let mut new_edges = 0usize;
    let mut new_hits = 0usize;
    let mut finding = None;
    let mut finding_serial: Vec<String> = Vec::new();
    let mut step_times: Vec<VirtTime> = Vec::new();
    let mut novel_vt_secs = 0.0f64;
    let branch_budget = VirtDuration::from_secs(cfg.branch_budget_secs, freq);

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
        let mut br: Branch = match cp.branch_with_input_source(src) {
            Ok(b) => b,
            Err(_) => {
                finding = Some(Finding::VmFault { step: i });
                break;
            }
        };
        let branch_id = br.id();
        sink.start_capture(branch_id);

        // Enforce singleton semantics: a step naming a singleton driver runs only
        // that one, alone (no other drivers during its runtime), and is terminal
        // (at most one singleton per timeline); any other batch runs concurrently.
        // Reflect the effective batch in the realized plan so the corpus/reproducer
        // record exactly what ran (and a re-execution collapses identically).
        let (batch, singleton_step) = effective_batch(&step.batch, rules);
        realized.steps[i].batch = batch.clone();

        let base = br.current_time();
        let budget_deadline = base + branch_budget;
        let mut faulted = false;
        for m in &batch {
            let d = &rules[m.driver];
            let at = base + VirtDuration::from_instructions(m.offset.max(0) as u64, freq);
            if br
                .sched_bash(at, d.target.clone(), &d.path(&cfg.driver_dir), false)
                .is_err()
            {
                faulted = true;
                break;
            }
        }

        // Drain a response per launched driver to reach a quiescent point, but no
        // longer than the branch budget.
        let mut pending = batch.len();
        while !faulted && pending > 0 {
            match br.run_until(budget_deadline) {
                Ok((_, RunOutcome::ActionResponse { .. })) => pending -= 1,
                Ok((_, RunOutcome::Ready)) => {}
                Ok((_, RunOutcome::ReachedTime)) => break,
                _ => faulted = true,
            }
        }

        // Coverage: each registered feedback buffer is a domain. Dedup ids;
        // same-id buffers are unioned and counted once.
        if !faulted {
            let ids = br.feedback_buffer_ids().unwrap_or_default();
            let mut seen = HashSet::new();
            for id in &ids {
                if !id.starts_with(&cfg.cov_prefix[..]) || !seen.insert(id.clone()) {
                    continue;
                }
                if let Ok(bufs) = br.feedback_buffers(id) {
                    let (e, h) = cov.observe(id, &bufs);
                    new_edges += e;
                    new_hits += h;
                }
            }
        }

        // Reclaim this branch's serial, then apply the oracles: a hard VM fault,
        // or a failed `Always` assertion on the serial (also how a dead container
        // surfaces, via the in-guest monitor).
        let serial = sink.take_capture(branch_id);
        if faulted {
            finding = Some(Finding::VmFault { step: i });
            finding_serial = serial;
            break 'steps;
        }
        if let Some(message) = assertion_failure_reason(&serial) {
            finding = Some(Finding::Assertion { step: i, message });
            finding_serial = serial;
            break 'steps;
        }

        // Capture the randomness the guest actually consumed this step, split by
        // channel: the RDRAND/RDSEED tape (`rng`) and the getrandom() tape
        // (`rand`). The lab merges both into one recording stream tagged by
        // source, so we partition the new entries here.
        let randoms = br.input_recording().random_inputs();
        let consumed = &randoms[base_random.min(randoms.len())..];
        realized.steps[i].rng = consumed
            .iter()
            .filter(|r| r.source != RandomSource::GetRandom)
            .flat_map(|r| r.bytes.iter().copied())
            .collect();
        realized.steps[i].rand = consumed
            .iter()
            .filter(|r| r.source == RandomSource::GetRandom)
            .flat_map(|r| r.bytes.iter().copied())
            .collect();

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

        // One singleton per timeline: a singleton step ends the plan. Drop any
        // trailing steps from the realized plan so it matches what ran (and stays
        // consistent with `step_times`).
        if singleton_step {
            realized.steps.truncate(i + 1);
            break 'steps;
        }
    }

    ExecOutcome {
        new_edges,
        new_hits,
        finding,
        realized,
        step_times,
        tip: cp,
        serial: finding_serial,
        novel_vt_secs,
    }
}

/// Reconstruct an evicted entry's tip by replaying its retained input prefix.
/// Locates the deepest live ancestor with [`longest_checkpoint_prefix`] and
/// replays the recorded suffix forward to the tip's time — *revival*, the only
/// execution counted as replay. Returns the tip and the guest seconds replayed.
fn revive(corpus: &mut Corpus, idx: usize, ready: &Checkpoint) -> Result<(Checkpoint, f64)> {
    let end = *corpus
        .entry(idx)
        .step_times()
        .last()
        .ok_or("revive: entry has no steps")?;
    let m = corpus
        .retained_prefix(idx)
        .ok_or("revive: retained prefix not in genealogy")?;
    let new_empty = m.new.io_inputs().is_empty() && m.new.random_inputs().is_empty();
    let (mut br, from_secs) = if new_empty {
        // The whole prefix is known ground: fork the deepest live ancestor and
        // replay the matching suffix from it.
        let from = m.start.time().as_secs_f64();
        (
            m.start
                .branch_with_input_source(RecordedInputSource::new(m.replay))?,
            from,
        )
    } else {
        // Defensive fallback (the retain anchor should keep the prefix known):
        // replay the full recording from the root.
        (
            ready.branch_with_input_source(RecordedInputSource::new(corpus.recording(idx)))?,
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

/// Resume the checkpoint to run `plan.steps[k..]` from: the state after step
/// `k-1` of the parent entry. `k == 0` forks the ready checkpoint; an appended
/// suffix forks the parent tip; an edit at step `k` rewinds the tip to step
/// `k-1`. Accumulates any revival replay into `replay_secs`.
fn resume(
    corpus: &mut Corpus,
    idx: usize,
    k: usize,
    ready: &Checkpoint,
    replay_secs: &mut f64,
) -> Result<Checkpoint> {
    if k == 0 {
        return Ok(ready.clone());
    }
    let tip = match corpus.tip(idx) {
        Some(t) => t,
        None => {
            let (t, replayed) = revive(corpus, idx, ready)?;
            *replay_secs += replayed;
            corpus.set_tip(idx, t.clone());
            t
        }
    };
    let target = corpus.entry(idx).step_times()[k - 1];
    if target >= tip.time() {
        // Appended suffix: resume at the tip itself.
        return Ok(tip);
    }
    // Edited step: rewind to the checkpoint after step k-1 (a genealogy prefix
    // query + recorded-suffix replay).
    Ok(tip.rewind(tip.time() - target)?)
}

fn same_kind(found: &Option<Finding>, target: &Finding) -> bool {
    matches!(found, Some(f) if f.kind() == target.kind())
}

/// Write a reproducer for bug `n`: the finding's kind/reason, where it was found,
/// and the plan (each step's resolved driver batch + the exact randomness the
/// guest consumed — `rng` is the RDRAND tape, `rand` the getrandom() tape). The
/// plan is replayable.
#[allow(clippy::too_many_arguments)]
fn save_solution(
    dir: &str,
    file: &str,
    n: u64,
    finding: &Finding,
    reason: &str,
    iter: u64,
    vt_secs: f64,
    plan: &Plan,
    rules: &[Rule],
) -> std::io::Result<String> {
    let steps: Vec<serde_json::Value> = plan
        .steps
        .iter()
        .map(|s| {
            let batch: Vec<serde_json::Value> = s
                .batch
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "driver": m.driver,
                        "name": rules.get(m.driver).map(|r| r.name.as_str()).unwrap_or("?"),
                        "target": rules.get(m.driver).map(|r| format!("{:?}", r.target)),
                        "offset": m.offset,
                    })
                })
                .collect();
            serde_json::json!({ "batch": batch, "rng": s.rng, "rand": s.rand })
        })
        .collect();
    let doc = serde_json::json!({
        "bug": n,
        "kind": finding.kind(),
        "reason": reason,
        "iter": iter,
        "vt_secs": vt_secs,
        "steps": steps,
    });
    std::fs::create_dir_all(dir)?;
    let path = format!("{dir}/{file}");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap())?;
    Ok(path)
}

/// Write the finding's serial to `<dir>/<file>` as plain text so the bug's
/// console proof can be read directly.
fn save_serial(dir: &str, file: &str, serial: &[String]) -> std::io::Result<String> {
    std::fs::create_dir_all(dir)?;
    let path = format!("{dir}/{file}");
    std::fs::write(&path, serial.join("\n"))?;
    Ok(path)
}

/// Delta-debug a finding: drop steps and clear per-step randomness while the same
/// kind of finding still reproduces. Each candidate is re-run from the ready
/// checkpoint (the genealogy serves the shared boot prefix).
#[allow(clippy::too_many_arguments)]
fn minimize(
    plan: &Plan,
    target: &Finding,
    ready: &Checkpoint,
    rules: &[Rule],
    cov: &mut CoverageMap,
    sink: &Sink,
    freq: u64,
    cfg: &Config,
    rng: &mut Rng,
) -> Plan {
    let mut best = plan.clone();
    let mut changed = true;
    while changed {
        changed = false;

        let mut i = 0;
        while i < best.steps.len() {
            let mut cand = best.clone();
            cand.steps.remove(i);
            let out = execute(
                &cand,
                ready.clone(),
                0,
                rules,
                cov,
                sink,
                freq,
                cfg,
                rng.next_u64(),
            );
            if same_kind(&out.finding, target) {
                best = out.realized;
                changed = true;
            } else {
                i += 1;
            }
        }

        for i in 0..best.steps.len() {
            if best.steps[i].rng.is_empty() && best.steps[i].rand.is_empty() {
                continue;
            }
            let mut cand = best.clone();
            cand.steps[i].rng.clear();
            cand.steps[i].rand.clear();
            let out = execute(
                &cand,
                ready.clone(),
                0,
                rules,
                cov,
                sink,
                freq,
                cfg,
                rng.next_u64(),
            );
            if same_kind(&out.finding, target) {
                best = out.realized;
                changed = true;
            }
        }
    }
    best
}

/// Campaign-wide counters the monitor thread reads. All are written by the
/// single fuzzing loop. `*_vt_us` are guest virtual microseconds: `novel`
/// explored new ground, `replay` revived evicted prefixes.
#[derive(Default)]
struct Stats {
    execs: AtomicU64,
    bugs: AtomicU64,
    unique: AtomicU64,
    novel_vt_us: AtomicU64,
    replay_vt_us: AtomicU64,
    domains: AtomicU64,
    edges: AtomicU64,
    edge_cap: AtomicU64,
    targets: AtomicU64,
    corpus: AtomicU64,
    cache: AtomicU64,
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
fn monitor(stats: Arc<Stats>, stop: Arc<AtomicBool>) {
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
        let unique = stats.unique.load(Ordering::Relaxed);
        let novel_vt = stats.novel_vt_us.load(Ordering::Relaxed) as f64 / 1e6;
        let replay_vt = stats.replay_vt_us.load(Ordering::Relaxed) as f64 / 1e6;
        let domains = stats.domains.load(Ordering::Relaxed);
        let edges = stats.edges.load(Ordering::Relaxed);
        let edge_cap = stats.edge_cap.load(Ordering::Relaxed);
        let targets = stats.targets.load(Ordering::Relaxed);
        let ncorp = stats.corpus.load(Ordering::Relaxed);
        let tnodes = stats.cache.load(Ordering::Relaxed);

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

/// Mirror the live search structures into the monitor's atomic counters.
fn publish(stats: &Stats, cov: &CoverageMap, corpus: &Corpus) {
    stats.domains.store(cov.domains() as u64, Ordering::Relaxed);
    stats.edges.store(cov.covered() as u64, Ordering::Relaxed);
    stats
        .edge_cap
        .store(cov.capacity() as u64, Ordering::Relaxed);
    stats.targets.store(cov.targets() as u64, Ordering::Relaxed);
    stats.corpus.store(corpus.len() as u64, Ordering::Relaxed);
    stats
        .cache
        .store(corpus.live_tips() as u64, Ordering::Relaxed);
}

/// The coverage-guided fuzzing loop (single worker). Owns the corpus, coverage
/// map, and PRNG; publishes counters for the monitor thread.
#[allow(clippy::too_many_arguments)]
fn fuzz_loop(
    ready: &Checkpoint,
    rules: &[Rule],
    cfg: &Config,
    freq: u64,
    ready_vt_secs: f64,
    sink: &Sink,
    cov: &mut CoverageMap,
    corpus: &mut Corpus,
    stats: &Stats,
) {
    let limits = Limits::new(rules.len());
    let mut rng = Rng::new(cfg.seed);
    let mut seen_reasons: HashSet<String> = HashSet::new();
    let mut iters = 0u64;

    while cfg.max_iters == 0 || iters < cfg.max_iters {
        iters += 1;
        stats.execs.fetch_add(1, Ordering::Relaxed);

        let (parent_idx, parent_plan) = match corpus.pick(&mut rng) {
            Some(p) => p,
            None => (0, Plan::empty(rules.len())),
        };
        let donor = corpus.donor(&mut rng);
        let plan = mutate(&parent_plan, donor.as_ref(), &limits, &mut rng);
        let k = common_prefix(&plan, &parent_plan);

        let mut replay_secs = 0.0f64;
        let resume_cp = match resume(corpus, parent_idx, k, ready, &mut replay_secs) {
            Ok(c) => c,
            Err(e) => {
                ui::warn(&format!("resume failed (corpus #{parent_idx}): {e}"));
                continue;
            }
        };

        let out = execute(
            &plan,
            resume_cp,
            k,
            rules,
            cov,
            sink,
            freq,
            cfg,
            rng.next_u64(),
        );
        stats
            .novel_vt_us
            .fetch_add((out.novel_vt_secs * 1e6) as u64, Ordering::Relaxed);
        stats
            .replay_vt_us
            .fetch_add((replay_secs * 1e6) as u64, Ordering::Relaxed);

        let vt_secs = (out.tip.time().as_secs_f64() - ready_vt_secs).max(0.0);

        if let Some(f) = out.finding.clone() {
            let id = stats.bugs.fetch_add(1, Ordering::Relaxed);
            let reason = match &f {
                Finding::Assertion { message, .. } => message.clone(),
                Finding::VmFault { .. } => "vm fault".to_string(),
            };
            // Only a new unique reason is printed and saved; recurrences are
            // tallied but otherwise dropped.
            if seen_reasons.insert(reason.clone()) {
                stats
                    .unique
                    .store(seen_reasons.len() as u64, Ordering::Relaxed);
                ui::solution(&format!(
                    "SOLUTION #{id} (from corpus entry {parent_idx}) — {reason}"
                ));
                for line in &out.serial {
                    ui::detail(line);
                }
                // Save raw reproducer + serial immediately — minimize re-runs the
                // VM many times, so don't risk losing the bug.
                if let Err(e) = save_solution(
                    &cfg.solutions_dir,
                    &format!("crash-{id}.json"),
                    id,
                    &f,
                    &reason,
                    iters,
                    vt_secs,
                    &out.realized,
                    rules,
                ) {
                    ui::warn(&format!("could not save crash-{id}.json: {e}"));
                }
                if let Err(e) = save_serial(
                    &cfg.solutions_dir,
                    &format!("crash-{id}.serial.log"),
                    &out.serial,
                ) {
                    ui::warn(&format!("could not save crash-{id}.serial.log: {e}"));
                }
                let minimal = minimize(
                    &out.realized,
                    &f,
                    ready,
                    rules,
                    cov,
                    sink,
                    freq,
                    cfg,
                    &mut rng,
                );
                match save_solution(
                    &cfg.solutions_dir,
                    &format!("crash-{id}.min.json"),
                    id,
                    &f,
                    &reason,
                    iters,
                    vt_secs,
                    &minimal,
                    rules,
                ) {
                    Ok(path) => ui::good(&format!(
                        "SOLUTION #{id} minimized {} -> {} steps, saved {path}",
                        out.realized.steps.len(),
                        minimal.steps.len()
                    )),
                    Err(e) => ui::warn(&format!("could not save crash-{id}.min.json: {e}")),
                }
            } else {
                stats
                    .unique
                    .store(seen_reasons.len() as u64, Ordering::Relaxed);
            }
        }

        // New coverage (a new edge, or an already-covered edge reaching a new
        // hit-count bucket) is kept permanently as a corpus entry — but only for a
        // plan that ran to completion. A plan that hit a finding stopped early, so
        // its tip/step_times cover only the steps before the fault and don't match
        // the full realized plan; its prefix coverage is already folded into the
        // map, so nothing is lost by not seeding it.
        if out.finding.is_none() && (out.new_edges > 0 || out.new_hits > 0) {
            let mut full_times = corpus.entry(parent_idx).step_times()[..k].to_vec();
            full_times.extend_from_slice(&out.step_times);
            let new_id = corpus.add(out.realized.clone(), full_times, out.tip.clone());
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

        publish(stats, cov, corpus);
    }
}

/// Run the coverage-guided campaign.
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
    ui::good(&format!(
        "discovered {} drivers across {} target(s)",
        rules.len(),
        targets.len()
    ));
    ui::info("fuzzing with 1 core");
    if let Err(e) = std::fs::create_dir_all(&cfg.solutions_dir) {
        ui::warn(&format!(
            "could not create solutions dir {}: {e}",
            cfg.solutions_dir
        ));
    } else {
        ui::info(&format!("saving reproducers to {}", cfg.solutions_dir));
    }

    let mut cov = CoverageMap::new();
    let mut corpus = Corpus::new(cfg.cache_budget);
    corpus.seed(&ready);

    let stats = Arc::new(Stats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let monitor_handle = {
        let stats = Arc::clone(&stats);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || monitor(stats, stop))
    };

    ui::spinner_start();
    fuzz_loop(
        &ready,
        &rules,
        &cfg,
        freq,
        ready_vt_secs,
        &sink,
        &mut cov,
        &mut corpus,
        &stats,
    );
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

    #[test]
    fn singleton_batch_collapses_to_one_and_normal_batches_pass_through() {
        let rule = |name: &str| Rule {
            target: BashTarget::host(),
            name: name.to_string(),
            singleton: name.starts_with(SINGLETON_PREFIX),
        };
        let rules = vec![rule("drv_a"), rule("singleton_mptest"), rule("drv_b")];

        // A batch naming a singleton collapses to that lone singleton, alone, and
        // is flagged terminal.
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
        assert!(is_singleton_step(&mixed, &rules));
        let (eff, is_s) = effective_batch(&mixed, &rules);
        assert!(is_s);
        assert_eq!(eff.len(), 1, "only the singleton runs");
        assert_eq!(eff[0].driver, 1);
        assert_eq!(eff[0].offset, 5, "the singleton's own offset is kept");

        // An all-normal batch runs unchanged and is not a singleton step.
        let normal = vec![
            Member {
                driver: 0,
                offset: 0,
            },
            Member {
                driver: 2,
                offset: 3,
            },
        ];
        assert!(!is_singleton_step(&normal, &rules));
        let (eff, is_s) = effective_batch(&normal, &rules);
        assert!(!is_s);
        assert_eq!(eff, normal);
    }

    #[test]
    fn saves_reproducer_json_and_serial_log() {
        let dir = std::env::temp_dir().join("lonepine-save-test");
        let dir = dir.to_str().unwrap();
        let _ = std::fs::remove_dir_all(dir);

        let rules = vec![
            Rule {
                target: BashTarget::host(),
                name: "drv-a".to_string(),
                singleton: false,
            },
            Rule {
                target: BashTarget::host(),
                name: "drv-b".to_string(),
                singleton: false,
            },
        ];
        let mut plan = Plan::empty(rules.len());
        plan.steps.push(Step {
            batch: vec![Member {
                driver: 1,
                offset: 42,
            }],
            rng: vec![1, 2, 3],
            rand: vec![4, 5, 6],
        });
        let finding = Finding::Assertion {
            step: 0,
            message: "boom".to_string(),
        };

        let path = save_solution(
            dir,
            "crash-7.json",
            7,
            &finding,
            "boom",
            99,
            12.5,
            &plan,
            &rules,
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["bug"].as_u64(), Some(7));
        assert_eq!(v["kind"].as_str(), Some("assertion"));
        assert_eq!(v["reason"].as_str(), Some("boom"));
        assert_eq!(v["steps"][0]["batch"][0]["name"].as_str(), Some("drv-b"));
        assert_eq!(v["steps"][0]["batch"][0]["offset"].as_i64(), Some(42));
        assert_eq!(v["steps"][0]["rng"][2].as_u64(), Some(3));
        assert_eq!(v["steps"][0]["rand"][0].as_u64(), Some(4));

        let log = save_serial(dir, "crash-7.log", &["l1".to_string(), "l2".to_string()]).unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "l1\nl2");

        let _ = std::fs::remove_dir_all(dir);
    }
}

// SPDX-License-Identifier: GPL-2.0

//! Per-driver determinism checker for a bedrock workload.
//!
//! Boots a guest, waits for the ready hypercall, takes a checkpoint, then runs
//! *every* driver the workload advertises under `/opt/bedrock/drivers/` `--runs`
//! times each, fanning the work out across `--cores` threads. Every run forks a
//! fresh branch from the shared checkpoint, so all runs of a driver start from
//! byte-identical guest state. A run's deterministic exit stream is reduced to a
//! 64-bit fingerprint (the same `LogEntry` fields the standalone
//! `bedrock-determinism` tool diffs); if a driver's runs don't all produce the
//! same fingerprint, the driver behaved non-deterministically and is reported.
//!
//! Run with:
//!
//! ```text
//! cargo run -p bedrock-lab --example lab_determinism_check -- \
//!     <vmlinux> <initramfs> --runs 5 --cores 8
//! ```
//!
//! Requires the guest to load `bedrock-io.ko` and issue the ready hypercall
//! before the deadline, and a workload that ships executables under
//! `/opt/bedrock/drivers/` (e.g. the `syzkaller` workload).
//!
//! Caveat: each driver run uses the blocking `Branch::bash` call, which has
//! no per-command deadline — a driver that hangs the guest will block its
//! worker thread indefinitely. Use `--limit`/`--container` to scope a run, or
//! a guest whose drivers are known to terminate.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bedrock_lab::{
    BashTarget, BranchId, Checkpoint, Event, EventSink, LabError, LabOpts, LogConfig, LogEntry,
    RngMode, VirtDuration, VirtTime, WorkloadDriver,
};
use bedrock_vm::{boot::defaults, load_kernel, LinuxBootConfig, VmBuilder};
use clap::Parser;

const BOOT_RNG_SEED: u64 = 0xbed0_0001;
/// Number of lock shards in the fingerprint sink. Branches hash into
/// `branch_id % SHARDS`, so concurrent runs on different branches rarely
/// contend on the same lock.
const SHARDS: usize = 64;

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let cores = args.cores.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    if args.runs < 2 {
        return Err("--runs must be at least 2 (determinism needs runs to compare)".into());
    }

    // ── Boot ──────────────────────────────────────────────────────────────
    let mut vm = VmBuilder::new().memory_mb(args.memory_mb).build()?;
    let kernel = fs::read(&args.vmlinux)?;
    let initramfs = fs::read(&args.initramfs)?;
    let (kernel_entry, kernel_end) = {
        let memory = vm.memory_mut()?;
        load_kernel(memory, &kernel)?
    };
    let mut boot = LinuxBootConfig::new(kernel_entry, kernel_end).cmdline(defaults::CMDLINE);
    boot = boot.initramfs(&initramfs);
    vm.setup_linux_boot(&boot)?;

    let sink = Arc::new(FingerprintSink::new(args.verbose));
    let freq = bedrock_vm::DEFAULT_TSC_FREQUENCY;

    eprintln!(
        "booting; waiting up to {}s for ready...",
        args.ready_deadline
    );
    let ready_cp = Checkpoint::initial_when_ready_with(
        vm,
        VirtTime::from_secs(args.ready_deadline, freq),
        LabOpts {
            sink: sink.clone(),
            rng: RngMode::Seeded(BOOT_RNG_SEED),
            ..Default::default()
        },
    )?;
    eprintln!(
        "ready at {:.3}s (checkpoint {:?})",
        ready_cp.time().as_secs_f64(),
        ready_cp.id()
    );

    // Let the workload settle for a moment past ready, then re-checkpoint.
    // Every driver run forks from this `base_cp`, so the captured exit window
    // is just the driver's own execution — not the ready-handshake tail.
    let settle = VirtDuration::from_secs(args.settle, freq);
    let mut idle = ready_cp.branch()?;
    idle.run_until(ready_cp.time() + settle)?;
    let base_cp = idle.checkpoint()?;
    eprintln!(
        "settled to base checkpoint at {:.3}s",
        base_cp.time().as_secs_f64()
    );

    // ── Enumerate drivers ─────────────────────────────────────────────────
    // Probe branch is dropped at the end of this block, freeing its
    // live-branch slot before the fan-out forks hundreds more.
    let mut drivers = {
        let mut probe = base_cp.branch()?;
        probe.workload_details()?
    };
    if let Some(filter) = &args.container {
        drivers.retain(|d| &d.container == filter);
    }
    if let Some(limit) = args.limit {
        drivers.truncate(limit);
    }
    if drivers.is_empty() {
        return Err("no drivers found in workload (is /opt/bedrock/drivers/ populated?)".into());
    }
    eprintln!(
        "found {} driver(s); running each {} time(s) across {} core(s)\n",
        drivers.len(),
        args.runs,
        cores
    );

    // ── Fan out: one work item per driver, N runs each ────────────────────
    let cursor = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let reports: Mutex<Vec<DriverReport>> = Mutex::new(Vec::new());
    let total = drivers.len();
    let log_config = if args.no_memory_hash {
        LogConfig::all_exits(0).with_no_memory_hash()
    } else {
        LogConfig::all_exits(0)
    };

    std::thread::scope(|scope| {
        for _ in 0..cores {
            scope.spawn(|| loop {
                let i = cursor.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    break;
                }
                let driver = &drivers[i];
                let report = check_driver(&base_cp, driver, args.runs, &log_config, &sink);
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                if report.is_nondeterministic() {
                    eprintln!(
                        "  [{n}/{total}] NON-DETERMINISTIC  {}::{}",
                        driver.container, driver.driver
                    );
                } else if let Some(err) = &report.error {
                    eprintln!(
                        "  [{n}/{total}] error  {}::{}  ({err})",
                        driver.container, driver.driver
                    );
                } else if args.verbose {
                    eprintln!(
                        "  [{n}/{total}] ok  {}::{}",
                        driver.container, driver.driver
                    );
                }
                reports.lock().unwrap().push(report);
            });
        }
    });

    // ── Report ────────────────────────────────────────────────────────────
    let mut reports = reports.into_inner().unwrap();
    reports.sort_by(|a, b| (&a.container, &a.driver).cmp(&(&b.container, &b.driver)));

    let nondeterministic: Vec<&DriverReport> =
        reports.iter().filter(|r| r.is_nondeterministic()).collect();
    let errored: Vec<&DriverReport> = reports
        .iter()
        .filter(|r| r.error.is_some() && !r.is_nondeterministic())
        .collect();
    let ok = reports.len() - nondeterministic.len() - errored.len();

    println!("\n{}", "=".repeat(64));
    println!(
        "determinism report: {} driver(s), {} run(s) each",
        reports.len(),
        args.runs
    );
    println!("{}", "=".repeat(64));
    println!("  deterministic:      {ok}");
    println!("  NON-deterministic:  {}", nondeterministic.len());
    println!("  errored:            {}", errored.len());

    if !nondeterministic.is_empty() {
        println!("\nnon-deterministic drivers:");
        for r in &nondeterministic {
            println!("  {}::{}", r.container, r.driver);
            for (idx, sig) in r.signatures.iter().enumerate() {
                println!(
                    "      run {idx}: fp={:#018x} status={} exit={} determ_exits={}",
                    sig.fingerprint, sig.status, sig.exit_code, sig.determ_exits
                );
            }
        }
    }
    if !errored.is_empty() {
        println!("\nerrored drivers:");
        for r in &errored {
            println!(
                "  {}::{}  ({})",
                r.container,
                r.driver,
                r.error.as_deref().unwrap_or("unknown")
            );
        }
    }

    // Non-zero exit when any driver diverged, so this doubles as a test gate.
    if nondeterministic.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} driver(s) behaved non-deterministically",
            nondeterministic.len()
        )
        .into())
    }
}

/// Run one driver `runs` times from `base_cp` and decide whether all runs
/// produced an identical deterministic signature.
fn check_driver(
    base_cp: &Checkpoint,
    driver: &WorkloadDriver,
    runs: u32,
    log_config: &LogConfig,
    sink: &FingerprintSink,
) -> DriverReport {
    let mut signatures = Vec::with_capacity(runs as usize);
    let mut error = None;
    for _ in 0..runs {
        match run_once(base_cp, driver, log_config, sink) {
            Ok(sig) => signatures.push(sig),
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
    }
    DriverReport {
        container: driver.container.clone(),
        driver: driver.driver.clone(),
        signatures,
        error,
    }
}

/// Fork a fresh branch, enable exit logging, run the driver to completion, and
/// return the run's deterministic signature.
fn run_once(
    base_cp: &Checkpoint,
    driver: &WorkloadDriver,
    log_config: &LogConfig,
    sink: &FingerprintSink,
) -> Result<RunSig, LabError> {
    let mut branch = base_cp.branch()?;
    branch.set_log_config(*log_config)?;
    let id = branch.id();
    let out = branch.bash(BashTarget::container(&driver.container), &driver.driver)?;
    let (fingerprint, determ_exits) = sink.take(id);
    // `branch` drops here, freeing its forked VM and live-branch slot.
    Ok(RunSig {
        fingerprint,
        determ_exits,
        status: out.status,
        exit_code: out.exit_code,
    })
}

/// The deterministic signature of a single driver run. Two runs are considered
/// to match iff every field here is equal — the fingerprint folds the guest
/// register + device-hash + memory-hash state of every deterministic exit, and
/// the status/exit/count fields catch coarser divergence the fold might miss.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RunSig {
    fingerprint: u64,
    determ_exits: u64,
    status: i32,
    exit_code: i32,
}

struct DriverReport {
    container: String,
    driver: String,
    /// One signature per completed run. Shorter than `runs` only if a run
    /// errored (then `error` is set and we stop early).
    signatures: Vec<RunSig>,
    error: Option<String>,
}

impl DriverReport {
    /// True if the runs completed but disagreed. An errored driver (fewer than
    /// 2 signatures) is reported separately, not as non-determinism.
    fn is_nondeterministic(&self) -> bool {
        self.signatures.len() >= 2 && self.signatures.iter().any(|s| *s != self.signatures[0])
    }
}

// ── Fingerprint sink ───────────────────────────────────────────────────────

/// Per-branch accumulator: a rolling FNV-1a hash over the compared fields of
/// each deterministic exit, plus a count of how many such exits were folded.
#[derive(Clone, Copy)]
struct RunAcc {
    hash: u64,
    determ_exits: u64,
}

impl Default for RunAcc {
    fn default() -> Self {
        Self {
            hash: FNV_OFFSET,
            determ_exits: 0,
        }
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[inline]
fn fnv_fold(mut h: u64, v: u64) -> u64 {
    for b in v.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Folds a deterministic `LogEntry`'s stable fields into a hash. Mirrors the
/// field set `bedrock-determinism`'s `compare_logs` diffs, so this fingerprint
/// diverges exactly when that tool would report a divergence. PEBS/internal
/// diagnostic fields are excluded — they drift by design even between
/// deterministic runs.
fn fold_entry(mut h: u64, e: &LogEntry) -> u64 {
    for v in [
        e.exit_reason as u64,
        e.tsc,
        e.rip,
        e.rflags,
        e.rax,
        e.rcx,
        e.rdx,
        e.rbx,
        e.rsp,
        e.rbp,
        e.rsi,
        e.rdi,
        e.r8,
        e.r9,
        e.r10,
        e.r11,
        e.r12,
        e.r13,
        e.r14,
        e.r15,
        e.memory_hash,
        e.apic_hash,
        e.serial_hash,
        e.ioapic_hash,
        e.rtc_hash,
        e.mtrr_hash,
        e.rdrand_hash,
        e.fs_base,
        e.gs_base,
        e.kernel_gs_base,
        e.cr3,
        e.cs_base,
        e.ds_base,
        e.es_base,
        e.ss_base,
        e.pending_dbg_exceptions,
        e.interruptibility_state as u64,
        e.cow_page_count as u64,
    ] {
        h = fnv_fold(h, v);
    }
    h
}

/// An [`EventSink`] that accumulates a per-branch deterministic-exit
/// fingerprint. Sharded so concurrent driver runs on different branches don't
/// serialize on a single lock.
struct FingerprintSink {
    shards: Vec<Mutex<HashMap<BranchId, RunAcc>>>,
    verbose: bool,
}

impl FingerprintSink {
    fn new(verbose: bool) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            verbose,
        }
    }

    fn shard(&self, branch: BranchId) -> &Mutex<HashMap<BranchId, RunAcc>> {
        // BranchId's inner u64 is private to the lab crate, so derive a shard
        // index from its Hash impl instead of the raw value.
        let mut h = std::collections::hash_map::DefaultHasher::new();
        branch.hash(&mut h);
        &self.shards[(h.finish() as usize) % SHARDS]
    }

    /// Remove and return a branch's accumulated `(fingerprint, determ_exits)`.
    /// Returns the empty-fold default if the branch logged no exits.
    fn take(&self, branch: BranchId) -> (u64, u64) {
        let acc = self
            .shard(branch)
            .lock()
            .unwrap()
            .remove(&branch)
            .unwrap_or_default();
        (acc.hash, acc.determ_exits)
    }
}

impl EventSink for FingerprintSink {
    fn on_event(&self, event: Event<'_>) {
        match event {
            Event::ExitLogged { branch, entry } => {
                if !entry.is_deterministic() {
                    return;
                }
                let mut g = self.shard(branch).lock().unwrap();
                let acc = g.entry(branch).or_default();
                acc.hash = fold_entry(acc.hash, entry);
                acc.determ_exits += 1;
            }
            Event::SerialLine { branch, at, line } if self.verbose => {
                eprintln!(
                    "[br {branch:?} vt {:>8.3}] {}",
                    at.as_secs_f64(),
                    String::from_utf8_lossy(line)
                );
            }
            _ => {}
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "lab_determinism_check")]
#[command(about = "Run every workload driver N times and report non-deterministic ones")]
struct Args {
    /// Path to the vmlinux ELF image.
    vmlinux: String,

    /// Path to an initramfs/initrd image.
    initramfs: String,

    /// Times to run each driver. Must be >= 2.
    #[arg(short = 'n', long, default_value_t = 3)]
    runs: u32,

    /// Parallel worker threads (default: available CPU parallelism). Each
    /// worker holds one forked VM at a time.
    #[arg(long)]
    cores: Option<usize>,

    /// Guest memory size in MB.
    #[arg(short = 'm', long, default_value_t = 5120)]
    memory_mb: usize,

    /// Virtual-time budget (seconds) for the guest to reach the ready
    /// hypercall.
    #[arg(long, default_value_t = 600)]
    ready_deadline: u64,

    /// Virtual-time (seconds) to advance past ready before checkpointing, to
    /// let the workload's containers settle.
    #[arg(long, default_value_t = 1)]
    settle: u64,

    /// Only check drivers in this container.
    #[arg(long)]
    container: Option<String>,

    /// Check at most this many drivers (after any --container filter).
    #[arg(long)]
    limit: Option<usize>,

    /// Skip memory hashing in the fingerprint (faster; loses detection of
    /// silent guest-memory divergence that doesn't surface in registers).
    #[arg(long)]
    no_memory_hash: bool,

    /// Print serial output and per-driver ok lines.
    #[arg(short, long)]
    verbose: bool,
}

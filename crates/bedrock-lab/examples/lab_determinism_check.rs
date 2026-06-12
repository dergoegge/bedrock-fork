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
//! Pass `--driver <substring>` for detail mode: instead of sweeping every
//! driver, it focuses on the single matching driver, runs it `--runs` times,
//! and diffs each completed run's exit stream against the first — reporting the
//! exact exit index, TSC, exit reason, and differing register/device fields
//! where non-determinism first appears. Use a high `--runs` for rare flakes.
//!
//! Pass `--save-dir <DIR>` to additionally capture raw artifacts for every
//! problematic (non-deterministic or not-checked) driver: a second pass
//! re-runs just those drivers and streams each run's `exit-log.jsonl` (the raw
//! `LogEntry` stream) and `serial.txt` into
//! `<DIR>/<container>__<driver>/run-NN/`, alongside a `summary.txt`.
//!
//! Requires the guest to load `bedrock-io.ko` and issue the ready hypercall
//! before the deadline, and a workload that ships executables under
//! `/opt/bedrock/drivers/` (e.g. the `syzkaller` workload).
//!
//! Each driver run is bounded two ways so a hang can't wedge its worker:
//! `--run-deadline-secs` of guest virtual time (default 60s) and
//! `--run-wall-timeout-secs` of real time (default 360s). The vt limit catches
//! idle/blocking hangs (the emulated TSC fast-forwards through idle) and most
//! busy loops; the wall limit is the backstop for a busy loop whose vt budget
//! takes too long to actually execute. Either is disabled by passing 0.

use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bedrock_lab::{
    ActionResponse, BashOutput, BashTarget, Branch, BranchId, Checkpoint, Event, EventSink,
    LabError, LabOpts, LogConfig, LogEntry, RngMode, RunOutcome, VirtDuration, VirtTime,
    WorkloadDriver,
};
use bedrock_vm::{boot::defaults, load_kernel, write_jsonl, ExitKind, LinuxBootConfig, VmBuilder};
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
    if args.single_step.is_some() && args.driver.is_none() {
        return Err("--single-step requires --driver (it's a detail-mode tool)".into());
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

    let sink = Arc::new(FingerprintSink::new(args.verbose, args.save_max_entries));
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
    // Boot log is done; go quiet for the fan-out unless --verbose.
    sink.end_boot();

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

    let log_config = if args.no_memory_hash {
        LogConfig::all_exits(0).with_no_memory_hash()
    } else {
        LogConfig::all_exits(0)
    };

    // ── Detail mode: focus on a single driver, diffing run streams ────────
    if let Some(want) = &args.driver {
        let matches: Vec<WorkloadDriver> = drivers
            .iter()
            .filter(|d| d.driver.contains(want.as_str()))
            .cloned()
            .collect();
        return match matches.len() {
            0 => Err(format!("--driver {want:?} matched no driver").into()),
            1 => run_detail(
                &base_cp,
                &matches[0],
                args.runs,
                cores,
                args.run_deadline_secs,
                args.run_wall_timeout_secs,
                &log_config,
                args.single_step,
                args.no_memory_hash,
                sink.as_ref(),
            ),
            n => Err(format!("--driver {want:?} matched {n} drivers; be more specific").into()),
        };
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

    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..cores {
            scope.spawn(|| loop {
                let i = cursor.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    break;
                }
                let driver = &drivers[i];
                let report = check_driver(
                    &base_cp,
                    driver,
                    args.runs,
                    args.run_deadline_secs,
                    args.run_wall_timeout_secs,
                    &log_config,
                    &sink,
                );
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                let name = format!("{}::{}", driver.container, short_driver(&driver.driver));
                if report.is_nondeterministic() {
                    eprintln!("  [{n}/{total}] NON-DETERMINISTIC  {name}");
                } else if let Some(nc) = &report.not_checked {
                    eprintln!("  [{n}/{total}] not checked  {name}  ({})", nc.category().0);
                } else if args.verbose {
                    eprintln!("  [{n}/{total}] ok  {name}");
                }
                reports.lock().unwrap().push(report);
            });
        }
    });
    let elapsed = started.elapsed();

    // ── Report ────────────────────────────────────────────────────────────
    let mut reports = reports.into_inner().unwrap();
    reports.sort_by(|a, b| (&a.container, &a.driver).cmp(&(&b.container, &b.driver)));

    let nondeterministic: Vec<&DriverReport> =
        reports.iter().filter(|r| r.is_nondeterministic()).collect();
    let not_checked: Vec<&DriverReport> = reports
        .iter()
        .filter(|r| r.not_checked.is_some() && !r.is_nondeterministic())
        .collect();
    let reproduced = reports.len() - nondeterministic.len() - not_checked.len();
    let checked = reproduced + nondeterministic.len();

    let bar = "═".repeat(70);
    println!("\n{bar}");
    println!(" Determinism check");
    println!("{bar}");
    println!(
        "  drivers        {}   ({} run(s) each, {}, {} core(s), {:.1}s)",
        reports.len(),
        args.runs,
        if args.no_memory_hash {
            "no memory hash"
        } else {
            "memory hash on"
        },
        cores,
        elapsed.as_secs_f64(),
    );
    println!("  reproduced     {reproduced}   (identical across all runs)");
    println!("  DIVERGENT      {}", nondeterministic.len());
    println!(
        "  not checked    {}   (no comparable result)",
        not_checked.len()
    );

    // Headline verdict — the one line a reader should be able to act on.
    println!("\n{bar}");
    if nondeterministic.is_empty() {
        if checked == 0 {
            println!(" VERDICT: ⚠ no driver could be checked (see causes below)");
        } else {
            println!(" VERDICT: ✓ all {checked} checked driver(s) were deterministic");
        }
    } else {
        println!(
            " VERDICT: ✗ {} of {checked} checked driver(s) behaved NON-deterministically",
            nondeterministic.len()
        );
    }
    println!("{bar}");

    if !nondeterministic.is_empty() {
        println!("\nNON-deterministic drivers — runs disagreed:");
        for r in &nondeterministic {
            println!("  {}::{}", r.container, short_driver(&r.driver));
            for (idx, sig) in r.signatures.iter().enumerate() {
                println!(
                    "      run {idx}: fp={:#018x} status={} exit={} determ_exits={}",
                    sig.fingerprint, sig.status, sig.exit_code, sig.determ_exits
                );
            }
        }
    }

    if !not_checked.is_empty() {
        // Group by cause so a reader sees "12 hang, 4 unhandled MSR read"
        // rather than 16 near-identical raw error lines.
        let mut groups: BTreeMap<String, (&'static str, Vec<&DriverReport>)> = BTreeMap::new();
        for r in &not_checked {
            let (label, explain) = r.not_checked.as_ref().unwrap().category();
            groups
                .entry(label)
                .or_insert((explain, Vec::new()))
                .1
                .push(r);
        }
        println!("\nNot checked ({}) — grouped by cause:", not_checked.len());
        for (label, (explain, group)) in &groups {
            println!("\n  [{}] {label}", group.len());
            println!("      {explain}");
            for r in group {
                let at = r
                    .not_checked
                    .as_ref()
                    .unwrap()
                    .at
                    .map(|t| format!(" (vt {:.1}s)", t.as_secs_f64()))
                    .unwrap_or_default();
                println!("      {}::{}{at}", r.container, short_driver(&r.driver));
            }
        }
    }

    // ── Save artifacts for problematic drivers (second pass) ──────────────
    // Re-run each non-deterministic or not-checked driver, streaming its raw
    // exit log + serial output to disk. The detection pass stays fast/light;
    // only the few problematic drivers pay for capture, and re-running them
    // reproduces the same forks deterministically.
    if let Some(save_dir) = &args.save_dir {
        let problematic: Vec<&DriverReport> = reports
            .iter()
            .filter(|r| r.is_nondeterministic() || r.not_checked.is_some())
            .collect();
        if problematic.is_empty() {
            println!("\nnothing problematic to save to {save_dir}.");
        } else {
            println!(
                "\nsaving artifacts for {} problematic driver(s) to {save_dir}/ ...",
                problematic.len()
            );
            sink.set_capturing(true);
            for r in &problematic {
                if let Err(e) = save_driver_artifacts(
                    &base_cp,
                    r,
                    args.runs,
                    args.run_deadline_secs,
                    args.run_wall_timeout_secs,
                    &log_config,
                    &sink,
                    save_dir,
                ) {
                    eprintln!(
                        "  warn: failed to save {}::{}: {e}",
                        r.container,
                        short_driver(&r.driver)
                    );
                }
            }
            sink.set_capturing(false);
            println!("artifacts saved under {save_dir}/");
        }
    }

    // Non-zero exit when any driver diverged, so this doubles as a test gate.
    // Not-checked drivers don't fail the gate — they're inconclusive, not
    // divergent — but the verdict line makes their count visible.
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

/// Trim the `/opt/bedrock/drivers/` prefix for compact display; the basename
/// (e.g. `syz-<hash>`) is already unique.
fn short_driver(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Parse a `START-END` emulated-TSC instruction range for `--single-step`.
fn parse_tsc_range(s: &str) -> Result<(u64, u64), String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("expected START-END, got {s:?}"))?;
    let start: u64 = a.trim().parse().map_err(|_| format!("bad START: {a:?}"))?;
    let end: u64 = b.trim().parse().map_err(|_| format!("bad END: {b:?}"))?;
    if end <= start {
        return Err(format!("END ({end}) must be > START ({start})"));
    }
    Ok((start, end))
}

/// Run one driver `runs` times from `base_cp` and decide whether all runs
/// produced an identical deterministic signature.
fn check_driver(
    base_cp: &Checkpoint,
    driver: &WorkloadDriver,
    runs: u32,
    vt_deadline_secs: f64,
    wall_timeout_secs: f64,
    log_config: &LogConfig,
    sink: &FingerprintSink,
) -> DriverReport {
    let mut signatures = Vec::with_capacity(runs as usize);
    let mut not_checked = None;
    for _ in 0..runs {
        match run_once(
            base_cp,
            driver,
            vt_deadline_secs,
            wall_timeout_secs,
            log_config,
            sink,
        ) {
            Ok(RunResult::Completed(sig)) => signatures.push(sig),
            Ok(RunResult::TimedOut { at, reason }) => {
                not_checked = Some(NotChecked {
                    at: Some(at),
                    reason,
                });
                break;
            }
            Err(e) => {
                not_checked = Some(NotChecked::classify(e));
                break;
            }
        }
    }
    DriverReport {
        container: driver.container.clone(),
        driver: driver.driver.clone(),
        signatures,
        not_checked,
    }
}

/// Outcome of a single driver run: either it replied (a comparable signature)
/// or it hit a timeout (virtual-time or wall-clock) without replying.
enum RunResult {
    Completed(RunSig),
    TimedOut {
        at: VirtTime,
        reason: NotCheckedReason,
    },
}

/// Fork a fresh branch, enable exit logging, drive the driver under both the
/// virtual-time and wall-clock bounds, and return its signature or a timeout.
fn run_once(
    base_cp: &Checkpoint,
    driver: &WorkloadDriver,
    vt_deadline_secs: f64,
    wall_timeout_secs: f64,
    log_config: &LogConfig,
    sink: &FingerprintSink,
) -> Result<RunResult, LabError> {
    let mut branch = base_cp.branch()?;
    branch.set_log_config(*log_config)?;
    let id = branch.id();

    let outcome = drive_bounded(
        &mut branch,
        &driver.container,
        &driver.driver,
        vt_deadline_secs,
        wall_timeout_secs,
    );
    let (fingerprint, determ_exits) = sink.take(id);
    match outcome? {
        DriveOutcome::Replied(out) => Ok(RunResult::Completed(RunSig {
            fingerprint,
            determ_exits,
            status: out.status,
            exit_code: out.exit_code,
        })),
        DriveOutcome::VtTimeout(at) => Ok(RunResult::TimedOut {
            at,
            reason: NotCheckedReason::TimedOut,
        }),
        DriveOutcome::WallTimeout(at) => Ok(RunResult::TimedOut {
            at,
            reason: NotCheckedReason::WallTimedOut,
        }),
        DriveOutcome::Unexpected { at, kind } => Err(LabError::UnexpectedExit { at, kind }),
    }
}

/// Virtual-time slice between wall-clock checks while driving a bounded run.
/// Small enough that a busy loop can't overshoot the wall budget by much,
/// large enough that idle fast-forward stays cheap.
const DRIVE_CHUNK_VT_SECS: f64 = 5.0;

/// Outcome of driving a single scheduled driver to completion or a bound.
enum DriveOutcome {
    Replied(BashOutput),
    VtTimeout(VirtTime),
    WallTimeout(VirtTime),
    Unexpected { at: VirtTime, kind: ExitKind },
}

/// Schedule `driver` in `container` and pump `branch` until it replies, hits
/// the virtual-time deadline (`vt_secs`), hits the wall-clock timeout
/// (`wall_secs`), or yields an unhandled exit. A bound `<= 0` is disabled.
///
/// The vt bound alone stops idle hangs (emulated TSC fast-forwards) and
/// busy loops (`run_until` stops at the target TSC); the wall bound is the
/// backstop for a busy loop whose vt budget is large enough to take real time.
/// We pump in `DRIVE_CHUNK_VT_SECS` slices and check the wall clock between
/// them, since a single `run_until` can't be interrupted mid-ioctl.
fn drive_bounded(
    branch: &mut Branch,
    container: &str,
    driver: &str,
    vt_secs: f64,
    wall_secs: f64,
) -> Result<DriveOutcome, LabError> {
    let freq = bedrock_vm::DEFAULT_TSC_FREQUENCY;

    // Fully unbounded: just block on bash (may never return for a hang).
    if vt_secs <= 0.0 && wall_secs <= 0.0 {
        return match branch.bash(BashTarget::container(container), driver) {
            Ok(out) => Ok(DriveOutcome::Replied(out)),
            Err(LabError::UnexpectedExit { at, kind }) => Ok(DriveOutcome::Unexpected { at, kind }),
            Err(e) => Err(e),
        };
    }

    let start = branch.current_time();
    let vt_deadline = (vt_secs > 0.0).then(|| start + VirtDuration::from_secs_f64(vt_secs, freq));
    let chunk = VirtDuration::from_secs_f64(DRIVE_CHUNK_VT_SECS, freq);
    let wall_start = Instant::now();

    branch.sched_bash(
        VirtTime::from_secs(0, freq), // 0 == "as soon as the guest is interruptible"
        BashTarget::container(container),
        driver,
    )?;

    loop {
        // Next chunk target, capped at the vt deadline if one is set.
        let mut target = branch.current_time() + chunk;
        if let Some(d) = vt_deadline {
            if target > d {
                target = d;
            }
        }
        let (at, outcome) = branch.run_until(target)?;
        match outcome {
            RunOutcome::ActionResponse {
                response: ActionResponse::Bash(out),
            } => return Ok(DriveOutcome::Replied(out)),
            // A non-bash response or a Ready shouldn't arrive for a driver
            // exec; keep pumping.
            RunOutcome::ActionResponse { .. } | RunOutcome::Ready => continue,
            RunOutcome::RngExhausted => {
                return Ok(DriveOutcome::Unexpected {
                    at,
                    kind: ExitKind::UnhandledExit { reason: 0 },
                })
            }
            RunOutcome::Yielded { kind } => return Ok(DriveOutcome::Unexpected { at, kind }),
            RunOutcome::ReachedTime => {
                if vt_deadline.is_some_and(|d| at >= d) {
                    return Ok(DriveOutcome::VtTimeout(at));
                }
                if wall_secs > 0.0 && wall_start.elapsed().as_secs_f64() >= wall_secs {
                    return Ok(DriveOutcome::WallTimeout(at));
                }
                continue; // next chunk
            }
        }
    }
}

/// A point where two runs' exit streams first differ.
struct Divergence {
    /// Index of the first differing exit (or the shorter length on a count
    /// mismatch).
    index: usize,
    /// The reference and divergent entries at `index` (None on a count
    /// mismatch, where there's no aligned pair).
    entries: Option<(LogEntry, LogEntry)>,
    /// Differing fields at `index`: (name, reference value, run value).
    field_diffs: Vec<(&'static str, u64, u64)>,
    /// `Some((ref_len, run_len))` if the streams had different lengths.
    len_mismatch: Option<(usize, usize)>,
}

/// Fields compared between two aligned exits — the same set `fold_entry` folds,
/// so an entry-level diff appears exactly when the fingerprint would differ.
fn entry_field_diffs(a: &LogEntry, b: &LogEntry) -> Vec<(&'static str, u64, u64)> {
    let mut d = Vec::new();
    macro_rules! cmp {
        ($f:ident) => {
            if a.$f as u64 != b.$f as u64 {
                d.push((stringify!($f), a.$f as u64, b.$f as u64));
            }
        };
    }
    cmp!(exit_reason);
    cmp!(tsc);
    cmp!(rip);
    cmp!(rflags);
    cmp!(rax);
    cmp!(rcx);
    cmp!(rdx);
    cmp!(rbx);
    cmp!(rsp);
    cmp!(rbp);
    cmp!(rsi);
    cmp!(rdi);
    cmp!(r8);
    cmp!(r9);
    cmp!(r10);
    cmp!(r11);
    cmp!(r12);
    cmp!(r13);
    cmp!(r14);
    cmp!(r15);
    cmp!(memory_hash);
    cmp!(apic_hash);
    cmp!(serial_hash);
    cmp!(ioapic_hash);
    cmp!(rtc_hash);
    cmp!(mtrr_hash);
    cmp!(rdrand_hash);
    cmp!(fs_base);
    cmp!(gs_base);
    cmp!(kernel_gs_base);
    cmp!(cr3);
    cmp!(cs_base);
    cmp!(ds_base);
    cmp!(es_base);
    cmp!(ss_base);
    cmp!(pending_dbg_exceptions);
    cmp!(interruptibility_state);
    cmp!(cow_page_count);
    d
}

/// First exit at which `run` diverges from `reference`, or `None` if identical.
fn first_divergence(reference: &[LogEntry], run: &[LogEntry]) -> Option<Divergence> {
    let n = reference.len().min(run.len());
    for i in 0..n {
        let field_diffs = entry_field_diffs(&reference[i], &run[i]);
        if !field_diffs.is_empty() {
            return Some(Divergence {
                index: i,
                entries: Some((reference[i], run[i])),
                field_diffs,
                len_mismatch: None,
            });
        }
    }
    if reference.len() != run.len() {
        return Some(Divergence {
            index: n,
            entries: None,
            field_diffs: Vec::new(),
            len_mismatch: Some((reference.len(), run.len())),
        });
    }
    None
}

/// Fork, drive the driver under both bounds, and return its outcome plus the
/// retained deterministic-exit stream (detail mode must be enabled on `sink`).
#[allow(clippy::too_many_arguments)]
fn detail_run(
    base_cp: &Checkpoint,
    driver: &WorkloadDriver,
    vt_deadline_secs: f64,
    wall_timeout_secs: f64,
    log_config: &LogConfig,
    single_step: Option<(u64, u64)>,
    sink: &FingerprintSink,
) -> Result<(DriveOutcome, Vec<LogEntry>), LabError> {
    let mut branch = base_cp.branch()?;
    // Single-step mode logs every instruction in the window (TscRange); plain
    // mode logs every deterministic exit.
    match single_step {
        Some((start, end)) => {
            let freq = bedrock_vm::DEFAULT_TSC_FREQUENCY;
            branch.single_step(
                VirtTime::from_instructions(start, freq),
                VirtTime::from_instructions(end, freq),
            )?;
        }
        None => branch.set_log_config(*log_config)?,
    }
    let id = branch.id();
    let outcome = drive_bounded(
        &mut branch,
        &driver.container,
        &driver.driver,
        vt_deadline_secs,
        wall_timeout_secs,
    );
    let (_, _, stream) = sink.take_run(id);
    Ok((outcome?, stream))
}

/// `--driver` detail mode: run one driver `runs` times, diffing each completed
/// run's exit stream against a reference to pinpoint the exact exit and fields
/// where non-determinism first appears.
///
/// The comparison runs fan out across `cores` threads — non-determinism here
/// can be host-concurrency-dependent (it surfaces under parallel VM load but
/// not in isolation), so reproducing it needs the same concurrency the bulk
/// sweep had. A reference is established sequentially first, then the rest run
/// in parallel, each diffing against that read-only reference.
#[allow(clippy::too_many_arguments)]
fn run_detail(
    base_cp: &Checkpoint,
    driver: &WorkloadDriver,
    runs: u32,
    cores: usize,
    vt_deadline_secs: f64,
    wall_timeout_secs: f64,
    log_config: &LogConfig,
    single_step: Option<(u64, u64)>,
    no_memory_hash: bool,
    sink: &FingerprintSink,
) -> Result<(), Box<dyn Error>> {
    sink.set_detail(true);
    let bar = "═".repeat(70);
    println!("\n{bar}");
    println!(" Detailed determinism check");
    println!("{bar}");
    println!("  driver:  {}::{}", driver.container, driver.driver);
    println!(
        "  runs:    {runs}   ({}, {cores} core(s), vt-limit {vt_deadline_secs}s, wall {wall_timeout_secs}s)",
        if no_memory_hash {
            "no memory hash"
        } else {
            "memory hash on"
        }
    );
    if let Some((s, e)) = single_step {
        println!("  single-step: instructions {s}..{e}  (per-instruction trace; exit indices are instructions in the window)");
    }
    let started = Instant::now();

    // Establish a reference from the first run that completes (a flaky driver
    // can occasionally time out; try a few times before giving up).
    let mut not_completed: Vec<(u32, NotChecked)> = Vec::new();
    let mut reference: Option<Vec<LogEntry>> = None;
    let mut ref_run = 0u32;
    let mut next_run = 0u32;
    let ref_attempts = runs.min(8);
    while next_run < ref_attempts {
        let run_idx = next_run;
        next_run += 1;
        let (outcome, stream) = detail_run(
            base_cp,
            driver,
            vt_deadline_secs,
            wall_timeout_secs,
            log_config,
            single_step,
            sink,
        )?;
        match outcome {
            DriveOutcome::Replied(_) => {
                ref_run = run_idx;
                reference = Some(stream);
                break;
            }
            other => not_completed.push((run_idx, drive_outcome_not_checked(other))),
        }
    }
    let Some(reference) = reference else {
        sink.set_detail(false);
        println!("\n  could not establish a reference: driver did not complete in {ref_attempts} attempt(s)");
        return Ok(());
    };
    let ref_len = reference.len();
    eprintln!(
        "  reference run {ref_run}: {ref_len} deterministic exits; fanning out remaining runs..."
    );

    // Remaining runs in parallel, each diffing against the read-only reference.
    let matched = AtomicUsize::new(0);
    let cursor = AtomicUsize::new(next_run as usize);
    let done = AtomicUsize::new(0);
    let divergences: Mutex<Vec<(u32, Divergence)>> = Mutex::new(Vec::new());
    let not_completed = Mutex::new(not_completed);
    let runs_usize = runs as usize;
    std::thread::scope(|scope| {
        for _ in 0..cores {
            scope.spawn(|| loop {
                let run_idx = cursor.fetch_add(1, Ordering::Relaxed);
                if run_idx >= runs_usize {
                    break;
                }
                let result = detail_run(
                    base_cp,
                    driver,
                    vt_deadline_secs,
                    wall_timeout_secs,
                    log_config,
                    single_step,
                    sink,
                );
                match result {
                    Ok((DriveOutcome::Replied(_), stream)) => {
                        match first_divergence(&reference, &stream) {
                            None => {
                                matched.fetch_add(1, Ordering::Relaxed);
                            }
                            Some(div) => {
                                divergences.lock().unwrap().push((run_idx as u32, div));
                            }
                        }
                    }
                    Ok((other, _)) => not_completed
                        .lock()
                        .unwrap()
                        .push((run_idx as u32, drive_outcome_not_checked(other))),
                    Err(e) => not_completed
                        .lock()
                        .unwrap()
                        .push((run_idx as u32, NotChecked::classify(e))),
                }
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                if d.is_multiple_of(50) {
                    eprintln!(
                        "  …{d} comparison runs ({} diverged)",
                        divergences.lock().unwrap().len()
                    );
                }
            });
        }
    });
    sink.set_detail(false);

    let mut divergences = divergences.into_inner().unwrap();
    divergences.sort_by_key(|(i, _)| *i);
    let mut not_completed = not_completed.into_inner().unwrap();
    not_completed.sort_by_key(|(i, _)| *i);
    let matched = matched.load(Ordering::Relaxed);
    let completed = 1 + matched + divergences.len();

    println!("\n  reference run:  {ref_run}  ({ref_len} deterministic exits)");
    println!("  completed:      {completed}/{runs}  (matched reference: {matched})");
    println!("  diverged:       {}", divergences.len());
    println!("  not completed:  {}", not_completed.len());

    println!("\n{bar}");
    if divergences.is_empty() {
        println!(" RESULT: ✓ no divergence reproduced in {runs} run(s)");
        println!("{bar}");
    } else {
        println!(
            " RESULT: ✗ {} of {completed} completed run(s) diverged from the reference",
            divergences.len()
        );
        println!("{bar}");
        report_divergences(&divergences, &reference);
    }

    if !not_completed.is_empty() {
        println!("\nnot-completed runs: {}", not_completed.len());
        for (run_idx, nc) in not_completed.iter().take(5) {
            let at = nc
                .at
                .map(|t| format!(" (vt {:.1}s)", t.as_secs_f64()))
                .unwrap_or_default();
            println!("  run {run_idx}: {}{at}", nc.category().0);
        }
        if not_completed.len() > 5 {
            println!("  … and {} more", not_completed.len() - 5);
        }
    }

    eprintln!(
        "\n(detail run took {:.1}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Map a non-`Replied` [`DriveOutcome`] to its [`NotChecked`] classification.
fn drive_outcome_not_checked(outcome: DriveOutcome) -> NotChecked {
    match outcome {
        DriveOutcome::VtTimeout(at) => NotChecked {
            at: Some(at),
            reason: NotCheckedReason::TimedOut,
        },
        DriveOutcome::WallTimeout(at) => NotChecked {
            at: Some(at),
            reason: NotCheckedReason::WallTimedOut,
        },
        DriveOutcome::Unexpected { at, kind } => {
            NotChecked::classify(LabError::UnexpectedExit { at, kind })
        }
        DriveOutcome::Replied(_) => NotChecked {
            at: None,
            reason: NotCheckedReason::Other("unexpected Replied".into()),
        },
    }
}

/// Print the first divergence in full detail, plus a one-line summary of any
/// others (where they diverged), so a reader can see the exact exit + fields.
fn report_divergences(divergences: &[(u32, Divergence)], reference: &[LogEntry]) {
    let (run_idx, div) = &divergences[0];
    if let Some((ref_len, run_len)) = div.len_mismatch {
        println!(
            "\nrun {run_idx}: exit-count mismatch — reference {ref_len} vs run {run_len} \
             (first {} exits matched)",
            div.index
        );
    } else if let Some((ref_e, _run_e)) = div.entries {
        let secs = ref_e.tsc as f64 / bedrock_vm::DEFAULT_TSC_FREQUENCY as f64;
        println!(
            "\nfirst divergence: run {run_idx}, exit #{} of {}",
            div.index,
            reference.len()
        );
        println!(
            "  at: tsc={} ({:.6}s)  reason={} ({})  rip={:#x}",
            ref_e.tsc,
            secs,
            exit_reason_name(ref_e.exit_reason),
            ref_e.exit_reason,
            ref_e.rip
        );
        println!("  differing fields (reference vs run {run_idx}):");
        for (f, av, bv) in &div.field_diffs {
            println!("    {f:<24} {av:#018x}  vs  {bv:#018x}");
        }
    }

    // Characterize the rest: do other divergent runs differ at the same exit?
    if divergences.len() > 1 {
        use std::collections::BTreeMap;
        let mut by_index: BTreeMap<usize, usize> = BTreeMap::new();
        for (_, d) in divergences {
            *by_index.entry(d.index).or_default() += 1;
        }
        println!(
            "\n  divergence exit-index distribution across {} divergent run(s):",
            divergences.len()
        );
        for (idx, count) in &by_index {
            println!("    exit #{idx}: {count} run(s)");
        }
    }
}

/// Re-run a problematic driver `runs` times, streaming each run's raw exit log
/// (`exit-log.jsonl`) and serial output (`serial.txt`) into
/// `<save_dir>/<container>__<driver>/run-NN/`, plus a `summary.txt` describing
/// why the driver was flagged. Requires the sink to be in capturing mode.
#[allow(clippy::too_many_arguments)]
fn save_driver_artifacts(
    base_cp: &Checkpoint,
    report: &DriverReport,
    runs: u32,
    vt_deadline_secs: f64,
    wall_timeout_secs: f64,
    log_config: &LogConfig,
    sink: &FingerprintSink,
    save_dir: &str,
) -> std::io::Result<()> {
    let ddir = Path::new(save_dir).join(format!(
        "{}__{}",
        report.container,
        short_driver(&report.driver)
    ));
    fs::create_dir_all(&ddir)?;
    write_artifact_summary(&ddir, report, runs)?;

    let to_io = |e: LabError| std::io::Error::other(e.to_string());
    for run_idx in 0..runs {
        let run_dir = ddir.join(format!("run-{run_idx:02}"));
        let mut branch = base_cp.branch().map_err(to_io)?;
        branch.set_log_config(*log_config).map_err(to_io)?;
        let id = branch.id();
        sink.start_capture(id, &run_dir)?;
        // Drive under the same bounds as detection, streaming every exit to the
        // capture file; any reply/timeout/unhandled-exit still leaves the
        // partial log, which is exactly what we want to save.
        let _ = drive_bounded(
            &mut branch,
            &report.container,
            &report.driver,
            vt_deadline_secs,
            wall_timeout_secs,
        );
        let (n, truncated) = sink.finish_capture(id);
        sink.take(id); // discard the fingerprint accumulator for this branch
        if truncated {
            eprintln!(
                "    note: {}::{} run-{run_idx:02} exit log truncated at {n} entries (--save-max-entries)",
                report.container,
                short_driver(&report.driver)
            );
        }
    }
    Ok(())
}

/// Write `summary.txt` describing why a driver was flagged and its detection
/// signatures, so each artifact folder is self-explanatory.
fn write_artifact_summary(ddir: &Path, report: &DriverReport, runs: u32) -> std::io::Result<()> {
    let mut f = BufWriter::new(File::create(ddir.join("summary.txt"))?);
    writeln!(f, "driver:  {}::{}", report.container, report.driver)?;
    if report.is_nondeterministic() {
        writeln!(f, "verdict: NON-DETERMINISTIC — detection runs disagreed")?;
        for (i, s) in report.signatures.iter().enumerate() {
            writeln!(
                f,
                "  detection run {i}: fp={:#018x} status={} exit={} determ_exits={}",
                s.fingerprint, s.status, s.exit_code, s.determ_exits
            )?;
        }
    } else if let Some(nc) = &report.not_checked {
        let (label, explain) = nc.category();
        writeln!(f, "verdict: NOT CHECKED — {label}")?;
        writeln!(f, "         {explain}")?;
        if let Some(at) = nc.at {
            writeln!(f, "         run gave up at vt {:.3}s", at.as_secs_f64())?;
        }
    }
    writeln!(f)?;
    writeln!(
        f,
        "{runs} fresh capture run(s) below; each run-NN/ holds exit-log.jsonl + serial.txt."
    )?;
    Ok(())
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
    /// failed to complete (then `not_checked` is set and we stop early).
    signatures: Vec<RunSig>,
    /// `Some` if a run never produced a comparable signature, so the driver
    /// couldn't be checked for determinism. Distinct from non-determinism.
    not_checked: Option<NotChecked>,
}

impl DriverReport {
    /// True if the runs completed but disagreed. A not-checked driver (fewer
    /// than 2 signatures) is reported separately, not as non-determinism.
    fn is_nondeterministic(&self) -> bool {
        self.signatures.len() >= 2 && self.signatures.iter().any(|s| *s != self.signatures[0])
    }
}

/// Why a driver couldn't be checked for determinism: a run failed to produce
/// a comparable signature. Captured structurally (not as a Debug string) so
/// the report can group identical causes and explain them.
struct NotChecked {
    /// Virtual time the run gave up at, if the failure carried one.
    at: Option<VirtTime>,
    reason: NotCheckedReason,
}

enum NotCheckedReason {
    /// The driver didn't reply within the per-run virtual-time deadline
    /// (`--run-deadline-secs`). Covers both blocking/idle hangs and CPU-bound
    /// busy loops.
    TimedOut,
    /// The run exceeded the per-run wall-clock timeout
    /// (`--run-wall-timeout-secs`) before reaching its vt deadline — a
    /// CPU-bound busy loop slow enough to burn real time.
    WallTimedOut,
    /// The VM issued the shutdown hypercall before the driver replied —
    /// typically the workload's own shutdown timer firing while the driver
    /// blocks/hangs and never returns (seen when the deadline is disabled).
    VmShutdown,
    /// The guest hit a VM exit the hypervisor doesn't emulate (e.g. an
    /// `RDMSR` on an unhandled MSR). Means "can't run here", not "divergent".
    UnhandledExit { reason: u32 },
    /// Some other lab error (VM ioctl failure, bad response, …).
    Other(String),
}

impl NotChecked {
    fn classify(e: LabError) -> Self {
        match e {
            LabError::UnexpectedExit { at, kind } => {
                let reason = match kind {
                    ExitKind::VmcallShutdown => NotCheckedReason::VmShutdown,
                    ExitKind::UnhandledExit { reason } => {
                        NotCheckedReason::UnhandledExit { reason }
                    }
                    other => NotCheckedReason::Other(format!("unexpected exit {other:?}")),
                };
                NotChecked {
                    at: Some(at),
                    reason,
                }
            }
            other => NotChecked {
                at: None,
                reason: NotCheckedReason::Other(other.to_string()),
            },
        }
    }

    /// A short, stable category label used to group identical causes, plus a
    /// one-line explanation of what the category means.
    fn category(&self) -> (String, &'static str) {
        match &self.reason {
            NotCheckedReason::TimedOut => (
                "timed out (virtual time)".to_string(),
                "the driver didn't reply within --run-deadline-secs of virtual time; it most likely blocks or loops",
            ),
            NotCheckedReason::WallTimedOut => (
                "timed out (wall clock)".to_string(),
                "the run exceeded --run-wall-timeout-secs of real time before its vt deadline; a slow CPU-bound busy loop",
            ),
            NotCheckedReason::VmShutdown => (
                "VM shut down mid-run".to_string(),
                "the driver never replied before the VM powered off — the program most likely blocks or hangs",
            ),
            NotCheckedReason::UnhandledExit { reason } => (
                format!("unhandled exit: {} ({reason})", exit_reason_name(*reason)),
                "the guest hit a VM exit the hypervisor doesn't emulate; the driver can't run here (not evidence of non-determinism)",
            ),
            NotCheckedReason::Other(msg) => (
                format!("lab error: {msg}"),
                "a run failed before producing a comparable signature",
            ),
        }
    }
}

/// Human-readable name for a VMX basic exit reason, mirroring
/// `bedrock_vm::LogEntry::exit_reason_str`.
fn exit_reason_name(reason: u32) -> &'static str {
    match reason {
        0 => "EXCEPTION_NMI",
        10 => "CPUID",
        16 => "RDTSC",
        28 => "CR_ACCESS",
        30 => "IO_INSTRUCTION",
        31 => "MSR_READ",
        32 => "MSR_WRITE",
        36 => "MWAIT",
        39 => "MONITOR",
        48 => "EPT_VIOLATION",
        51 => "RDTSCP",
        55 => "XSETBV",
        57 => "RDRAND",
        61 => "RDSEED",
        _ => "OTHER",
    }
}

// ── Fingerprint sink ───────────────────────────────────────────────────────

/// Per-branch accumulator: a rolling FNV-1a hash over the compared fields of
/// each deterministic exit, a count of those exits, and (detail mode only) the
/// retained stream itself. Lives in the sharded map so the hot path takes just
/// the shard lock — detail retention piggybacks on that same lock rather than
/// adding a global one, which would serialize exit logging and perturb the
/// very concurrency timing we're trying to reproduce.
struct RunAcc {
    hash: u64,
    determ_exits: u64,
    /// Retained deterministic-exit stream; empty unless detail mode is on.
    stream: Vec<LogEntry>,
}

impl Default for RunAcc {
    fn default() -> Self {
        Self {
            hash: FNV_OFFSET,
            determ_exits: 0,
            stream: Vec::new(),
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
    /// While true, serial output is printed regardless of `verbose` — this is
    /// the boot log, emitted on the reserved boot branch before the ready
    /// checkpoint exists. Flipped off by [`FingerprintSink::end_boot`] once
    /// boot completes, so the parallel driver fan-out stays quiet unless
    /// `--verbose` is set.
    boot_phase: AtomicBool,
    /// When true, exits and serial output for branches in `captures` are also
    /// streamed to disk. Off during the parallel detection pass (so the hot
    /// path never touches `captures`); flipped on for the artifact-saving
    /// second pass via [`FingerprintSink::set_capturing`].
    capturing: AtomicBool,
    /// Per-branch open artifact writers, keyed by the branch being captured.
    /// Only populated during the second pass, one entry at a time.
    captures: Mutex<HashMap<BranchId, Capture>>,
    /// Cap on exit-log entries written per captured run (bounds disk for runs
    /// that idle-fast-forward for a long time, e.g. hangs).
    save_max_entries: usize,
    /// When true, retain each branch's full deterministic-exit stream (in the
    /// sharded `RunAcc`) for the single-driver `--driver` detail mode, which
    /// diffs streams entry-by-entry. Off during the bulk passes.
    detail: AtomicBool,
}

/// Open artifact writers for one captured run.
struct Capture {
    jsonl: BufWriter<File>,
    serial: BufWriter<File>,
    entries_written: usize,
    truncated: bool,
}

impl FingerprintSink {
    fn new(verbose: bool, save_max_entries: usize) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            verbose,
            boot_phase: AtomicBool::new(true),
            capturing: AtomicBool::new(false),
            captures: Mutex::new(HashMap::new()),
            save_max_entries,
            detail: AtomicBool::new(false),
        }
    }

    /// Stop unconditionally echoing serial output. Call once boot is done.
    fn end_boot(&self) {
        self.boot_phase.store(false, Ordering::Relaxed);
    }

    /// Enable/disable in-memory retention of per-branch exit streams (detail
    /// mode). Enabled only around the single-driver `--driver` pass.
    fn set_detail(&self, on: bool) {
        self.detail.store(on, Ordering::Relaxed);
    }

    /// Enable/disable disk capture globally. Enabled only around the
    /// single-threaded artifact-saving pass.
    fn set_capturing(&self, on: bool) {
        self.capturing.store(on, Ordering::Relaxed);
    }

    /// Begin capturing `branch`'s exit log and serial output into `run_dir`
    /// (`exit-log.jsonl` + `serial.txt`). Requires [`Self::set_capturing(true)`].
    fn start_capture(&self, branch: BranchId, run_dir: &Path) -> std::io::Result<()> {
        fs::create_dir_all(run_dir)?;
        let jsonl = BufWriter::new(File::create(run_dir.join("exit-log.jsonl"))?);
        let serial = BufWriter::new(File::create(run_dir.join("serial.txt"))?);
        self.captures.lock().unwrap().insert(
            branch,
            Capture {
                jsonl,
                serial,
                entries_written: 0,
                truncated: false,
            },
        );
        Ok(())
    }

    /// Flush and close `branch`'s capture. Returns `(entries_written, truncated)`.
    fn finish_capture(&self, branch: BranchId) -> (usize, bool) {
        let Some(mut cap) = self.captures.lock().unwrap().remove(&branch) else {
            return (0, false);
        };
        let _ = cap.jsonl.flush();
        let _ = cap.serial.flush();
        (cap.entries_written, cap.truncated)
    }

    fn shard(&self, branch: BranchId) -> &Mutex<HashMap<BranchId, RunAcc>> {
        // BranchId's inner u64 is private to the lab crate, so derive a shard
        // index from its Hash impl instead of the raw value.
        let mut h = std::collections::hash_map::DefaultHasher::new();
        branch.hash(&mut h);
        &self.shards[(h.finish() as usize) % SHARDS]
    }

    /// Remove and return a branch's accumulator: fingerprint, deterministic
    /// exit count, and retained stream (empty unless detail mode was on).
    fn take_run(&self, branch: BranchId) -> (u64, u64, Vec<LogEntry>) {
        let acc = self
            .shard(branch)
            .lock()
            .unwrap()
            .remove(&branch)
            .unwrap_or_default();
        (acc.hash, acc.determ_exits, acc.stream)
    }

    /// Remove a branch's accumulator, returning just `(fingerprint, exits)`.
    fn take(&self, branch: BranchId) -> (u64, u64) {
        let (hash, exits, _) = self.take_run(branch);
        (hash, exits)
    }
}

impl EventSink for FingerprintSink {
    fn on_event(&self, event: Event<'_>) {
        match event {
            Event::ExitLogged { branch, entry } => {
                if entry.is_deterministic() {
                    let mut g = self.shard(branch).lock().unwrap();
                    let acc = g.entry(branch).or_default();
                    acc.hash = fold_entry(acc.hash, entry);
                    acc.determ_exits += 1;
                    // Detail mode: retain the stream for diffing, under the same
                    // shard lock (no extra global contention).
                    if self.detail.load(Ordering::Relaxed) {
                        acc.stream.push(*entry);
                    }
                }
                // When capturing, stream every exit (deterministic or not) to
                // the run's JSONL so the saved log is the full stream.
                if self.capturing.load(Ordering::Relaxed) {
                    if let Some(cap) = self.captures.lock().unwrap().get_mut(&branch) {
                        if cap.entries_written < self.save_max_entries {
                            let _ = write_jsonl(&mut cap.jsonl, std::slice::from_ref(entry));
                            cap.entries_written += 1;
                        } else {
                            cap.truncated = true;
                        }
                    }
                }
            }
            Event::SerialLine { branch, at, line } => {
                if self.verbose || self.boot_phase.load(Ordering::Relaxed) {
                    eprintln!(
                        "[br {branch:?} vt {:>8.3}] {}",
                        at.as_secs_f64(),
                        String::from_utf8_lossy(line)
                    );
                }
                if self.capturing.load(Ordering::Relaxed) {
                    if let Some(cap) = self.captures.lock().unwrap().get_mut(&branch) {
                        let _ = cap.serial.write_all(line);
                        let _ = cap.serial.write_all(b"\n");
                    }
                }
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

    /// Per-run virtual-time limit (guest seconds). A driver that doesn't reply
    /// within this much guest time is reported as "timed out (virtual time)".
    /// Bounds idle hangs (the emulated TSC fast-forwards) and busy loops alike.
    /// Set to 0 to disable.
    #[arg(long, default_value_t = 60.0)]
    run_deadline_secs: f64,

    /// Per-run wall-clock timeout (real seconds). Backstop for a CPU-bound busy
    /// loop whose virtual-time budget takes too long to execute in real time;
    /// such a run is reported as "timed out (wall clock)". Set to 0 to disable.
    #[arg(long, default_value_t = 360.0)]
    run_wall_timeout_secs: f64,

    /// Detail mode: focus on the single driver whose path contains this
    /// substring (must match exactly one). Runs it `--runs` times and diffs
    /// each completed run's exit stream against the first, pinpointing the
    /// exact exit and fields where non-determinism first appears.
    #[arg(long)]
    driver: Option<String>,

    /// Detail mode only: single-step (MTF) the guest within this emulated-TSC
    /// instruction range `START-END`, logging every retired instruction in the
    /// window. Use it to bracket a known divergence (from a normal detail run's
    /// reported TSC) and pinpoint the exact instruction where two runs differ.
    /// Requires `--driver`.
    #[arg(long = "single-step", value_parser = parse_tsc_range)]
    single_step: Option<(u64, u64)>,

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

    /// Save raw artifacts (exit-log.jsonl + serial.txt) for every problematic
    /// (non-deterministic or not-checked) driver into this directory. Each gets
    /// `<container>__<driver>/{summary.txt,run-NN/...}`, captured by re-running
    /// only the flagged drivers after detection.
    #[arg(long)]
    save_dir: Option<String>,

    /// Cap on exit-log entries written per captured run (bounds disk for runs
    /// that idle-fast-forward, e.g. hangs). Only affects --save-dir output.
    #[arg(long, default_value_t = 100_000)]
    save_max_entries: usize,

    /// Print serial output and per-driver ok lines.
    #[arg(short, long)]
    verbose: bool,
}

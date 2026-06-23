// SPDX-License-Identifier: GPL-2.0

//! `lonepine` binary: parse flags with clap and run the campaign.

use std::path::PathBuf;

use clap::Parser;
use lonepine::campaign::{run_campaign, Config};

/// Coverage-guided driver fuzzer for the bedrock hypervisor.
///
/// Fuzzes a workload (see `workloads/README.md`): a directory with a
/// `compose.yaml` describing the container topology and an `images.tar` of the
/// container archives (produced by the workload's `build.sh`). Both are served to
/// the deterministic guest over the file-transmission hypercall at boot.
#[derive(Parser, Debug)]
#[command(name = "lonepine", version, about)]
struct Args {
    /// Path to the guest kernel image.
    #[arg(long)]
    vmlinux: PathBuf,

    /// Path to the (generic podman) initramfs image.
    #[arg(long)]
    initramfs: PathBuf,

    /// Workload directory: must contain `compose.yaml` and `images.tar`.
    /// Override either path explicitly with `--compose` / `--images`.
    #[arg(long)]
    workload: Option<PathBuf>,

    /// Workload `compose.yaml` (defaults to `<workload>/compose.yaml`).
    #[arg(long)]
    compose: Option<PathBuf>,

    /// Workload `images.tar` (defaults to `<workload>/images.tar`).
    #[arg(long)]
    images: Option<PathBuf>,

    /// Campaign PRNG seed.
    #[arg(long, default_value_t = 0x5ca1_ab1e)]
    seed: u64,

    /// Number of iterations to run (0 = forever).
    #[arg(long, default_value_t = 0)]
    iters: u64,

    /// Guest memory in MiB.
    #[arg(long = "mem", default_value_t = 10240)]
    memory_mb: usize,

    /// Virtual-time budget (seconds) for the one-time boot to the ready
    /// checkpoint. Container workloads can take many emulated minutes to settle.
    #[arg(long = "ready-deadline-secs", default_value_t = 3600)]
    ready_deadline_secs: u64,

    /// Directory the workload registers drivers under.
    #[arg(long = "driver-dir", default_value = "/opt/bedrock/drivers")]
    driver_dir: String,

    /// Feedback-buffer id prefix that scopes which buffers count as coverage
    /// (each distinct id is a domain; same-id buffers are unioned). The guest's
    /// Go coverage shim registers buffers under `go-<symbol>`; pass empty to
    /// match every registered feedback buffer.
    #[arg(long = "cov-prefix", default_value = "go-")]
    cov_prefix: String,

    /// Per-step branch budget: max virtual-time seconds a step runs before
    /// lonepine stops waiting for its drivers and checkpoints where it is.
    #[arg(long = "branch-budget-secs", default_value_t = 600)]
    branch_budget_secs: u64,

    /// Max live VM checkpoint tips kept in the corpus (others are dropped and
    /// revived on demand via the radix genealogy). Bounds cached VM memory.
    #[arg(long = "cache-budget", default_value_t = 512)]
    cache_budget: usize,

    /// Directory to write reproducers to: `crash-<n>.json` (raw, saved as soon
    /// as a bug is found), `crash-<n>.serial.log`, and `crash-<n>.min.json`.
    #[arg(long = "solutions-dir", default_value = "lonepine-solutions")]
    solutions_dir: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Resolve the workload files: explicit --compose/--images win, else derive
    // them from --workload.
    let compose = args
        .compose
        .or_else(|| args.workload.as_ref().map(|d| d.join("compose.yaml")))
        .ok_or("need --workload <dir> or --compose <file>")?;
    let images = args
        .images
        .or_else(|| args.workload.as_ref().map(|d| d.join("images.tar")))
        .ok_or("need --workload <dir> or --images <file>")?;
    for (what, path) in [("compose.yaml", &compose), ("images.tar", &images)] {
        if !path.exists() {
            return Err(format!("workload {what} not found: {}", path.display()).into());
        }
    }

    let cfg = Config {
        vmlinux: args.vmlinux,
        initramfs: args.initramfs,
        compose,
        images,
        seed: args.seed,
        max_iters: args.iters,
        memory_mb: args.memory_mb,
        ready_deadline_secs: args.ready_deadline_secs,
        driver_dir: args.driver_dir,
        cov_prefix: args.cov_prefix.into_bytes(),
        branch_budget_secs: args.branch_budget_secs,
        cache_budget: args.cache_budget,
        solutions_dir: args.solutions_dir,
        ..Config::default()
    };
    run_campaign(cfg)
}

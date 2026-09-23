// SPDX-License-Identifier: GPL-2.0
//! AFL++'s Bedrock plugin. The C ABI is single-threaded per runner. Each
//! execution forks the same checkpoint, including guest RNG and coverage state.
//!
//! The coverage map size is not fixed: the guest communicates it through the
//! `HYPERCALL_REGISTER_FEEDBACK_BUFFER` hypercall (the `size` argument) when it
//! registers its `afl-coverage` buffer, and the host discovers it here. AFL++
//! queries it via [`bedrock_afl_map_size`] and points its `trace_bits` at the
//! host-side bitmap this plugin owns (via [`bedrock_afl_bitmap`]) — the same
//! shape as libnyx's `nyx_get_bitmap_buffer_size` / `nyx_get_bitmap_buffer`.

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bedrock_lab::{
    Checkpoint, Event, EventSink, FuzzOutcome, LabOpts, RngMode, RunOutcome, VirtDuration, VirtTime,
};
use bedrock_vm::{
    boot::defaults, load_kernel, ExitKind, LinuxBootConfig, VmBuilder, DEFAULT_TSC_FREQUENCY,
};
use serde::Deserialize;

/// The bump-on-ABI-break version reported by [`bedrock_afl_abi_version`]. The
/// AFL++ side refuses to run against a plugin whose version it doesn't know.
pub const ABI_VERSION: u32 = 2;
/// Identifier the guest registers its AFL coverage bitmap under.
pub const COVERAGE_ID: &[u8] = b"afl-coverage";
/// The largest coverage map the host will accept from the guest, as a sanity
/// bound. A guest coverage buffer can be at most one feedback buffer
/// (`VMCALL_FEEDBACK_BUFFER_MAX_SIZE` = 1 MiB), so this can never be exceeded in
/// practice; it just guards against a nonsensical registration.
pub const MAX_MAP_SIZE: usize = 256 * 4096;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Round `n` up to the next multiple of 64. AFL++ reads coverage in wide chunks
/// (SIMD `classify_counts`), so the backing bitmap must be a multiple of 64
/// bytes even when the guest's real map size isn't. Mirrors libnyx, which rounds
/// its bitmap size up the same way.
fn round_up_64(n: usize) -> usize {
    (n + 63) & !63
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Guest kernel vmlinux. Required unless `parent_state` is set.
    #[serde(default)]
    pub kernel: Option<PathBuf>,
    /// Guest initramfs. Required unless `parent_state` is set.
    #[serde(default)]
    pub initramfs: Option<PathBuf>,
    /// Worker mode: path to the JSON a `bedrock-afl-root` holder published (see
    /// [`RootState`]). When set, this runner forks that shared, already-booted
    /// root VM instead of booting its own — the whole point of a multi-process
    /// campaign sharing one root. `kernel`/`initramfs` are ignored.
    #[serde(default)]
    pub parent_state: Option<PathBuf>,
    #[serde(default = "default_memory")]
    pub memory_mb: usize,
    #[serde(default = "default_cmdline")]
    pub cmdline: String,
    #[serde(default = "default_boot_timeout")]
    pub boot_timeout_secs: u64,
    #[serde(default)]
    pub files: Vec<(String, String)>,
    #[serde(default)]
    pub serial: bool,
}
fn default_memory() -> usize {
    1024
}
fn default_boot_timeout() -> u64 {
    120
}
fn default_cmdline() -> String {
    defaults::CMDLINE.to_owned()
}

/// What a `bedrock-afl-root` holder publishes about its parked root VM so that
/// worker processes can fork it. Serialized as JSON to the state file the
/// holder writes and the workers' configs point at via `parent_state`.
#[derive(serde::Serialize, Deserialize)]
pub struct RootState {
    /// Global VM id of the parked root, for `Vm::create_forked` / `attach_forked`.
    pub parent_id: u64,
    /// The root's checkpoint virtual time, in emulated-TSC ticks (exact).
    pub time_instructions: u64,
    /// Emulated TSC frequency the tree runs at.
    pub tsc_frequency: u64,
    /// Guest coverage-map size in bytes (from the root's registration).
    pub map_size: usize,
    /// Guest fuzz-input capacity in bytes.
    pub capacity: usize,
}

struct SerialLog(bool);
impl EventSink for SerialLog {
    fn on_event(&self, event: Event<'_>) {
        if self.0 {
            if let Event::SerialLine { line, .. } = event {
                eprintln!("bedrock guest: {}", String::from_utf8_lossy(line));
            }
        }
    }
}

pub struct Runner {
    checkpoint: Checkpoint,
    pub capacity: usize,
    /// The guest's real coverage-map size in bytes, taken from its
    /// `afl-coverage` feedback-buffer registration. This is what
    /// [`bedrock_afl_map_size`] reports to AFL++.
    map_size: usize,
    /// Host-side coverage bitmap AFL++'s `trace_bits` points at. Allocated once,
    /// at `round_up_64(map_size)` bytes, and never resized, so the pointer we
    /// hand out via [`bedrock_afl_bitmap`] stays valid for the runner's life.
    bitmap: Vec<u8>,
    input: Vec<u8>,
    pub message: String,
    /// Set from `BEDROCK_AFL_DEBUG` at load time: log the one-time boot and,
    /// per exec, the virtual/wall time it took. Read once so the hot path does
    /// no per-exec env lookup.
    debug: bool,
}

impl Runner {
    /// Build a runner from a config JSON. If the config sets `parent_state`, the
    /// runner attaches to a shared, already-booted root VM (worker mode);
    /// otherwise it boots its own from `kernel`/`initramfs` (boot mode).
    pub fn load(path: &Path) -> Result<Self> {
        let config: Config = serde_json::from_slice(&fs::read(path)?)?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::from_config(config, base)
    }

    /// Build a runner from an already-parsed [`Config`]. Relative paths in it
    /// resolve against `base` (the config file's directory). Lets a tool adjust
    /// the config before booting/attaching — the replay tool turns `serial` on
    /// this way without editing the campaign's config file.
    pub fn from_config(config: Config, base: &Path) -> Result<Self> {
        match &config.parent_state {
            Some(state) => Self::attach(&base.join(state), config.serial),
            None => Self::boot(config, base),
        }
    }

    /// Attach to the shared root VM a `bedrock-afl-root` holder published, forking
    /// it per testcase instead of booting. RNG mode, coverage/input buffer
    /// registrations, and guest state are all inherited through the fork. With
    /// `serial` set, guest serial lines from the forks are echoed to stderr.
    fn attach(state_path: &Path, serial: bool) -> Result<Self> {
        let state: RootState = serde_json::from_slice(&fs::read(state_path)?)?;
        let at = VirtTime::from_instructions(state.time_instructions, state.tsc_frequency);
        let checkpoint = Checkpoint::attach_forked(
            state.parent_id,
            at,
            LabOpts {
                tsc_frequency: state.tsc_frequency,
                sink: Arc::new(SerialLog(serial)),
                ..Default::default()
            },
        )?;
        let debug = std::env::var_os("BEDROCK_AFL_DEBUG").is_some();
        if debug {
            eprintln!(
                "[bedrock-afl] worker attached to shared root VM (parent_id={}, \
                 coverage map {} bytes) — no boot",
                state.parent_id, state.map_size
            );
        }
        Ok(Self {
            checkpoint,
            capacity: state.capacity,
            map_size: state.map_size,
            bitmap: vec![0u8; round_up_64(state.map_size)],
            input: Vec::new(),
            message: String::new(),
            debug,
        })
    }

    fn boot(mut config: Config, base: &Path) -> Result<Self> {
        let kernel = base.join(
            config
                .kernel
                .take()
                .ok_or("config needs `kernel` (or `parent_state` for worker mode)")?,
        );
        let initramfs = base.join(
            config
                .initramfs
                .take()
                .ok_or("config needs `initramfs` (or `parent_state` for worker mode)")?,
        );
        if !(64..=1048576).contains(&config.memory_mb) || config.boot_timeout_secs == 0 {
            return Err("invalid memory_mb or boot_timeout_secs".into());
        }
        for (_, host) in &mut config.files {
            *host = base.join(&*host).to_string_lossy().into_owned();
        }
        let mut vm = VmBuilder::new().memory_mb(config.memory_mb).build()?;
        let kernel = fs::read(kernel)?;
        let initramfs = fs::read(initramfs)?;
        let (entry, end) = load_kernel(vm.memory_mut()?, &kernel)?;
        vm.setup_linux_boot(
            &LinuxBootConfig::new(entry, end)
                .cmdline(&config.cmdline)
                .initramfs(&initramfs),
        )?;
        let ready = Checkpoint::initial_when_ready_with(
            vm,
            VirtTime::from_secs(config.boot_timeout_secs, DEFAULT_TSC_FREQUENCY),
            LabOpts {
                rng: RngMode::Seeded(0xbed0_af1),
                files: config.files,
                sink: Arc::new(SerialLog(config.serial)),
                ..Default::default()
            },
        )?;
        let mut branch = ready.branch()?;
        let (_, outcome) = branch.run_for(VirtDuration::from_secs(
            config.boot_timeout_secs,
            ready.tsc_frequency(),
        ))?;
        if !matches!(
            outcome,
            RunOutcome::Yielded {
                kind: ExitKind::FuzzNextInput
            }
        ) {
            return Err(format!("guest did not request its first input: {outcome:?}").into());
        }
        let capacity = branch.fuzz_input_capacity()?;

        // Discover the coverage-map size from the guest's registration rather
        // than assuming any fixed value. All buffers registered under the id
        // must agree on a length (they are byte-wise merged into one map).
        //
        // The map need NOT be zero at the checkpoint: a live target (e.g. an
        // lnd node) executes instrumented code during setup, right up to the
        // snapshot, so a few edges are already set. That baseline is harmless —
        // every fork inherits the same snapshot, so those edges are constant
        // across testcases and never register as new coverage.
        let maps = branch.feedback_buffers(COVERAGE_ID)?;
        if maps.is_empty() {
            return Err(
                "guest registered no afl-coverage feedback buffer before its first input".into(),
            );
        }
        let map_size = maps[0].len();
        if map_size == 0 || map_size > MAX_MAP_SIZE {
            return Err(format!(
                "guest afl-coverage buffer size {map_size} is out of range \
                                (1..={MAX_MAP_SIZE})"
            )
            .into());
        }
        if maps.iter().any(|map| map.len() != map_size) {
            return Err("guest registered afl-coverage buffers of differing sizes".into());
        }

        let checkpoint = branch.checkpoint()?;
        let debug = std::env::var_os("BEDROCK_AFL_DEBUG").is_some();
        if debug {
            eprintln!(
                "[bedrock-afl] guest BOOTED once; input checkpoint at {:.4}s virtual, \
                       coverage map {map_size} bytes",
                checkpoint.time().as_secs_f64()
            );
        }
        Ok(Self {
            checkpoint,
            capacity,
            map_size,
            bitmap: vec![0u8; round_up_64(map_size)],
            input: Vec::new(),
            message: String::new(),
            debug,
        })
    }

    /// The guest's real coverage-map size in bytes.
    pub fn map_size(&self) -> usize {
        self.map_size
    }

    /// Virtual time of the fork-source checkpoint every execution starts from.
    pub fn checkpoint_time(&self) -> VirtTime {
        self.checkpoint.time()
    }

    /// Snapshot the fork-source VM's identity for a `bedrock-afl-root` holder to
    /// publish, so worker processes can [`attach`](Self::attach) and share it.
    pub fn root_state(&self) -> Result<RootState> {
        Ok(RootState {
            parent_id: self.checkpoint.vm_id()?,
            time_instructions: self.checkpoint.time().instructions(),
            tsc_frequency: self.checkpoint.tsc_frequency(),
            map_size: self.map_size,
            capacity: self.capacity,
        })
    }

    /// The host-side coverage bitmap. Its length is `round_up_64(map_size())`;
    /// only the first `map_size()` bytes are meaningful.
    pub fn bitmap(&self) -> &[u8] {
        &self.bitmap
    }

    pub fn set_input(&mut self, input: &[u8]) -> Result<()> {
        if input.len() > self.capacity {
            return Err(format!(
                "input has {} bytes; guest capacity is {} (set afl-fuzz -G)",
                input.len(),
                self.capacity
            )
            .into());
        }
        self.input.clear();
        self.input.extend_from_slice(input);
        Ok(())
    }

    /// Execute the current input against a fresh fork of the checkpoint,
    /// leaving the merged edge coverage in [`bitmap`](Self::bitmap).
    ///
    /// Returns 0 = success/skip, 1 = reported guest crash, 2 = virtual timeout.
    /// Infrastructure and unexpected protocol exits are errors, never crashes.
    pub fn run(&mut self, timeout_ms: u32) -> Result<i32> {
        self.run_then(timeout_ms, |_| Ok(()))
    }

    /// [`run`](Self::run), then hand the still-live fork to `post` before it is
    /// discarded. `post` runs after the verdict is final — outcome classified,
    /// coverage merged — so nothing it does can change what this call reports.
    /// It can e.g. [`Branch::bash`] into the guest: on ok/crash the guest is
    /// parked in its fuzz hypercall with the testcase over; on a timeout the
    /// testcase is still in progress and the command probes it live. Driving the
    /// fork this way advances its virtual time and perturbs its continuation, so
    /// `post` observes the guest at the verdict, not what it would do next.
    /// Not used on the AFL++ hot path (`post` is a no-op there).
    pub fn run_then(
        &mut self,
        timeout_ms: u32,
        post: impl FnOnce(&mut bedrock_lab::Branch) -> Result<()>,
    ) -> Result<i32> {
        if timeout_ms == 0 {
            return Err("zero timeout".into());
        }
        let map_size = self.map_size;
        for b in &mut self.bitmap {
            *b = 0;
        }
        self.message.clear();
        let t0 = std::time::Instant::now();
        let mut branch = self.checkpoint.branch()?;
        let fork_ms = t0.elapsed().as_secs_f64() * 1000.0;
        branch.serve_fuzz_input(&self.input)?;
        let (end_time, outcome) = branch.run_for(VirtDuration::from_millis(
            u64::from(timeout_ms),
            self.checkpoint.tsc_frequency(),
        ))?;
        if self.debug {
            // Each exec forks the SAME checkpoint, so `start` is constant across
            // execs and `delta` is the virtual time one testcase consumed. A real
            // reboot would be seconds (boot-to-ready); a fork is a few ms. `wall`
            // is host-side cost (fork COW + run + teardown), `fork` just the fork.
            let start = self.checkpoint.time().as_secs_f64();
            eprintln!(
                "[bedrock-afl] exec: checkpoint={start:.4}s delta_ms={:.3} \
                       wall_ms={:.2} fork_ms={fork_ms:.2} outcome={outcome:?}",
                (end_time.as_secs_f64() - start) * 1000.0,
                t0.elapsed().as_secs_f64() * 1000.0
            );
        }
        let (result, merge_coverage) = match outcome {
            RunOutcome::ReachedTime => (2, true),
            RunOutcome::Yielded {
                kind: ExitKind::FuzzNextInput,
            } => {
                match branch.fuzz_outcome()? {
                    FuzzOutcome::Ok => (0, true),
                    // AFL++ has no skip result. Retain no target edges for this input.
                    FuzzOutcome::Skip => (0, false),
                    FuzzOutcome::Fail(message) => {
                        self.message = message;
                        (1, true)
                    }
                    other => return Err(format!("unknown guest status: {other:?}").into()),
                }
            }
            other => return Err(format!("unexpected guest exit: {other:?}").into()),
        };
        if merge_coverage {
            let maps = branch.feedback_buffers(COVERAGE_ID)?;
            if maps.is_empty() || maps.iter().any(|map| map.len() != map_size) {
                return Err("guest coverage registration changed incompatibly".into());
            }
            for map in maps {
                for (dst, &src) in self.bitmap[..map_size].iter_mut().zip(map) {
                    *dst = (*dst).max(src);
                }
            }
        }
        // AFL++ uses byte zero to distinguish an executed but edgeless input.
        self.bitmap[0] = 1;
        post(&mut branch)?;
        Ok(result)
    }
}

thread_local! {
    static ERROR: RefCell<CString> = RefCell::new(CString::default());
}
fn ffi<T>(failure: T, f: impl FnOnce() -> Result<T>) -> T {
    let result = catch_unwind(AssertUnwindSafe(f));
    let error = match result {
        Ok(Ok(value)) => return value,
        Ok(Err(error)) => error.to_string(),
        Err(_) => "panic in Bedrock backend".to_owned(),
    };
    ERROR.with(|slot| *slot.borrow_mut() = CString::new(error.replace('\0', "?")).unwrap());
    failure
}

#[no_mangle]
pub extern "C" fn bedrock_afl_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub extern "C" fn bedrock_afl_error() -> *const c_char {
    ERROR.with(|slot| slot.borrow().as_ptr())
}

// All non-null pointers below must point to live C buffers/Runner handles of
// the stated lengths; handles may only be used by one thread at a time.
#[no_mangle]
pub unsafe extern "C" fn bedrock_afl_new(path: *const c_char) -> *mut Runner {
    ffi(std::ptr::null_mut(), || {
        if path.is_null() {
            return Err("null config path".into());
        }
        Ok(Box::into_raw(Box::new(Runner::load(Path::new(
            CStr::from_ptr(path).to_str()?,
        ))?)))
    })
}
#[no_mangle]
pub unsafe extern "C" fn bedrock_afl_free(runner: *mut Runner) {
    ffi((), || {
        if !runner.is_null() {
            drop(Box::from_raw(runner));
        }
        Ok(())
    });
}
#[no_mangle]
pub unsafe extern "C" fn bedrock_afl_capacity(runner: *const Runner) -> usize {
    ffi(0, || Ok(runner.as_ref().ok_or("null runner")?.capacity))
}
/// The guest's coverage-map size in bytes. AFL++ points its `trace_bits` at a
/// buffer of this size (rounded up to a multiple of 64).
#[no_mangle]
pub unsafe extern "C" fn bedrock_afl_map_size(runner: *const Runner) -> usize {
    ffi(0, || Ok(runner.as_ref().ok_or("null runner")?.map_size))
}
/// Pointer to the host-side coverage bitmap AFL++ reads as `trace_bits`. Valid
/// for the runner's lifetime; `round_up_64(map_size)` bytes long.
#[no_mangle]
pub unsafe extern "C" fn bedrock_afl_bitmap(runner: *mut Runner) -> *mut u8 {
    ffi(std::ptr::null_mut(), || {
        Ok(runner.as_mut().ok_or("null runner")?.bitmap.as_mut_ptr())
    })
}
#[no_mangle]
pub unsafe extern "C" fn bedrock_afl_set_input(
    runner: *mut Runner,
    input: *const u8,
    len: usize,
) -> i32 {
    ffi(-1, || {
        let runner = runner.as_mut().ok_or("null runner")?;
        let input = if len == 0 {
            &[]
        } else {
            if input.is_null() {
                return Err("null input".into());
            }
            std::slice::from_raw_parts(input, len)
        };
        runner.set_input(input)?;
        Ok(0)
    })
}
#[no_mangle]
pub unsafe extern "C" fn bedrock_afl_run(runner: *mut Runner, timeout_ms: u32) -> i32 {
    ffi(-1, || runner.as_mut().ok_or("null runner")?.run(timeout_ms))
}

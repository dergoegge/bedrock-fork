// SPDX-License-Identifier: GPL-2.0

//! Checkpoints — immutable moments in virtual time.

use std::sync::Arc;

use bedrock_vm::file_xfer::FileServer;
use bedrock_vm::{
    EventCategories, EventConfig as VmEventConfig, ExitKind, RdrandConfig, Vm, VmError,
};

use crate::branch::{Branch, BranchId, RunOutcome};
use crate::error::{LabError, Result};
use crate::event::{
    drain_serial_events, emit_feedback_buffer_registered, Discard, Event, EventSink, PartialLine,
};
use crate::inner::{LabInner, PrefixLoc, RewindPlan};
use crate::radix::NodeId;
use crate::rng::{InputRecording, InputSource, IoInput, RecordedInputSource, RngMode};
use crate::time::{VirtDuration, VirtTime};
use crate::tree::Tree;

/// Tree-wide options passed to [`Checkpoint::initial_when_ready_with`].
///
/// All fields have sensible defaults; use struct-update syntax for the ones
/// you want to override:
///
/// ```ignore
/// use bedrock_lab::{Checkpoint, LabOpts, RngMode};
/// let cp = Checkpoint::initial_when_ready_with(vm, deadline, LabOpts {
///     rng: RngMode::Seeded(0xC0FFEE),
///     ..Default::default()
/// })?;
/// ```
pub struct LabOpts {
    /// Emulated TSC frequency in Hz. Must match the value the [`Vm`] was
    /// built with.
    pub tsc_frequency: u64,
    /// Where to forward serial lines, branch creations, and checkpoint
    /// creations. Defaults to a sink that discards everything.
    pub sink: Arc<dyn EventSink>,
    /// How guest `RDRAND`/`RDSEED` is served for every branch in this tree.
    pub rng: RngMode,
    /// Host files exposed to the guest over the file-transmission hypercall
    /// (`HYPERCALL_FILE_FETCH`), as `(guest_name, host_path)` pairs. The
    /// generic podman initrd downloads its workload files (`compose.yaml` /
    /// `images.tar`) by name during boot, so callers booting such an initrd
    /// must supply them here. Files are only fetched before the ready
    /// hypercall, so they are served during this constructor's boot loop and
    /// need not persist into the tree.
    pub files: Vec<(String, String)>,
}

impl Default for LabOpts {
    fn default() -> Self {
        Self {
            tsc_frequency: bedrock_vm::DEFAULT_TSC_FREQUENCY,
            sink: Arc::new(Discard),
            rng: RngMode::Inherit,
            files: Vec::new(),
        }
    }
}

/// A stable identifier for a checkpoint within its tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointId(pub(crate) u64);

/// Where a candidate input recording sits relative to everything the tree has
/// already executed — the result of [`Checkpoint::longest_checkpoint_prefix`].
///
/// It splits the candidate into three consecutive spans along the genealogy:
///
/// - **already checkpointed** — the inputs captured by [`start`](Self::start),
///   the deepest existing checkpoint whose recording is a prefix of the
///   candidate. This is the best place to fork from; reaching it is free.
/// - **replay** ([`replay`](Self::replay)) — the recorded inputs between
///   `start` and the point the candidate first leaves every known path. They
///   were executed before (they lie on an existing trie path) but no checkpoint
///   was kept along them, so reaching the divergence means forking `start` and
///   re-running these forward.
/// - **new** ([`new`](Self::new)) — the inputs from the divergence onward, which
///   the tree has never executed.
///
/// The replay/new boundary is reported as a virtual *time*
/// ([`diverges_at`](Self::diverges_at)), not merely a token count: the idle
/// stretch between the last replayed input and the first diverging one is itself
/// replay ground — reaching the divergence means running `start` forward to
/// `diverges_at` even across input-free time. So a non-empty replay span is *not*
/// the only thing that implies replay work; `diverges_at > start.time()` does
/// too. `diverges_at` is `None` exactly when the candidate never leaves known
/// ground (it is a prefix of, or equal to, an existing path); then
/// [`new`](Self::new) is empty and [`replay`](Self::replay) carries the whole
/// tail past `start`.
#[derive(Debug, Clone)]
pub struct PrefixMatch {
    /// Deepest checkpoint whose recording is a prefix of the candidate.
    pub start: Checkpoint,
    /// Recorded inputs between `start` and the divergence, replayed forward
    /// from `start` to reproduce the shared execution.
    pub replay: InputRecording,
    /// Candidate inputs from the divergence onward — the genuinely new path.
    pub new: InputRecording,
    /// Virtual time at which the candidate first diverges from every known
    /// path: the boundary between [`replay`](Self::replay) and [`new`](Self::new).
    /// `None` if it never diverges.
    pub diverges_at: Option<VirtTime>,
}

/// An immutable moment in virtual time — a halted VM that can be forked into
/// one or more [`Branch`]es.
///
/// `Checkpoint` is a cheap-to-clone handle (`Arc` under the hood). All clones
/// of the same checkpoint refer to the same frozen VM and share the same tree
/// registry. The underlying VM is dropped automatically when the last handle
/// (and any descendant branch/checkpoint that pinned it) goes away.
#[derive(Clone)]
pub struct Checkpoint {
    pub(crate) inner: Arc<CheckpointInner>,
}

pub(crate) struct CheckpointInner {
    pub(crate) id: CheckpointId,
    pub(crate) time: VirtTime,
    /// The halted VM. Used only as a `vm.fork()` source — never run again.
    pub(crate) vm: Vm,
    pub(crate) lab: Arc<LabInner>,
    /// Serial line in progress at the moment this checkpoint was taken.
    /// Descendant branches start with this prepended so a line that
    /// straddles `Branch::checkpoint` is not split across two events.
    pub(crate) partial_line: PartialLine,
    /// Userspace input source captured at this checkpoint's virtual time.
    /// Branches fork their own clone, so the order in which sibling branches
    /// run does not affect the RNG or I/O inputs any individual branch sees.
    /// `None` for kernel-side RNG modes without a userspace source — those
    /// propagate through the VM-state COW like everything else.
    pub(crate) input_source: Option<Box<dyn InputSource>>,
    /// Next source-provided I/O action not yet queued because it was beyond
    /// the last run target or the VM queue was full.
    pub(crate) pending_input_io: Option<IoInput>,
    /// True once the input source has no more I/O actions.
    pub(crate) input_io_exhausted: bool,
    /// Inputs consumed along the path to this checkpoint.
    pub(crate) input_recording: InputRecording,
}

impl Checkpoint {
    /// Run a fully-set-up root [`Vm`] directly until the guest issues the
    /// ready hypercall, then create the initial checkpoint at that point.
    ///
    /// This is the usual constructor for Linux workload exploration: the VM is
    /// booted without forking, which matches `bedrock-cli`'s startup path, and
    /// only the ready guest is handed to the lab for branching. `deadline`
    /// bounds the boot in virtual time and must use
    /// [`bedrock_vm::DEFAULT_TSC_FREQUENCY`]; use
    /// [`Checkpoint::initial_when_ready_with`] to pick a different rate.
    ///
    /// The VM must already have its kernel/initramfs loaded and
    /// [`Vm::setup_linux_boot`](bedrock_vm::Vm::setup_linux_boot) applied.
    /// The guest must eventually issue `HYPERCALL_READY`; otherwise this
    /// returns an error when the deadline is reached or on any unexpected VM
    /// exit. Serial output and feedback-buffer registrations before ready are
    /// emitted through the configured [`EventSink`] using reserved
    /// [`BranchId(0)`](crate::BranchId), and the ready checkpoint inherits any
    /// feedback-buffer registrations.
    pub fn initial_when_ready(vm: Vm, deadline: VirtTime) -> Result<Self> {
        Self::initial_when_ready_with(vm, deadline, LabOpts::default())
    }

    /// One-stop ready constructor that takes a [`LabOpts`] for everything
    /// configurable about the tree.
    ///
    /// If `opts.rng` is [`RngMode::Seeded`] or [`RngMode::Source`], the VM's
    /// `RDRAND`/`RDSEED` mode is configured before the root VM is first run.
    /// If `opts.rng` is [`RngMode::Source`], the userspace source is not
    /// consumed during the root boot; root boot simply exits to userspace if
    /// the guest executes `RDRAND`/`RDSEED` before ready.
    pub fn initial_when_ready_with(mut vm: Vm, deadline: VirtTime, opts: LabOpts) -> Result<Self> {
        Self::check_frequency(deadline.frequency(), opts.tsc_frequency)?;
        let (mut opts, input_source) = Self::configure_rng(&vm, opts)?;
        // The guest downloads its workload files (compose.yaml / images.tar)
        // over `HYPERCALL_FILE_FETCH` during boot, before it issues
        // `HYPERCALL_READY`. Serve them from the host paths the caller supplied.
        // Take them out of `opts` (which is moved into the checkpoint below);
        // they need not persist past boot.
        let mut file_server = FileServer::new(std::mem::take(&mut opts.files));
        // Capture guest console output as `Serial` event records during boot,
        // the same channel branches use; the root VM gets reserved `BranchId(0)`.
        vm.set_event_config(&VmEventConfig::enabled(EventCategories::SERIAL))
            .map_err(|source| {
                LabError::Vm(VmError::Ioctl {
                    operation: "SET_EVENT_CONFIG",
                    source,
                })
            })?;
        vm.set_stop_at_tsc(Some(deadline.instructions()))?;
        let mut partial_line = PartialLine::default();
        loop {
            let exit = vm.run()?;
            let at = VirtTime::from_instructions(exit.emulated_tsc, opts.tsc_frequency);
            let event_len = exit.event_len as usize;
            if event_len > 0 {
                if let Some(buffer) = vm.event_buffer() {
                    drain_serial_events(
                        &buffer[..event_len.min(buffer.len())],
                        opts.tsc_frequency,
                        BranchId(0),
                        opts.sink.as_ref(),
                        &mut partial_line,
                    );
                }
            }
            match exit.kind() {
                ExitKind::VmcallReady => {
                    vm.set_stop_at_tsc(None)?;
                    return Self::initial_at_with_configured_rng(
                        vm,
                        at,
                        opts,
                        partial_line,
                        input_source,
                    );
                }
                ExitKind::FeedbackBufferRegistered => {
                    emit_feedback_buffer_registered(&vm, at, BranchId(0), opts.sink.as_ref())?;
                    continue;
                }
                ExitKind::FileFetch => {
                    file_server.serve(&mut vm).map_err(|source| {
                        LabError::Vm(VmError::Ioctl {
                            operation: "FILE_FETCH",
                            source,
                        })
                    })?;
                    continue;
                }
                ExitKind::Continue | ExitKind::EventBufferFull => continue,
                kind => return Err(LabError::UnexpectedExit { at, kind }),
            }
        }
    }

    fn check_frequency(lhs: u64, rhs: u64) -> Result<()> {
        if lhs != rhs {
            return Err(LabError::FrequencyMismatch { lhs, rhs });
        }
        Ok(())
    }

    fn configure_rng(vm: &Vm, opts: LabOpts) -> Result<(LabOpts, Option<Box<dyn InputSource>>)> {
        let LabOpts {
            tsc_frequency,
            sink,
            rng,
            files,
        } = opts;

        let (rdrand_config, input_source) = match rng {
            RngMode::Inherit => (None, None),
            RngMode::Seeded(seed) => (Some(RdrandConfig::seeded_rng(seed)), None),
            RngMode::Source(source) => (Some(RdrandConfig::exit_to_userspace()), Some(source)),
        };
        if let Some(config) = rdrand_config {
            vm.set_rdrand_config(&config)?;
        }
        Ok((
            LabOpts {
                tsc_frequency,
                sink,
                rng: RngMode::Inherit,
                files,
            },
            input_source,
        ))
    }

    fn initial_at_with_configured_rng(
        vm: Vm,
        time: VirtTime,
        opts: LabOpts,
        partial_line: PartialLine,
        input_source: Option<Box<dyn InputSource>>,
    ) -> Result<Self> {
        let LabOpts {
            tsc_frequency,
            sink,
            rng: _,
            files: _,
        } = opts;

        let lab = LabInner::new(tsc_frequency, sink);
        let id = CheckpointId(lab.next_checkpoint_id());
        let inner = Arc::new(CheckpointInner {
            id,
            time,
            vm,
            lab: lab.clone(),
            partial_line,
            input_source,
            pending_input_io: None,
            input_io_exhausted: false,
            input_recording: InputRecording::new(),
        });
        lab.graph.lock().unwrap().register(&inner);
        lab.sink.on_event(Event::CheckpointCreated {
            checkpoint: id,
            from_branch: None,
            parent: None,
            at: time,
        });
        Ok(Self { inner })
    }

    /// This checkpoint's ID, stable for the lifetime of the tree.
    pub fn id(&self) -> CheckpointId {
        self.inner.id
    }

    /// The virtual time at which this checkpoint was taken.
    pub fn time(&self) -> VirtTime {
        self.inner.time
    }

    /// The TSC frequency of the tree this checkpoint belongs to.
    pub fn tsc_frequency(&self) -> u64 {
        self.inner.lab.tsc_frequency
    }

    /// Inputs consumed along the path to this checkpoint.
    pub fn input_recording(&self) -> &InputRecording {
        &self.inner.input_recording
    }

    /// Clone this checkpoint's consumed-input recording for replay.
    pub fn input_recording_to_source(&self) -> crate::RecordedInputSource {
        crate::RecordedInputSource::new(self.inner.input_recording.clone())
    }

    /// Fork a fresh [`Branch`] from this checkpoint.
    ///
    /// Multiple branches can be forked from the same checkpoint; each gets
    /// its own COW VM, its own clone of any userspace input source, and
    /// explores forward independently. Two sibling branches see the same
    /// input stream regardless of the order in which they're driven.
    pub fn branch(&self) -> Result<Branch> {
        let input_source = self.inner.input_source.as_ref().map(|s| s.clone_box());
        self.branch_inner(input_source, false)
    }

    /// Fork a branch that *overrides* the checkpoint's userspace input
    /// source, regardless of the tree's original [`RngMode`](crate::RngMode).
    ///
    /// The source can provide both RDRAND/RDSEED values and caller-consumed
    /// I/O inputs. Intended for fuzzing loops: snapshot the guest at a
    /// "ready" point once, then call this per iteration with the next input
    /// wrapped in an [`InputSource`] so each iteration sees fresh bytes. The
    /// override forces the kernel into exit-to-userspace mode on the new
    /// branch's VM — descendants of *this* branch then inherit that mode via
    /// the usual VM-state COW.
    pub fn branch_with_input_source<S: InputSource + 'static>(&self, source: S) -> Result<Branch> {
        self.branch_inner(Some(Box::new(source)), true)
    }

    fn branch_inner(
        &self,
        input_source: Option<Box<dyn InputSource>>,
        force_exit_to_userspace: bool,
    ) -> Result<Branch> {
        let child_vm = self.inner.vm.fork()?;
        if force_exit_to_userspace {
            child_vm.set_rdrand_config(&RdrandConfig::exit_to_userspace())?;
        }
        let id = BranchId(self.inner.lab.next_branch_id());
        let mut branch = Branch::new(
            id,
            self.clone(),
            child_vm,
            self.inner.time,
            self.inner.lab.clone(),
            self.inner.partial_line.clone(),
            input_source,
            self.inner.pending_input_io.clone(),
            self.inner.input_io_exhausted,
            self.inner.input_recording.clone(),
        );
        // Forked VMs start with the event stream disabled; turn on the lab's
        // always-on capture (SERIAL, plus the input-recording categories for a
        // sourced branch) from the first instruction.
        branch.enable_event_capture()?;
        Ok(branch)
    }

    /// Parent checkpoint in the lab tree, if any. `None` for the root.
    ///
    /// The parent is the closest ancestor on this checkpoint's line: the nearest
    /// checkpoint whose input recording is a prefix of this one's. This is the
    /// ancestry [`Tree`](crate::Tree) renders.
    pub fn parent(&self) -> Option<Checkpoint> {
        self.inner
            .lab
            .graph
            .lock()
            .unwrap()
            .parent(self.inner.id)
            .map(|inner| Checkpoint { inner })
    }

    /// Locate a candidate input recording against this tree's genealogy: find
    /// the deepest existing checkpoint whose recording is a prefix of
    /// `candidate`, and classify the rest of the candidate into the inputs that
    /// merely *replay* previously-executed ground and the inputs that strike out
    /// on a *new* path. See [`PrefixMatch`].
    ///
    /// This is a read-only query — it forks and runs nothing. The intended use
    /// is to start a new line from the deepest shared checkpoint instead of from
    /// the root: fork [`PrefixMatch::start`], replay
    /// [`PrefixMatch::replay`] forward to [`PrefixMatch::diverges_at`] (exactly
    /// as [`Checkpoint::rewind`] replays a recorded suffix), then drive the new
    /// inputs from there.
    ///
    /// `candidate` is matched on its canonical token sequence (see
    /// [`InputRecording`]), so it must be supplied as a recording — what
    /// [`input_recording`](Self::input_recording) /
    /// [`Branch::input_recording`](crate::Branch::input_recording) expose, or
    /// the recording behind a [`RecordedInputSource`] (use
    /// [`longest_checkpoint_prefix_of`](Self::longest_checkpoint_prefix_of)).
    ///
    /// Returns `None` only if no checkpoint at all is a prefix of `candidate`
    /// (not even the root — e.g. the root checkpoint has been dropped).
    pub fn longest_checkpoint_prefix(&self, candidate: &InputRecording) -> Option<PrefixMatch> {
        let loc = self
            .inner
            .lab
            .graph
            .lock()
            .unwrap()
            .locate_prefix(candidate)?;
        Some(PrefixMatch::from(loc))
    }

    /// [`longest_checkpoint_prefix`](Self::longest_checkpoint_prefix) for the
    /// recording backing a [`RecordedInputSource`].
    pub fn longest_checkpoint_prefix_of(
        &self,
        source: &RecordedInputSource,
    ) -> Option<PrefixMatch> {
        self.longest_checkpoint_prefix(source.recording())
    }

    /// Retain this checkpoint's input prefix in the genealogy as a corpus entry,
    /// returning a [`RetainedInput`] handle.
    ///
    /// Admission pins the *input*, not the VM: the recording's trie node survives
    /// even after this checkpoint's VM is dropped (e.g. evicted from a live LRU),
    /// so the prefix stays classifiable as known and **revivable** — re-derivable
    /// by forking the deepest live ancestor and replaying the recorded suffix.
    /// The expensive VM remains an ordinary eviction candidate; only the cheap
    /// input path is held. Dropping the returned handle releases the anchor, and
    /// the node is pruned unless something else still anchors it.
    pub fn retain(&self) -> RetainedInput {
        let recording = self.inner.input_recording.clone();
        let node = self.inner.lab.graph.lock().unwrap().retain(&recording);
        RetainedInput {
            lab: self.inner.lab.clone(),
            node,
            recording,
        }
    }

    /// Take a new [`Checkpoint`] at `self.time() - by`.
    ///
    /// Resolves the rewind against the genealogy trie
    /// ([`Genealogy::rewind_plan`](crate::inner::RewindPlan)): the inputs `self`
    /// consumed up to the target time are a prefix of its
    /// [`input_recording`](Checkpoint::input_recording), and the deepest existing
    /// checkpoint on that prefix at or before the target is forked and replayed
    /// forward to the exact target time. Replaying the line's own *recorded*
    /// inputs reproduces its exact state regardless of RNG mode or any
    /// [`branch_with_input_source`](Checkpoint::branch_with_input_source)
    /// override taken along the way.
    ///
    /// If a checkpoint already sits at exactly the target `(input prefix, time)`,
    /// it is returned directly without replaying or adding a node.
    ///
    /// The replay mechanism follows the line's randomness mode, read from
    /// `self`:
    ///
    /// - **Sourced line** (a userspace [`InputSource`](crate::InputSource) drove
    ///   it): the recorded suffix is fed back through a [`RecordedInputSource`],
    ///   so the rewound checkpoint is itself in replay mode (its recording is
    ///   exhausted). To explore a *new* future from it, fork with
    ///   [`branch_with_input_source`](Checkpoint::branch_with_input_source) and
    ///   supply fresh input.
    /// - **Kernel-seeded line**: randomness is reproduced by the VM-state CoW, so
    ///   only the recorded I/O suffix is re-scheduled; the rewound checkpoint
    ///   stays seeded and a plain [`branch`](Checkpoint::branch) keeps drawing
    ///   fresh seeded randomness.
    ///
    /// Errors with [`LabError::NoCheckpointBefore`] if no checkpoint is at or
    /// before the target time, or [`LabError::RewindReplayIncomplete`] if the
    /// replay cannot reach the target (a sign of residual non-determinism — the
    /// recording no longer matches what the guest consumes).
    pub fn rewind(&self, by: VirtDuration) -> Result<Checkpoint> {
        if by.frequency() != self.inner.lab.tsc_frequency {
            return Err(LabError::FrequencyMismatch {
                lhs: by.frequency(),
                rhs: self.inner.lab.tsc_frequency,
            });
        }
        let target = self.inner.time - by;

        // Resolve against the trie, then drop the lock before any fork/replay
        // (which re-locks the graph to register the new checkpoint).
        let plan = self
            .inner
            .lab
            .graph
            .lock()
            .unwrap()
            .rewind_plan(self.inner.id, target);
        let (from, suffix) = match plan {
            RewindPlan::Existing(inner) => return Ok(Checkpoint { inner }),
            RewindPlan::Replay { from, suffix } => (Checkpoint { inner: from }, suffix),
            RewindPlan::NoAncestor => return Err(LabError::NoCheckpointBefore { target }),
        };

        let mut tmp = if self.inner.input_source.is_some() {
            // Sourced line: feed the recorded suffix (randomness + I/O) via
            // exit-to-userspace. Correct even if the suffix crosses a
            // branch_with_input_source override, since the recording is the
            // ground truth for what reached the guest.
            from.branch_with_input_source(RecordedInputSource::new(suffix))?
        } else {
            // Seeded line: the VM-state CoW reproduces randomness on its own;
            // re-issue only the recorded I/O suffix on its original schedule.
            let mut branch = from.branch()?;
            for io in suffix.io_inputs() {
                branch.sched_bash(io.at, io.target.clone(), &io.command, io.record_output)?;
            }
            branch
        };

        loop {
            let (at, outcome) = tmp.run_until(target)?;
            match outcome {
                RunOutcome::ReachedTime => break,
                // Recorded I/O responses land mid-replay; keep pumping. `Ready`
                // can recur on a replayed boot segment — also benign here.
                RunOutcome::ActionResponse { .. } | RunOutcome::Ready => continue,
                RunOutcome::RngExhausted => {
                    return Err(LabError::RewindReplayIncomplete { target })
                }
                RunOutcome::Yielded { kind } => return Err(LabError::UnexpectedExit { at, kind }),
            }
        }
        tmp.checkpoint()
    }

    /// Take a read-only snapshot of the entire tree this checkpoint belongs to.
    pub fn tree(&self) -> Tree {
        Tree::from_lab(&self.inner.lab)
    }
}

impl std::fmt::Debug for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checkpoint")
            .field("id", &self.inner.id)
            .field("time", &self.inner.time)
            .finish()
    }
}

impl From<PrefixLoc> for PrefixMatch {
    fn from(loc: PrefixLoc) -> Self {
        PrefixMatch {
            start: Checkpoint { inner: loc.start },
            replay: loc.replay,
            new: loc.new,
            diverges_at: loc.diverges_at,
        }
    }
}

impl Drop for CheckpointInner {
    /// When a checkpoint's last handle goes away, its VM is freed — so tell the
    /// genealogy to forget the registration and prune the now-unanchored node
    /// (unless a [`RetainedInput`] still pins its input prefix). This is the
    /// coordinated eviction that keeps the trie bounded by the live + retained
    /// set rather than growing with every checkpoint ever taken.
    fn drop(&mut self) {
        // Best-effort: a poisoned lock during teardown is not worth panicking in
        // a destructor over. `on_drop` only touches `Weak`s, never strong
        // handles, so it cannot re-enter this `Drop`.
        if let Ok(mut graph) = self.lab.graph.lock() {
            graph.on_drop(self.id);
        }
    }
}

/// A retained input prefix — a corpus entry in the genealogy.
///
/// Created by [`Checkpoint::retain`]. While this handle is alive it anchors the
/// recording's trie node, so the prefix stays known and revivable even after the
/// checkpoint's VM has been dropped. The anchor holds only the (cheap) input
/// recording, never the (expensive) VM. Dropping the handle releases the anchor;
/// the node is then pruned unless something else still anchors it.
pub struct RetainedInput {
    lab: Arc<LabInner>,
    node: NodeId,
    recording: InputRecording,
}

impl RetainedInput {
    /// The retained input recording — the corpus entry, replayable to reconstruct
    /// the checkpoint it was taken from.
    pub fn recording(&self) -> &InputRecording {
        &self.recording
    }

    /// Locate this retained input against the genealogy, as
    /// [`Checkpoint::longest_checkpoint_prefix`] does — the usual way to revive
    /// it: fork [`PrefixMatch::start`] and replay forward. Returns `None` only if
    /// not even the root checkpoint is live.
    pub fn longest_checkpoint_prefix(&self) -> Option<PrefixMatch> {
        let loc = self
            .lab
            .graph
            .lock()
            .unwrap()
            .locate_prefix(&self.recording)?;
        Some(PrefixMatch::from(loc))
    }
}

impl Drop for RetainedInput {
    fn drop(&mut self) {
        if let Ok(mut graph) = self.lab.graph.lock() {
            graph.release(self.node);
        }
    }
}

impl std::fmt::Debug for RetainedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedInput")
            .field("node", &self.node)
            .finish()
    }
}

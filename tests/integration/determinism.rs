//! Determinism of the execution tree: sibling branches forked from one
//! checkpoint produce bit-identical results, and rewinding a checkpoint
//! lands at an earlier — and reproducible — point.

use bedrock_lab::{
    BashTarget, Branch, Checkpoint, EventConfig, ExitCapture, InputSource, IoInput, RunOutcome,
    VirtDuration, VirtTime,
};

use crate::common;

/// Fork a fresh branch off `ready`, capture every exit, drive it through a
/// fixed deterministic workload, and return its normalized exit-record stream
/// (the per-exit guest state: register and device-state hashes, served
/// randomness, injected interrupts, I/O transactions). Two sibling branches
/// that ran this must return byte-identical streams.
fn exit_stream(ready: &Checkpoint) -> Vec<serde_json::Value> {
    let sink = common::capture_sink();
    let mut branch = ready.branch().expect("fork branch");

    // Capture a record for every exit. Memory hashing stays off: register and
    // device-state hashes already pin down divergence, and hashing multi-GB
    // guest memory on every exit would dominate the test's run time.
    branch
        .set_event_config(&EventConfig {
            exits: ExitCapture::AllExits { memory_hash: false },
            ..Default::default()
        })
        .expect("enable exit capture");
    let id = branch.id();

    // Identical deterministic work on both siblings: a bash command (exercises
    // the deterministic I/O channel and a guest-entropy read) followed by a
    // fixed idle advance (exercises deterministic timer-interrupt injection).
    branch
        .bash(
            BashTarget::host(),
            "echo determinism-probe; cat /proc/sys/kernel/random/boot_id",
            true,
        )
        .expect("bash");
    branch.run_for(vt_dur!(50 ms)).expect("idle advance");

    sink.take_deterministic(id)
}

#[test]
fn sibling_branches_are_bit_identical() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("sibling_branches_are_bit_identical");
    };

    let a = exit_stream(&ready);
    let b = exit_stream(&ready);

    assert!(
        !a.is_empty(),
        "expected exit records to be captured — is exit logging wired up?"
    );
    assert_eq!(
        a.len(),
        b.len(),
        "number of deterministic exit records diverged: {} vs {}",
        a.len(),
        b.len(),
    );
    // Compare record-by-record so the first divergence localizes the bug.
    for (i, (ra, rb)) in a.iter().zip(&b).enumerate() {
        assert_eq!(
            ra, rb,
            "guest state diverged at deterministic exit record {i}:\n a={ra}\n b={rb}",
        );
    }
}

#[test]
fn rewind_lands_earlier_and_reproduces() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("rewind_lands_earlier_and_reproduces");
    };

    // Advance a branch a full second past ready, then freeze it.
    let mut branch = ready.branch().expect("fork branch");
    branch.run_for(vt_dur!(1 s)).expect("advance 1s");
    let cp = branch.checkpoint().expect("checkpoint");

    // Rewind half a second. The result must sit strictly before the
    // checkpoint and no earlier than where we started.
    let earlier = cp.rewind(vt_dur!(500 ms)).expect("rewind");
    assert!(
        earlier.time() == cp.time() - vt_dur!(500 ms),
        "rewound checkpoint ({:.3}s) should be exactly 0.5s before cp ({:.3}s)",
        earlier.time().as_secs_f64(),
        cp.time().as_secs_f64(),
    );

    // A branch off the rewound point still runs — rewinding yields a live,
    // forkable checkpoint, not a dead handle.
    let mut resumed = earlier.branch().expect("fork rewound branch");
    let out = resumed
        .bash(BashTarget::host(), "echo post-rewind", true)
        .expect("bash after rewind");
    assert!(
        out.output_lossy().contains("post-rewind"),
        "expected command output after rewind, got {:?}",
        out.output_lossy(),
    );
}

/// A deterministic [`InputSource`]: an LCG randomness stream plus a fixed list
/// of scheduled I/O actions. Cloned per branch, so every replay of the same
/// line sees identical bytes and commands.
#[derive(Clone)]
struct FixedSource {
    rng: u64,
    io: Vec<IoInput>,
    io_pos: usize,
}

impl FixedSource {
    fn new(io: Vec<IoInput>) -> Self {
        Self {
            rng: 0x1234_5678_9abc_def0,
            io,
            io_pos: 0,
        }
    }
}

impl InputSource for FixedSource {
    fn next_rng_u64(&mut self) -> Option<u64> {
        self.rng = self
            .rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        Some(self.rng)
    }

    fn next_io_input(&mut self) -> Option<IoInput> {
        let input = self.io.get(self.io_pos).cloned();
        if input.is_some() {
            self.io_pos += 1;
        }
        input
    }

    fn clone_box(&self) -> Box<dyn InputSource> {
        Box::new(self.clone())
    }
}

/// Drive `branch` to `target`, pumping through scheduled-I/O responses (and the
/// occasional replayed `Ready`). Panics on any other pause reason.
fn drive_to(branch: &mut Branch, target: VirtTime) {
    loop {
        let (_at, outcome) = branch.run_until(target).expect("run_until");
        match outcome {
            RunOutcome::ReachedTime => break,
            RunOutcome::ActionResponse { .. } | RunOutcome::Ready => continue,
            other => panic!("unexpected outcome while driving to {target:?}: {other:?}"),
        }
    }
}

/// Fork a fresh source-driven branch off `cp`, idle-advance it to `until`
/// capturing every exit, and return the normalized exit-record stream. Idle
/// advance alone is enough to expose a wrong base state: each injected timer
/// exit carries a guest register/device-state hash, so two checkpoints holding
/// different state diverge on the very first record.
///
/// Idle (`run_until`) is used rather than a blocking `bash`, because a blocking
/// `bash` on a *sourced* branch can trip over a guest `HYPERCALL_GET_RANDOM`
/// that its inner loop doesn't serve; `run_until` feeds those from the source.
fn forward_stream(cp: &Checkpoint, until: VirtTime) -> Vec<serde_json::Value> {
    let sink = common::capture_sink();
    let mut branch = cp
        .branch_with_input_source(FixedSource::new(Vec::new()))
        .expect("fork sourced branch");
    branch
        .set_event_config(&EventConfig {
            exits: ExitCapture::AllExits { memory_hash: false },
            ..Default::default()
        })
        .expect("enable exit capture");
    let id = branch.id();
    drive_to(&mut branch, until);
    sink.take_deterministic(id)
}

/// Rewinding a *sourced* line must reproduce that line's exact state.
///
/// A sourced line forked off the seeded base tree (the fuzzer's
/// `branch_with_input_source` pattern) consumes inputs that live only in its
/// own recording, not in any ancestor checkpoint. Rewind has to replay those
/// recorded inputs to land back on the line rather than on the seeded state the
/// base tree would reach. This forks such a line, rewinds it, and checks the
/// rewound state against an independently rebuilt reference.
#[test]
fn rewind_reproduces_a_sourced_line() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("rewind_reproduces_a_sourced_line");
    };
    let freq = ready.tsc_frequency();
    let t1 = ready.time() + VirtDuration::from_secs(1, freq);
    let t2 = ready.time() + VirtDuration::from_secs(2, freq);

    // The source schedules a urandom-reading bash inside the [ready, t1] prefix,
    // so the line consumes both randomness (the GET_RANDOM it triggers) and I/O
    // — a correct rewind has to replay both from the recording.
    let io = vec![IoInput {
        at: ready.time() + VirtDuration::from_millis(500, freq),
        target: BashTarget::host(),
        command: "head -c 32 /dev/urandom | od -An -tx1".to_string(),
        record_output: false,
    }];

    // Build the full sourced line to t2 and freeze it.
    let mut line = ready
        .branch_with_input_source(FixedSource::new(io.clone()))
        .expect("fork sourced line");
    drive_to(&mut line, t2);
    let cp = line.checkpoint().expect("checkpoint sourced line");

    // Rewind half-way back.
    let earlier = cp.rewind(t2 - t1).expect("rewind sourced line");
    assert_eq!(
        earlier.time(),
        t1,
        "rewound checkpoint should land exactly at t1"
    );

    // Independently rebuild the *correct* state at t1 by replaying the same
    // source from scratch — a known-good reference.
    let mut reference = ready
        .branch_with_input_source(FixedSource::new(io))
        .expect("fork reference line");
    drive_to(&mut reference, t1);
    let cp_ref = reference.checkpoint().expect("checkpoint reference");

    // Equal state ⇒ identical forward behavior. A wrong rewind diverges at once.
    let t3 = t1 + VirtDuration::from_secs(1, freq);
    let rewound_stream = forward_stream(&earlier, t3);
    let reference_stream = forward_stream(&cp_ref, t3);

    assert!(
        !rewound_stream.is_empty(),
        "expected exit records from the forward replay"
    );
    assert_eq!(
        rewound_stream.len(),
        reference_stream.len(),
        "rewound and reference forward streams differ in length: {} vs {}",
        rewound_stream.len(),
        reference_stream.len(),
    );
    for (i, (a, b)) in rewound_stream.iter().zip(&reference_stream).enumerate() {
        assert_eq!(
            a, b,
            "rewound state diverged from the reference at forward exit {i}:\n rewound={a}\n ref={b}",
        );
    }
}

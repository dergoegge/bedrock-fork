//! Genealogy trie, exercised by long lines of checkpoints.
//!
//! Each `bash` call a branch makes appends to its input recording, so a chain
//! of bash-then-checkpoint steps interns a deep path in the genealogy radix
//! tree — one node per recorded input, a checkpoint at each step's prefix. These
//! tests walk such chains to check ancestry and rewind end to end: the
//! trie-derived parent of a checkpoint is the step before it, divergent branches
//! share their fork point, and rewinding to a step's exact time dedups back to
//! the interned checkpoint instead of replaying.
//!
//! The genealogy is *content-addressed*: a checkpoint is identified by the
//! inputs that produced it. Execution is deterministic, so two branches that run
//! identical commands reach bit-identical states and collide on the same trie
//! node — by design. Each test therefore tags its `bash` commands with a unique
//! string so its checkpoints don't collide with another (parallel) test's.

use bedrock_lab::{
    BashTarget, Branch, Checkpoint, InputRecording, InputSource, IoInput, RunOutcome, VirtTime,
};

use crate::common;

/// Build a chain of `len` checkpoints off `ready`, each one bash call deeper
/// than the last. `tag` makes this chain's commands — and so its recordings and
/// checkpoints — unique to the calling test. Returns `len + 1` checkpoints,
/// `ready` first.
fn bash_chain(ready: &Checkpoint, tag: &str, len: usize) -> Vec<Checkpoint> {
    let mut chain = vec![ready.clone()];
    for i in 0..len {
        let mut branch = chain[i].branch().expect("fork branch");
        let out = branch
            .bash(BashTarget::host(), &format!("echo {tag}-step-{i}"), true)
            .expect("bash");
        assert!(
            out.success(),
            "bash step {i} failed: status={} exit={}",
            out.status,
            out.exit_code,
        );
        chain.push(branch.checkpoint().expect("checkpoint"));
    }
    chain
}

#[test]
fn long_bash_chain_builds_a_linear_genealogy() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("long_bash_chain_builds_a_linear_genealogy");
    };

    let chain = bash_chain(&ready, "lin", 8);

    // Every step strictly extends the previous recording (at least its own I/O
    // request) and advances virtual time — so the chain is a single descending
    // path, never a collision.
    for pair in chain.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        assert!(
            next.time() > prev.time(),
            "checkpoint time should advance along the chain"
        );
        let prev_io = prev.input_recording().io_inputs().len();
        let next_io = next.input_recording().io_inputs().len();
        assert!(
            next_io > prev_io,
            "each bash should add an I/O input to the recording: {prev_io} -> {next_io}"
        );
    }

    // The trie-derived parent of each checkpoint is exactly the step before it
    // (its closest shorter input prefix); the root has none.
    assert!(
        chain[0].parent().is_none(),
        "the ready checkpoint is the root of the tree"
    );
    for i in 1..chain.len() {
        let parent = chain[i].parent().expect("non-root checkpoint has a parent");
        assert_eq!(
            parent.id(),
            chain[i - 1].id(),
            "checkpoint {i}'s parent should be the previous step ({})",
            i - 1,
        );
    }

    // Rewinding the tip back to any earlier step's exact time returns that very
    // checkpoint (same id): the trie already holds a node at that (input prefix,
    // time), so rewind dedups to it rather than forking and replaying.
    let tip = chain.last().expect("non-empty chain");
    for (i, target) in chain[..chain.len() - 1].iter().enumerate() {
        let rewound = tip
            .rewind(tip.time() - target.time())
            .expect("rewind to an interned checkpoint");
        assert_eq!(
            rewound.id(),
            target.id(),
            "rewinding the tip to step {i} (t={:.3}s) should return the interned \
             checkpoint, not a fresh replay",
            target.time().as_secs_f64(),
        );
        assert_eq!(rewound.time(), target.time());
    }
}

#[test]
fn branches_from_a_midpoint_share_their_origin() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("branches_from_a_midpoint_share_their_origin");
    };

    // Drive a short chain, then fork two divergent lines from its tip.
    let chain = bash_chain(&ready, "fork", 3);
    let fork = chain.last().expect("non-empty chain").clone();

    let mut a = fork.branch().expect("fork branch a");
    a.bash(BashTarget::host(), "echo fork-branch-a", true)
        .expect("bash a");
    let cp_a = a.checkpoint().expect("checkpoint a");

    let mut b = fork.branch().expect("fork branch b");
    b.bash(BashTarget::host(), "echo fork-branch-b", true)
        .expect("bash b");
    let cp_b = b.checkpoint().expect("checkpoint b");

    // Divergent commands ⇒ divergent recordings ⇒ distinct trie nodes.
    assert_ne!(
        cp_a.id(),
        cp_b.id(),
        "two branches that ran different commands must be distinct checkpoints"
    );

    // Both diverged from `fork`, so it is the parent of each — the trie split at
    // the first differing input, below their shared prefix.
    assert_eq!(
        cp_a.parent().expect("a has a parent").id(),
        fork.id(),
        "branch a's parent is the fork point"
    );
    assert_eq!(
        cp_b.parent().expect("b has a parent").id(),
        fork.id(),
        "branch b's parent is the fork point"
    );

    // Rewinding either tip to the fork's time dedups back to the fork point,
    // confirming it stayed on both lines' prefix after the split.
    for tip in [&cp_a, &cp_b] {
        let rewound = tip
            .rewind(tip.time() - fork.time())
            .expect("rewind to the fork point");
        assert_eq!(
            rewound.id(),
            fork.id(),
            "rewinding to the fork time should return the shared origin checkpoint"
        );
    }
}

/// A deterministic [`InputSource`]: a fixed RNG value plus a scripted list of
/// [`IoInput`]s, each firing at its own `at` time. Cloned per branch so sibling
/// lines that share a script see identical inputs.
#[derive(Clone)]
struct ScriptedSource {
    io: Vec<IoInput>,
    pos: usize,
}

impl ScriptedSource {
    fn new(io: Vec<IoInput>) -> Self {
        Self { io, pos: 0 }
    }
}

impl InputSource for ScriptedSource {
    fn next_rng_u64(&mut self) -> Option<u64> {
        Some(0xD1CE_D1CE_D1CE_D1CE)
    }

    fn next_io_input(&mut self) -> Option<IoInput> {
        let input = self.io.get(self.pos).cloned();
        if input.is_some() {
            self.pos += 1;
        }
        input
    }

    fn clone_box(&self) -> Box<dyn InputSource> {
        Box::new(self.clone())
    }
}

/// The `command`s of a recording's I/O inputs, in order. Lets a test assert
/// which scripted commands landed in a span without depending on the
/// (guest-driven) randomness tokens that interleave them.
fn io_commands(rec: &InputRecording) -> Vec<String> {
    rec.io_inputs().iter().map(|i| i.command.clone()).collect()
}

/// The recorded emit time of the I/O input carrying `command`.
fn io_time(rec: &InputRecording, command: &str) -> VirtTime {
    rec.io_inputs()
        .iter()
        .find(|i| i.command == command)
        .unwrap_or_else(|| panic!("recording has an I/O input {command:?}"))
        .at
}

/// One scripted host command, scheduled to fire at virtual time `at`.
fn io_at(at: VirtTime, command: &str) -> IoInput {
    IoInput {
        at,
        target: BashTarget::host(),
        command: command.to_string(),
        record_output: false,
    }
}

/// Drive `branch` to `target`, pumping through the scheduled-I/O responses its
/// source injects along the way.
fn drive_to(branch: &mut Branch, target: VirtTime) {
    loop {
        let (_at, outcome) = branch.run_until(target).expect("run_until");
        match outcome {
            RunOutcome::ReachedTime => break,
            RunOutcome::ActionResponse { .. } | RunOutcome::Ready => continue,
            other => panic!("unexpected outcome driving to {target:?}: {other:?}"),
        }
    }
}

/// Rewinding one branch of a fork into its *own* divergent segment splits the
/// tree: it interns a checkpoint between the fork point and that branch's tip,
/// so two branches that started with a common parent end up with different
/// parents.
///
/// The inputs are scripted with explicit `at` times rather than driven by
/// `bash`/`sleep`, so the c/d divergence sits at an exact virtual time and the
/// rewind below lands squarely in the post-divergence segment.
#[test]
fn rewind_splits_tree() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("rewind_splits_tree");
    };

    // Shared actions a, b; then a divergent c / d at t_cd. Run on well past the
    // divergence so the rewind has room to land after it.
    let t_a = ready.time() + vt_dur!(1 s);
    let t_b = ready.time() + vt_dur!(2 s);
    let t_cd = ready.time() + vt_dur!(3 s);
    let end = ready.time() + vt_dur!(5 s);

    let abc_script = vec![
        io_at(t_a, "echo rsplit-a"),
        io_at(t_b, "echo rsplit-b"),
        io_at(t_cd, "echo rsplit-c"),
    ];
    let abd_script = vec![
        io_at(t_a, "echo rsplit-a"),
        io_at(t_b, "echo rsplit-b"),
        io_at(t_cd, "echo rsplit-d"),
    ];

    let mut abc = ready
        .branch_with_input_source(ScriptedSource::new(abc_script))
        .expect("fork abc");
    drive_to(&mut abc, end);
    let cp_abc = abc.checkpoint().expect("checkpoint abc");

    let mut abd = ready
        .branch_with_input_source(ScriptedSource::new(abd_script))
        .expect("fork abd");
    drive_to(&mut abd, end);
    let cp_abd = abd.checkpoint().expect("checkpoint abd");

    // The two lines share their [a, b] prefix and diverge only at c / d, so they
    // start with the same parent (the checkpoint they both forked from).
    let origin = cp_abc.parent().expect("abc has a parent");
    assert_eq!(
        origin.id(),
        cp_abd.parent().expect("abd has a parent").id(),
        "abc and abd share a parent before the rewind",
    );

    // Rewind abd into its own d-segment, after the c/d divergence at t_cd. The
    // rewound checkpoint's recording is [a, b, d, ...] — on abd's line but not
    // abc's — so it becomes abd's new parent without touching abc's.
    let rewound = cp_abd
        .rewind(vt_dur!(500 ms))
        .expect("rewind into the d-segment");
    assert!(
        rewound.time() > t_cd,
        "the rewind must land after the c/d divergence to stay on abd's line",
    );

    assert_eq!(
        cp_abd.parent().expect("abd has a parent").id(),
        rewound.id(),
        "the rewound checkpoint becomes abd's parent",
    );
    assert_eq!(
        rewound.parent().expect("rewound has a parent").id(),
        origin.id(),
        "the rewound checkpoint descends from the original common parent",
    );
    assert_ne!(
        cp_abc.parent().expect("abc has a parent").id(),
        cp_abd.parent().expect("abd has a parent").id(),
        "abc and abd now have different parents — the tree split",
    );
}

/// Materializing the shared `[a, b]` prefix as its own checkpoint — *after* the
/// divergent `abc`/`abd` already exist — makes it their common parent.
///
/// The genealogy is content-addressed: `ab`'s recording is a literal prefix of
/// both `abc`'s and `abd`'s, and its state is bit-identical to the point they
/// shared before diverging. So `parent()` (deepest checkpoint whose recording is
/// a prefix, frozen no later) resolves to `ab` for both. This is *dynamic* — it
/// re-parents `abc`/`abd` away from the root they originally forked from, purely
/// by interning a checkpoint that lands on their shared path.
#[test]
fn materializing_a_shared_prefix_reparents_descendants() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("materializing_a_shared_prefix_reparents_descendants");
    };

    let t_a = ready.time() + vt_dur!(1 s);
    let t_b = ready.time() + vt_dur!(2 s);
    let t_cd = ready.time() + vt_dur!(3 s);
    let end = ready.time() + vt_dur!(5 s);

    // abc and abd: identical [a, b], diverging only at c / d.
    let mut abc = ready
        .branch_with_input_source(ScriptedSource::new(vec![
            io_at(t_a, "reparent-a"),
            io_at(t_b, "reparent-b"),
            io_at(t_cd, "reparent-c"),
        ]))
        .expect("fork abc");
    drive_to(&mut abc, end);
    let cp_abc = abc.checkpoint().expect("checkpoint abc");

    let mut abd = ready
        .branch_with_input_source(ScriptedSource::new(vec![
            io_at(t_a, "reparent-a"),
            io_at(t_b, "reparent-b"),
            io_at(t_cd, "reparent-d"),
        ]))
        .expect("fork abd");
    drive_to(&mut abd, end);
    let cp_abd = abd.checkpoint().expect("checkpoint abd");

    // Before `ab` exists they share a parent — the root they both forked from.
    let origin = cp_abc.parent().expect("abc has a parent");
    assert_eq!(
        origin.id(),
        cp_abd.parent().expect("abd has a parent").id(),
        "abc and abd share a parent before `ab` exists",
    );

    // Now run just [a, b] and freeze between b (2s) and the c/d divergence (3s),
    // so `ab`'s recording is a strict prefix of both abc's and abd's.
    let mut ab = ready
        .branch_with_input_source(ScriptedSource::new(vec![
            io_at(t_a, "reparent-a"),
            io_at(t_b, "reparent-b"),
        ]))
        .expect("fork ab");
    drive_to(&mut ab, t_b + vt_dur!(500 ms));
    let cp_ab = ab.checkpoint().expect("checkpoint ab");

    assert!(
        cp_ab.time() > t_b && cp_ab.time() < t_cd,
        "ab must freeze on the shared prefix, after b and before the c/d split",
    );
    assert_ne!(
        cp_ab.id(),
        origin.id(),
        "ab is a fresh checkpoint below the root"
    );

    // ab is now the common parent of both divergent lines — they were re-parented
    // off the root onto it.
    assert_eq!(
        cp_abc.parent().expect("abc has a parent").id(),
        cp_ab.id(),
        "ab becomes abc's parent",
    );
    assert_eq!(
        cp_abd.parent().expect("abd has a parent").id(),
        cp_ab.id(),
        "ab becomes abd's parent",
    );
    // ab itself still descends from the original common ancestor.
    assert_eq!(
        cp_ab.parent().expect("ab has a parent").id(),
        origin.id(),
        "ab descends from the original common ancestor",
    );
}

/// Build `abc` and `abd` checkpoints off `ready` sharing an `[a, b]` prefix and
/// diverging at `c`/`d`, then return the recording a third line `abx` (same
/// `[a, b]`, divergent `x`) produces *without* interning it — the candidate to
/// classify against the tree.
///
/// The `abc`/`abd` checkpoints are returned so the caller keeps them alive: a
/// dropped checkpoint is now pruned from the genealogy, so without holding them
/// their shared `[a, b]` path (and the c/d split) would vanish.
fn abc_abd_tree_and_abx(
    ready: &Checkpoint,
    tag: &str,
) -> (Vec<Checkpoint>, VirtTime, InputRecording) {
    let t_a = ready.time() + vt_dur!(1 s);
    let t_b = ready.time() + vt_dur!(2 s);
    let t_cd = ready.time() + vt_dur!(3 s);
    let end = ready.time() + vt_dur!(5 s);

    let mut tips = Vec::new();
    for last in ["c", "d"] {
        let mut br = ready
            .branch_with_input_source(ScriptedSource::new(vec![
                io_at(t_a, &format!("{tag}-a")),
                io_at(t_b, &format!("{tag}-b")),
                io_at(t_cd, &format!("{tag}-{last}")),
            ]))
            .unwrap_or_else(|_| panic!("fork ab{last}"));
        drive_to(&mut br, end);
        tips.push(
            br.checkpoint()
                .unwrap_or_else(|_| panic!("checkpoint ab{last}")),
        );
    }

    // `abx`: same shared prefix, a third divergent tail. Drive it but do NOT
    // checkpoint, so the candidate's own `x` path stays uninterned.
    let mut abx = ready
        .branch_with_input_source(ScriptedSource::new(vec![
            io_at(t_a, &format!("{tag}-a")),
            io_at(t_b, &format!("{tag}-b")),
            io_at(t_cd, &format!("{tag}-x")),
        ]))
        .expect("fork abx");
    drive_to(&mut abx, end);
    (tips, t_cd, abx.input_recording().clone())
}

/// With checkpoints only at the divergent tips `abc`/`abd` (none on the shared
/// `ab` prefix), classifying `abx` starts from the root and replays the shared
/// `[a, b]`; only `x` is new — the boundary sitting at the c/d/x divergence.
#[test]
fn longest_prefix_replays_shared_prefix_and_marks_new() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("longest_prefix_replays_shared_prefix_and_marks_new");
    };

    // `_tips` keeps abc/abd alive so the shared `[a, b]` path and c/d split stay
    // in the genealogy (a dropped checkpoint is pruned).
    let (_tips, _t_cd, candidate) = abc_abd_tree_and_abx(&ready, "lpn");
    let res = ready
        .longest_checkpoint_prefix(&candidate)
        .expect("a checkpoint (at least the root) is a prefix");

    // No checkpoint sits on the shared prefix, so the deepest one that is a
    // prefix of `abx` is the root the divergent lines forked from.
    assert_eq!(
        res.start.id(),
        ready.id(),
        "start from the root when nothing on the shared prefix is checkpointed",
    );

    // `[a, b]` are replayed (previously executed, no checkpoint kept); `x` is new.
    let replay = io_commands(&res.replay);
    let new = io_commands(&res.new);
    assert!(
        replay.iter().any(|c| c == "lpn-a") && replay.iter().any(|c| c == "lpn-b"),
        "the shared a/b commands are replay territory: {replay:?}",
    );
    assert!(
        !replay.iter().any(|c| c == "lpn-x"),
        "the divergent x must not be in the replay span: {replay:?}",
    );
    assert!(
        new.iter().any(|c| c == "lpn-x"),
        "the divergent x is the new path: {new:?}",
    );
    assert!(
        !new.iter().any(|c| c == "lpn-a" || c == "lpn-b"),
        "the shared a/b must not be in the new span: {new:?}",
    );

    // The replay/new boundary is the virtual time of the first diverging input.
    assert_eq!(
        res.diverges_at,
        Some(io_time(&candidate, "lpn-x")),
        "divergence is reported at the c/d/x split's virtual time",
    );
}

/// Materializing a checkpoint on the shared `ab` prefix makes it the start: `abx`
/// then forks straight from `ab` with nothing to replay through (no shared input
/// remains between `ab` and the divergence) — only `x` is new. The divergence
/// time still lands ahead of `ab`'s freeze, so the *time* between them is replay
/// ground even though no input falls in it.
#[test]
fn longest_prefix_starts_from_a_checkpoint_on_the_shared_prefix() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("longest_prefix_starts_from_a_checkpoint_on_the_shared_prefix");
    };

    let t_a = ready.time() + vt_dur!(1 s);
    let t_b = ready.time() + vt_dur!(2 s);

    let (_tips, t_cd, candidate) = abc_abd_tree_and_abx(&ready, "lps");

    // Freeze `ab` between b and the c/d/x divergence, so its recording is a
    // strict prefix of the candidate's.
    let mut ab = ready
        .branch_with_input_source(ScriptedSource::new(vec![
            io_at(t_a, "lps-a"),
            io_at(t_b, "lps-b"),
        ]))
        .expect("fork ab");
    drive_to(&mut ab, t_b + vt_dur!(500 ms));
    let cp_ab = ab.checkpoint().expect("checkpoint ab");
    assert!(
        cp_ab.time() > t_b && cp_ab.time() < t_cd,
        "ab must freeze on the shared prefix, after b and before the c/d split",
    );

    let res = ready
        .longest_checkpoint_prefix(&candidate)
        .expect("a checkpoint is a prefix");

    assert_eq!(
        res.start.id(),
        cp_ab.id(),
        "the deepest checkpoint on the shared prefix is the start",
    );
    // No scripted command needs replaying — `ab` already captured a and b, and x
    // is past the divergence.
    assert!(
        io_commands(&res.replay).is_empty(),
        "no scripted input remains to replay between ab and the divergence: {:?}",
        io_commands(&res.replay),
    );
    assert!(
        io_commands(&res.new).iter().any(|c| c == "lps-x"),
        "x is the new path",
    );
    // The boundary is still the divergence time, which is strictly after ab's
    // freeze: that gap is replay ground (a pure time advance, no input in it).
    let diverges_at = res.diverges_at.expect("the candidate diverges at x");
    assert_eq!(diverges_at, io_time(&candidate, "lps-x"));
    assert!(
        diverges_at > cp_ab.time(),
        "replay still advances time from ab's freeze to the divergence",
    );
}

/// A candidate that never leaves known ground (it equals an existing line's
/// recording) has no new span: the deepest checkpoint on it is its own tip, and
/// `diverges_at` is `None`. Also exercises the `RecordedInputSource` convenience.
#[test]
fn longest_prefix_of_fully_known_path_has_no_new_span() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("longest_prefix_of_fully_known_path_has_no_new_span");
    };

    let chain = bash_chain(&ready, "lpf", 3);
    let tip = chain.last().expect("non-empty chain");

    let res = ready
        .longest_checkpoint_prefix(tip.input_recording())
        .expect("the tip's own recording is a prefix of itself");

    assert_eq!(
        res.start.id(),
        tip.id(),
        "the deepest checkpoint on a fully-known recording is its own tip",
    );
    assert_eq!(
        res.new,
        InputRecording::new(),
        "a fully-known candidate has no new inputs",
    );
    assert_eq!(
        res.replay,
        InputRecording::new(),
        "starting at the tip leaves nothing to replay",
    );
    assert!(
        res.diverges_at.is_none(),
        "a candidate that never diverges has no divergence time",
    );

    // Same query via the RecordedInputSource convenience.
    let via_source = ready
        .longest_checkpoint_prefix_of(&tip.input_recording_to_source())
        .expect("recorded source resolves the same way");
    assert_eq!(via_source.start.id(), tip.id());
    assert!(via_source.diverges_at.is_none());
}

/// A dropped checkpoint is forgotten by the genealogy: its node is pruned, so it
/// is no longer a start point and its path reads as new ground again. This is the
/// coordinated eviction — the lab's drop hook prunes, so the trie doesn't leak.
#[test]
fn dropping_a_checkpoint_prunes_it_from_the_genealogy() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("dropping_a_checkpoint_prunes_it_from_the_genealogy");
    };

    let chain = bash_chain(&ready, "prune", 1);
    let r1 = chain[1].input_recording().clone();

    // While `cp1` is live it is the deepest checkpoint on its own recording.
    // (Inline temporaries so the returned PrefixMatch — which clones cp1's Arc —
    // drops immediately and doesn't itself keep cp1 alive.)
    assert_eq!(
        ready.longest_checkpoint_prefix(&r1).unwrap().start.id(),
        chain[1].id(),
        "a live checkpoint is the start for its own recording",
    );
    assert!(
        ready
            .longest_checkpoint_prefix(&r1)
            .unwrap()
            .diverges_at
            .is_none(),
        "its own recording never diverges",
    );

    // Drop cp1: `chain` holds the only strong handle to it, while the outer
    // `ready` keeps the root alive. Its VM is freed and its node pruned.
    drop(chain);

    let after = ready
        .longest_checkpoint_prefix(&r1)
        .expect("the root is still a prefix");
    assert_eq!(
        after.start.id(),
        ready.id(),
        "with cp1 gone the deepest live checkpoint is the root",
    );
    assert!(
        after.diverges_at.is_some(),
        "cp1's pruned path now reads as new ground",
    );
}

/// A retained input is a corpus entry: its checkpoint's VM can be dropped, yet
/// the input prefix stays in the genealogy — classifiable as known and
/// **revivable** (replayable from the deepest live ancestor). Releasing the
/// handle prunes it. This is the corpus-on-top model: pin the cheap input, not
/// the expensive VM.
#[test]
fn retained_input_survives_checkpoint_drop_and_is_revivable() {
    let Some(ready) = common::ready_checkpoint() else {
        return common::skip("retained_input_survives_checkpoint_drop_and_is_revivable");
    };

    let chain = bash_chain(&ready, "retain", 1);
    let r1 = chain[1].input_recording().clone();
    // Admit cp1's input to the corpus — this pins the input, not the VM.
    let retained = chain[1].retain();

    // Drop the checkpoint's VM (chain holds the only strong handle; `ready` keeps
    // the root alive). The retained anchor must keep the input prefix alive.
    drop(chain);

    let m = ready
        .longest_checkpoint_prefix(&r1)
        .expect("the root is a prefix");
    // No live checkpoint sits on the path, so the start falls back to the root —
    // but the whole recording is still *known* (retained), so it is all replay (a
    // revival) with nothing new.
    assert_eq!(
        m.start.id(),
        ready.id(),
        "start falls back to the live root"
    );
    assert!(
        m.diverges_at.is_none(),
        "the retained path is fully known — revival, not new exploration",
    );
    assert!(
        io_commands(&m.replay)
            .iter()
            .any(|c| c.contains("retain-step-0")),
        "the retained input is the replay (revival) span: {:?}",
        io_commands(&m.replay),
    );
    assert_eq!(m.new, InputRecording::new(), "nothing is new");
    drop(m);

    // The handle's own revival query agrees.
    let via = retained
        .longest_checkpoint_prefix()
        .expect("retained input locates against the live tree");
    assert_eq!(via.start.id(), ready.id());
    assert!(via.diverges_at.is_none());
    drop(via);

    // Releasing the corpus anchor prunes the input prefix: it now reads as new.
    drop(retained);
    let after = ready
        .longest_checkpoint_prefix(&r1)
        .expect("the root is still a prefix");
    assert!(
        after.diverges_at.is_some(),
        "after releasing the retained anchor the path is pruned",
    );
}

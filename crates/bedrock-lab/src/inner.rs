// SPDX-License-Identifier: GPL-2.0

//! Internal shared state.
//!
//! `LabInner` is the genealogy registry shared by all live [`Checkpoint`]
//! handles and by every live [`Branch`]. Checkpoints register themselves as
//! `Weak` references so the registry never extends their lifetime. Branches —
//! which are non-`Clone` owning handles — register lightweight by-value
//! metadata that they remove on drop or when consumed by `Branch::checkpoint`.
//!
//! The checkpoint side of the registry is a **radix tree over the input
//! recording** (the generic structure lives in [`crate::radix`]; this module
//! adds the checkpoint semantics). Each checkpoint's [`InputRecording`]
//! linearizes to a single canonical token sequence (see
//! [`InputRecording::linearize`]); a checkpoint is interned at the trie node
//! whose root-to-node path equals that sequence. Because the recording is the
//! complete, deterministic record of everything non-deterministic that reached
//! the guest, this makes "B descends from A" exactly "A's recording is a prefix
//! of B's" — a content-addressed relation keyed purely on the inputs. Two
//! checkpoints that share an input prefix share a path; they diverge at the
//! first differing input. Checkpoints that consumed the *same* inputs but were
//! frozen at different virtual times (a pure time advance with no inputs
//! between) live in the same node, ordered by time.
//!
//! [`Checkpoint::rewind`](crate::Checkpoint::rewind) is then a prefix query
//! ([`Genealogy::rewind_plan`]): truncate the recording at the target time, find
//! the deepest existing checkpoint on that prefix, and replay the recorded
//! suffix forward. The trie *is* the ancestry: a checkpoint's parent is the
//! nearest checkpoint on a shorter prefix.

use std::collections::{BTreeMap, HashMap};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, Weak,
};

use crate::branch::BranchId;
use crate::checkpoint::{Checkpoint, CheckpointId, CheckpointInner};
use crate::event::EventSink;
use crate::radix::{NodeId, RadixTree};
use crate::rng::{InputRecording, RecordingToken};
use crate::time::VirtTime;

/// Metadata about a live branch, kept in [`LabInner::live_branches`] so the
/// tree view can show branches the user is currently holding.
#[derive(Debug, Clone)]
pub(crate) struct BranchMeta {
    pub(crate) id: BranchId,
    pub(crate) origin: crate::checkpoint::CheckpointId,
    pub(crate) current_time: VirtTime,
}

/// Shared lab state. One instance per execution tree, held by every node
/// (checkpoint or branch) in the tree via [`Arc`].
pub(crate) struct LabInner {
    pub(crate) tsc_frequency: u64,
    next_checkpoint_id: AtomicU64,
    next_branch_id: AtomicU64,
    pub(crate) graph: Mutex<Genealogy>,
    pub(crate) live_branches: Mutex<HashMap<BranchId, BranchMeta>>,
    pub(crate) sink: Arc<dyn EventSink>,
}

impl LabInner {
    pub(crate) fn new(tsc_frequency: u64, sink: Arc<dyn EventSink>) -> Arc<Self> {
        Arc::new(Self {
            tsc_frequency,
            next_checkpoint_id: AtomicU64::new(0),
            // BranchId(0) is reserved for root-VM boot/setup events emitted
            // before the ready checkpoint exists.
            next_branch_id: AtomicU64::new(1),
            graph: Mutex::new(Genealogy::default()),
            live_branches: Mutex::new(HashMap::new()),
            sink,
        })
    }

    pub(crate) fn next_checkpoint_id(&self) -> u64 {
        self.next_checkpoint_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn next_branch_id(&self) -> u64 {
        self.next_branch_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// The per-node value in the genealogy trie. A node is kept while it is
/// *anchored* — it holds a live checkpoint, or it has been retained as a corpus
/// entry — and is pruned otherwise (see [`anchored`] and [`Genealogy::on_drop`]).
#[derive(Default)]
pub(crate) struct NodeData {
    /// Checkpoints interned here: those whose recording linearizes to exactly
    /// this node's path, keyed by the virtual time they were frozen at. Held as
    /// `Weak` — whoever holds the [`Checkpoint`] handles (e.g. a fuzzer's live
    /// LRU) owns the VM's lifetime — and tagged with the id so a dropping
    /// checkpoint removes its own entry. A `Vec` per time tolerates the (rare)
    /// case of two distinct checkpoints at the same prefix and time.
    live: BTreeMap<VirtTime, Vec<(CheckpointId, Weak<CheckpointInner>)>>,
    /// How many [`RetainedInput`](crate::RetainedInput) handles pin this node's
    /// input prefix. While `> 0` the node survives with no live checkpoint, so
    /// the prefix stays revivable — this is the corpus anchor, holding only the
    /// (cheap) input path, never the (expensive) VM.
    retained: usize,
}

/// Whether `data` must keep its node alive: it still holds a live checkpoint, or
/// it is retained as a corpus entry. An unanchored node is pruned.
fn anchored(data: &NodeData) -> bool {
    data.retained > 0
        || data
            .live
            .values()
            .any(|cps| cps.iter().any(|(_, w)| w.strong_count() > 0))
}

/// Where a registered checkpoint lives in the trie.
struct CpLoc {
    node: NodeId,
    time: VirtTime,
    weak: Weak<CheckpointInner>,
}

/// The checkpoint genealogy: a [`RadixTree`] keyed on the linearized input
/// recording, with a time-ordered bucket of checkpoints at every node. See the
/// [module docs](self) for the model.
pub(crate) struct Genealogy {
    tree: RadixTree<RecordingToken, NodeData>,
    /// Fast lookup from a checkpoint id to its node, freeze time, and handle.
    index: HashMap<CheckpointId, CpLoc>,
}

impl Default for Genealogy {
    fn default() -> Self {
        Self {
            tree: RadixTree::new(),
            index: HashMap::new(),
        }
    }
}

/// The action [`Checkpoint::rewind`](crate::Checkpoint::rewind) should take to
/// reach a target virtual time, decided entirely from the trie.
pub(crate) enum RewindPlan {
    /// A checkpoint already sits at exactly the target `(input prefix, time)`;
    /// return it directly without replaying.
    Existing(Arc<CheckpointInner>),
    /// Fork `from` (the deepest checkpoint on the target's input prefix at or
    /// before the target time) and replay `suffix` — the exact recorded inputs
    /// between `from` and the target — forward to the target time.
    Replay {
        from: Arc<CheckpointInner>,
        suffix: InputRecording,
    },
    /// No checkpoint exists at or before the target time (the target precedes
    /// the root checkpoint).
    NoAncestor,
}

/// Where a candidate input recording sits relative to the executed tree, as
/// resolved by [`Genealogy::locate_prefix`].
pub(crate) struct PrefixLoc {
    /// Deepest live checkpoint whose recording is a prefix of the candidate —
    /// the best place to fork from.
    pub(crate) start: Arc<CheckpointInner>,
    /// Recorded inputs between `start` and the divergence point: the matching
    /// tail to replay forward from `start`.
    pub(crate) replay: InputRecording,
    /// Candidate inputs from the divergence point onward — the never-executed
    /// path. Empty when the candidate stays entirely on known ground.
    pub(crate) new: InputRecording,
    /// Virtual time at which the candidate first leaves every known path — the
    /// boundary between `replay` and `new`. `None` when it never diverges.
    pub(crate) diverges_at: Option<VirtTime>,
}

impl Genealogy {
    /// Intern a checkpoint by its input recording. The checkpoint is stored as a
    /// `Weak`, so the registry never keeps it alive.
    pub(crate) fn register(&mut self, cp: &Arc<CheckpointInner>) {
        let tokens = cp.input_recording.linearize();
        let node = self.tree.insert(&tokens);
        self.tree
            .value_mut(node)
            .live
            .entry(cp.time)
            .or_default()
            .push((cp.id, Arc::downgrade(cp)));
        self.index.insert(
            cp.id,
            CpLoc {
                node,
                time: cp.time,
                weak: Arc::downgrade(cp),
            },
        );
    }

    /// Called from [`CheckpointInner`]'s drop — the checkpoint `id`'s VM is going
    /// away (e.g. evicted from the live LRU). Forget its registration and, if its
    /// node is no longer anchored, prune the node and any now-redundant ancestors,
    /// restoring compression. A node still anchored by a retained-input handle
    /// survives, so its input prefix stays revivable. This is the coordinated
    /// eviction that keeps the trie from accumulating dead entries.
    pub(crate) fn on_drop(&mut self, id: CheckpointId) {
        let Some(loc) = self.index.remove(&id) else {
            return;
        };
        let data = self.tree.value_mut(loc.node);
        if let Some(cps) = data.live.get_mut(&loc.time) {
            cps.retain(|(cid, _)| *cid != id);
            if cps.is_empty() {
                data.live.remove(&loc.time);
            }
        }
        self.tree.prune_upward(loc.node, anchored);
    }

    /// Pin the node for `recording` as a corpus entry so its input prefix is
    /// retained — and thus stays revivable — even after its checkpoint's VM is
    /// dropped. Returns the node id for the [`RetainedInput`](crate::RetainedInput)
    /// handle to [`release`](Self::release) later. Re-retaining the same recording
    /// just bumps the anchor count.
    pub(crate) fn retain(&mut self, recording: &InputRecording) -> NodeId {
        let node = self.tree.insert(&recording.linearize());
        self.tree.value_mut(node).retained += 1;
        node
    }

    /// Release one retained-input anchor on `node`. If that was the last anchor
    /// and no live checkpoint remains, the node is pruned.
    pub(crate) fn release(&mut self, node: NodeId) {
        let data = self.tree.value_mut(node);
        data.retained = data.retained.saturating_sub(1);
        self.tree.prune_upward(node, anchored);
    }

    /// Every live checkpoint in the tree, sorted by id. Dropped checkpoints
    /// (whose `Weak` no longer upgrades) are filtered out.
    pub(crate) fn checkpoints(&self) -> Vec<Checkpoint> {
        let mut checkpoints: Vec<_> = self
            .index
            .values()
            .filter_map(|loc| loc.weak.upgrade())
            .map(|inner| Checkpoint { inner })
            .collect();
        checkpoints.sort_by_key(|cp| cp.id());
        checkpoints
    }

    /// The parent checkpoint of `id`: the closest ancestor on its line — the
    /// nearest checkpoint whose recording is a prefix of `id`'s and which was
    /// frozen no later than `id`. `None` for the root.
    ///
    /// "Closest" walks up the trie from `id`'s node: within the same node (same
    /// recording) the parent is the latest strictly-earlier checkpoint; failing
    /// that, the latest checkpoint at or before `id`'s time on each shallower
    /// ancestor node, taking the first one found.
    pub(crate) fn parent(&self, id: CheckpointId) -> Option<Arc<CheckpointInner>> {
        let loc = self.index.get(&id)?;
        let mut node = loc.node;
        let mut same_node = true;
        loop {
            if let Some(arc) = latest_before(self.tree.value(node), loc.time, same_node, id) {
                return Some(arc);
            }
            node = self.tree.parent(node)?;
            same_node = false;
        }
    }

    /// Decide how to rewind the checkpoint `id` to `target`. See [`RewindPlan`].
    pub(crate) fn rewind_plan(&self, id: CheckpointId, target: VirtTime) -> RewindPlan {
        let Some(loc) = self.index.get(&id) else {
            return RewindPlan::NoAncestor;
        };
        // `id`'s node path is its recording linearized; truncate it to the
        // inputs served strictly before the target time — a prefix of the path.
        // The bound is `<`, not `<=`: a checkpoint frozen at TSC `T` halts
        // *before* serving an input timestamped exactly `T` (that input is the
        // first action of whatever resumes from it), so its recording holds the
        // inputs strictly before `T`. Truncating the same way makes rewinding to
        // an existing checkpoint's time land on that checkpoint's exact prefix —
        // so it dedups to the interned checkpoint instead of replaying a
        // duplicate, and never replays one input too many.
        let full = self.tree.path(loc.node);
        let prefix_len = full.iter().take_while(|t| t.at() < target).count();
        let prefix = &full[..prefix_len];

        // Among every node whose path is a prefix of `prefix` (a genuine replay
        // ancestor of the target), find the latest live checkpoint at or before
        // `target`. On a single line time and depth move together, so "latest
        // time" already picks the deepest fork point; the depth tiebreak is just
        // belt-and-braces.
        let walk = self.tree.walk_prefix(prefix);
        let mut best: Option<(VirtTime, usize, Arc<CheckpointInner>)> = None;
        for &node in &walk.nodes {
            if let Some((t, arc)) = latest_at_or_before(self.tree.value(node), target) {
                let depth = self.tree.depth(node);
                let better = match &best {
                    None => true,
                    Some((bt, bd, _)) => t > *bt || (t == *bt && depth > *bd),
                };
                if better {
                    best = Some((t, depth, arc));
                }
            }
        }

        // A checkpoint already at exactly (prefix, target) is the rewind result.
        if let Some(node) = walk.exact {
            if let Some(cps) = self.tree.value(node).live.get(&target) {
                for (_, w) in cps {
                    if let Some(arc) = w.upgrade() {
                        return RewindPlan::Existing(arc);
                    }
                }
            }
        }

        match best {
            Some((_, depth, from)) => {
                // The suffix is the recorded inputs between `from` (which already
                // holds `prefix[..depth]`) and the target.
                let suffix = InputRecording::from_tokens(&prefix[depth..]);
                RewindPlan::Replay { from, suffix }
            }
            None => RewindPlan::NoAncestor,
        }
    }

    /// Locate `candidate` against the trie: the deepest checkpoint on a prefix
    /// of it (the fork point), the recorded inputs between that checkpoint and
    /// the point the candidate first leaves every known path (the replay span),
    /// the inputs from there on (the new span), and the virtual time of that
    /// divergence. See [`PrefixLoc`]. `None` if not even the root checkpoint is
    /// live.
    ///
    /// The divergence is a virtual *time*, not just a token count: a candidate
    /// can rejoin known ground for a stretch with no inputs in it (a pure time
    /// advance), so reaching the divergence means running the fork forward to
    /// `diverges_at` — that idle stretch is replay ground too.
    pub(crate) fn locate_prefix(&self, candidate: &InputRecording) -> Option<PrefixLoc> {
        let cand = candidate.linearize();
        let walk = self.tree.walk_prefix(&cand);
        let matched_len = walk.matched_len;
        // The first candidate token off every known path, if any, marks where
        // the new path begins.
        let diverges_at = cand.get(matched_len).map(|t| t.at());

        // The deepest prefix node carrying a live checkpoint we could fork from.
        // A checkpoint qualifies only if frozen no later than the divergence —
        // otherwise it has already run past the point we'd branch off. With no
        // divergence the whole candidate is known ground, so any prefix
        // checkpoint qualifies (unbounded search). `walk.nodes` is ordered
        // root-first by increasing depth, so the last hit is the deepest.
        let mut best: Option<(usize, Arc<CheckpointInner>)> = None;
        for &node in &walk.nodes {
            let found = match diverges_at {
                Some(t) => latest_at_or_before(self.tree.value(node), t).map(|(_, arc)| arc),
                None => latest_live(self.tree.value(node)),
            };
            if let Some(arc) = found {
                best = Some((self.tree.depth(node), arc));
            }
        }
        let (depth, start) = best?;

        Some(PrefixLoc {
            // `start` already holds `cand[..depth]`; the matching tail up to the
            // divergence is what a replay must re-feed.
            replay: InputRecording::from_tokens(&cand[depth..matched_len]),
            new: InputRecording::from_tokens(&cand[matched_len..]),
            start,
            diverges_at,
        })
    }
}

/// The latest (highest-time) live checkpoint in `data`, regardless of time.
fn latest_live(data: &NodeData) -> Option<Arc<CheckpointInner>> {
    for (_, cps) in data.live.iter().rev() {
        for (_, w) in cps {
            if let Some(arc) = w.upgrade() {
                return Some(arc);
            }
        }
    }
    None
}

/// The latest live checkpoint in `data` with time at or before `target`.
fn latest_at_or_before(
    data: &NodeData,
    target: VirtTime,
) -> Option<(VirtTime, Arc<CheckpointInner>)> {
    for (&t, cps) in data.live.range(..=target).rev() {
        for (_, w) in cps {
            if let Some(arc) = w.upgrade() {
                return Some((t, arc));
            }
        }
    }
    None
}

/// The latest live checkpoint in `data` that could be `exclude`'s parent:
/// strictly before `upper` when this is `exclude`'s own node (a same-recording,
/// earlier sibling), or at/before `upper` on a shallower ancestor node. Never
/// returns `exclude` itself.
fn latest_before(
    data: &NodeData,
    upper: VirtTime,
    same_node: bool,
    exclude: CheckpointId,
) -> Option<Arc<CheckpointInner>> {
    for (&t, cps) in data.live.range(..=upper).rev() {
        if same_node && t >= upper {
            continue;
        }
        for (_, w) in cps {
            if let Some(arc) = w.upgrade() {
                if arc.id != exclude {
                    return Some(arc);
                }
            }
        }
    }
    None
}

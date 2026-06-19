// SPDX-License-Identifier: GPL-2.0

//! A generic radix tree (compressed trie) over sequences of tokens.
//!
//! This is pure structure: it knows nothing about checkpoints, virtual time, or
//! the lab. [`Genealogy`](crate::inner::Genealogy) layers the checkpoint
//! genealogy on top by using `RecordingToken` as the token type and a
//! time-ordered bucket of checkpoints as the per-node value.
//!
//! Each node owns the run of tokens on the edge from its parent (radix
//! compression), so a path that no other path diverges from is stored as a
//! single edge rather than one node per token. Inserting a path that diverges
//! partway along an existing edge *splits* that edge, inserting an intermediate
//! node at the divergence point. Sibling edges always start with distinct
//! tokens, so at most one child continues any given token.
//!
//! [`prune_upward`](RadixTree::prune_upward) is the inverse: it removes a node
//! once a caller-supplied predicate says it is no longer anchored, restoring
//! compression by merging an unanchored single-child node back into its child.
//! Nodes live in a slab so a removed node's id is never silently reassigned —
//! external handles into the tree (e.g. a retained-input anchor) stay valid.

use std::fmt::Debug;

/// Index of a node within a [`RadixTree`]. The root is always [`ROOT`].
pub(crate) type NodeId = usize;

/// The root node — the empty-prefix node every tree starts with.
pub(crate) const ROOT: NodeId = 0;

struct Node<T, V> {
    /// Tokens on the edge from this node's parent into this node. Empty only for
    /// the root.
    edge: Vec<T>,
    parent: Option<NodeId>,
    /// Child node ids; their `edge[0]` tokens are pairwise distinct.
    children: Vec<NodeId>,
    /// Number of tokens on the root-to-this path (`parent.depth + edge.len()`).
    depth: usize,
    value: V,
}

/// A compressed trie keyed on `&[T]` paths, with a `V` value at every node.
pub(crate) struct RadixTree<T, V> {
    /// Slab of nodes; a `None` slot is free. A node's id is its index and stays
    /// stable until the node is removed — a freed slot is only ever recycled by a
    /// later [`alloc`](RadixTree::alloc), never reassigned while the node is
    /// live — so ids held outside the tree remain valid across removals.
    nodes: Vec<Option<Node<T, V>>>,
    /// Indices of `None` slots, available for reuse.
    free: Vec<NodeId>,
}

/// The outcome of walking a query path against the tree, produced by
/// [`RadixTree::walk_prefix`].
pub(crate) struct PrefixWalk {
    /// Every node whose full root-to-node path is a prefix of the query, in
    /// root-first order. Always starts with [`ROOT`].
    pub(crate) nodes: Vec<NodeId>,
    /// `Some(node)` when the query lands exactly on a node boundary (that node is
    /// the last entry of [`nodes`](Self::nodes)); `None` when it ends partway
    /// along an edge or diverges from the tree, in which case no node sits at the
    /// query.
    pub(crate) exact: Option<NodeId>,
    /// How many leading query tokens lie on an existing path, counting a final
    /// partial run along the edge the query diverges from. Equals the query
    /// length when the query stays entirely on known paths, and the deepest
    /// prefix node's depth when the query diverges exactly at a node boundary.
    /// Unlike [`nodes`](Self::nodes)/[`exact`](Self::exact) it can land *between*
    /// nodes, so it pinpoints where a query first leaves the tree even when that
    /// point is mid-edge (no node sits there).
    pub(crate) matched_len: usize,
}

impl<T: Clone + PartialEq + Debug, V: Default> RadixTree<T, V> {
    /// Create a tree containing only the empty-prefix root.
    pub(crate) fn new() -> Self {
        Self {
            nodes: vec![Some(Node {
                edge: Vec::new(),
                parent: None,
                children: Vec::new(),
                depth: 0,
                value: V::default(),
            })],
            free: Vec::new(),
        }
    }

    /// Shared reference to a live node.
    fn node(&self, id: NodeId) -> &Node<T, V> {
        self.nodes[id].as_ref().expect("live radix node")
    }

    /// Mutable reference to a live node.
    fn node_mut(&mut self, id: NodeId) -> &mut Node<T, V> {
        self.nodes[id].as_mut().expect("live radix node")
    }

    /// Place `node` in a free slot (reusing a removed id) or at the end, and
    /// return its id.
    fn alloc(&mut self, node: Node<T, V>) -> NodeId {
        if let Some(id) = self.free.pop() {
            self.nodes[id] = Some(node);
            id
        } else {
            self.nodes.push(Some(node));
            self.nodes.len() - 1
        }
    }

    /// Free `id`'s slot for later reuse. The caller has already detached it from
    /// the tree.
    fn free_node(&mut self, id: NodeId) {
        self.nodes[id] = None;
        self.free.push(id);
    }

    /// Number of tokens on the root-to-`node` path.
    pub(crate) fn depth(&self, node: NodeId) -> usize {
        self.node(node).depth
    }

    /// The parent of `node`, or `None` for the root.
    pub(crate) fn parent(&self, node: NodeId) -> Option<NodeId> {
        self.node(node).parent
    }

    /// Number of children of `node`.
    pub(crate) fn child_count(&self, node: NodeId) -> usize {
        self.node(node).children.len()
    }

    /// Shared reference to `node`'s value.
    pub(crate) fn value(&self, node: NodeId) -> &V {
        &self.node(node).value
    }

    /// Mutable reference to `node`'s value.
    pub(crate) fn value_mut(&mut self, node: NodeId) -> &mut V {
        &mut self.node_mut(node).value
    }

    /// The full root-to-`node` token path.
    pub(crate) fn path(&self, node: NodeId) -> Vec<T> {
        let mut edges: Vec<&[T]> = Vec::new();
        let mut cur = Some(node);
        while let Some(n) = cur {
            edges.push(&self.node(n).edge);
            cur = self.node(n).parent;
        }
        edges.reverse();
        edges.into_iter().flatten().cloned().collect()
    }

    /// Insert `path`, creating nodes (and splitting compressed edges) as needed,
    /// and return the node whose path equals `path`. Idempotent: inserting an
    /// existing path returns its node without changing the tree.
    pub(crate) fn insert(&mut self, path: &[T]) -> NodeId {
        let mut node = ROOT;
        let mut pos = 0usize;
        loop {
            if pos == path.len() {
                return node;
            }
            let Some(child) = self.child_starting_with(node, &path[pos]) else {
                // No child continues this token: attach the rest as a fresh leaf.
                return self.push_leaf(node, path[pos..].to_vec());
            };
            let common = common_prefix_len(&self.node(child).edge, &path[pos..]);
            let edge_len = self.node(child).edge.len();
            if common == edge_len {
                // Whole edge matched: descend.
                pos += edge_len;
                node = child;
                continue;
            }
            // Partial match: split the edge so the shared run becomes its own
            // node, then attach the remaining tokens (if any) below the split.
            let split = self.split_edge(node, child, common);
            pos += common;
            if pos == path.len() {
                return split;
            }
            return self.push_leaf(split, path[pos..].to_vec());
        }
    }

    /// The node whose path equals `path` exactly, if it is present as a node
    /// boundary (not merely partway along an edge). Used by tests; production
    /// queries go through [`walk_prefix`](Self::walk_prefix).
    #[cfg(test)]
    pub(crate) fn get(&self, path: &[T]) -> Option<NodeId> {
        self.walk_prefix(path).exact
    }

    /// Walk `path` from the root, collecting every node whose full path is a
    /// prefix of `path`. See [`PrefixWalk`].
    pub(crate) fn walk_prefix(&self, path: &[T]) -> PrefixWalk {
        let mut nodes = vec![ROOT];
        let mut node = ROOT;
        let mut pos = 0usize;
        loop {
            if pos == path.len() {
                return PrefixWalk {
                    nodes,
                    exact: Some(node),
                    matched_len: pos,
                };
            }
            let Some(child) = self.child_starting_with(node, &path[pos]) else {
                // Diverges from the tree at a node boundary: `pos` tokens matched.
                return PrefixWalk {
                    nodes,
                    exact: None,
                    matched_len: pos,
                };
            };
            let common = common_prefix_len(&self.node(child).edge, &path[pos..]);
            if common < self.node(child).edge.len() {
                // Ends partway along this edge: no node sits at `path`, and the
                // child carries a token `path` doesn't, so it isn't a prefix. The
                // shared `common` tokens of the edge still matched.
                return PrefixWalk {
                    nodes,
                    exact: None,
                    matched_len: pos + common,
                };
            }
            pos += self.node(child).edge.len();
            node = child;
            nodes.push(node);
        }
    }

    /// Drop anchor-free nodes on the path from `start` up toward the root,
    /// restoring radix compression. `anchored` reports whether a node's value
    /// must keep the node alive. Walking up from `start`:
    ///
    /// - an anchored node, a real branch point (>= 2 children), or the root stops
    ///   the walk;
    /// - an unanchored leaf is removed, and the walk continues at its parent
    ///   (which may now itself be prunable);
    /// - an unanchored node with exactly one child is merged into that child (its
    ///   edge prepended), collapsing the chain — the parent's child count is
    ///   unchanged, so the walk stops.
    ///
    /// Surviving nodes keep their ids.
    pub(crate) fn prune_upward(&mut self, start: NodeId, anchored: impl Fn(&V) -> bool) {
        let mut cur = start;
        loop {
            if cur == ROOT || anchored(&self.node(cur).value) {
                return;
            }
            let nchildren = self.child_count(cur);
            if nchildren >= 2 {
                return;
            }
            let parent = self.node(cur).parent.expect("non-root node has a parent");
            if nchildren == 0 {
                self.detach_child(parent, cur);
                self.free_node(cur);
                cur = parent;
            } else {
                let child = self.node(cur).children[0];
                self.merge_into_child(cur, child, parent);
                return;
            }
        }
    }

    /// Remove `child` from `parent`'s child list (it is being freed).
    fn detach_child(&mut self, parent: NodeId, child: NodeId) {
        self.node_mut(parent).children.retain(|&c| c != child);
    }

    /// Merge `cur` into its only `child`: prepend `cur`'s edge to the child's and
    /// reparent the child to `cur`'s `parent`, then free `cur`. The child keeps
    /// its id, depth, and value (the total edge length to it is unchanged).
    fn merge_into_child(&mut self, cur: NodeId, child: NodeId, parent: NodeId) {
        let mut edge = std::mem::take(&mut self.node_mut(cur).edge);
        edge.append(&mut self.node_mut(child).edge);
        self.node_mut(child).edge = edge;
        self.node_mut(child).parent = Some(parent);
        if let Some(slot) = self
            .node_mut(parent)
            .children
            .iter_mut()
            .find(|c| **c == cur)
        {
            *slot = child;
        }
        self.free_node(cur);
    }

    /// Append a new leaf child of `parent` carrying `edge`, and return it.
    fn push_leaf(&mut self, parent: NodeId, edge: Vec<T>) -> NodeId {
        let depth = self.node(parent).depth + edge.len();
        let leaf = self.alloc(Node {
            edge,
            parent: Some(parent),
            children: Vec::new(),
            depth,
            value: V::default(),
        });
        self.node_mut(parent).children.push(leaf);
        leaf
    }

    /// Split `child`'s incoming edge after `common` tokens, inserting a fresh
    /// intermediate node between `parent` and `child`. Returns the intermediate
    /// node, whose path is `parent`'s path followed by the shared `common`
    /// tokens.
    fn split_edge(&mut self, parent: NodeId, child: NodeId, common: usize) -> NodeId {
        let child_edge = std::mem::take(&mut self.node_mut(child).edge);
        let (shared, rest) = child_edge.split_at(common);
        let mid_depth = self.node(parent).depth + common;
        let mid = self.alloc(Node {
            edge: shared.to_vec(),
            parent: Some(parent),
            children: vec![child],
            depth: mid_depth,
            value: V::default(),
        });
        // `child` keeps its depth; only its incoming edge and parent change.
        self.node_mut(child).edge = rest.to_vec();
        self.node_mut(child).parent = Some(mid);
        if let Some(slot) = self
            .node_mut(parent)
            .children
            .iter_mut()
            .find(|c| **c == child)
        {
            *slot = mid;
        }
        mid
    }

    /// The child of `node` whose edge starts with `token`, if any. Sibling edges
    /// start with distinct tokens, so this is unique.
    fn child_starting_with(&self, node: NodeId, token: &T) -> Option<NodeId> {
        self.node(node)
            .children
            .iter()
            .copied()
            .find(|&c| self.node(c).edge.first() == Some(token))
    }
}

/// Length of the longest common prefix of two token slices.
fn common_prefix_len<T: PartialEq>(a: &[T], b: &[T]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
#[path = "radix_tests.rs"]
mod tests;

// SPDX-License-Identifier: GPL-2.0

//! Unit tests for the generic radix tree, exercised with byte tokens so the
//! structural invariants (edge compression, splitting, prefix walks) are
//! checked in isolation from the checkpoint genealogy that uses it.

use super::{RadixTree, ROOT};

/// Build a tree of `u8` paths with `i32` node values, all defaulting to 0.
fn tree() -> RadixTree<u8, i32> {
    RadixTree::new()
}

#[test]
fn root_has_empty_path_and_zero_depth() {
    let t = tree();
    assert_eq!(t.depth(ROOT), 0);
    assert_eq!(t.parent(ROOT), None);
    assert!(t.path(ROOT).is_empty());
    // The empty path resolves to the root.
    assert_eq!(t.get(b""), Some(ROOT));
}

#[test]
fn single_path_round_trips() {
    let mut t = tree();
    let n = t.insert(b"abc");
    assert_eq!(t.get(b"abc"), Some(n));
    assert_eq!(t.path(n), b"abc".to_vec());
    assert_eq!(t.depth(n), 3);
    // A path stored as a compressed edge has no node at its interior.
    assert_eq!(t.get(b"ab"), None);
    assert_eq!(t.get(b"a"), None);
}

#[test]
fn insert_is_idempotent() {
    let mut t = tree();
    let a = t.insert(b"hello");
    let b = t.insert(b"hello");
    assert_eq!(
        a, b,
        "re-inserting an existing path must return the same node"
    );
}

#[test]
fn diverging_paths_split_a_shared_edge() {
    let mut t = tree();
    let abc = t.insert(b"abc");
    let abd = t.insert(b"abd");
    // The shared "ab" run becomes its own node, parenting both leaves.
    let ab = t
        .get(b"ab")
        .expect("split node for the shared prefix exists");
    assert_eq!(t.depth(ab), 2);
    assert_eq!(t.parent(abc), Some(ab));
    assert_eq!(t.parent(abd), Some(ab));
    assert_eq!(t.parent(ab), Some(ROOT));
    // Both originals are still retrievable at full depth.
    assert_eq!(t.get(b"abc"), Some(abc));
    assert_eq!(t.get(b"abd"), Some(abd));
    assert_eq!(t.depth(abc), 3);
    assert_eq!(t.depth(abd), 3);
}

#[test]
fn inserting_a_prefix_of_an_existing_path_splits() {
    let mut t = tree();
    let abc = t.insert(b"abc");
    // "ab" is a strict prefix of the existing compressed edge "abc".
    let ab = t.insert(b"ab");
    assert_eq!(t.depth(ab), 2);
    assert_eq!(t.parent(abc), Some(ab));
    assert_eq!(t.get(b"ab"), Some(ab));
    assert_eq!(t.get(b"abc"), Some(abc));
}

#[test]
fn extending_an_existing_path_adds_a_child() {
    let mut t = tree();
    let ab = t.insert(b"ab");
    let abcd = t.insert(b"abcd");
    assert_eq!(t.parent(abcd), Some(ab));
    assert_eq!(t.depth(abcd), 4);
    assert_eq!(t.path(abcd), b"abcd".to_vec());
}

#[test]
fn three_way_branch_keeps_sibling_edges_distinct() {
    let mut t = tree();
    let a1 = t.insert(b"app");
    let a2 = t.insert(b"apple");
    let a3 = t.insert(b"apply");
    // "app" is a node (a2/a3 branch below it); "appl" is the next split.
    let app = t.get(b"app").expect("app node");
    assert_eq!(a1, app);
    let appl = t.get(b"appl").expect("appl split node");
    assert_eq!(t.parent(a2), Some(appl));
    assert_eq!(t.parent(a3), Some(appl));
    assert_eq!(t.parent(appl), Some(app));
    for (path, node) in [(b"apple".as_slice(), a2), (b"apply".as_slice(), a3)] {
        assert_eq!(t.get(path), Some(node));
        assert_eq!(t.path(node), path.to_vec());
    }
}

#[test]
fn walk_prefix_reports_exact_node() {
    let mut t = tree();
    t.insert(b"abc");
    t.insert(b"abd");
    let walk = t.walk_prefix(b"abc");
    let ab = t.get(b"ab").unwrap();
    let abc = t.get(b"abc").unwrap();
    assert_eq!(walk.exact, Some(abc));
    // root, the "ab" split node, then the "abc" leaf — every prefix node.
    assert_eq!(walk.nodes, vec![ROOT, ab, abc]);
    // The whole query stayed on a known path.
    assert_eq!(walk.matched_len, 3);
}

#[test]
fn walk_prefix_stops_mid_edge_with_no_exact_node() {
    let mut t = tree();
    t.insert(b"abc");
    // "ab" lands partway along the compressed "abc" edge: a prefix of the path,
    // but not a node, so no node is visited past the root.
    let walk = t.walk_prefix(b"ab");
    assert_eq!(walk.exact, None);
    assert_eq!(walk.nodes, vec![ROOT]);
    // No node sits at "ab", but both its tokens matched partway along the edge.
    assert_eq!(walk.matched_len, 2);
}

#[test]
fn walk_prefix_stops_where_the_query_diverges() {
    let mut t = tree();
    t.insert(b"abc");
    t.insert(b"abd");
    // "abe" matches "ab" exactly then diverges (no child starts with 'e').
    let walk = t.walk_prefix(b"abe");
    let ab = t.get(b"ab").unwrap();
    assert_eq!(walk.exact, None);
    assert_eq!(walk.nodes, vec![ROOT, ab]);
    // "ab" matched at the node boundary; 'e' diverges, so only 2 tokens matched.
    assert_eq!(walk.matched_len, 2);
}

#[test]
fn values_persist_across_splits() {
    let mut t = tree();
    let abc = t.insert(b"abc");
    *t.value_mut(abc) = 7;
    // Splitting the edge to insert "abd" must not disturb the existing node's
    // value (the split inserts a fresh intermediate node above it).
    let abd = t.insert(b"abd");
    *t.value_mut(abd) = 9;
    assert_eq!(*t.value(abc), 7);
    assert_eq!(*t.value(abd), 9);
    // The freshly-created split node carries the default value.
    let ab = t.get(b"ab").unwrap();
    assert_eq!(*t.value(ab), 0);
}

// Pruning treats a non-zero value as "anchored" (the genealogy's live/retained
// anchor); 0 is the default, unanchored.

#[test]
fn prune_removes_unanchored_leaf_and_recompresses() {
    let mut t = tree();
    let abc = t.insert(b"abc");
    let abd = t.insert(b"abd");
    *t.value_mut(abc) = 1; // anchored
                           // `abd` is unanchored (value 0): prune from it.
    t.prune_upward(abd, |v| *v != 0);
    assert_eq!(t.get(b"abd"), None, "unanchored leaf is removed");
    // `ab` dropped to a single child and is itself unanchored, so it merges into
    // `abc`; `abc` keeps its id, depth, and value.
    assert_eq!(t.get(b"ab"), None, "single-child split node merged away");
    assert_eq!(t.get(b"abc"), Some(abc), "surviving node keeps its id");
    assert_eq!(t.path(abc), b"abc".to_vec());
    assert_eq!(t.depth(abc), 3);
    assert_eq!(*t.value(abc), 1);
    assert_eq!(t.child_count(ROOT), 1);
}

#[test]
fn prune_keeps_anchored_node() {
    let mut t = tree();
    let abc = t.insert(b"abc");
    let abd = t.insert(b"abd");
    *t.value_mut(abc) = 1;
    *t.value_mut(abd) = 1; // both anchored
    t.prune_upward(abd, |v| *v != 0);
    assert_eq!(t.get(b"abd"), Some(abd), "anchored leaf survives the prune");
    assert_eq!(t.get(b"abc"), Some(abc));
    assert!(
        t.get(b"ab").is_some(),
        "split node kept (still a branch point)"
    );
}

#[test]
fn prune_stops_at_branch_point() {
    let mut t = tree();
    let abc = t.insert(b"abc");
    let abd = t.insert(b"abd");
    let abe = t.insert(b"abe");
    *t.value_mut(abc) = 1;
    *t.value_mut(abd) = 1; // abe unanchored
    t.prune_upward(abe, |v| *v != 0);
    assert_eq!(t.get(b"abe"), None, "unanchored leaf removed");
    let ab = t.get(b"ab").expect("branch point remains");
    assert_eq!(t.child_count(ab), 2, "ab still forks abc/abd");
    assert_eq!(t.get(b"abc"), Some(abc));
    assert_eq!(t.get(b"abd"), Some(abd));
}

#[test]
fn reinsert_after_prune_rebuilds_path_with_stable_ids() {
    let mut t = tree();
    let abc = t.insert(b"abc");
    let abd = t.insert(b"abd");
    *t.value_mut(abc) = 1;
    t.prune_upward(abd, |v| *v != 0); // abd removed, ab merged into abc
                                      // Re-inserting "abd" splits abc's edge at "ab" again.
    let abd2 = t.insert(b"abd");
    *t.value_mut(abd2) = 2;
    assert_eq!(t.get(b"abd"), Some(abd2));
    assert_eq!(
        t.get(b"abc"),
        Some(abc),
        "abc's id is stable across the churn"
    );
    assert_eq!(*t.value(abc), 1);
    assert_eq!(*t.value(abd2), 2);
    let ab = t.get(b"ab").expect("split node recreated");
    assert_eq!(t.child_count(ab), 2);
}

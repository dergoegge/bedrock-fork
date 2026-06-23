// SPDX-License-Identifier: GPL-2.0

//! AFL-style coverage archive, generalized to *many domains*.
//!
//! Each registered feedback buffer is a coverage map, keyed by its id. The
//! guest's Go coverage shim registers every instrumented module under a
//! `go-<symbol>` id (`--cov-prefix`, default `go-`, scopes which ids count;
//! empty matches all). Buffers sharing an id describe the *same* instrumented
//! domain (e.g. two running instances of one binary), so their coverage is
//! unioned and counted once.
//! Distinct ids are independent domains, each with its own virgin map, and the
//! number of domains is unbounded.
//!
//! An input is *interesting* when, for any domain, the union of that domain's
//! buffers sets a bucket bit never seen before. Two flavors are distinguished
//! and counted separately so they never conflate: a **new edge** (a slot going
//! from uncovered to covered) is the headline coverage metric and reconciles
//! with [`CoverageMap::covered`]; a **new hit** (an already-covered slot
//! reaching a new AFL hit-count bucket) is loop-sensitivity signal only. Both
//! make the input interesting; only the former grows the edge total.

use std::collections::HashMap;

/// AFL `classify_counts`: map a raw hit-count to a single bucket bit so that
/// "this edge ran more times than before" also registers as new coverage.
pub fn bucket(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

/// The campaign's global search signals: a virgin bucket-map per coverage domain
/// (keyed by feedback-buffer id), plus a best-score-per-assertion-target map for
/// hill-climbing on assertions.
#[derive(Debug, Default)]
pub struct CoverageMap {
    domains: HashMap<Vec<u8>, Vec<u8>>,
    /// Best signed-closeness score seen per assertion target (keyed by message).
    /// See [`crate::oracle::assertion_observations`].
    targets: HashMap<String, i128>,
}

impl CoverageMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one coverage domain given every buffer registered under `id` this
    /// run. The buffers are unioned (bucket bits OR-ed across instances) and
    /// compared against the domain's virgin map. Returns `(new_edges, new_hits)`:
    ///
    /// - `new_edges` — slots that went from **uncovered to covered** (a genuinely
    ///   new edge). This is the headline metric and reconciles with
    ///   [`covered`](Self::covered): summing it over runs equals the growth in
    ///   `covered()`.
    /// - `new_hits` — slots that were **already covered** but gained a new
    ///   hit-count *bucket* bit (the edge ran enough more times to cross an AFL
    ///   bucket boundary). Not a new edge — kept as an interestingness signal,
    ///   counted separately so it can't inflate the edge total.
    ///
    /// Both update the virgin map.
    pub fn observe(&mut self, id: &[u8], buffers: &[&[u8]]) -> (usize, usize) {
        let len = buffers.iter().map(|b| b.len()).max().unwrap_or(0);
        if len == 0 {
            return (0, 0);
        }
        let virgin = self.domains.entry(id.to_vec()).or_default();
        if virgin.len() < len {
            virgin.resize(len, 0);
        }
        let mut new_edges = 0usize;
        let mut new_hits = 0usize;
        for (e, slot) in virgin.iter_mut().enumerate().take(len) {
            let mut u = 0u8;
            for b in buffers {
                if let Some(&c) = b.get(e) {
                    u |= bucket(c);
                }
            }
            if u & !*slot != 0 {
                if *slot == 0 {
                    new_edges += 1;
                } else {
                    new_hits += 1;
                }
                *slot |= u;
            }
        }
        (new_edges, new_hits)
    }

    /// Total edge slots covered across all domains (a campaign progress metric).
    pub fn covered(&self) -> usize {
        self.domains
            .values()
            .map(|v| v.iter().filter(|&&x| x != 0).count())
            .sum()
    }

    /// Total edge slots across all domains (the denominator for coverage %):
    /// the sum of every domain's virgin-map length, i.e. how many edges the
    /// instrumented modules report.
    pub fn capacity(&self) -> usize {
        self.domains.values().map(|v| v.len()).sum()
    }

    /// Number of distinct coverage domains seen so far.
    pub fn domains(&self) -> usize {
        self.domains.len()
    }

    /// Hill-climbing on assertions: record one `(key, score)` observation and
    /// return `true` if it improved that target's best score — i.e. an input
    /// that got closer to satisfying a `Sometimes` or to breaking an `Always`
    /// (first sight of a key always counts). Improving inputs are corpus-worthy.
    pub fn observe_target(&mut self, key: &str, score: i128) -> bool {
        match self.targets.get(key) {
            Some(&best) if score <= best => false,
            _ => {
                self.targets.insert(key.to_string(), score);
                true
            }
        }
    }

    /// Number of distinct assertion targets seen so far.
    pub fn targets(&self) -> usize {
        self.targets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucketing() {
        assert_eq!(bucket(0), 0);
        assert_eq!(bucket(1), 1);
        assert_eq!(bucket(3), 4);
        assert_eq!(bucket(5), 8);
        assert_eq!(bucket(200), 128);
    }

    #[test]
    fn target_improvement_is_hill_climb() {
        let mut m = CoverageMap::new();
        assert!(m.observe_target("reach", 1)); // first sight
        assert!(!m.observe_target("reach", 1)); // no improvement
        assert!(!m.observe_target("reach", 0)); // worse
        assert!(m.observe_target("reach", 5)); // closer => improvement
        assert!(m.observe_target("other", -3)); // new key, first sight
        assert_eq!(m.targets(), 2);
    }

    #[test]
    fn first_observation_is_new_then_stable() {
        let mut m = CoverageMap::new();
        let a: &[u8] = &[1, 0, 0, 0];
        assert_eq!(m.observe(b"cov-x", &[a]), (1, 0));
        assert_eq!(m.observe(b"cov-x", &[a]), (0, 0));
        assert_eq!(m.covered(), 1);
        assert_eq!(m.domains(), 1);
    }

    #[test]
    fn same_id_instances_are_unioned_and_counted_once() {
        let mut m = CoverageMap::new();
        // Two instances of the same domain: instance A hit edge 0, B hit edge 1.
        let a: &[u8] = &[1, 0, 0];
        let b: &[u8] = &[0, 1, 0];
        assert_eq!(m.observe(b"cov-bin", &[a, b]), (2, 0)); // edges 0 and 1 are new
        assert_eq!(m.covered(), 2); // union of both, one domain
        assert_eq!(m.domains(), 1);
        // Re-observing either instance alone adds nothing new.
        assert_eq!(m.observe(b"cov-bin", &[a]), (0, 0));
        assert_eq!(m.observe(b"cov-bin", &[b]), (0, 0));
        // A genuinely new edge from one instance is still new.
        let c: &[u8] = &[0, 0, 1];
        assert_eq!(m.observe(b"cov-bin", &[c]), (1, 0));
    }

    #[test]
    fn duplicate_instances_count_once() {
        let mut m = CoverageMap::new();
        let a: &[u8] = &[1, 0];
        // Two identical instances => union == single instance, counted once.
        assert_eq!(m.observe(b"cov-bin", &[a, a]), (1, 0));
        assert_eq!(m.observe(b"cov-bin", &[a]), (0, 0));
        assert_eq!(m.covered(), 1);
    }

    #[test]
    fn distinct_ids_are_independent_domains() {
        let mut m = CoverageMap::new();
        let a: &[u8] = &[1, 0, 0];
        assert_eq!(m.observe(b"cov-one", &[a]), (1, 0));
        // Same edge index, different domain => still new (separate virgin map).
        assert_eq!(m.observe(b"cov-two", &[a]), (1, 0));
        assert_eq!(m.domains(), 2);
        assert_eq!(m.covered(), 2);
    }

    #[test]
    fn more_hits_same_edge_is_new() {
        let mut m = CoverageMap::new();
        assert_eq!(m.observe(b"cov-x", &[&[1]]), (1, 0)); // first hit: a new edge
                                                          // count 5 -> bucket 8: a new *bit* on an already-covered slot => a hit,
                                                          // not a new edge.
        assert_eq!(m.observe(b"cov-x", &[&[5]]), (0, 1));
        assert_eq!(m.observe(b"cov-x", &[&[6]]), (0, 0)); // 6 -> same bucket 8
                                                          // Still one covered edge despite the bucket climb.
        assert_eq!(m.covered(), 1);
    }
}

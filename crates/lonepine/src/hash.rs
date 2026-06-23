// SPDX-License-Identifier: GPL-2.0

//! Stable 128-bit hashing for trie keys. Stability matters only within a single
//! process run (the trie is rebuilt each campaign), but using a fixed algorithm
//! rather than the randomized `RandomState` keeps results reproducible from the
//! campaign seed and makes the worked-trace tests deterministic.

const FNV_OFFSET_128: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
const FNV_PRIME_128: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013B;

/// FNV-1a over a byte slice, producing a 128-bit digest.
pub fn fnv1a_128(bytes: &[u8]) -> u128 {
    let mut h = FNV_OFFSET_128;
    for &b in bytes {
        h ^= b as u128;
        h = h.wrapping_mul(FNV_PRIME_128);
    }
    h
}

/// Combine a parent node hash with an edge hash into the child node hash.
/// `combine` is associative-order-sensitive (it is *not* commutative), which is
/// what we want: the path to a node is an ordered sequence of edges.
pub fn combine(parent: u128, edge: u128) -> u128 {
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&parent.to_le_bytes());
    buf[16..].copy_from_slice(&edge.to_le_bytes());
    fnv1a_128(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_is_stable_and_distinct() {
        assert_eq!(fnv1a_128(b"abc"), fnv1a_128(b"abc"));
        assert_ne!(fnv1a_128(b"abc"), fnv1a_128(b"abd"));
        assert_ne!(fnv1a_128(b""), fnv1a_128(b"a"));
    }

    #[test]
    fn combine_is_order_sensitive() {
        let a = fnv1a_128(b"a");
        let b = fnv1a_128(b"b");
        assert_ne!(combine(a, b), combine(b, a));
        assert_eq!(combine(a, b), combine(a, b));
    }
}

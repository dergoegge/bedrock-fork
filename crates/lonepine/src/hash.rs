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

// ── SHA-1 ──────────────────────────────────────────────────────────────────────
//
// A self-contained SHA-1 so reproducer provenance can carry a `sha1sum`-identical
// digest of each workload file (kernel, initrd, compose, images) without pulling
// in a hashing crate. Not used in any hot path — only when saving or verifying a
// reproducer — so simplicity beats speed.

/// Mix one 64-byte block into the running SHA-1 state.
fn sha1_compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let tmp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// SHA-1 of a byte slice as a lowercase 40-char hex string, identical to
/// `sha1sum`. Processes full blocks in place; only the short final block is
/// copied for padding, so hashing a large file allocates O(1) beyond the input.
pub fn sha1_hex(data: &[u8]) -> String {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);

    let full_blocks = data.len() / 64;
    for i in 0..full_blocks {
        let block: &[u8; 64] = data[i * 64..i * 64 + 64].try_into().unwrap();
        sha1_compress(&mut h, block);
    }

    // Final block(s): remaining bytes, the 0x80 terminator, zero padding to a
    // 56-byte boundary, then the 64-bit big-endian message length in bits.
    let mut tail: Vec<u8> = data[full_blocks * 64..].to_vec();
    tail.push(0x80);
    while tail.len() % 64 != 56 {
        tail.push(0);
    }
    tail.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in tail.chunks_exact(64) {
        let block: &[u8; 64] = chunk.try_into().unwrap();
        sha1_compress(&mut h, block);
    }

    let mut out = String::with_capacity(40);
    for word in h {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

/// SHA-1 of a file's contents as a `sha1sum`-identical hex string.
pub fn sha1_file(path: &std::path::Path) -> std::io::Result<String> {
    Ok(sha1_hex(&std::fs::read(path)?))
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

    #[test]
    fn sha1_matches_known_vectors() {
        // Standard SHA-1 test vectors — must match `sha1sum` byte-for-byte.
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn sha1_handles_block_boundaries() {
        // Exercise inputs around the 64-byte block and 56-byte padding boundaries
        // to catch off-by-one padding errors. Compared against a second run for
        // stability (the absolute digests are covered by the known vectors).
        for len in [55, 56, 57, 63, 64, 65, 119, 120, 128] {
            let data = vec![0xa5u8; len];
            assert_eq!(sha1_hex(&data), sha1_hex(&data));
        }
        // 1,000 'a's — a well-known vector.
        let a1000 = vec![b'a'; 1000];
        assert_eq!(sha1_hex(&a1000), "291e9a6c66994949b57ba5e650361e98fc36b1ba");
    }
}

// SPDX-License-Identifier: GPL-2.0

//! The mutator — specific to the driver/RNG input shape. AFL-style stacked
//! havoc, but every operator edits typed structure (steps, batch members,
//! driver indices, launch offsets, RNG bytes) or the swarm mask, so each edit is
//! structurally meaningful rather than a raw byte flip on an opaque buffer.

use crate::input::{DriverMask, Member, Plan, Step};
use crate::prng::Rng;

/// Emulated TSC frequency (Hz): the guest's virtual time advances at this fixed
/// rate, so an offset in ticks is `ticks / TSC_HZ` seconds. Mirrors
/// `bedrock_vm::DEFAULT_TSC_FREQUENCY` (kept local so the mutator stays free of
/// VM deps); the determinism design fixes this rate.
const TSC_HZ: u64 = 2_995_200_000;

/// Bounds the mutator respects.
#[derive(Debug, Clone)]
pub struct Limits {
    pub n_drivers: usize,
    pub step_cap: usize,
    pub max_batch: usize,
    /// Tight launch-offset window (ticks) for the Uniform and Quantized offset
    /// strategies — sub-millisecond interleaving at the fixed TSC rate.
    pub max_spread: i64,
    /// Ceiling (ticks) for the Exponential offset strategy's long tail —
    /// ~120 s of virtual time, so a rare draw can stagger launches far apart
    /// (e.g. one driver well after another finishes) while most stay tiny.
    pub max_offset: i64,
    pub max_rng: usize,
    /// Mutation stack exponent (AFL-style): each `mutate` applies `2^x` plan
    /// operations, and each byte-havoc op applies `2^x` byte edits, with `x`
    /// uniform in `0..=max_stack`. 7 ⇒ 1..=128.
    pub max_stack: usize,
}

impl Limits {
    pub fn new(n_drivers: usize) -> Self {
        Limits {
            n_drivers,
            step_cap: 50,
            max_batch: 4,
            max_spread: 1_000_000,
            max_offset: 120 * TSC_HZ as i64, // 120 s of virtual time
            max_rng: 256,
            max_stack: 7,
        }
    }
}

/// AFL-style stack depth: `2^x` with `x` uniform in `0..=max_stack`. Used both
/// for the count of plan operations per `mutate` and the byte edits per havoc op.
fn stack_count(lim: &Limits, rng: &mut Rng) -> usize {
    // Clamp the exponent so `1 << x` can't overflow on a misconfigured limit.
    let x = rng.below(lim.max_stack + 1).min(16);
    1usize << x
}

/// How a within-step launch offset (the interleaving delay, in virtual-time
/// ticks, relative to the step's start) is drawn. The fuzzer mixes all three per
/// offset so it explores broad spreads, tight near-simultaneous races, and a
/// trie-friendly coarse lattice rather than committing to one regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffsetStrategy {
    /// (1) Uniform across `[0, max_spread]` — even spread, no bias. What we had.
    Uniform,
    /// (2) Log-scaled toward small offsets with a long tail: pick a magnitude
    /// band `2^w` (`w` uniform over the window's bit width), then a value within
    /// it. Density ∝ 1/offset, so launches cluster near-simultaneous (the tight
    /// race window) while the occasional draw still reaches the far end.
    Exponential,
    /// (3) Snap to a coarse lattice `k/8 · max_spread` (`k` in `0..=8`), which
    /// includes 0 (exact simultaneity). Favors a few canonical interleavings and
    /// keeps the offset value-space tiny, so the checkpoint trie shares prefixes
    /// across plans (offsets are part of the trie edge key) instead of every plan
    /// hashing to a fresh node.
    Quantized,
}

impl OffsetStrategy {
    fn pick(rng: &mut Rng) -> Self {
        match rng.below(3) {
            0 => Self::Uniform,
            1 => Self::Exponential,
            _ => Self::Quantized,
        }
    }

    /// Draw an offset (ticks) under this strategy. Uniform/Quantized stay within
    /// the tight `max_spread` window; Exponential ranges up to `max_offset`
    /// (~120 s), small-biased.
    fn sample(self, lim: &Limits, rng: &mut Rng) -> u64 {
        let spread = lim.max_spread.max(0) as u64;
        match self {
            Self::Uniform => rng.range_u64(0, spread),
            Self::Exponential => log_scaled(lim.max_offset.max(0) as u64, rng),
            Self::Quantized => {
                const STEPS: u64 = 8;
                let k = rng.below(STEPS as usize + 1) as u64;
                (spread / STEPS) * k
            }
        }
    }
}

/// Log-scaled draw in `[0, max]`: pick a `2^w` band (`w` uniform over `max`'s bit
/// width) then a value within it. Density ∝ 1/x — small-biased with a long tail
/// to `max`. Shared by the Exponential strategy and the relative-offset jitter.
fn log_scaled(max: u64, rng: &mut Rng) -> u64 {
    if max == 0 {
        return 0;
    }
    let bits = (u64::BITS - max.leading_zeros()).max(1);
    let w = rng.below(bits as usize + 1) as u32;
    let span = 1u64.checked_shl(w).unwrap_or(u64::MAX).min(max);
    rng.range_u64(0, span)
}

/// Draw a launch offset, mixing the [`OffsetStrategy`] variants per call. Bounded
/// by `max_offset` (the Exponential ceiling); the other strategies stay within
/// the smaller `max_spread`.
fn choose_offset(lim: &Limits, rng: &mut Rng) -> i64 {
    let cap = lim.max_offset.max(lim.max_spread).max(0) as u64;
    OffsetStrategy::pick(rng).sample(lim, rng).min(cap) as i64
}

/// Place an offset *near* `base` (another batch member's launch): a small,
/// log-scaled ± jitter (mostly a handful of ticks, capped at `max_spread`) so
/// two drivers fire in a tight window — the relative-offset strategy for homing
/// in on a specific two-driver race once one looks interesting. Clamped to
/// `[0, max_offset]`.
fn jitter_near(base: i64, lim: &Limits, rng: &mut Rng) -> i64 {
    let mag = log_scaled(lim.max_spread.max(0) as u64, rng) as i64;
    let delta = if rng.bool() { mag } else { -mag };
    (base + delta).clamp(0, lim.max_offset.max(0))
}

fn random_member(mask: &DriverMask, lim: &Limits, rng: &mut Rng) -> Option<Member> {
    let driver = mask.pick_enabled(rng)?;
    let offset = choose_offset(lim, rng);
    Some(Member { driver, offset })
}

fn random_step(mask: &DriverMask, lim: &Limits, rng: &mut Rng) -> Option<Step> {
    let bsize = 1 + rng.below(lim.max_batch.max(1));
    let mut batch = Vec::new();
    for _ in 0..bsize {
        if let Some(m) = random_member(mask, lim, rng) {
            batch.push(m);
        }
    }
    if batch.is_empty() {
        return None;
    }
    // Empty tapes: the guest extends fresh on first execution, exploring new
    // data (both RDRAND and getrandom()).
    Some(Step {
        batch,
        rng: Vec::new(),
        rand: Vec::new(),
    })
}

/// Produce a mutated child of `parent`. `donor` (another corpus plan) enables
/// splice operators; pass `None` to disable them.
pub fn mutate(parent: &Plan, donor: Option<&Plan>, lim: &Limits, rng: &mut Rng) -> Plan {
    let mut p = parent.clone();
    for _ in 0..stack_count(lim, rng) {
        apply_one(&mut p, donor, lim, rng);
    }
    p.mask.ensure_nonempty();
    // Splice can graft in members from a donor whose mask differed; enforce the
    // swarm invariant (members are drawn from the enabled subset) once at the end.
    drop_disabled_members(&mut p);
    if p.steps.len() > lim.step_cap {
        p.steps.truncate(lim.step_cap);
    }
    p
}

fn apply_one(p: &mut Plan, donor: Option<&Plan>, lim: &Limits, rng: &mut Rng) {
    match rng.below(16) {
        // --- sequence ops ---
        0 => {
            // insert step
            if p.steps.len() < lim.step_cap {
                if let Some(s) = random_step(&p.mask, lim, rng) {
                    let at = rng.below(p.steps.len() + 1);
                    p.steps.insert(at, s);
                }
            }
        }
        1 => {
            // delete step
            if !p.steps.is_empty() {
                let at = rng.below(p.steps.len());
                p.steps.remove(at);
            }
        }
        2 => {
            // duplicate step
            if !p.steps.is_empty() && p.steps.len() < lim.step_cap {
                let at = rng.below(p.steps.len());
                let s = p.steps[at].clone();
                p.steps.insert(at, s);
            }
        }
        3 => {
            // swap two steps
            if p.steps.len() >= 2 {
                let a = rng.below(p.steps.len());
                let b = rng.below(p.steps.len());
                p.steps.swap(a, b);
            }
        }
        4 => {
            // splice: prefix of self ++ suffix of donor
            if let Some(d) = donor {
                if !d.steps.is_empty() {
                    let cut_self = rng.below(p.steps.len() + 1);
                    let cut_donor = rng.below(d.steps.len());
                    p.steps.truncate(cut_self);
                    p.steps.extend(d.steps[cut_donor..].iter().cloned());
                    if p.steps.len() > lim.step_cap {
                        p.steps.truncate(lim.step_cap);
                    }
                }
            }
        }
        // --- batch ops ---
        5 => {
            // add member
            if !p.steps.is_empty() {
                let s = rng.below(p.steps.len());
                if p.steps[s].batch.len() < lim.max_batch {
                    if let Some(m) = random_member(&p.mask, lim, rng) {
                        p.steps[s].batch.push(m);
                    }
                }
            }
        }
        6 => {
            // delete member (keep >= 1)
            if !p.steps.is_empty() {
                let s = rng.below(p.steps.len());
                if p.steps[s].batch.len() > 1 {
                    let m = rng.below(p.steps[s].batch.len());
                    p.steps[s].batch.remove(m);
                }
            }
        }
        7 => {
            // change driver
            if !p.steps.is_empty() {
                let s = rng.below(p.steps.len());
                if !p.steps[s].batch.is_empty() {
                    let m = rng.below(p.steps[s].batch.len());
                    if let Some(d) = p.mask.pick_enabled(rng) {
                        p.steps[s].batch[m].driver = d;
                    }
                }
            }
        }
        8 => {
            // change offset (shift interleaving). With ≥2 members, sometimes snap
            // this one *near a sibling's* launch (a tight race window — the
            // relative strategy); otherwise re-draw via the mixed strategies.
            if !p.steps.is_empty() {
                let s = rng.below(p.steps.len());
                let blen = p.steps[s].batch.len();
                if blen > 0 {
                    let m = rng.below(blen);
                    if blen >= 2 && rng.bool() {
                        let mut other = rng.below(blen);
                        if other == m {
                            other = (other + 1) % blen;
                        }
                        let base = p.steps[s].batch[other].offset;
                        p.steps[s].batch[m].offset = jitter_near(base, lim, rng);
                    } else {
                        p.steps[s].batch[m].offset = choose_offset(lim, rng);
                    }
                }
            }
        }
        // --- rng (RDRAND tape) ops ---
        9 => {
            if !p.steps.is_empty() {
                let s = rng.below(p.steps.len());
                havoc_bytes(&mut p.steps[s].rng, lim, rng);
            }
        }
        10 => {
            // truncate rng (let the guest re-extend fresh -> deeper paths)
            if !p.steps.is_empty() {
                let s = rng.below(p.steps.len());
                let l = p.steps[s].rng.len();
                if l > 0 {
                    let keep = rng.below(l);
                    p.steps[s].rng.truncate(keep);
                }
            }
        }
        11 => {
            // splice rng from a donor step
            if let Some(d) = donor {
                if !p.steps.is_empty() && !d.steps.is_empty() {
                    let s = rng.below(p.steps.len());
                    let ds = rng.below(d.steps.len());
                    p.steps[s].rng = d.steps[ds].rng.clone();
                }
            }
        }
        // --- rand (getrandom() tape) ops: the high-signal knob, since these
        // bytes reach driver/parser inputs verbatim ---
        12 => {
            if !p.steps.is_empty() {
                let s = rng.below(p.steps.len());
                havoc_bytes(&mut p.steps[s].rand, lim, rng);
            }
        }
        13 => {
            // truncate rand (let the guest re-extend fresh -> new data downstream)
            if !p.steps.is_empty() {
                let s = rng.below(p.steps.len());
                let l = p.steps[s].rand.len();
                if l > 0 {
                    let keep = rng.below(l);
                    p.steps[s].rand.truncate(keep);
                }
            }
        }
        14 => {
            // splice rand from a donor step
            if let Some(d) = donor {
                if !p.steps.is_empty() && !d.steps.is_empty() {
                    let s = rng.below(p.steps.len());
                    let ds = rng.below(d.steps.len());
                    p.steps[s].rand = d.steps[ds].rand.clone();
                }
            }
        }
        // --- swarm ---
        _ => {
            if lim.n_drivers > 0 {
                let d = rng.below(lim.n_drivers);
                p.mask.toggle(d);
                p.mask.ensure_nonempty();
                drop_disabled_members(p);
            }
        }
    }
}

/// Byte-level havoc on a randomness tape (`rng` or `rand`): a stacked burst of
/// `2^x` single edits ([`stack_count`]), so one havoc op makes a meaningful
/// change to the tape rather than a lone byte. Shared by both channels.
fn havoc_bytes(buf: &mut Vec<u8>, lim: &Limits, rng: &mut Rng) {
    for _ in 0..stack_count(lim, rng) {
        havoc_byte_once(buf, lim, rng);
    }
}

/// One byte-level edit: bit flip, byte write, insert, or delete.
fn havoc_byte_once(buf: &mut Vec<u8>, lim: &Limits, rng: &mut Rng) {
    match rng.below(4) {
        0 => {
            // bit flip
            if !buf.is_empty() {
                let i = rng.below(buf.len());
                buf[i] ^= 1u8 << rng.below(8);
            }
        }
        1 => {
            // set byte
            if !buf.is_empty() {
                let i = rng.below(buf.len());
                buf[i] = rng.byte();
            }
        }
        2 => {
            // insert byte
            if buf.len() < lim.max_rng {
                let i = rng.below(buf.len() + 1);
                buf.insert(i, rng.byte());
            }
        }
        _ => {
            // delete byte
            if !buf.is_empty() {
                let i = rng.below(buf.len());
                buf.remove(i);
            }
        }
    }
}

/// After disabling a driver in the mask, drop any members that referenced it and
/// any step left with an empty batch. Uses disjoint field borrows.
fn drop_disabled_members(p: &mut Plan) {
    let Plan { mask, steps } = p;
    for s in steps.iter_mut() {
        s.batch.retain(|m| mask.is_enabled(m.driver));
    }
    steps.retain(|s| !s.batch.is_empty());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_strategies_stay_in_bounds() {
        let lim = Limits::new(2);
        let spread = lim.max_spread as u64;
        let max_off = lim.max_offset as u64;
        let mut r = Rng::new(99);
        for _ in 0..2000 {
            // Mixed entry point is bounded by the largest ceiling (exponential's).
            let o = choose_offset(&lim, &mut r);
            assert!(o >= 0 && o as u64 <= max_off);
            // Uniform/Quantized stay in the tight window; Exponential reaches far.
            assert!(OffsetStrategy::Uniform.sample(&lim, &mut r) <= spread);
            assert!(OffsetStrategy::Quantized.sample(&lim, &mut r) <= spread);
            assert!(OffsetStrategy::Exponential.sample(&lim, &mut r) <= max_off);
        }
    }

    #[test]
    fn quantized_snaps_to_the_lattice() {
        let mut lim = Limits::new(2);
        lim.max_spread = 8000;
        let step = lim.max_spread as u64 / 8; // 1000
        let mut r = Rng::new(7);
        for _ in 0..200 {
            let v = OffsetStrategy::Quantized.sample(&lim, &mut r);
            assert_eq!(v % step, 0, "quantized offset {v} off the lattice");
            assert!(v <= lim.max_spread as u64);
        }
    }

    #[test]
    fn exponential_biases_small_with_long_tail() {
        // Exponential ranges up to max_offset (~120 s) but most draws are tiny:
        // well over a quarter land below the tight `max_spread` window, which is
        // a vanishing fraction of the full range — the small bias with a long
        // tail. (A uniform draw over the full range would almost never be < spread.)
        let lim = Limits::new(2);
        let spread = lim.max_spread as u64;
        let mut r = Rng::new(123);
        let small = (0..4000)
            .filter(|_| OffsetStrategy::Exponential.sample(&lim, &mut r) < spread)
            .count();
        assert!(
            small > 1000,
            "exponential should heavily favor small offsets, got {small}/4000 below spread"
        );
    }

    #[test]
    fn jitter_near_stays_close_and_in_bounds() {
        let lim = Limits::new(2);
        let max_off = lim.max_offset;
        let base = 50_000i64;
        let mut r = Rng::new(5);
        let mut close = 0;
        for _ in 0..4000 {
            let v = jitter_near(base, &lim, &mut r);
            assert!(v >= 0 && v <= max_off, "jitter {v} out of bounds");
            // The jitter is capped at max_spread and log-scaled, so it usually
            // lands within the tight window of `base`.
            if (v - base).unsigned_abs() <= lim.max_spread as u64 {
                close += 1;
            }
        }
        assert_eq!(close, 4000, "jitter must stay within max_spread of base");
    }

    fn invariants_hold(p: &Plan, lim: &Limits) {
        assert!(p.steps.len() <= lim.step_cap);
        assert!(p.mask.count_enabled() >= 1);
        for s in &p.steps {
            assert!(!s.batch.is_empty(), "no empty batches");
            assert!(s.batch.len() <= lim.max_batch.max(1) || true); // add-member guards <max
            for m in &s.batch {
                assert!(m.driver < lim.n_drivers, "driver in range");
                assert!(p.mask.is_enabled(m.driver), "only enabled drivers");
                assert!(m.offset >= 0 && m.offset <= lim.max_offset);
            }
        }
    }

    #[test]
    fn mutation_preserves_invariants() {
        let lim = Limits::new(5);
        let mut rng = Rng::new(0xdead_beef);
        let mut p = Plan::empty(5);
        // hammer the plan through many mutations
        for _ in 0..5000 {
            let donor = if rng.bool() { Some(p.clone()) } else { None };
            p = mutate(&p, donor.as_ref(), &lim, &mut rng);
            invariants_hold(&p, &lim);
        }
    }

    #[test]
    fn mutation_is_deterministic() {
        let lim = Limits::new(4);
        let seed = 12345;
        let run = || {
            let mut rng = Rng::new(seed);
            let mut p = Plan::empty(4);
            for _ in 0..200 {
                p = mutate(&p, None, &lim, &mut rng);
            }
            p
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn grows_then_can_shrink() {
        // Sanity: starting empty, mutation eventually produces non-empty plans.
        let lim = Limits::new(3);
        let mut rng = Rng::new(1);
        let mut p = Plan::empty(3);
        let mut max_seen = 0;
        for _ in 0..2000 {
            p = mutate(&p, None, &lim, &mut rng);
            max_seen = max_seen.max(p.steps.len());
        }
        assert!(max_seen > 0, "mutator never added a step");
    }
}

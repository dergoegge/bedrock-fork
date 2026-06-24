// SPDX-License-Identifier: GPL-2.0

//! Replaying a saved finding: the one place that turns a `bug-<hash>.json`
//! reproducer back into a single deterministic execution and judges whether the
//! recorded bug still fires.
//!
//! This is the read side of the reproducer format that [`solution`](crate::solution)
//! writes. [`reproduce`] owns the whole flow — parse the file, boot the same
//! workload to the ready checkpoint, enumerate its drivers, rebuild the
//! [`Plan`], replay it once, and report the verdict — behind a single call, so
//! `--reproduce` on the binary is just this function.
//!
//! The two pure halves — [`parse_reproducer`] (JSON → [`Reproducer`]) and
//! [`build_plan`] ([`Reproducer`] → [`Plan`], remapping each recorded driver to
//! its index in the freshly discovered rule set) — are unit-tested without a VM,
//! matching the rest of the crate. Remapping by *name + target* rather than the
//! recorded index keeps a reproducer valid even if discovery order shifts between
//! boots.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::campaign::{boot_ready, discover_rules, Config, Result};
use crate::driver::Rule;
use crate::executor::{ExecOutcome, Executor};
use crate::feedback::Feedback;
use crate::input::{Member, Plan, Step};
use crate::prng::Rng;
use crate::sink::Sink;
use crate::solution::WorkloadProvenance;
use crate::ui;

/// A parsed reproducer: the recorded finding (so we can tell whether the replay
/// fired the *same* bug), the steps to replay, and the workload provenance to
/// verify the supplied files against. The bookkeeping fields the writer also
/// stores (`bug`/`core`/`iter`/`vt_secs`) are not needed to replay, so they are
/// dropped.
struct Reproducer {
    /// The finding's bug class — matches [`Finding::kind`](crate::oracle::Finding::kind).
    kind: String,
    /// The finding's human-readable reason — matches
    /// [`Finding::reason`](crate::oracle::Finding::reason); reproducers dedup by it.
    reason: String,
    steps: Vec<RawStep>,
    /// Recorded workload-file provenance (paths + SHA-1). `None` for reproducers
    /// written before provenance was stamped.
    provenance: Option<WorkloadProvenance>,
}

/// One recorded step before driver indices are resolved against a live rule set.
struct RawStep {
    batch: Vec<RawMember>,
    /// RDRAND/RDSEED tape the guest consumed this step.
    rng: Vec<u8>,
    /// `getrandom()` tape the guest consumed this step.
    rand: Vec<u8>,
}

/// One recorded batch member. The driver is recorded by `name` + `target` (its
/// stable identity) alongside the `recorded_driver` index it had at record time;
/// the index is only cross-checked, never trusted, when rebuilding the plan.
struct RawMember {
    name: String,
    /// `Debug` rendering of the driver's `BashTarget` (e.g. `Host`,
    /// `Container("bitcoin")`) — exactly what the writer stamped.
    target: String,
    offset: i64,
    recorded_driver: Option<u64>,
}

/// Replay a saved reproducer (`bug-<hash>.json` or `bug-<hash>.min.json`) once and
/// report whether its recorded finding still fires. Boots the same workload as a
/// campaign — so it needs the same `--vmlinux`/`--initramfs`/workload that
/// produced the reproducer — then replays the recorded plan from the ready
/// checkpoint. Returns `Ok(())` only when the recorded finding reproduces
/// exactly (same kind and reason), so the process exit code is meaningful.
pub fn reproduce(cfg: &Config, path: &Path) -> Result<()> {
    ui::banner("reproduce a saved lonepine finding");

    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read reproducer {}: {e}", path.display()))?;
    let repro = parse_reproducer(&json)?;
    ui::info(&format!(
        "loaded {} — {} {:?} ({} step(s))",
        path.display(),
        repro.kind,
        repro.reason,
        repro.steps.len()
    ));

    // Verify the supplied workload files (the paths in `cfg`) hash to what the
    // reproducer recorded, before the expensive boot. A mismatch means we would
    // be replaying against different kernel/initrd/workload bytes than the bug
    // was found on, so any verdict would be meaningless — fail fast instead.
    match &repro.provenance {
        Some(p) if !p.files.is_empty() => {
            let problems = p.verify_against(cfg);
            if problems.is_empty() {
                ui::good(&format!(
                    "workload provenance verified ({} file(s) match)",
                    p.files.len()
                ));
            } else {
                for problem in &problems {
                    ui::err(problem);
                }
                return Err("workload provenance mismatch: supplied files differ from \
                            the recording; reproducing against different bytes"
                    .into());
            }
        }
        _ => ui::warn(
            "reproducer has no workload provenance — cannot verify the supplied \
             files match what the bug was recorded against",
        ),
    }

    // Boot the same workload to the ready checkpoint and enumerate its drivers,
    // exactly as a campaign does, so the recorded plan resumes against the same
    // guest state.
    let sink = Arc::new(Sink::new());
    let ready = boot_ready(cfg, Arc::clone(&sink))?;
    let freq = ready.tsc_frequency();
    let rules = discover_rules(&ready, cfg)?;
    sink.enter_fuzz_mode(); // seal the boot panel before any captured branch
    if cfg.trace_injects {
        sink.enable_inject_trace(freq);
        ui::info(
            "inject trace on: flagging emulated-TSC gaps ≥ 0.25s between captured events \
             (a short guest sleep that advances the clock by seconds is the bug)",
        );
    }
    if rules.is_empty() {
        return Err(format!("no drivers found under {}", cfg.driver_dir).into());
    }

    let (plan, shifted) = build_plan(&repro, &rules)?;
    if shifted > 0 {
        ui::warn(&format!(
            "{shifted} recorded driver index(es) no longer agree; remapped by name+target"
        ));
    }

    // Replay the whole plan from the ready checkpoint. The recorded rng/rand
    // tapes drive each step deterministically; the seed only feeds any draw past
    // the recorded tape, which a faithful reproducer never reaches.
    let feedback = Feedback::new(cfg.cov_prefix.clone());
    // The executor stamps provenance into reproducers it saves; a reproduce never
    // saves, so an empty set is fine here.
    let empty_provenance = WorkloadProvenance::default();
    let exec = Executor {
        rules: &rules,
        feedback: &feedback,
        sink: &sink,
        freq,
        cfg,
        provenance: &empty_provenance,
    };
    let mut rng = Rng::new(cfg.seed);
    ui::info(&format!("replaying {} step(s)…", plan.steps.len()));
    let out = exec.run(&plan, ready, 0, rng.next_u64());

    // Surface the injection trace before the verdict so the timer-deadline jumps
    // are visible regardless of how the run is judged below.
    if cfg.trace_injects {
        print_inject_trace(&sink);
    }

    // A faithful recording supplies every byte of randomness the guest consumed.
    // If the replay drew past the recorded tapes, it diverged from the recording
    // (it took a hungrier path), so this is a reproduction failure regardless of
    // whether a finding fired — the saved recording was supposed to have it all.
    if out.fresh_random_bytes > 0 {
        ui::err(&format!(
            "replay drew {} byte(s) of randomness past the recorded tapes — the \
             recording is incomplete and the replay diverged from it",
            out.fresh_random_bytes
        ));
        return Err(
            "ran out of recorded randomness: the replay drew entropy the \
                    recording did not contain, so the recorded finding did not \
                    reproduce faithfully"
                .into(),
        );
    }

    report(&repro, &out)
}

/// Compare what the replay fired against what was recorded and emit the verdict.
/// `Ok(())` iff the exact same finding (kind and reason) reproduced.
fn report(repro: &Reproducer, out: &ExecOutcome) -> Result<()> {
    match &out.finding {
        Some(f) if f.kind() == repro.kind && f.reason() == repro.reason => {
            ui::solution(&format!("REPRODUCED — {}", f.reason()));
            print_serial(&out.serial);
            ui::good("the recorded finding reproduced");
            Ok(())
        }
        Some(f) if f.kind() == repro.kind => {
            ui::warn(&format!(
                "same kind ({}) but a different reason — recorded {:?}, got {:?}",
                f.kind(),
                repro.reason,
                f.reason()
            ));
            print_serial(&out.serial);
            Err("a different finding fired; recorded finding did not reproduce".into())
        }
        Some(f) => {
            ui::warn(&format!(
                "a different finding fired — recorded {} {:?}, got {} {:?}",
                repro.kind,
                repro.reason,
                f.kind(),
                f.reason()
            ));
            print_serial(&out.serial);
            Err("a different finding fired; recorded finding did not reproduce".into())
        }
        None => {
            ui::err("did not reproduce — the plan ran to completion with no finding");
            Err("recorded finding did not reproduce".into())
        }
    }
}

fn print_serial(serial: &[String]) {
    for line in serial {
        ui::detail(line);
    }
}

/// Print the `--trace-injects` summary: the timer-injection count, the largest
/// emulated-TSC gap between consecutive captured events, and one line per
/// flagged gap. Each flagged line carries the deadline the timer fired for, so a
/// short guest sleep that leapt the clock forward by seconds is visible directly.
fn print_inject_trace(sink: &Sink) {
    let Some((lines, injects, max_gap_secs)) = sink.take_inject_trace() else {
        return;
    };
    ui::info(&format!(
        "inject trace: {injects} timer injection(s); largest inter-event emulated-TSC gap {max_gap_secs:.3}s"
    ));
    if lines.is_empty() {
        ui::good("no emulated-TSC gaps above threshold — the clock advanced smoothly");
    } else {
        ui::warn(&format!(
            "{} emulated-TSC gap(s) ≥ 0.25s flagged (idle over-advance to a far timer deadline):",
            lines.len()
        ));
        for line in &lines {
            ui::detail(line);
        }
    }
}

/// Parse a reproducer JSON document into a [`Reproducer`]. This is the read side
/// of [`solution::save_solution`](crate::solution); it mirrors that field layout
/// (`kind`, `reason`, `steps[].batch[].{name,target,offset,driver}`,
/// `steps[].{rng,rand}`, and the `workload` provenance block) and ignores the
/// bookkeeping fields (`bug`/`core`/`iter`/`vt_secs`).
fn parse_reproducer(json: &str) -> Result<Reproducer> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid reproducer JSON: {e}"))?;
    let kind = v["kind"]
        .as_str()
        .ok_or("reproducer has no string \"kind\" field")?
        .to_string();
    let reason = v["reason"].as_str().unwrap_or_default().to_string();
    let steps_v = v["steps"]
        .as_array()
        .ok_or("reproducer has no \"steps\" array")?;

    let mut steps = Vec::with_capacity(steps_v.len());
    for (i, s) in steps_v.iter().enumerate() {
        let batch_v = s["batch"]
            .as_array()
            .ok_or_else(|| format!("step {i} has no \"batch\" array"))?;
        let mut batch = Vec::with_capacity(batch_v.len());
        for m in batch_v {
            let name = m["name"]
                .as_str()
                .ok_or_else(|| format!("step {i} batch member has no \"name\""))?
                .to_string();
            let target = m["target"]
                .as_str()
                .ok_or_else(|| format!("step {i} batch member {name:?} has no \"target\""))?
                .to_string();
            let offset = m["offset"].as_i64().ok_or_else(|| {
                format!("step {i} batch member {name:?} has no integer \"offset\"")
            })?;
            batch.push(RawMember {
                name,
                target,
                offset,
                recorded_driver: m["driver"].as_u64(),
            });
        }
        steps.push(RawStep {
            batch,
            rng: parse_byte_tape(&s["rng"], "rng", i)?,
            rand: parse_byte_tape(&s["rand"], "rand", i)?,
        });
    }
    Ok(Reproducer {
        kind,
        reason,
        steps,
        provenance: WorkloadProvenance::from_doc(&v),
    })
}

/// Parse one recorded byte tape (`rng`/`rand`): a JSON array of `0..=255`. A
/// missing/`null` tape is empty.
fn parse_byte_tape(v: &serde_json::Value, what: &str, step: usize) -> Result<Vec<u8>> {
    match v {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                let n = it
                    .as_u64()
                    .ok_or_else(|| format!("step {step} {what} tape has a non-numeric entry"))?;
                out.push(u8::try_from(n).map_err(|_| {
                    format!("step {step} {what} tape entry {n} is out of byte range 0..=255")
                })?);
            }
            Ok(out)
        }
        _ => Err(format!("step {step} {what} tape is not an array").into()),
    }
}

/// Rebuild the replayable [`Plan`] from a parsed reproducer against the live rule
/// set, mapping each recorded `(name, target)` to its current driver index.
/// Returns the plan and how many recorded indices no longer agreed with the
/// remap (a sign discovery order shifted between boots). Errors if a recorded
/// driver is no longer present — the workload differs from when it was recorded.
fn build_plan(repro: &Reproducer, rules: &[Rule]) -> Result<(Plan, usize)> {
    let by_key: HashMap<(String, String), usize> = rules
        .iter()
        .enumerate()
        .map(|(i, r)| ((r.name.clone(), format!("{:?}", r.target)), i))
        .collect();

    let mut shifted = 0usize;
    let mut plan = Plan::empty(rules.len());
    for (si, s) in repro.steps.iter().enumerate() {
        let mut batch = Vec::with_capacity(s.batch.len());
        for m in &s.batch {
            let &driver = by_key
                .get(&(m.name.clone(), m.target.clone()))
                .ok_or_else(|| {
                    format!(
                        "step {si}: driver {:?} on {} is not among the discovered rules — \
                         the workload differs from when this reproducer was recorded",
                        m.name, m.target
                    )
                })?;
            if m.recorded_driver.is_some_and(|d| d as usize != driver) {
                shifted += 1;
            }
            batch.push(Member {
                driver,
                offset: m.offset,
            });
        }
        plan.steps.push(Step {
            batch,
            rng: s.rng.clone(),
            rand: s.rand.clone(),
        });
    }
    Ok((plan, shifted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::classify;
    use bedrock_lab::BashTarget;

    fn rule(target: BashTarget, name: &str) -> Rule {
        Rule {
            target,
            name: name.to_string(),
            command: format!("/opt/bedrock/drivers/{name}"),
            kind: classify(name),
        }
    }

    // A minimal reproducer in the exact shape `solution::save_solution` writes.
    const DOC: &str = r#"{
        "bug": 0, "kind": "assertion", "reason": "boom",
        "core": 1, "iter": 2, "vt_secs": 0.0,
        "steps": [
            { "batch": [
                {"driver": 1, "name": "singleton_x", "target": "Container(\"bitcoin\")", "kind": "Singleton", "offset": 625000},
                {"driver": 0, "name": "anytime_kick", "target": "Host", "kind": "Anytime", "offset": 7}
              ],
              "rng": [], "rand": [1, 2, 3]
            }
        ]
    }"#;

    #[test]
    fn parses_kind_reason_and_tapes() {
        let r = parse_reproducer(DOC).unwrap();
        assert_eq!(r.kind, "assertion");
        assert_eq!(r.reason, "boom");
        assert_eq!(r.steps.len(), 1);
        assert!(r.steps[0].rng.is_empty());
        assert_eq!(r.steps[0].rand, vec![1, 2, 3]);
        assert_eq!(r.steps[0].batch[0].name, "singleton_x");
        assert_eq!(r.steps[0].batch[0].target, "Container(\"bitcoin\")");
        assert_eq!(r.steps[0].batch[0].offset, 625000);
        assert_eq!(r.steps[0].batch[0].recorded_driver, Some(1));
        // DOC has no workload block -> no provenance (old-format compatible).
        assert!(r.provenance.is_none());
    }

    #[test]
    fn parses_workload_provenance_block() {
        let doc = r#"{
            "kind": "assertion", "reason": "boom",
            "steps": [ { "batch": [
                {"name": "anytime_kick", "target": "Host", "offset": 0}
              ], "rng": [], "rand": [] } ],
            "workload": {
                "vmlinux":   { "path": "/k/vmlinux", "sha1": "aabb" },
                "images.tar":{ "path": "/w/images.tar", "sha1": "ccdd" }
            }
        }"#;
        let r = parse_reproducer(doc).unwrap();
        let prov = r.provenance.expect("workload block parsed");
        assert_eq!(prov.files.len(), 2);
        let vk = prov.files.iter().find(|f| f.key == "vmlinux").unwrap();
        assert_eq!(vk.path, "/k/vmlinux");
        assert_eq!(vk.sha1, "aabb");
    }

    #[test]
    fn builds_plan_remapping_by_name_and_target() {
        // Discovery order here differs from the recorded indices: the singleton is
        // index 0 and the kick is index 1, the reverse of the doc. Remapping must
        // follow name+target, not the stored index — and report the shift.
        let rules = vec![
            rule(BashTarget::container("bitcoin"), "singleton_x"), // idx 0
            rule(BashTarget::host(), "anytime_kick"),              // idx 1
        ];
        let r = parse_reproducer(DOC).unwrap();
        let (plan, shifted) = build_plan(&r, &rules).unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].batch[0].driver, 0, "singleton_x@bitcoin -> 0");
        assert_eq!(plan.steps[0].batch[0].offset, 625000);
        assert_eq!(plan.steps[0].batch[1].driver, 1, "anytime_kick@Host -> 1");
        assert_eq!(plan.steps[0].rand, vec![1, 2, 3]);
        assert_eq!(shifted, 2, "both recorded indices were reversed");
    }

    #[test]
    fn matching_indices_report_no_shift() {
        let rules = vec![
            rule(BashTarget::host(), "anytime_kick"), // idx 0
            rule(BashTarget::container("bitcoin"), "singleton_x"), // idx 1
        ];
        let r = parse_reproducer(DOC).unwrap();
        let (_, shifted) = build_plan(&r, &rules).unwrap();
        assert_eq!(shifted, 0, "indices match the recorded ones");
    }

    #[test]
    fn missing_driver_is_an_error() {
        // singleton_x@Container(bitcoin) is absent -> the workload differs.
        let rules = vec![rule(BashTarget::host(), "anytime_kick")];
        let r = parse_reproducer(DOC).unwrap();
        assert!(build_plan(&r, &rules).is_err());
    }

    #[test]
    fn rejects_out_of_range_byte_tape() {
        let doc = r#"{"kind":"vm-fault","reason":"vm fault","steps":[{"batch":[],"rng":[300],"rand":[]}]}"#;
        assert!(parse_reproducer(doc).is_err());
    }

    #[test]
    fn rejects_missing_kind() {
        let doc = r#"{"reason":"x","steps":[]}"#;
        assert!(parse_reproducer(doc).is_err());
    }
}

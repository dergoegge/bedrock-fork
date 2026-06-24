// SPDX-License-Identifier: GPL-2.0

//! Recording a finding: the one place that turns a bug into reproducer files.
//!
//! [`record_finding`] owns the whole flow — serialize the raw reproducer and its
//! serial proof immediately (so a crash is never lost), delta-debug it down to a
//! minimal plan, then serialize the minimized reproducer — behind a single call.
//! The worker loop hands it a finding and its provenance; everything about the
//! `bug-<hash>.*` file format and the minimization strategy lives here.

use std::path::Path;

use bedrock_lab::Checkpoint;

use crate::campaign::Config;
use crate::driver::Rule;
use crate::executor::Executor;
use crate::hash::sha1_file;
use crate::input::Plan;
use crate::oracle::Finding;
use crate::prng::Rng;
use crate::ui;

/// The workload files a [`Config`] points at, in a fixed order, keyed by the
/// name stored in (and looked up from) a reproducer's `workload` block. The
/// single source of truth for both stamping and verifying provenance, so the two
/// sides can never disagree on which files matter.
pub fn config_workload_files(cfg: &Config) -> [(&'static str, &Path); 4] {
    [
        ("vmlinux", cfg.vmlinux.as_path()),
        ("initramfs", cfg.initramfs.as_path()),
        ("compose", cfg.compose.as_path()),
        ("images", cfg.images.as_path()),
    ]
}

/// One workload file's recorded provenance: the host path it was served from and
/// its SHA-1, so a reproduce can confirm it is replaying against the same bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileProvenance {
    /// Canonical key: `vmlinux` | `initramfs` | `compose` | `images`.
    pub key: String,
    pub path: String,
    pub sha1: String,
}

/// SHA-1 provenance for every workload file a reproducer depends on. Config paths
/// left empty (a workload with no compose/images, say) are skipped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkloadProvenance {
    pub files: Vec<FileProvenance>,
}

impl WorkloadProvenance {
    /// Hash every non-empty workload file the config points at. Returns the first
    /// I/O error — a missing or unreadable workload file is worth surfacing, not
    /// silently recording a reproducer without it.
    pub fn collect(cfg: &Config) -> std::io::Result<Self> {
        let mut files = Vec::new();
        for (key, path) in config_workload_files(cfg) {
            if path.as_os_str().is_empty() {
                continue;
            }
            files.push(FileProvenance {
                key: key.to_string(),
                path: path.display().to_string(),
                sha1: sha1_file(path)?,
            });
        }
        // Canonical (key-sorted) order so a round-trip through the JSON object
        // form — whose keys serialize alphabetically — compares equal.
        files.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(WorkloadProvenance { files })
    }

    /// The `"workload"` JSON object: `{ <key>: { "path", "sha1" }, … }`.
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for f in &self.files {
            map.insert(
                f.key.clone(),
                serde_json::json!({ "path": f.path, "sha1": f.sha1 }),
            );
        }
        serde_json::Value::Object(map)
    }

    /// Check each recorded file against the live config: the path configured for
    /// the same key must exist and hash to the recorded SHA-1. Returns one
    /// human-readable problem string per mismatch, missing path, or unreadable
    /// file; an empty vec means every recorded file matched.
    pub fn verify_against(&self, cfg: &Config) -> Vec<String> {
        let live = config_workload_files(cfg);
        let mut problems = Vec::new();
        for f in &self.files {
            let Some(path) = live.iter().find(|(k, _)| *k == f.key).map(|(_, p)| *p) else {
                problems.push(format!(
                    "{}: recorded but not part of this run's config",
                    f.key
                ));
                continue;
            };
            if path.as_os_str().is_empty() {
                problems.push(format!(
                    "{}: no path supplied for this run (recorded {})",
                    f.key, f.path
                ));
                continue;
            }
            match sha1_file(path) {
                Ok(h) if h == f.sha1 => {}
                Ok(h) => problems.push(format!(
                    "{}: sha1 mismatch — recorded {} ({}), but supplied {} is {}",
                    f.key,
                    f.sha1,
                    f.path,
                    path.display(),
                    h
                )),
                Err(e) => problems.push(format!(
                    "{}: cannot read supplied {} to verify: {e}",
                    f.key,
                    path.display()
                )),
            }
        }
        problems
    }

    /// Parse a reproducer's `workload` block. `None` when the reproducer predates
    /// provenance (the block is absent); an empty block parses to an empty set.
    pub fn from_doc(doc: &serde_json::Value) -> Option<Self> {
        let obj = doc.get("workload")?.as_object()?;
        let mut files = Vec::new();
        for (key, entry) in obj {
            files.push(FileProvenance {
                key: key.clone(),
                path: entry
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or_default()
                    .to_string(),
                sha1: entry
                    .get("sha1")
                    .and_then(|s| s.as_str())
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        files.sort_by(|a, b| a.key.cmp(&b.key));
        Some(WorkloadProvenance { files })
    }
}

/// Where and when a finding turned up — the provenance stamped into its
/// reproducer files and the UI line.
pub struct FoundAt {
    /// Run-local bug counter, shown in the UI line only. Reproducer files are
    /// named by a content hash of the inputs (`bug-<input-hash>`), not this.
    pub id: u64,
    /// Corpus entry the parent plan was picked from.
    pub from: usize,
    /// Worker core that found it.
    pub core: usize,
    /// Worker iteration it was found on.
    pub iter: u64,
    /// Guest virtual seconds the plan reached.
    pub vt_secs: f64,
}

/// Persist and minimize a finding. Writes the raw reproducer + serial proof
/// up front (minimization re-runs the VM many times, so the bug is saved before
/// that risk), then minimizes and writes the minimized reproducer. Emits the UI
/// lines for the solution. The reason is taken from the finding.
pub fn record_finding(
    exec: &Executor,
    found: &FoundAt,
    finding: &Finding,
    plan: &Plan,
    serial: &[String],
    ready: &Checkpoint,
    rng: &mut Rng,
) {
    let dir = &exec.cfg.solutions_dir;
    let id = found.id;
    let reason = finding.reason();

    // Name the finding by a content hash of its inputs (the plan), not a per-run
    // counter: identical inputs always produce the same `bug-<hash>` stem, so a
    // bug has a stable identity across runs and cores, and the same bug rediscovered
    // later overwrites its own files instead of piling up `crash-0`, `crash-1`, …
    let stem = format!("bug-{:032x}", plan.input_hash());

    ui::solution(&format!(
        "SOLUTION #{id} {stem} (from corpus entry {}) — {reason}",
        found.from
    ));
    for line in serial {
        ui::detail(line);
    }

    // The workload provenance (kernel/initrd/compose/images paths + SHA-1) was
    // hashed once at startup — see [`WorkloadProvenance::collect`] — so a finding
    // never pays to re-hash a multi-hundred-MB `images.tar`. Stamp it into the
    // reproducer so a replay can confirm it runs against the same bytes. Omit the
    // block entirely if it is empty (no workload files, or startup hashing
    // failed).
    let provenance = (!exec.provenance.files.is_empty()).then_some(exec.provenance);

    // Save the raw reproducer + serial immediately — minimization re-runs the VM
    // many times, so don't risk losing the bug.
    if let Err(e) = save_solution(
        dir,
        &format!("{stem}.json"),
        found,
        finding,
        &reason,
        plan,
        exec.rules,
        provenance,
    ) {
        ui::warn(&format!("could not save {stem}.json: {e}"));
    }
    if let Err(e) = save_serial(dir, &format!("{stem}.serial.log"), serial) {
        ui::warn(&format!("could not save {stem}.serial.log: {e}"));
    }

    let minimal = minimize(exec, plan, finding, ready, rng);
    match save_solution(
        dir,
        &format!("{stem}.min.json"),
        found,
        finding,
        &reason,
        &minimal,
        exec.rules,
        provenance,
    ) {
        Ok(path) => ui::good(&format!(
            "SOLUTION {stem} minimized {} -> {} steps, saved {path}",
            plan.steps.len(),
            minimal.steps.len()
        )),
        Err(e) => ui::warn(&format!("could not save {stem}.min.json: {e}")),
    }
}

/// Whether a re-run reproduced the same *kind* of finding as the target.
fn same_kind(found: &Option<Finding>, target: &Finding) -> bool {
    matches!(found, Some(f) if f.kind() == target.kind())
}

/// Delta-debug a finding: drop steps and clear per-step randomness while the same
/// kind of finding still reproduces. Each candidate is re-run from the ready
/// checkpoint (the genealogy serves the shared boot prefix).
fn minimize(
    exec: &Executor,
    plan: &Plan,
    target: &Finding,
    ready: &Checkpoint,
    rng: &mut Rng,
) -> Plan {
    let mut best = plan.clone();
    let mut changed = true;
    while changed {
        changed = false;

        let mut i = 0;
        while i < best.steps.len() {
            let mut cand = best.clone();
            cand.steps.remove(i);
            let out = exec.run(&cand, ready.clone(), 0, rng.next_u64());
            if same_kind(&out.finding, target) {
                best = out.realized;
                changed = true;
            } else {
                i += 1;
            }
        }

        for i in 0..best.steps.len() {
            if best.steps[i].rng.is_empty() && best.steps[i].rand.is_empty() {
                continue;
            }
            let mut cand = best.clone();
            cand.steps[i].rng.clear();
            cand.steps[i].rand.clear();
            let out = exec.run(&cand, ready.clone(), 0, rng.next_u64());
            if same_kind(&out.finding, target) {
                best = out.realized;
                changed = true;
            }
        }
    }
    best
}

/// Write a reproducer JSON for bug `found.id`: the finding's kind/reason, where
/// it was found, the plan (each step's resolved driver batch + the exact
/// randomness the guest consumed — `rng` is the RDRAND tape, `rand` the
/// getrandom() tape), and the `workload` provenance (kernel/initrd/compose/images
/// paths + SHA-1). The plan is replayable.
#[allow(clippy::too_many_arguments)]
fn save_solution(
    dir: &str,
    file: &str,
    found: &FoundAt,
    finding: &Finding,
    reason: &str,
    plan: &Plan,
    rules: &[Rule],
    provenance: Option<&WorkloadProvenance>,
) -> std::io::Result<String> {
    let steps: Vec<serde_json::Value> = plan
        .steps
        .iter()
        .map(|s| {
            let batch: Vec<serde_json::Value> = s
                .batch
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "driver": m.driver,
                        "name": rules.get(m.driver).map(|r| r.name.as_str()).unwrap_or("?"),
                        "target": rules.get(m.driver).map(|r| format!("{:?}", r.target)),
                        "kind": rules.get(m.driver).map(|r| format!("{:?}", r.kind)),
                        "offset": m.offset,
                    })
                })
                .collect();
            serde_json::json!({ "batch": batch, "rng": s.rng, "rand": s.rand })
        })
        .collect();
    let mut doc = serde_json::json!({
        "bug": found.id,
        "kind": finding.kind(),
        "reason": reason,
        "core": found.core,
        "iter": found.iter,
        "vt_secs": found.vt_secs,
        "steps": steps,
    });
    if let Some(p) = provenance {
        doc["workload"] = p.to_json();
    }
    std::fs::create_dir_all(dir)?;
    let path = format!("{dir}/{file}");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap())?;
    Ok(path)
}

/// Write the finding's serial to `<dir>/<file>` as plain text so the bug's
/// console proof can be read directly.
fn save_serial(dir: &str, file: &str, serial: &[String]) -> std::io::Result<String> {
    std::fs::create_dir_all(dir)?;
    let path = format!("{dir}/{file}");
    std::fs::write(&path, serial.join("\n"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::DriverKind;
    use crate::input::{Member, Step};
    use bedrock_lab::BashTarget;

    #[test]
    fn saves_reproducer_json_and_serial_log() {
        let dir = std::env::temp_dir().join("lonepine-save-test");
        let dir = dir.to_str().unwrap();
        let _ = std::fs::remove_dir_all(dir);

        let rules = vec![
            Rule {
                target: BashTarget::host(),
                name: "drv-a".to_string(),
                command: "/opt/bedrock/drivers/drv-a".to_string(),
                kind: DriverKind::Parallel,
            },
            Rule {
                target: BashTarget::host(),
                name: "drv-b".to_string(),
                command: "/opt/bedrock/drivers/drv-b".to_string(),
                kind: DriverKind::Parallel,
            },
        ];
        let mut plan = Plan::empty(rules.len());
        plan.steps.push(Step {
            batch: vec![Member {
                driver: 1,
                offset: 42,
            }],
            rng: vec![1, 2, 3],
            rand: vec![4, 5, 6],
        });
        let finding = Finding::Assertion {
            step: 0,
            message: "boom".to_string(),
        };
        let found = FoundAt {
            id: 7,
            from: 0,
            core: 2,
            iter: 99,
            vt_secs: 12.5,
        };

        let path = save_solution(
            dir,
            "crash-7.json",
            &found,
            &finding,
            "boom",
            &plan,
            &rules,
            None,
        )
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["bug"].as_u64(), Some(7));
        assert_eq!(v["kind"].as_str(), Some("assertion"));
        assert_eq!(v["reason"].as_str(), Some("boom"));
        assert_eq!(v["core"].as_u64(), Some(2));
        assert_eq!(v["steps"][0]["batch"][0]["name"].as_str(), Some("drv-b"));
        assert_eq!(v["steps"][0]["batch"][0]["offset"].as_i64(), Some(42));
        assert_eq!(v["steps"][0]["rng"][2].as_u64(), Some(3));
        assert_eq!(v["steps"][0]["rand"][0].as_u64(), Some(4));

        let log = save_serial(dir, "crash-7.log", &["l1".to_string(), "l2".to_string()]).unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "l1\nl2");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn provenance_collects_hashes_and_round_trips() {
        let dir = std::env::temp_dir().join("lonepine-prov-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vmlinux = dir.join("vmlinux");
        let initramfs = dir.join("initrd");
        let compose = dir.join("compose.yaml");
        std::fs::write(&vmlinux, b"kernel-bytes").unwrap();
        std::fs::write(&initramfs, b"initrd-bytes").unwrap();
        std::fs::write(&compose, b"services: {}").unwrap();

        let cfg = Config {
            vmlinux: vmlinux.clone(),
            initramfs: initramfs.clone(),
            compose: compose.clone(),
            // images left empty — must be skipped, not error.
            images: std::path::PathBuf::new(),
            ..Config::default()
        };

        let prov = WorkloadProvenance::collect(&cfg).unwrap();
        assert_eq!(prov.files.len(), 3, "empty images path is skipped");
        let vk = prov.files.iter().find(|f| f.key == "vmlinux").unwrap();
        assert_eq!(vk.sha1, crate::hash::sha1_hex(b"kernel-bytes"));
        assert_eq!(vk.path, vmlinux.display().to_string());
        assert!(prov.files.iter().all(|f| f.key != "images"));

        // Round-trip through the JSON form the reproducer stores.
        let doc = serde_json::json!({ "workload": prov.to_json() });
        let parsed = WorkloadProvenance::from_doc(&doc).unwrap();
        assert_eq!(parsed, prov);

        // A doc with no workload block parses to None (old reproducers).
        assert!(WorkloadProvenance::from_doc(&serde_json::json!({ "bug": 0 })).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_against_detects_matches_and_mismatches() {
        let dir = std::env::temp_dir().join("lonepine-verify-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vmlinux = dir.join("vmlinux");
        let initramfs = dir.join("initrd");
        std::fs::write(&vmlinux, b"kernel-v1").unwrap();
        std::fs::write(&initramfs, b"initrd-bytes").unwrap();

        let cfg = Config {
            vmlinux: vmlinux.clone(),
            initramfs: initramfs.clone(),
            compose: std::path::PathBuf::new(),
            images: std::path::PathBuf::new(),
            ..Config::default()
        };
        let prov = WorkloadProvenance::collect(&cfg).unwrap();

        // Same files -> no problems.
        assert!(prov.verify_against(&cfg).is_empty());

        // Rewrite the kernel: its SHA-1 no longer matches the recorded one.
        std::fs::write(&vmlinux, b"kernel-v2-different").unwrap();
        let problems = prov.verify_against(&cfg);
        assert_eq!(problems.len(), 1, "only the kernel changed");
        assert!(problems[0].contains("vmlinux"));
        assert!(problems[0].contains("sha1 mismatch"));

        // A recorded file no longer supplied (empty path) is also a problem.
        let cfg_missing = Config {
            vmlinux: std::path::PathBuf::new(),
            ..cfg.clone()
        };
        let problems = prov.verify_against(&cfg_missing);
        assert!(problems.iter().any(|p| p.contains("no path supplied")));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

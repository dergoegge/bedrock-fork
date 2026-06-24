// SPDX-License-Identifier: GPL-2.0

//! Dual-mode lab event sink for serial capture (ported from flux).
//!
//! During boot, the sink shows every serial line in a fixed-height scrolling
//! panel so the user can watch the workload come up (and its container monitor
//! announce `[podman]` lifecycle events). Once [`Sink::enter_fuzz_mode`] is
//! called, the panel is sealed and the sink instead buffers per-branch lines
//! keyed by [`BranchId`]. The campaign calls [`Sink::start_capture`] before
//! running a branch and [`Sink::take_capture`] after, so captured serial can be
//! scanned for failed assertions (the bug oracle) and attached to a finding.

use std::collections::HashMap;
use std::sync::Mutex;

use bedrock_lab::{BranchId, Event, EventSink};
use bedrock_vm::events::{Event as VmEvent, EventKind};

use crate::ui::BootLog;

/// Smallest emulated-TSC gap between two consecutive captured events that the
/// inject trace flags. Normal APIC timer ticks are ≤ a few milliseconds apart;
/// a quarter second of guest time elapsing with no event in between is the
/// signature of an idle over-advance (`handle_idle` jumping the emulated TSC to
/// a far-future timer deadline), which is exactly what we are hunting.
const TRACE_GAP_SECS: f64 = 0.25;

pub struct Sink {
    inner: Mutex<Inner>,
}

struct Inner {
    mode: Mode,
    captures: HashMap<BranchId, Vec<String>>,
    /// The in-place boot-log panel (used only in `Boot` mode).
    boot: BootLog,
    /// Injection-trace state; `None` until [`Sink::enable_inject_trace`].
    trace: Option<InjectTrace>,
}

/// Accumulated state for the `--trace-injects` diagnostic: enough to measure
/// the emulated-TSC gap between consecutive captured events per branch and to
/// summarize the timer-injection stream afterward.
struct InjectTrace {
    /// Emulated TSC frequency, to render ticks as seconds.
    freq: u64,
    /// Last captured-event emulated TSC seen on each branch.
    last_tsc: HashMap<BranchId, u64>,
    /// One line per flagged gap, drained by [`Sink::take_inject_trace`].
    lines: Vec<String>,
    /// Total timer injections observed across all branches.
    injects: u64,
    /// Largest single inter-event gap seen (emulated TSC ticks).
    max_gap: u64,
}

enum Mode {
    /// Show boot + discovery serial in a fixed-height scrolling panel.
    Boot,
    /// Buffer lines for branches registered via `start_capture`; drop the rest
    /// (boot pre-checkpoint output we already saw shouldn't reappear).
    Fuzz,
}

impl Default for Sink {
    fn default() -> Self {
        Self::new()
    }
}

impl Sink {
    pub fn new() -> Self {
        Sink {
            inner: Mutex::new(Inner {
                mode: Mode::Boot,
                captures: HashMap::new(),
                boot: BootLog::new(),
                trace: None,
            }),
        }
    }

    /// Turn on the injection trace. `freq` is the guest's emulated TSC
    /// frequency (so gaps render as seconds). After this, every captured
    /// [`Event::Record`] updates the per-branch gap tracker and large gaps are
    /// recorded for [`Sink::take_inject_trace`]. The executor must also enable
    /// the [`INJECT`](bedrock_lab::EventCategories::INJECT) category on its
    /// branches (it does so when `Config::trace_injects` is set) for timer
    /// injections to reach the sink.
    pub fn enable_inject_trace(&self, freq: u64) {
        self.inner.lock().unwrap().trace = Some(InjectTrace {
            freq,
            last_tsc: HashMap::new(),
            lines: Vec::new(),
            injects: 0,
            max_gap: 0,
        });
    }

    /// Drain the flagged gap lines and return `(lines, injects, max_gap_secs)`,
    /// or `None` if the trace was never enabled. `injects` is the total timer
    /// injections observed; `max_gap_secs` is the largest inter-event gap.
    pub fn take_inject_trace(&self) -> Option<(Vec<String>, u64, f64)> {
        let mut s = self.inner.lock().unwrap();
        let t = s.trace.as_mut()?;
        let lines = std::mem::take(&mut t.lines);
        let injects = t.injects;
        let max_gap_secs = t.max_gap as f64 / t.freq as f64;
        Some((lines, injects, max_gap_secs))
    }

    /// Flip out of `Boot` mode, sealing the boot panel. Call once after the
    /// discovery checkpoint is taken and before the fuzz loop starts.
    pub fn enter_fuzz_mode(&self) {
        let mut s = self.inner.lock().unwrap();
        s.boot.finish();
        s.mode = Mode::Fuzz;
    }

    /// Begin recording lines for `branch`.
    pub fn start_capture(&self, branch: BranchId) {
        self.inner
            .lock()
            .unwrap()
            .captures
            .insert(branch, Vec::new());
    }

    /// Stop recording for `branch` and return the accumulated lines.
    pub fn take_capture(&self, branch: BranchId) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .captures
            .remove(&branch)
            .unwrap_or_default()
    }
}

impl EventSink for Sink {
    fn on_event(&self, event: Event<'_>) {
        match event {
            Event::SerialLine { branch, at, line } => {
                let body = String::from_utf8_lossy(line);
                let body = body.trim_end_matches('\n');
                let mut s = self.inner.lock().unwrap();
                match s.mode {
                    Mode::Boot => {
                        // Compact form for the scrolling panel: a timestamp plus
                        // the message, without the heavy per-branch prefix.
                        let compact = format!("{:>7.2}s  {body}", at.as_secs_f64());
                        s.boot.push(&compact);
                    }
                    Mode::Fuzz => {
                        if let Some(buf) = s.captures.get_mut(&branch) {
                            // Tag each captured line with its branch id and
                            // virtual time — context for finding reports.
                            buf.push(format!(
                                "[br {branch:?} vt {:>8.3}] {body}",
                                at.as_secs_f64()
                            ));
                        }
                    }
                }
            }
            // Announce feedback-buffer registrations during boot so the user
            // can confirm an instrumented workload wired up its coverage buffer.
            Event::FeedbackBufferRegistered {
                at, id, slot, size, ..
            } => {
                let mut s = self.inner.lock().unwrap();
                if matches!(s.mode, Mode::Boot) {
                    let msg = format!(
                        "{:>7.2}s  feedback buffer registered: id={:?} slot={slot} size={size}",
                        at.as_secs_f64(),
                        String::from_utf8_lossy(id),
                    );
                    s.boot.push(&msg);
                }
            }
            // Unified event-stream records (only forwarded for categories a
            // branch opted into). With the inject trace on, watch the emulated
            // TSC between consecutive records: a large gap means the guest's
            // emulated TSC leapt forward with nothing happening in between — an
            // idle over-advance to a far-future APIC timer deadline.
            Event::Record { branch, record } => {
                let mut s = self.inner.lock().unwrap();
                let Some(trace) = s.trace.as_mut() else {
                    return;
                };
                let freq = trace.freq;
                let tsc = record.tsc();
                if record.kind() == EventKind::Inject.as_u16() {
                    trace.injects += 1;
                }
                if let Some(prev) = trace.last_tsc.insert(branch, tsc) {
                    let gap = tsc.saturating_sub(prev);
                    if gap as f64 / freq as f64 >= TRACE_GAP_SECS {
                        if gap > trace.max_gap {
                            trace.max_gap = gap;
                        }
                        // Decode the record that *follows* the gap. After an
                        // idle jump that record is the timer injection itself,
                        // whose `target_tsc` is the deadline the timer was armed
                        // for — the value the guest's clock leapt to.
                        let detail = match record.event() {
                            VmEvent::Inject(p) => format!(
                                "timer inject vector={} deadline_tsc={} fired_tsc={}",
                                p.vector, p.target_tsc, tsc
                            ),
                            VmEvent::IoChannel(..) => "io-channel record".to_string(),
                            VmEvent::Randomness(..) => "randomness record".to_string(),
                            VmEvent::Exit(..) => "exit record".to_string(),
                            _ => "event".to_string(),
                        };
                        trace.lines.push(format!(
                            "[br {branch:?} vt {:>8.3}] +{:.3}s emulated-TSC gap — {detail}",
                            tsc as f64 / freq as f64,
                            gap as f64 / freq as f64,
                        ));
                    }
                }
            }
            _ => {}
        }
    }
}

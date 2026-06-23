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

use crate::ui::BootLog;

pub struct Sink {
    inner: Mutex<Inner>,
}

struct Inner {
    mode: Mode,
    captures: HashMap<BranchId, Vec<String>>,
    /// The in-place boot-log panel (used only in `Boot` mode).
    boot: BootLog,
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
            }),
        }
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
            _ => {}
        }
    }
}

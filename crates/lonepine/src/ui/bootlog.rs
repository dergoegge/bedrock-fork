// SPDX-License-Identifier: GPL-2.0

//! The boot-log panel: a fixed-height, in-place scrolling view of guest serial.
//!
//! Booting a container workload emits thousands of kernel/journal lines; we
//! don't want all of them in the scrollback. On a terminal, [`BootLog`] keeps
//! only the last [`BOOT_WINDOW`] lines visible, redrawing them in place as new
//! lines arrive (a small marquee panel), then [`finish`](BootLog::finish) seals
//! the panel so the rest of the session prints below it. Piped/quiet output
//! falls back to plain line-by-line (or nothing) so captures keep the full log.

use std::collections::VecDeque;
use std::io::Write;
use std::time::{Duration, Instant};

use super::{color, dimmed, quiet};

/// How many of the most recent boot lines stay on screen at once.
const BOOT_WINDOW: usize = 5;

const REPAINT_INTERVAL: Duration = Duration::from_millis(33);

/// Current terminal width in columns, or 120 if it can't be determined.
fn term_width() -> usize {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            return ws.ws_col as usize;
        }
    }
    120
}

/// Extra-dim styling for trailing boot-history lines.
fn faint(s: &str) -> String {
    if !color() {
        s.to_string()
    } else {
        format!("\x1b[2;38;2;110;110;120m{s}\x1b[0m")
    }
}

/// A fixed-height, in-place scrolling view of the guest's boot log.
pub struct BootLog {
    lines: VecDeque<String>,
    drawn: usize,
    animate: bool,
    /// Last time the panel was actually painted. Boot emits serial faster than
    /// any terminal can usefully show, and a flush per line would throttle the
    /// guest to I/O speed — so we coalesce repaints to ~30 fps.
    last_paint: Option<Instant>,
}

impl Default for BootLog {
    fn default() -> Self {
        Self::new()
    }
}

impl BootLog {
    pub fn new() -> Self {
        Self {
            lines: VecDeque::with_capacity(BOOT_WINDOW),
            drawn: 0,
            // Only the in-place marquee needs a real terminal; over a pipe the
            // cursor moves would be garbage, so fall back to plain printing.
            animate: color() && !quiet(),
            last_paint: None,
        }
    }

    /// Feed one boot line (already without its trailing newline).
    ///
    /// The guest emits boot serial far faster than a terminal can show, and doing
    /// real work in this callback throttles the guest (it runs inside the VM's
    /// event dispatch). So we *sample*: a line that arrives within
    /// [`REPAINT_INTERVAL`] of the last paint is dropped untouched — only ~30
    /// lines a second are kept, formatted, and painted.
    pub fn push(&mut self, line: &str) {
        if quiet() {
            return;
        }
        if !self.animate {
            println!("{line}");
            return;
        }
        let now = Instant::now();
        if self
            .last_paint
            .is_some_and(|t| now.duration_since(t) < REPAINT_INTERVAL)
        {
            return; // sampled out
        }
        let budget = term_width().saturating_sub(4).max(20);
        let clean = crate::shape::strip_ansi(line);
        let truncated: String = clean.chars().take(budget).collect();
        if self.lines.len() == BOOT_WINDOW {
            self.lines.pop_front();
        }
        self.lines.push_back(truncated);
        self.redraw();
        self.last_paint = Some(now);
    }

    fn redraw(&mut self) {
        let mut out = String::new();
        if self.drawn > 0 {
            // Move back up to the top of the previously-drawn panel.
            out.push_str(&format!("\x1b[{}A", self.drawn));
        }
        let last = self.lines.len().saturating_sub(1);
        for (i, line) in self.lines.iter().enumerate() {
            // `\x1b[2K` clears the whole line first so a shorter new line
            // doesn't leave stale tail characters from the old one.
            let bar = if color() {
                "\x1b[2m│\x1b[0m "
            } else {
                "│ "
            };
            // The freshest line is a touch brighter than the trailing history.
            let body = if i == last { dimmed(line) } else { faint(line) };
            out.push_str(&format!("\x1b[2K{bar}{body}\n"));
        }
        self.drawn = self.lines.len();
        print!("{out}");
        let _ = std::io::stdout().flush();
    }

    /// Seal the panel: paint the final lines (a throttled push may have left
    /// newer lines unshown), then leave them on screen so everything after prints
    /// below. Safe to call when nothing was drawn.
    pub fn finish(&mut self) {
        if self.animate && !self.lines.is_empty() {
            self.redraw();
        }
        self.lines.clear();
        self.drawn = 0;
        self.last_paint = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootlog_window_caps_lines() {
        // With color/quiet off, push just no-ops to stdout; exercise the cap on
        // the buffer directly by forcing animate.
        let mut bl = BootLog {
            lines: VecDeque::new(),
            drawn: 0,
            animate: true,
            last_paint: None,
        };
        for i in 0..20 {
            // bypass the repaint sampler by clearing last_paint each time
            bl.last_paint = None;
            bl.push(&format!("line {i}"));
        }
        assert!(bl.lines.len() <= BOOT_WINDOW);
    }
}

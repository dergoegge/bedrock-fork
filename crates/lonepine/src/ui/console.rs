// SPDX-License-Identifier: GPL-2.0

//! The bottom-pinned console writer and its live spinner.
//!
//! Every finished log line flows through [`emit`], which clears the spinner from
//! the terminal's last line, writes the content, then redraws the spinner
//! beneath it so it stays pinned to the bottom. A single `OUT` lock serializes
//! concurrent workers, the monitor, and the spinner thread so their writes never
//! interleave. The styling of those log lines lives in the parent façade; this
//! module owns only *where* they land relative to the spinner.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use super::{color, quiet};

/// Whether the persistent bottom spinner is currently animating.
static SPIN_ON: AtomicBool = AtomicBool::new(false);

/// Serializes all stdout writes and tracks the bottom spinner so log lines and
/// the spinner's in-place animation never corrupt each other.
static OUT: Mutex<Out> = Mutex::new(Out {
    frame: 0,
    spinner_visible: false,
    status: None,
});

struct Out {
    /// Animation frame, advanced by the spinner thread.
    frame: usize,
    /// Whether the spinner currently occupies the terminal's last line.
    spinner_visible: bool,
    /// Live parenthetical the campaign refreshes (e.g. time/iters since the
    /// last corpus find); rendered after the spinner's action word.
    status: Option<String>,
}

/// Update the spinner's live parenthetical (see [`Out::status`]). The next
/// repaint picks it up; cheap, called a few times a second by the campaign.
pub fn set_spinner_status(status: String) {
    OUT.lock().unwrap().status = Some(status);
}

/// Print a finished log line (or block) above the spinner: clear the spinner
/// line if present, write the content, then redraw the spinner beneath it so it
/// stays pinned to the bottom.
pub(super) fn emit(content: &str) {
    let mut out = OUT.lock().unwrap();
    let mut buf = String::new();
    if out.spinner_visible {
        buf.push_str("\r\x1b[2K");
        out.spinner_visible = false;
    }
    buf.push_str(content);
    buf.push('\n');
    if SPIN_ON.load(Ordering::Relaxed) && color() {
        buf.push_str(&spinner_line(out.frame, out.status.as_deref()));
        out.spinner_visible = true;
    }
    print!("{buf}");
    let _ = std::io::stdout().flush();
}

/// Clear the spinner line (if any) and print to stderr — for errors, which are
/// shown even in quiet mode.
pub(super) fn emit_error(line: &str) {
    let mut out = OUT.lock().unwrap();
    if out.spinner_visible {
        print!("\r\x1b[2K");
        out.spinner_visible = false;
        let _ = std::io::stdout().flush();
    }
    eprintln!("{line}");
}

/// Render the bottom spinner for animation frame `frame`: a bracketed, advancing
/// ASCII spinner glyph plus a shimmering action word that rotates every few
/// seconds (a bright band sweeps the text).
fn spinner_line(frame: usize, status: Option<&str>) -> String {
    const SPIN: [&str; 4] = ["|", "/", "-", "\\"];
    let g = SPIN[frame % SPIN.len()];
    // Hold each word for ~24 frames (~3s at the 120 ms tick) before rotating.
    let word = action_word(frame / 24);
    let suffix = match status {
        Some(s) => format!(" ({s})"),
        None => String::new(),
    };
    shimmer(&format!("[{g}] {word}{suffix}"), frame)
}

/// A rotating, playful description of what the fuzzer is busy doing. Picked
/// pseudo-randomly from `group` (the word-rotation index) so successive words
/// don't just march down the list.
fn action_word(group: usize) -> &'static str {
    const WORDS: [&str; 24] = [
        "fuzzing",
        "mutating",
        "rewinding",
        "branching",
        "exploring",
        "splicing",
        "scheduling",
        "replaying",
        "time-traveling",
        "swarming",
        "scattering",
        "bit-flipping",
        "perturbing",
        "checkpointing",
        "spelunking",
        "rummaging",
        "wrangling",
        "tinkering",
        "poking bits",
        "prodding",
        "jostling",
        "shuffling",
        "nudging",
        "havocking",
    ];
    let mixed = group.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40;
    WORDS[mixed % WORDS.len()]
}

/// Color `text` with a calm blue base and a bright band that sweeps left→right
/// as `frame` advances — the shimmer effect shared by the banner and spinner.
fn shimmer(text: &str, frame: usize) -> String {
    if !color() {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len().max(1);
    let span = n + 6;
    let pos = (frame % span) as f64 - 3.0;
    let mut out = String::new();
    for (i, &ch) in chars.iter().enumerate() {
        let (mut r, mut g, mut b) = (90u8, 150u8, 230u8);
        let d = (i as f64 - pos).abs();
        if d < 2.0 {
            let lift = (1.0 - d / 2.0) * 0.85;
            r = (r as f64 + (255.0 - r as f64) * lift) as u8;
            g = (g as f64 + (255.0 - g as f64) * lift) as u8;
            b = (b as f64 + (255.0 - b as f64) * lift) as u8;
        }
        out.push_str(&format!("\x1b[1;38;2;{r};{g};{b}m{ch}"));
    }
    out.push_str("\x1b[0m");
    out
}

/// Start the always-on, shimmering bottom spinner. No-op when output is piped or
/// quiet. Idempotent. Spawns one detached thread that repaints the spinner in
/// place a few times a second until [`spinner_stop`].
pub fn spinner_start() {
    if quiet() || !color() {
        return;
    }
    if SPIN_ON.swap(true, Ordering::Relaxed) {
        return; // already running
    }
    std::thread::spawn(|| {
        while SPIN_ON.load(Ordering::Relaxed) {
            {
                let mut out = OUT.lock().unwrap();
                out.frame = out.frame.wrapping_add(1);
                let line = spinner_line(out.frame, out.status.as_deref());
                print!("\r\x1b[2K{line}");
                out.spinner_visible = true;
                let _ = std::io::stdout().flush();
            }
            std::thread::sleep(Duration::from_millis(120));
        }
    });
}

/// Stop the spinner and clear its line. Safe to call when it was never started.
pub fn spinner_stop() {
    if !SPIN_ON.swap(false, Ordering::Relaxed) {
        return;
    }
    let mut out = OUT.lock().unwrap();
    if out.spinner_visible {
        print!("\r\x1b[2K");
        out.spinner_visible = false;
        let _ = std::io::stdout().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_word_in_range() {
        for g in 0..1000 {
            let _ = action_word(g); // index must stay in bounds
        }
    }
}

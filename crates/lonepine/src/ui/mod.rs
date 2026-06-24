// SPDX-License-Identifier: GPL-2.0

//! Terminal output (ported from flux), split into three seams:
//!
//! - this façade — tagged, colored message styling, so all human-facing output
//!   stays consistent;
//! - [`console`] — the bottom-pinned writer + live spinner every line flows
//!   through, so log lines and the spinner never corrupt each other;
//! - [`bootlog`] — the fixed-height scrolling boot-log panel.
//!
//! Tags telegraph the message class at a glance —
//!
//! - `[+]` green   — something good happened (new coverage, a corpus add).
//! - `[*]` blue    — neutral status / progress.
//! - `[!]` yellow  — a warning worth noticing.
//! - `[x]` red     — an error.
//! - `✦` magenta  — a solution (a bug), bracketed in sparkles, impossible to miss.
//!
//! Indented sub-details (under a heartbeat or status line) print dim with no tag.
//!
//! Color is emitted only to a real terminal with `NO_COLOR` unset; piped or
//! benchmark output stays plain. In benchmark mode everything but errors and the
//! final result line is suppressed.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

mod bootlog;
mod console;

pub use bootlog::BootLog;
pub use console::{set_spinner_status, spinner_start, spinner_stop};

static QUIET: AtomicBool = AtomicBool::new(false);
static COLOR: OnceLock<bool> = OnceLock::new();

/// Configure output once at startup. `quiet` (benchmark mode) suppresses all but
/// errors and the explicit result line.
pub fn init(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

pub(super) fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

pub(super) fn color() -> bool {
    *COLOR.get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal())
}

// 24-bit color helpers. Plain passthrough when color is off.
pub(super) fn paint(s: &str, r: u8, g: u8, b: u8, bold: bool) -> String {
    if !color() {
        return s.to_string();
    }
    let bld = if bold { "1;" } else { "" };
    format!("\x1b[{bld}38;2;{r};{g};{b}m{s}\x1b[0m")
}

pub(super) fn dimmed(s: &str) -> String {
    if !color() {
        s.to_string()
    } else {
        format!("\x1b[2m{s}\x1b[0m")
    }
}

const BLUE: (u8, u8, u8) = (90, 170, 255);
const GREEN: (u8, u8, u8) = (90, 220, 130);
const YELLOW: (u8, u8, u8) = (240, 200, 90);
const RED: (u8, u8, u8) = (245, 100, 100);
const MAGENTA: (u8, u8, u8) = (220, 120, 240);

fn tagged(tag: &str, c: (u8, u8, u8), msg: &str) {
    if quiet() {
        return;
    }
    console::emit(&format!("{} {msg}", paint(tag, c.0, c.1, c.2, true)));
}

/// `[*]` neutral status / progress.
pub fn info(msg: &str) {
    tagged("[*]", BLUE, msg);
}

/// `[+]` something good happened.
pub fn good(msg: &str) {
    tagged("[+]", GREEN, msg);
}

/// `[!]` a warning worth noticing.
pub fn warn(msg: &str) {
    tagged("[!]", YELLOW, msg);
}

/// `[x]` an error. Clears the spinner first, then prints to stderr (shown even
/// in quiet mode).
pub fn err(msg: &str) {
    console::emit_error(&format!(
        "{} {msg}",
        paint("[x]", RED.0, RED.1, RED.2, true)
    ));
}

/// A solution (a bug). Loud on purpose: bold magenta, sparkles.
pub fn solution(headline: &str) {
    if quiet() {
        return;
    }
    let spark = paint("✦", MAGENTA.0, MAGENTA.1, MAGENTA.2, true);
    let body = paint(headline, MAGENTA.0, MAGENTA.1, MAGENTA.2, true);
    console::emit(&format!("{spark} {body} {spark}"));
}

/// A periodic heartbeat line: the run's vitals, printed above the spinner under
/// the plain `[*]` info marker. The always-running spinner (see
/// [`spinner_start`]) is the live "breathing" indicator; this is the slow stats
/// pulse.
pub fn heartbeat(msg: &str) {
    info(msg);
}

/// An indented sub-detail under a heartbeat/status line.
pub fn detail(msg: &str) {
    if quiet() {
        return;
    }
    console::emit(&format!("    {}", dimmed(msg)));
}

/// Shimmering wordmark, printed once at startup. A bright band sweeps across a
/// blue→magenta gradient title a few times, then settles. Animation runs only on
/// a color terminal; otherwise a single plain line is printed.
pub fn banner(subtitle: &str) {
    if quiet() {
        return;
    }
    const WORD: &str = "l o n e p i n e";
    if !color() {
        println!("{WORD}  —  {subtitle}");
        return;
    }
    let chars: Vec<char> = WORD.chars().collect();
    let n = chars.len();
    // Base gradient: blue (90,170,255) → magenta (220,120,240).
    let base = |i: usize| -> (u8, u8, u8) {
        let t = if n <= 1 {
            0.0
        } else {
            i as f64 / (n - 1) as f64
        };
        let lerp = |a: u8, b: u8| (a as f64 + (b as f64 - a as f64) * t) as u8;
        (lerp(90, 220), lerp(170, 120), lerp(255, 240))
    };
    let frames = 22;
    for f in 0..frames {
        // Bright band position sweeps left→right across [-2, n+2].
        let pos = (f as f64 / frames as f64) * (n as f64 + 4.0) - 2.0;
        let mut out = String::from("\r  ");
        for (i, &ch) in chars.iter().enumerate() {
            let (mut r, mut g, mut b) = base(i);
            let d = (i as f64 - pos).abs();
            if d < 1.5 {
                // Lift toward white near the band — the shimmer highlight.
                let lift = (1.0 - d / 1.5) * 0.85;
                r = (r as f64 + (255.0 - r as f64) * lift) as u8;
                g = (g as f64 + (255.0 - g as f64) * lift) as u8;
                b = (b as f64 + (255.0 - b as f64) * lift) as u8;
            }
            out.push_str(&format!("\x1b[1;38;2;{r};{g};{b}m{ch}"));
        }
        out.push_str("\x1b[0m");
        print!("{out}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::thread::sleep(Duration::from_millis(34));
    }
    // Settle on the static gradient + subtitle.
    let mut out = String::from("\r  ");
    for (i, &ch) in chars.iter().enumerate() {
        let (r, g, b) = base(i);
        out.push_str(&format!("\x1b[1;38;2;{r};{g};{b}m{ch}"));
    }
    out.push_str("\x1b[0m");
    println!("{out}   {}", dimmed(subtitle));
}

//! Holds a shared, booted root VM for a multi-process Bedrock fuzzing campaign.
//!
//! Boots the config's guest to its first fuzz-input checkpoint, writes the
//! parked root VM's identity ([`bedrock_afl::RootState`] as JSON) to the given
//! path, then parks — keeping the root VM alive so many worker `afl-fuzz`
//! processes can fork it (each via a config whose `parent_state` points at that
//! JSON). This makes the expensive boot happen once and be shared across every
//! core. Send SIGTERM/SIGINT to release the root VM and end the campaign.

use bedrock_afl::Runner;
use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: bedrock-afl-root ROOT_CONFIG.json STATE_OUT.json".into());
    }

    // The root config has no `parent_state`, so this boots the guest to its
    // first fuzz-input checkpoint (paying the lnd/bitcoind startup cost once).
    let runner = Runner::load(Path::new(&args[1]))?;
    let state = runner.root_state()?;

    // Write via a temp file + rename so a worker never reads a partial state.
    let out = &args[2];
    let tmp = format!("{out}.tmp");
    fs::write(&tmp, serde_json::to_vec(&state)?)?;
    fs::rename(&tmp, out)?;

    eprintln!(
        "bedrock-afl-root: root VM booted and parked (parent_id={}, coverage map {} bytes, \
         capacity {} bytes). Workers may now fork it. Holding — SIGTERM to release.",
        state.parent_id, state.map_size, state.capacity
    );

    // Park forever, keeping `runner` — and thus the root VM — alive. The root is
    // never run again; workers only fork it, which a parked parent permits.
    loop {
        std::thread::park();
    }
}

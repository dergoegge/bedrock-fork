//! Replay AFL++ testcases (queue entries, crashes, hangs) against the Bedrock
//! snapshot exactly as `afl-fuzz` executed them.
//!
//! Every execution forks the same checkpoint the fuzzer forked — same guest
//! memory, same kernel-side seeded RNG state, same buffer registrations — and
//! serves the file's bytes at the same `HYPERCALL_FUZZ_NEXT_INPUT` the
//! checkpoint is parked on, then runs for the same virtual-time budget. The
//! outcome is therefore identical to what AFL++ observed: give it the `-t`
//! value the campaign used to confirm a hang, or a larger one to learn whether
//! the input merely runs long.
//!
//! Because the fork is still alive after the run, `--exec`/`--exec-in` can run
//! diagnostic commands *inside the guest* through the deterministic I/O channel
//! (`bedrock-io.ko`). They run after the verdict is final: on ok/crash the
//! testcase is over and the guest is parked in its fuzz hypercall; on a timeout
//! the testcase is still in progress and the command probes it live. The
//! command itself advances the guest, so it perturbs only what happens *after*
//! the verdict — to see the unperturbed continuation, replay again with a
//! larger budget and no `--exec`.

use bedrock_afl::{Config, Runner};
use bedrock_lab::{BashTarget, Branch};
use std::{env, fs, path::Path, time::Instant};

const USAGE: &str = "\
usage: bedrock-afl-replay [OPTIONS] CONFIG TIMEOUT_MS INPUT...

Replays each INPUT file against the fuzzing checkpoint described by CONFIG
(boot mode, or worker mode via `parent_state`), each in a fresh fork, with a
TIMEOUT_MS virtual-time budget — use the campaign's afl-fuzz `-t` value to
reproduce its verdicts exactly.

Options:
  --serial              echo guest serial output (kernel + journal console)
  --exec CMD            once the verdict is in, run CMD on the guest host and
                        print its output (on a timeout the testcase is still
                        running and gets probed live; the command perturbs only
                        what follows the verdict, never the verdict)
  --exec-in NAME CMD    same, inside the podman container NAME

Per-input result: 0 = ok/skip, 1 = crash (guest reported failure),
2 = timeout (no result within TIMEOUT_MS virtual).";

struct Exec {
    target: BashTarget,
    cmd: String,
}

fn label(result: i32) -> &'static str {
    match result {
        0 => "ok",
        1 => "crash",
        2 => "timeout",
        _ => "?",
    }
}

fn run_execs(branch: &mut Branch, execs: &[Exec], out: &mut String) {
    for exec in execs {
        let where_ = match &exec.target {
            BashTarget::Host => "host".to_owned(),
            BashTarget::Container(name) => format!("container {name}"),
        };
        match branch.bash(exec.target.clone(), &exec.cmd, true) {
            Ok(output) => {
                out.push_str(&format!(
                    "--- [{where_}] {} (exit {}, status {}) ---\n{}",
                    exec.cmd,
                    output.exit_code,
                    output.status,
                    String::from_utf8_lossy(&output.output)
                ));
                if !output.output.ends_with(b"\n") {
                    out.push('\n');
                }
            }
            Err(error) => {
                // Most likely the guest finished the testcase (fuzz-input exit)
                // while the command was running — i.e. it was slow, not hung.
                out.push_str(&format!(
                    "--- [{where_}] {} FAILED: {error} (guest left the testcase \
                     while the command ran?) ---\n",
                    exec.cmd
                ));
                return;
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut serial = false;
    let mut execs: Vec<Exec> = Vec::new();
    let mut positional: Vec<String> = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--serial" => serial = true,
            "--exec" => execs.push(Exec {
                target: BashTarget::Host,
                cmd: args.next().ok_or("--exec needs a command")?,
            }),
            "--exec-in" => execs.push(Exec {
                target: BashTarget::Container(args.next().ok_or("--exec-in needs a container")?),
                cmd: args.next().ok_or("--exec-in needs a command")?,
            }),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            _ if arg.starts_with("--") => {
                return Err(format!("unknown option {arg}\n\n{USAGE}").into())
            }
            _ => positional.push(arg),
        }
    }
    if positional.len() < 3 {
        return Err(USAGE.into());
    }
    let config_path = Path::new(&positional[0]);
    let timeout: u32 = positional[1].parse()?;

    let mut config: Config = serde_json::from_slice(&fs::read(config_path)?)?;
    config.serial |= serial;
    let mut runner = Runner::from_config(config, config_path.parent().unwrap_or(Path::new(".")))?;
    let start = runner.checkpoint_time();
    eprintln!(
        "guest coverage map: {} bytes, input capacity: {} bytes, checkpoint at {:.4}s virtual",
        runner.map_size(),
        runner.capacity,
        start.as_secs_f64()
    );

    for path in &positional[2..] {
        runner.set_input(&fs::read(path)?)?;
        let wall = Instant::now();
        let mut virtual_ms = 0.0;
        let mut post_mortem = String::new();
        let result = runner.run_then(timeout, |branch| {
            virtual_ms = (branch.current_time() - start).as_secs_f64() * 1000.0;
            run_execs(branch, &execs, &mut post_mortem);
            Ok(())
        })?;
        let wall_ms = wall.elapsed().as_secs_f64() * 1000.0;
        let edges = runner.bitmap().iter().filter(|&&b| b != 0).count();
        println!(
            "{path}: result={result} ({}) edges={edges} virtual_ms={virtual_ms:.3} \
             wall_ms={wall_ms:.0} message={}",
            label(result),
            runner.message
        );
        print!("{post_mortem}");
    }
    Ok(())
}

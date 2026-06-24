# Bitcoin Core functional-test workload

Runs [Bitcoin Core](https://github.com/bitcoin/bitcoin)'s `p2p_orphan_handling.py`
functional test inside bedrock so the fuzzer can replay it across many
deterministic timelines and catch **intermittent (flaky) failures** that pass on
a single CI run, while steering on edge coverage of an instrumented `bitcoind`.

`p2p_orphan_handling.py` exercises `bitcoind`'s handling of *orphan
transactions* — transactions whose parents the node hasn't seen yet: it drives a
regtest node over a Python P2P connection (`MiniWallet` + the framework's
`P2PInterface`) and asserts on orphanage admission/eviction, `getdata`/`tx`
request scheduling and timeouts, malleated-witness handling, and the 1p1c
package paths. These announce/request/evict races, driven by timers
(`setmocktime`) and per-peer delays, are exactly where varying bedrock's
controlled randomness and deterministic schedule is most likely to surface
bugs.

## Layout

- `Dockerfile` — builds an **instrumented** `bitcoind` + `bitcoin-cli` (trace-pc-guard
  coverage, depends-built boost+sqlite, statically linked) and ships the upstream
  functional-test framework, the test, and a `config.ini` pointing at the
  binaries. Installs the test as the singleton driver
  `/opt/bedrock/drivers/singleton_p2p_orphan_handling`.
- `compose.yaml` — one container (`bitcoin`) that signals the VM ready and idles;
  the fuzzer execs the driver into it each iteration.
- `singleton_p2p_orphan_handling` — the driver script (committed; copied into the
  image): runs the test through the upstream test runner with `-c 200`.
- `ready.c` — the ready-VMCALL helper baked into the image.
- `build.sh` — builds the image and packs `images.tar`.

## Driver

`singleton_p2p_orphan_handling` runs the test through the upstream functional
test runner: `python3 test/functional/test_runner.py p2p_orphan_handling.py
--combinedlogslen=200`. Per [`../README.md`](../README.md), the `singleton_`
prefix marks it as a unit/functional-test driver: on any timeline only one runs,
with no other test driver alongside it (no-op `anytime_kick` preemptions may
still interleave to perturb `bitcoind`'s thread schedule). The framework starts a
regtest `bitcoind`, runs the whole test, and exits non-zero on the first failed
assertion; the runner propagates that non-zero exit, and the in-guest workload
monitor turns it into a failed assertion the fuzzer reports as a bug (the default
workload property — any non-zero exit is a bug).

The runner (rather than the test script directly) is used for its
`--combinedlogslen`/`-c` flag: **on failure it prints the last 200 lines of the
combined logs to stdout** — the framework log plus each node's
`regtest/debug.log` (via `combine_logs.py`) — so the finding's serial log carries
`bitcoind`'s own log around the failure, not just the Python traceback. The
runner reads `test/config.ini` to locate the instrumented binaries and manages
the per-run datadir itself; no `procps` is needed (its "already running" `pgrep`
check is wrapped in `try/except OSError`). Note this means per-subtest `INFO`
lines no longer stream live to serial — a passing run is terse; a failing run
emits the combined log tail.

The first driver run on each forked timeline builds the shared 199-block regtest
cache under `/opt/bitcoin/test/cache` (the framework mines it to fixed addresses,
no wallet needed); the framework `mkdtemp()`s a fresh datadir root per run, so no
`--tmpdir` is passed.

The framework's wall-clock timeouts are deliberately left **on**: a run that
crosses an RPC/wait timeout under bedrock is itself a finding worth surfacing
(the test exits non-zero, which the lab reports), so the driver passes no
`--timeout-factor`.

## Coverage

`bitcoind` is compiled with clang `-fsanitize-coverage=trace-pc-guard` and every
executable is linked against the `libpcguard` → `libfeedback` shim (`guest/`)
with `-Wl,--build-id`, so each `bitcoind` process registers a per-edge coverage
buffer (`cov-<build-id>`) the lab reads back to steer the search. Multiple
`bitcoind` processes share one build-id, so the host unions their per-process
maps into a single domain.

This is safe because the shim **no-ops outside bedrock**: `feedback_buffer_init`
probes the emulated CPUID processor brand string (`"Bedrock VM CPU"`, see
`guest/libvmcall.h` / `crates/bedrock-vmx/src/exits/cpuid.rs`) and, when it isn't
running under bedrock, skips the registration VMCALL (which would otherwise
fault as an illegal instruction). So any instrumented binary that runs on the
*build* host — depends/secp256k1 build-time tools, or someone running the image
directly — executes without faulting. The shim runtime itself is compiled
without the coverage flag (or its hooks would instrument and recurse into
themselves).

Coverage uses the default `go-`-less prefix, so run the fuzzer with
`--cov-prefix cov-` (or `--cov-prefix ""` to match every buffer).

`bitcoind` is heavily multithreaded, so beyond edge coverage there is real signal
in **schedule** exploration. The shim's schedule levers are left **off** by
default for this first driver (clean edge-coverage signal): set
`BEDROCK_SCHED_COV=1` (feed back observed thread-transition order as coverage)
and/or `BEDROCK_SLEEP_PERIOD`/`BEDROCK_SLEEP_MAX_US` (per-edge deterministic
thread sleeps) in the runtime stage to make the mutator drive `bitcoind`'s
interleavings, the way the `libmultiprocess` workload does. The host's built-in
`anytime_kick` preemption driver is always available to perturb the schedule.

## Build details

- **Dependencies** come from Bitcoin Core's in-tree `depends/` system rather than
  distro `-dev` packages — boost (always) and the wallet's sqlite, built and
  statically linked, so the runtime image needs no dev libraries. `depends` also
  emits the CMake toolchain file the main build consumes. We trim Qt/GUI, QR,
  ZMQ, USDT and the Cap'n Proto IPC stack (`NO_QT=1 NO_QR=1 NO_ZMQ=1 NO_USDT=1
  NO_IPC=1`); the toolchain then turns those CMake features off automatically.
- **Wallet is ON.** `p2p_orphan_handling.py` itself uses `MiniWallet` (pure
  Python), but the framework's shared-cache setup removes an empty `wallets/` dir
  that only a wallet-capable `bitcoind` creates, so a wallet build keeps the
  framework on its well-trodden path.
- **clang is required** (gcc lacks trace-pc-guard). We pass the depends toolchain
  but override the compiler to clang — the toolchain's `if(NOT DEFINED …)` guards
  let `-D` win. No `CMAKE_BUILD_TYPE`: Bitcoin Core strips `-DNDEBUG` from every
  config, so `assert()`s stay live regardless; `-O1 -g0` keeps the build fast and
  the binary small.
- `BUILD_TESTS=OFF` (drops the unit tests, `bitcoin-tx`/`-util`/`-wallet`),
  `BUILD_BENCH=OFF`, `BUILD_BITCOIN_BIN=OFF` (no IPC wrapper) and
  `ENABLE_EXTERNAL_SIGNER=OFF` keep the build to just `bitcoind` + `bitcoin-cli`.

## Build & run

```bash
./build.sh                                                          # needs docker + network
nix run .#lonepine -- --workload workloads/bitcoin-functional --cov-prefix cov-
```

`build.sh` clones a pinned Bitcoin Core commit (override with
`BITCOIN_REF=<ref> ./build.sh`). To port another functional test, add a second
`singleton_<test>` driver that runs it — the framework, binaries and `config.ini`
are already in the image.

# libmultiprocess workload

Runs the [libmultiprocess](https://github.com/bitcoin-core/libmultiprocess) unit
tests inside bedrock so the fuzzer can replay them across many deterministic
timelines and catch **intermittent (flaky) failures** that pass on a single run.

libmultiprocess is the Cap'n Proto IPC library Bitcoin Core uses for its
multiprocess mode. Its test suite (`mptest`, built on Cap'n Proto's `kj-test`
framework) deliberately races connection setup and teardown against in-flight
RPC calls across threads — the kind of concurrency that breaks when the schedule
shifts, which is exactly what varying bedrock's deterministic interleaving and
controlled randomness exercises.

## Layout

- `Dockerfile` — builds upstream libmultiprocess + its `mptest` binary, then
  installs that binary as the singleton driver `/opt/bedrock/drivers/singleton_mptest`.
- `compose.yaml` — one container (`mptest`) that signals the VM ready and idles;
  the fuzzer execs the driver into it.
- `ready.c` — the ready-VMCALL helper baked into the image.
- `build.sh` — builds the image and packs `images.tar`.

## Driver

`singleton_mptest` is the upstream `mptest` binary. Per
[`../README.md`](../README.md), the `singleton_` prefix marks it as a unit-test
driver: on any timeline only one runs at a time, with no other driver alongside
it. It runs the whole `kj-test` suite and exits non-zero on the first failing
test; the in-guest workload monitor turns that non-zero exec exit into a failed
assertion, which the fuzzer reports as a bug (the default workload property —
any non-zero exit is a bug). The finding's serial log names the failing
`KJ_TEST(...)`.

## Coverage

`mptest` is compiled with LLVM `-fsanitize-coverage=trace-pc-guard` and linked
against the `libpcguard` → `libfeedback` shim (`guest/`), so it registers a
per-edge coverage buffer (`cov-<build-id>`) that the lab reads back to steer the
search over libmultiprocess + test code. The shim runtime is built without the
coverage flag, and the Cap'n Proto code generator (`mpgen`) is built once
uninstrumented and reused (via `-DMPGEN_EXECUTABLE`) so no instrumented binary
ever issues a coverage VMCALL on the build host. Coverage uses the default
`go-`-less prefix, so run the fuzzer with `--cov-prefix cov-` (or `--cov-prefix ""`
to match every buffer).

## Build & run

```bash
./build.sh                                            # needs docker + network
nix run .#lonepine -- --workload workloads/libmultiprocess --cov-prefix cov-
```

`build.sh` clones a pinned libmultiprocess commit (override with
`LIBMP_REF=<ref> ./build.sh`).

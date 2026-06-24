#!/usr/bin/env bash
# Build the Bitcoin Core functional-test workload's container image and pack it
# into a docker-archive tarball at workloads/bitcoin-functional/images.tar. That
# file and compose.yaml are served to the guest at runtime over the
# file-transmission hypercall (the guest's generic initrd downloads them at
# boot) — e.g.
#   nix run .#lonepine -- --workload workloads/bitcoin-functional --cov-prefix cov-
# See nix/podman-initrd.nix.
#
# Usage:  ./build.sh
#
# Requires a working `docker` daemon (or `podman` with a `docker` shim) and
# network access (the Dockerfile clones Bitcoin Core + apt-installs its build
# deps, and depends fetches dependency sources). The build clones a pinned
# Bitcoin Core commit; override it with
#   BITCOIN_REF=<ref> ./build.sh
# (passed through to the Dockerfile's ARG).

set -euo pipefail
cd "$(dirname "$0")"

DOCKER="${DOCKER:-docker}"

# Stage the shared guest libraries into this Docker build context. Docker's COPY
# can't reach files outside the context, so the single sources under guest/ are
# copied in here and removed on exit — keeping one source of truth instead of
# committed dups. The coverage shim is libfeedback (backend) + libpcguard
# (trace-pc-guard frontend); ready.c (committed in this dir) needs only the
# header-only libvmcall.h.
GUEST=../../guest
trap 'rm -f libvmcall.h libfeedback.h libfeedback.c libpcguard.c' EXIT
cp "$GUEST/libvmcall.h" "$GUEST/libfeedback.h" "$GUEST/libfeedback.c" \
   "$GUEST/libpcguard.c" .

BUILD_ARGS=()
if [ -n "${BITCOIN_REF:-}" ]; then
  BUILD_ARGS+=(--build-arg "BITCOIN_REF=$BITCOIN_REF")
fi

$DOCKER build "${BUILD_ARGS[@]}" -t bedrock/bitcoin-functional:latest .

# Pack into one docker-archive. `podman load` inside the initrd reads the
# embedded manifest to recover the image's name+tag, so the tarball's filename
# is opaque to consumers.
$DOCKER save bedrock/bitcoin-functional:latest -o images.tar

echo
echo "Wrote $(pwd)/images.tar ($(du -h images.tar | cut -f1))"

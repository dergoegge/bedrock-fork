#!/usr/bin/env bash
# Build the concurrency-fuzz workload's container image and pack it into a
# docker-archive tarball at workloads/concurrency-fuzz/images.tar. That file and
# compose.yaml are served to the guest at runtime over the file-transmission
# hypercall (the guest's generic initrd downloads them at boot), e.g. via
# `nix run .#lonepine -- --workload workloads/concurrency-fuzz`. See
# nix/podman-initrd.nix.
#
# The image bakes the benchmark's target binaries and their singleton drivers
# (see ../README.md) plus the ready helper. The fuzzing scheduler itself is
# guest infrastructure (sched_ext BPF + scx-init in nix/podman-initrd.nix), and
# thread-fuzz (which each driver uses to opt its target in) is bind-mounted
# into the container by the guest, so neither is part of this image.
# The guest kernel must be built with sched_ext + BTF (see nix/guest-kernel.nix).
#
# Usage:  ./build.sh
#
# Requires a working `docker` daemon (or `podman` with a `docker` shim) and
# network access (the image build fetches Debian packages).

set -euo pipefail
cd "$(dirname "$0")"

DOCKER="${DOCKER:-docker}"

# Stage the shared guest libraries into the Docker build context. Docker's
# COPY can't reach files outside the context, so the single sources under
# guest/ are copied in here and removed on exit, keeping one source of truth
# instead of committed dups: libvmcall.h (hypercalls), libassert.h (the
# Always-assertion reporter each target uses), and the coverage shim
# (libfeedback, the backend; libpcguard, the LLVM trace-pc-guard frontend)
# that instruments every target — see ../README.md.
GUEST=../../guest
trap 'rm -f fuzz/libvmcall.h fuzz/libassert.h fuzz/libfeedback.h fuzz/libfeedback.c fuzz/libpcguard.c' EXIT
cp "$GUEST/libvmcall.h" "$GUEST/libassert.h" "$GUEST/libfeedback.h" \
   "$GUEST/libfeedback.c" "$GUEST/libpcguard.c" fuzz/

$DOCKER build -t bedrock/concurrency-fuzz:latest fuzz/

# Pack into one docker-archive. `podman load` inside the initrd reads the
# embedded manifest to recover the image's name+tag, so the tarball's filename
# is opaque to consumers.
$DOCKER save bedrock/concurrency-fuzz:latest -o images.tar

echo
echo "Wrote $(pwd)/images.tar ($(du -h images.tar | cut -f1))"

#!/usr/bin/env bash
# Build the syzkaller workload's single container image and pack it into a
# docker-archive tarball at workloads/syzkaller/images.tar. Hand that file
# (along with compose.yaml) to mkPodmanInitrd in flake.nix to bake it into a
# bootable bedrock initramfs.
#
# The image build downloads a syzkaller corpus database and compiles every
# program in it into a standalone binary under /opt/bedrock/drivers/. This
# is heavy: expect a long build and a large image when compiling the full
# corpus. Cap it for iteration with MAX_PROGS, e.g.:
#
#   MAX_PROGS=2000 ./build.sh
#
# Usage:  ./build.sh
#
# Requires a working `docker` daemon (or `podman` with a `docker` shim).

set -euo pipefail
cd "$(dirname "$0")"

DOCKER="${DOCKER:-docker}"

# Optional knobs forwarded to the Dockerfile build args.
BUILD_ARGS=()
[[ -n "${MAX_PROGS:-}" ]]     && BUILD_ARGS+=(--build-arg "MAX_PROGS=${MAX_PROGS}")
[[ -n "${CORPUS_URL:-}" ]]    && BUILD_ARGS+=(--build-arg "CORPUS_URL=${CORPUS_URL}")
[[ -n "${SYZKALLER_REF:-}" ]] && BUILD_ARGS+=(--build-arg "SYZKALLER_REF=${SYZKALLER_REF}")

$DOCKER build "${BUILD_ARGS[@]}" -t bedrock/syzkaller:latest .

# Pack the single image into one docker-archive. `podman load` inside the
# initrd reads the embedded manifest to recover the image's name+tag, so the
# tarball's filename is opaque to consumers.
$DOCKER save bedrock/syzkaller:latest -o images.tar

echo
echo "Wrote $(pwd)/images.tar ($(du -h images.tar | cut -f1))"

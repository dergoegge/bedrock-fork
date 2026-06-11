# syntax=docker/dockerfile:1
#
# Single-container syzkaller determinism workload.
#
# The build downloads a syzkaller corpus database, unpacks it, and compiles
# every program in it into a standalone binary. Those binaries are baked at
# /opt/bedrock/drivers/ where the bedrock-io kernel module enumerates them
# (`find /opt/bedrock/drivers -type f -perm -100`) as per-container drivers
# for the ACTION_GET_WORKLOAD_DETAILS RPC. The fuzzer/lab then execs each
# syscall program under the deterministic hypervisor.

# ---------------------------------------------------------------------------
# Stage 1: build syzkaller host tools, fetch the corpus, compile every prog.
# ---------------------------------------------------------------------------
# The upstream setup doc says Go 1.23, but syzkaller master's go.mod has
# moved well past that (it pins a newer toolchain via a `go >=` directive).
# Rather than chase the exact version, start from a recent Go and let
# GOTOOLCHAIN=auto download whatever toolchain go.mod demands.
FROM golang:1.24-bookworm AS build
ENV GOTOOLCHAIN=auto

# Which syzkaller revision to build the host tools (syz-db, syz-prog2c) from.
ARG SYZKALLER_REF=master
# Corpus database to compile. Defaults to the upstream KASAN/GCE root corpus
# named in the workload goal.
ARG CORPUS_URL=https://storage.googleapis.com/syzkaller/corpus/ci-upstream-kasan-gce-root-corpus.db
# 0 = compile the entire corpus. Override (e.g. --build-arg MAX_PROGS=2000)
# to cap the binary count for faster iteration / a smaller image.
ARG MAX_PROGS=0

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev make git wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build only the host tools we need: syz-prog2c (program -> C) and syz-db
# (corpus.db -> dir of programs). Both depend on the generated descriptions.
RUN git clone --depth 1 --branch "$SYZKALLER_REF" \
        https://github.com/google/syzkaller /syzkaller
WORKDIR /syzkaller
RUN make descriptions db prog2c

# Fetch + unpack the corpus.
RUN wget -q -O /corpus.db "$CORPUS_URL" \
    && ./bin/syz-db unpack /corpus.db /corpus \
    && echo "unpacked $(find /corpus -type f | wc -l) corpus programs"

# Compile every program into /opt/bedrock/drivers/.
COPY compile_corpus.sh /compile_corpus.sh
RUN chmod +x /compile_corpus.sh \
    && MAX_PROGS="$MAX_PROGS" /compile_corpus.sh \
         /corpus /opt/bedrock/drivers /syzkaller/bin/syz-prog2c

# Build the ready/shutdown VMCALL helper.
COPY vmcall/bedrock-vmcall.c /src/bedrock-vmcall.c
RUN gcc -O2 -static -o /bedrock-vmcall /src/bedrock-vmcall.c

# ---------------------------------------------------------------------------
# Stage 2: minimal runtime carrying just the drivers + the VMCALL helper.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim
COPY --from=build /opt/bedrock/drivers/ /opt/bedrock/drivers/
COPY --from=build /bedrock-vmcall /usr/local/bin/bedrock-vmcall
# Keep the container alive by default; compose overrides the entrypoint to
# drive the ready/sleep/shutdown lifecycle.
ENTRYPOINT ["/bin/sh", "-c", "exec sleep infinity"]

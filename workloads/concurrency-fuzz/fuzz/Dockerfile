# syntax=docker/dockerfile:1
#
# Concurrency-fuzz workload image: a small benchmark suite of classic
# concurrency-bug patterns (see ../README.md for the taxonomy and per-target
# writeups), each installed as a singleton driver so lonepine can fuzz which
# one runs, when, and under what schedule.
#
# Every target is built with LLVM `-fsanitize-coverage=trace-pc-guard` and
# linked against the libpcguard -> libfeedback shim (+ `-Wl,--build-id`), so
# it registers a per-edge coverage buffer ("cov-<build-id>") lonepine reads
# back to steer the search — the same pattern as the bitcoin-functional and
# libmultiprocess workloads. Coverage requires clang (gcc doesn't implement
# trace-pc-guard). The shim runtime (libpcguard.c, libfeedback.c) is compiled
# WITHOUT the coverage flag, or its own hooks would instrument and recurse
# into themselves.
#
# The fuzzing scheduler itself is NOT in this image. It is a generic guest
# capability: the sched_ext BPF scheduler and its init service (scx-init) live
# in the initrd (see nix/podman-initrd.nix) and are loaded once at boot. The
# thread-fuzz helper, which opts a process into the scheduler, is bind-mounted
# into the container by the guest (not baked here); each driver wraps its
# target in it. So no fuzzing machinery needs per-image setup.
#
# Build context is this directory (fuzz/); build.sh stages guest/libvmcall.h,
# guest/libassert.h (how each target reports its bug as an explicit `Always`
# assertion; see ../README.md) and the coverage shim in.

FROM debian:trixie AS build

# clang: the trace-pc-guard instrumentor (trixie ships clang 19). binutils:
# its ld supplies --build-id, which libfeedback needs to key the coverage
# buffer. libc6-dev: headers for the pthread targets.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang binutils libc6-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY queue.c lost_update.c reclaim_race.c deadlock.c ready.c \
     libvmcall.h libassert.h libfeedback.h libfeedback.c libpcguard.c ./

# bedrock-ready: issues the ready VMCALL so the lab can take the boot
# checkpoint. Static, no coverage.
RUN clang -O2 -static -o bedrock-ready ready.c

# Coverage runtime, built WITHOUT -fsanitize-coverage (plain clang), or its
# own instrumentation hooks would recurse into themselves.
RUN clang -O2 -I. -c libpcguard.c -o libpcguard.o \
 && clang -O2 -I. -c libfeedback.c -o libfeedback.o

# Targets: instrumented and linked against the shim + --build-id (which is
# what lets libfeedback key the buffer on the binary's build-id, since
# libpcguard passes it NULL). -fno-sanitize-link-runtime: with
# -fsanitize-coverage, clang otherwise tries to link compiler-rt's standalone
# sanitizer runtime, which we don't want — libpcguard.o *is* our trace-pc-guard
# runtime. Dynamically linked (not -static): sanitizer coverage's guard-table
# section doesn't play well with static linking, and debian:trixie-slim (the
# runtime stage) already ships the glibc these need. Stripped, but keeping the
# .note.gnu.build-id note and guard table, so coverage keying and recording
# still work.
RUN for t in queue lost_update reclaim_race deadlock; do \
      clang -O2 -pthread -fsanitize-coverage=trace-pc-guard -fno-sanitize-link-runtime \
        -Wl,--build-id -o "$t" "$t.c" libpcguard.o libfeedback.o \
      && strip "$t"; \
    done

FROM debian:trixie-slim
# BEDROCK_SCHED_COV=1 feeds back the order threads are observed running
# (hashed tid transitions) as coverage, so the fuzzer keeps exploring new
# interleavings after edge coverage saturates (see guest/libpcguard.c).
# `podman exec` inherits image ENV, so the drivers pick it up.
#
# The pcguard shim's own thread-sleep injection (BEDROCK_SLEEP_PERIOD /
# BEDROCK_SLEEP_MAX_US) is deliberately left OFF: scx-fuzz's in-kernel chaos
# scheduler already owns thread pausing for this workload (see
# guest/scx-fuzz/), so a second, independent pausing mechanism would just add
# noise rather than a new lever.
ENV BEDROCK_SCHED_COV=1
COPY --from=build /src/queue         /usr/local/bin/queue
COPY --from=build /src/lost_update   /usr/local/bin/lost_update
COPY --from=build /src/reclaim_race  /usr/local/bin/reclaim_race
COPY --from=build /src/deadlock      /usr/local/bin/deadlock
COPY --from=build /src/bedrock-ready /usr/local/bin/bedrock-ready

# Each target is a singleton driver: on any timeline only one runs, with no
# other test driver alongside it (see ../../README.md). thread-fuzz is
# bind-mounted into the container by the guest, not baked here.
COPY singleton_queue singleton_lost_update singleton_reclaim_race singleton_deadlock \
     /opt/bedrock/drivers/
RUN chmod +x /opt/bedrock/drivers/singleton_queue \
             /opt/bedrock/drivers/singleton_lost_update \
             /opt/bedrock/drivers/singleton_reclaim_race \
             /opt/bedrock/drivers/singleton_deadlock

# Overridden by compose; a sane default so the container idles if run directly.
ENTRYPOINT ["/bin/sh", "-c", "sleep infinity"]

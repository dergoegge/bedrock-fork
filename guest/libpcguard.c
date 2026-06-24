// SPDX-License-Identifier: GPL-2.0
//
// bedrock libpcguard: LLVM SanitizerCoverage trace-pc-guard frontend over
// libfeedback. Link it into a target built with
// `-fsanitize-coverage=trace-pc-guard` (and `-Wl,--build-id`, so the binary
// carries the build-id libfeedback keys the buffer on); the instrumentation
// calls __sanitizer_cov_trace_pc_guard_init once per module (handing us its
// table of 32-bit guard slots) and __sanitizer_cov_trace_pc_guard on every
// edge, which we turn into feedback_record() calls.
//
// Build this (and libfeedback.c) WITHOUT -fsanitize-coverage, or the hooks
// recurse into themselves.
//
// Thread-interleaving perturbation: when BEDROCK_SLEEP_PERIOD=N (N>0) is set in
// the environment, each edge has a ~1/N chance of a short nanosleep, so threads
// yield the CPU at instrumented points throughout their execution — a
// fine-grained lever on the schedule that exposes concurrency races, completing
// the host's coarse preemption kicks. The decision uses a per-thread PRNG seeded
// once from the controlled randomness channel (HYPERCALL_GET_RANDOM via
// getrandom()), so the perturbation is deterministic and fuzzer-steerable: the
// lab records the seed bytes, the mutator varies them to explore different
// interleavings, and a reproducer replays the exact same schedule. There is no
// per-edge hypercall — only the one-per-thread seed — so the hot path stays a
// cheap PRNG step. Disabled by default (period 0).
//
// Scheduling coverage: when BEDROCK_SCHED_COV=1 is set, the *order in which
// threads are observed running* is fed back as coverage. Each edge notes the
// current thread's id (tid); whenever it differs from the thread that ran the
// previous edge, that (prev -> cur) transition is recorded into a reserved tail
// region of the same feedback buffer. New thread transitions thus count as new
// coverage, so the fuzzer keeps a gradient toward unexplored interleavings even
// after edge coverage saturates — and because bedrock is single-vCPU and
// deterministic, the transition sequence (and thus this coverage) is
// reproducible and steerable by the same inputs that vary the schedule (sleeps,
// kicks, randomness). (Thread *name* is useless as the identity here: every
// thread inherits the process comm, so they'd all collapse to one — the tid
// distinguishes them.) Disabled by default.

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "libfeedback.h"

// Total guards assigned across all _init calls (the edge-coverage region of the
// buffer, slots [0, num_guards)). Written only from _init, a single-threaded
// load-time hook.
static uint32_t num_guards = 0;

// Scheduling-coverage region: when enabled, SCHED_SLOTS slots reserved at
// [num_guards, num_guards + SCHED_SLOTS) hold hashed thread-name transitions.
#define SCHED_SLOTS 8192u
static int sched_cov = 0; // BEDROCK_SCHED_COV: record thread-order coverage

// The thread (its hashed name) observed at the previous edge. A plain global is
// correct here: bedrock is single-vCPU, so threads are time-sliced and only one
// runs at a time — accesses are serial and the transition sequence stays
// deterministic.
static uint32_t last_thread = 0;

// Sleep-injection config, read once at load from the environment. `period == 0`
// disables it (the default). Otherwise each edge sleeps with probability
// 1/period for a duration uniform in [0, max_ns].
static uint32_t sleep_period = 0;
static uint64_t sleep_max_ns = 0;

// Per-thread PRNG for the sleep decision, lazily seeded from the controlled
// randomness channel on the thread's first edge.
static __thread uint64_t tls_rng;
static __thread int tls_seeded;

// Per-thread cached identity: the thread's tid, fetched once on the thread's
// first edge. The tid is unique per thread and deterministic under bedrock, so
// it distinguishes threads (which a name can't — they share the process comm).
static __thread uint32_t tls_thread;
static __thread int tls_thread_set;

// xorshift64*: cheap, decent-quality per-edge step (no hypercall on the hot
// path).
static uint64_t next_rand(uint64_t *s) {
    uint64_t x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1DULL;
}

// This thread's identity for scheduling coverage: its tid. Cached so the
// gettid() syscall happens once per thread, not per edge.
static uint32_t thread_id(void) {
    if (!tls_thread_set) {
        uint32_t tid = (uint32_t)syscall(SYS_gettid);
        tls_thread = tid ? tid : 1u; // 0 is reserved for "no previous thread"
        tls_thread_set = 1;
    }
    return tls_thread;
}

// If scheduling coverage is on, record a transition whenever the running thread
// changed since the previous edge. Single-vCPU ⇒ the global read/write is serial
// and deterministic.
static void record_schedule(void) {
    if (!sched_cov) {
        return;
    }
    uint32_t cur = thread_id();
    uint32_t prev = last_thread;
    if (prev == cur) {
        return;
    }
    last_thread = cur;
    // Hash the (prev -> cur) transition into the reserved tail region.
    uint64_t h = (uint64_t)prev * 0x9E3779B97F4A7C15ULL ^ (uint64_t)cur;
    h ^= h >> 29;
    feedback_record((uint64_t)num_guards + (uint32_t)(h % SCHED_SLOTS));
}

// Occasionally yield at this edge to perturb the thread interleaving. Seeds the
// per-thread PRNG from getrandom() (the fuzzer-controlled, recorded channel) on
// first use, then sleeps with probability 1/period for a short, PRNG-chosen
// duration. A no-op when disabled.
static void maybe_yield(void) {
    if (sleep_period == 0) {
        return;
    }
    if (!tls_seeded) {
        uint64_t seed = 0;
        // Controlled randomness: makes each thread's sleep schedule replayable
        // and steerable by mutating the getrandom tape. Fall back to a fixed
        // constant if the read short-reads (still deterministic).
        if (getrandom(&seed, sizeof(seed), 0) != (ssize_t)sizeof(seed) || seed == 0) {
            seed = 0x9E3779B97F4A7C15ULL;
        }
        tls_rng = seed;
        tls_seeded = 1;
    }
    uint64_t r = next_rand(&tls_rng);
    if (r % sleep_period != 0) {
        return;
    }
    uint64_t ns = sleep_max_ns ? (next_rand(&tls_rng) % (sleep_max_ns + 1)) : 0;
    struct timespec ts = {.tv_sec = 0, .tv_nsec = (long)ns};
    // Trace every pause to stdout. dprintf() writes the fd directly (no stdio
    // buffering), so the line is visible immediately even when stdout is a pipe
    // and the thread is about to block in nanosleep.
    dprintf(STDOUT_FILENO, "[bedrock-pcguard] thread %u paused for %llu ns\n",
            thread_id(), (unsigned long long)ns);
    nanosleep(&ts, NULL);
}

// Called once per module at load (single-threaded, before any edge). Assign
// each still-zero guard a unique 1-based index (0 stays reserved for "disabled";
// the stock guard clauses skip an empty or already-initialized range), then size
// and register the buffer. feedback_buffer_init() is idempotent, so a single
// instrumented binary (one _init) sizes the buffer exactly; extra DSOs extend
// the count but can't grow the pinned buffer, so their guards alias modulo it.
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) {
        return;
    }
    for (uint32_t *guard = start; guard < stop; guard++) {
        *guard = ++num_guards;
    }
    // Read the perturbation/coverage config once (here, before any edge fires).
    const char *period = getenv("BEDROCK_SLEEP_PERIOD");
    if (period) {
        sleep_period = (uint32_t)strtoul(period, NULL, 10);
    }
    const char *max_us = getenv("BEDROCK_SLEEP_MAX_US");
    sleep_max_ns = (max_us ? strtoull(max_us, NULL, 10) : 50ull) * 1000ull;
    const char *sc = getenv("BEDROCK_SCHED_COV");
    sched_cov = sc && strtoul(sc, NULL, 10) != 0;
    // Reserve the scheduling-coverage tail region only when enabled. NULL build
    // id: libfeedback keys on the binary's GNU build-id (the target must be
    // linked with -Wl,--build-id).
    size_t slots = (size_t)num_guards + (sched_cov ? SCHED_SLOTS : 0u);
    feedback_buffer_init(slots, NULL);
}

// Every edge: bump its counter, then (optionally) note the thread-order
// transition and maybe yield to perturb scheduling. _init already assigned the
// index and registered the buffer, so the only setup on the hot path is the
// (lazy, one-per-thread) PRNG seed and name fetch.
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t idx = *guard;
    if (idx == 0) {
        return;
    }
    feedback_record(idx - 1); // 1-based guard -> 0-based buffer slot
    record_schedule();
    maybe_yield();
}

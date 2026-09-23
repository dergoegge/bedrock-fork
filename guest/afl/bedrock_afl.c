/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include "bedrock_afl.h"
#include "libvmcall.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Coverage bitmap size, the guest's choice. Sized for this demo target (a
 * handful of edges); the host reads it from the feedback-buffer registration,
 * so it can be anything up to VMCALL_FEEDBACK_BUFFER_MAX_SIZE — a real target
 * would use 64 KiB+. Deliberately NOT AFL's 64 KiB default, to make it obvious
 * the size AFL reports came from here and is not hardcoded on the host. */
#define MAP_SIZE 4096u
#define INPUT_SIZE VMCALL_FEEDBACK_BUFFER_MAX_SIZE
struct input_header {
  int64_t length;
  uint64_t status, aux, reserved;
};
static volatile struct input_header *input;
static uint8_t *bitmap;
static uint32_t next_guard;

static _Noreturn void setup_failed(void) {
  vmcall_shutdown();
  for (;;) {}
}

static void *register_buffer(size_t size, const char *id) {
  void *buffer = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  if (buffer == MAP_FAILED || mlock(buffer, size)) setup_failed();
  memset(buffer, 0, size);
  if (vmcall_register_feedback_buffer(buffer, size, id, strlen(id)) >=
      VMCALL_ERR - 4ULL) setup_failed();
  return buffer;
}

_Noreturn void bedrock_afl_fail(const char *message) {
  if (!input) setup_failed();
  volatile uint8_t *data = (volatile uint8_t *)input + VMCALL_FUZZ_INPUT_HEADER_LEN;
  size_t len = 0;
  /* No libc calls: also used from fatal signal handlers. */
  while (message[len] && len < INPUT_SIZE - VMCALL_FUZZ_INPUT_HEADER_LEN) {
    data[len] = (uint8_t)message[len];
    ++len;
  }
  input->aux = len;
  input->status = VMCALL_FUZZ_STATUS_FAIL;
  vmcall_fuzz_next_input();
  setup_failed();
}

static void crash_handler(int sig) {
  (void)sig;
  bedrock_afl_fail("guest target received a fatal signal");
}

void bedrock_afl_init(void) {
  input = register_buffer(INPUT_SIZE, VMCALL_FUZZ_INPUT_BUFFER_ID);
  bitmap = register_buffer(MAP_SIZE, "afl-coverage");
  static unsigned char signal_stack[65536];
  stack_t stack = {.ss_sp = signal_stack, .ss_size = sizeof(signal_stack)};
  if (sigaltstack(&stack, NULL)) setup_failed();
  struct sigaction action = {.sa_handler = crash_handler,
                            .sa_flags = SA_ONSTACK};
  sigemptyset(&action.sa_mask);
  const int signals[] = {SIGSEGV, SIGABRT, SIGILL, SIGBUS, SIGFPE, SIGSYS};
  for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i)
    if (sigaction(signals[i], &action, NULL)) setup_failed();
  vmcall_ready();
}

const uint8_t *bedrock_afl_next(size_t *size) {
  static int first = 1;
  /* Preserve the completed testcase's map until the host reads it. Every
   * testcase forks this first request, where the map is still empty. */
  if (first) { memset(bitmap, 0, MAP_SIZE); first = 0; }
  input->status = VMCALL_FUZZ_STATUS_OK;
  input->aux = 0;
  vmcall_fuzz_next_input();
  int64_t length = input->length;
  if (length == VMCALL_FUZZ_INPUT_EOF) return NULL;
  if (length < 0 || (uint64_t)length > INPUT_SIZE - VMCALL_FUZZ_INPUT_HEADER_LEN)
    bedrock_afl_fail("invalid input length");
  *size = (size_t)length;
  return (const uint8_t *)input + VMCALL_FUZZ_INPUT_HEADER_LEN;
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  if (start == stop || *start) return;
  for (uint32_t *guard = start; guard < stop; ++guard)
    *guard = (++next_guard % (MAP_SIZE - 1)) + 1;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
  if (bitmap && *guard) {
    uint8_t count = bitmap[*guard] + 1;
    bitmap[*guard] = count ? count : 1;
  }
}

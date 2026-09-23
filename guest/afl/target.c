/* SPDX-License-Identifier: GPL-2.0 */
#include "bedrock_afl.h"
#include <signal.h>

/* The state assertion proves each input resumes from the same VM snapshot. */
static unsigned executions;
static volatile unsigned sink;
__attribute__((noinline))
static void target(const uint8_t *data, size_t size) {
  if (++executions != 1) bedrock_afl_fail("snapshot state leaked between inputs");
  if (size && data[0] == 'H') {
    for (;;) ++sink;
  }
  if (size >= 3 && data[0] == 'B') {
    ++sink;
    if (data[1] == 'U') {
      ++sink;
      if (data[2] == 'G') raise(SIGSEGV);
    }
  }
}

int main(void) {
  bedrock_afl_init();
  size_t size;
  const uint8_t *data;
  while ((data = bedrock_afl_next(&size))) target(data, size);
  return 0;
}

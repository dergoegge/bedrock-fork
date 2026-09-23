/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BEDROCK_AFL_H
#define BEDROCK_AFL_H
#include <stddef.h>
#include <stdint.h>

/* Call once after target setup, then loop over bedrock_afl_next().
 * This runtime is single-threaded. Compile target objects with Clang's
 * -fsanitize-coverage=trace-pc-guard; compile the runtime without it. */
void bedrock_afl_init(void);
const uint8_t *bedrock_afl_next(size_t *size);
_Noreturn void bedrock_afl_fail(const char *message);
#endif

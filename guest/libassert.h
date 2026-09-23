/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header-only C port of bedrock_assertions::Assertion for guest workload code
 * that isn't Rust (crates/bedrock-assertions/src/{assertion,condition}.rs is
 * the source of truth for the wire format this must match byte-for-byte).
 *
 * Appends one JSON line to the shared assertion sink (/bedrock/assertions.jsonl,
 * bind-mounted into every container by containers.conf — see
 * nix/podman-initrd.nix), the same sink the host-side workload-monitor and any
 * `eventually_` driver already write to. guest/init pipes that file through
 * `systemd-cat -t assertions`, so each line reaches the serial console tagged
 * for lonepine's oracle (crates/lonepine/src/oracle.rs), which treats a
 * failing `Always` — Rust or C, it can't tell the difference — as a bug
 * reported by its message, and *every* evaluation (passing or not) as a
 * hill-climbing signal the mutator can steer by.
 *
 * This is deliberately in addition to, not instead of, the generic
 * "exit code is zero" assertion the guest's workload-monitor emits for any
 * process that dies non-zero: that only tells the fuzzer *that* something
 * failed. Reporting the actual condition (operands and all) gives a specific,
 * dedupable message, and asserting it on every evaluation — not just the
 * failing one — gives the search a numeric signal to climb well before a run
 * happens to hit the violation.
 */
#ifndef BEDROCK_LIBASSERT_H
#define BEDROCK_LIBASSERT_H

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BEDROCK_ASSERTIONS_PATH "/bedrock/assertions.jsonl"

/*
 * Append one JSON line to the assertion sink in a single write(), matching
 * the sink's atomicity contract (see guest/workload-monitor/src/main.rs: "one
 * write of a single sub-PIPE_BUF line keeps appends atomic across the file's
 * concurrent writers") so this never interleaves a partial line with another
 * driver or the workload monitor writing at the same time. Best-effort: a
 * sink failure must not take down the caller's own bug detection, so errors
 * are reported to stderr and swallowed.
 */
static inline void bedrock_assert_emit(const char *json)
{
	int fd = open(BEDROCK_ASSERTIONS_PATH, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd < 0) {
		perror("open " BEDROCK_ASSERTIONS_PATH);
		return;
	}
	size_t len = strlen(json);
	if (write(fd, json, len) != (ssize_t)len)
		perror("write " BEDROCK_ASSERTIONS_PATH);
	close(fd);
}

/*
 * Escape a message for embedding in a JSON string. Call sites only ever pass
 * plain ASCII descriptions, so backslash and double-quote are the only
 * characters handled; anything else (control characters) is not expected and
 * not escaped.
 */
static inline void bedrock_json_escape(char *out, size_t out_len, const char *in)
{
	size_t o = 0;

	for (size_t i = 0; in[i] != '\0' && o + 2 < out_len; i++) {
		if (in[i] == '"' || in[i] == '\\') {
			if (o + 3 >= out_len)
				break;
			out[o++] = '\\';
		}
		out[o++] = in[i];
	}
	out[o] = '\0';
}

/*
 * Build and emit an Always assertion over `x <op> y` (op is the Condition
 * variant's serde tag: "Lt"/"Gt"/"Lte"/"Gte"/"Eq"), then return the evaluated
 * result so callers can act on a violation. `file`/`line` are normally
 * __FILE__/__LINE__ from the call site; column is not tracked from C (no
 * compiler-portable equivalent), so it is always reported as 1.
 */
static inline int bedrock_always_cmp(const char *op, long long x, long long y, int result,
				      const char *message, const char *file, int line)
{
	char msg[256];
	char json[512];

	bedrock_json_escape(msg, sizeof(msg), message);
	snprintf(json, sizeof(json),
		 "{\"Always\":{\"condition\":{\"%s\":{\"x\":%lld,\"y\":%lld}},"
		 "\"result\":%s,\"message\":\"%s\","
		 "\"location\":{\"file\":\"%s\",\"line\":%d,\"column\":1}}}\n",
		 op, x, y, result ? "true" : "false", msg, file, line);
	bedrock_assert_emit(json);
	return result;
}

/* Build and emit an Always assertion over a bare boolean condition. */
static inline int bedrock_always_bool_impl(int cond, const char *message, const char *file, int line)
{
	char msg[256];
	char json[512];

	bedrock_json_escape(msg, sizeof(msg), message);
	snprintf(json, sizeof(json),
		 "{\"Always\":{\"condition\":{\"Bool\":%s},"
		 "\"result\":%s,\"message\":\"%s\","
		 "\"location\":{\"file\":\"%s\",\"line\":%d,\"column\":1}}}\n",
		 cond ? "true" : "false", cond ? "true" : "false", msg, file, line);
	bedrock_assert_emit(json);
	return cond;
}

#define bedrock_always_lt(x, y, msg) \
	bedrock_always_cmp("Lt", (long long)(x), (long long)(y), (x) < (y), (msg), __FILE__, __LINE__)
#define bedrock_always_gt(x, y, msg) \
	bedrock_always_cmp("Gt", (long long)(x), (long long)(y), (x) > (y), (msg), __FILE__, __LINE__)
#define bedrock_always_lte(x, y, msg) \
	bedrock_always_cmp("Lte", (long long)(x), (long long)(y), (x) <= (y), (msg), __FILE__, __LINE__)
#define bedrock_always_gte(x, y, msg) \
	bedrock_always_cmp("Gte", (long long)(x), (long long)(y), (x) >= (y), (msg), __FILE__, __LINE__)
#define bedrock_always_eq(x, y, msg) \
	bedrock_always_cmp("Eq", (long long)(x), (long long)(y), (x) == (y), (msg), __FILE__, __LINE__)
#define bedrock_always_bool(cond, msg) \
	bedrock_always_bool_impl((cond), (msg), __FILE__, __LINE__)

#endif /* BEDROCK_LIBASSERT_H */

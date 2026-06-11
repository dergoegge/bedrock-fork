#!/usr/bin/env bash
# Compile every syzkaller corpus program into a standalone binary.
#
# Adapted from syzkaller's own compile_all.sh: each program in the unpacked
# corpus is turned into C with `syz-prog2c`, then compiled with gcc. The
# resulting binaries land flat in OUT_DIR so the bedrock-io module's
# `find /opt/bedrock/drivers -type f -perm -100` enumeration picks each one
# up as an invocable driver.
#
# Runs inside the workload's Docker build (see Dockerfile). Not meant to be
# run on the host.
set -u
set -o pipefail

CORPUS_DIR="${1:?usage: compile_corpus.sh <corpus-dir> <out-dir> <syz-prog2c>}"
OUT_DIR="${2:?missing out dir}"
SYZ_PROG2C="${3:?missing syz-prog2c path}"
ARCH="${ARCH:-amd64}"
OS="${OS:-linux}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 1)}"
# 0 (default) compiles the entire corpus. Set MAX_PROGS to cap the count for
# faster iteration / smaller images.
MAX_PROGS="${MAX_PROGS:-0}"

die() { echo "error: $*" >&2; exit 1; }

[[ -d "$CORPUS_DIR" ]]   || die "corpus dir does not exist: $CORPUS_DIR"
[[ -x "$SYZ_PROG2C" ]]   || die "not executable: $SYZ_PROG2C"
command -v gcc >/dev/null   || die "gcc not found"
command -v xargs >/dev/null || die "xargs not found"

mkdir -p "$OUT_DIR"

# The corpus may carry a small handful of non-program metadata files; restrict
# to regular files and (optionally) cap the count.
mapfile -t PROGS < <(find "$CORPUS_DIR" -type f | sort)
if [[ "$MAX_PROGS" -gt 0 && "${#PROGS[@]}" -gt "$MAX_PROGS" ]]; then
  echo "capping corpus: ${#PROGS[@]} -> $MAX_PROGS programs (MAX_PROGS)"
  PROGS=("${PROGS[@]:0:$MAX_PROGS}")
fi

NUM_PROGS="${#PROGS[@]}"
echo "corpus dir:  $CORPUS_DIR"
echo "programs:    $NUM_PROGS"
echo "syz-prog2c:  $SYZ_PROG2C"
echo "out dir:     $OUT_DIR"
echo "target:      $OS/$ARCH"
echo "jobs:        $JOBS"
[[ "$NUM_PROGS" -gt 0 ]] || die "no files found in corpus dir"

compile_one() {
  local prog="$1"
  local name cfile binfile
  name="$(basename "$prog")"
  cfile="$(mktemp)"
  binfile="$OUT_DIR/syz-${name}"

  # Best-effort: a program that fails prog2c or gcc is simply skipped so one
  # bad entry never aborts the whole corpus build.
  if ! "$SYZ_PROG2C" -prog "$prog" -os "$OS" -arch "$ARCH" >"$cfile" 2>/dev/null; then
    rm -f "$cfile"; return 0
  fi
  if ! gcc -x c -O2 -pthread -w "$cfile" -o "$binfile" 2>/dev/null; then
    rm -f "$cfile" "$binfile"; return 0
  fi
  rm -f "$cfile"
}
export OUT_DIR OS ARCH SYZ_PROG2C
export -f compile_one

printf '%s\0' "${PROGS[@]}" |
  xargs -0 -n 1 -P "$JOBS" bash -c 'compile_one "$1"' _

BUILT="$(find "$OUT_DIR" -type f -perm -100 | wc -l)"
echo
echo "done: compiled $BUILT / $NUM_PROGS programs into $OUT_DIR"
[[ "$BUILT" -gt 0 ]] || die "no programs compiled successfully"

#!/usr/bin/env bash
set -euo pipefail

CATEGORY="${1:?Usage: verify_target.sh <category> <program_name>}"
NAME="${2:?Usage: verify_target.sh <category> <program_name>}"

ORIG_SRC="original/$CATEGORY/$NAME.c"
DEOBF_SRC="deobfuscated/$CATEGORY/$NAME.c"
EXPECTED_OUT="tests/$CATEGORY/${NAME}.expected_stdout"

if [[ ! -f "$DEOBF_SRC" ]]; then
  echo "[FAIL] Missing recovered file: $DEOBF_SRC"
  exit 1
fi

# 1. Structural Check: Reject raw Tigress state-machine copy-pastes
if grep -qE "_1_.*_next|__opaque_|switch\s*\(_1_" "$DEOBF_SRC"; then
  echo "[FAIL] Tigress dispatcher/opaque artifacts detected in $DEOBF_SRC. Recover clean C control flow."
  exit 1
fi

# 2. Compile Original (Reference) & Deobfuscated Candidate
BIN_ORIG=$(mktemp)
BIN_DEOBF=$(mktemp)
trap 'rm -f "$BIN_ORIG" "$BIN_DEOBF"' EXIT

gcc -O2 "$ORIG_SRC" -lm -o "$BIN_ORIG"
if ! gcc -O2 -Wall -Wextra "$DEOBF_SRC" -lm -o "$BIN_DEOBF"; then
  echo "[FAIL] Compilation failed for $DEOBF_SRC"
  exit 1
fi

# 3. Functional Equivalence Check (Exit code + stdout comparison + harness tests)
ACTUAL_OUT=$(mktemp)
trap 'rm -f "$BIN_ORIG" "$BIN_DEOBF" "$ACTUAL_OUT"' EXIT

if ! "$BIN_DEOBF" > "$ACTUAL_OUT"; then
  echo "[FAIL] Runtime assertion or non-zero exit code in $DEOBF_SRC"
  exit 1
fi

if ! diff -u "$EXPECTED_OUT" "$ACTUAL_OUT"; then
  echo "[FAIL] Output mismatch against ground truth!"
  exit 1
fi

# Optional: Run custom external test driver if present in tests/<category>/<name>_test.c
if [[ -f "tests/$CATEGORY/${NAME}_test.c" ]]; then
  BIN_TEST=$(mktemp)
  gcc -O2 -Dmain=student_main "$DEOBF_SRC" "tests/$CATEGORY/${NAME}_test.c" -lm -o "$BIN_TEST"
  "$BIN_TEST"
  rm -f "$BIN_TEST"
fi

echo "[PASS] $CATEGORY/$NAME: Compiled cleanly, structural checks passed, and all tests succeeded!"
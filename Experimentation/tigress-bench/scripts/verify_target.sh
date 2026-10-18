#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
ROOT_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
cd "$ROOT_DIR"

CATEGORY="${1:?Usage: verify_target.sh <category> <program_name>}"
NAME="${2:?Usage: verify_target.sh <category> <program_name>}"

DEOBF_SRC="deobfuscated/$CATEGORY/$NAME.c"
TEST_RUNNER="tests/$CATEGORY/${NAME}_runner.sh"
JSONL_LOG="logs/benchmark_results.jsonl"
DETAIL_LOG="logs/validation_detail.log"
mkdir -p logs

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

record_outcome() {
  local status="$1"
  local exit_code="$2"
  local msg="$3"
  local loc=0
  [[ -f "$DEOBF_SRC" ]] && loc=$(wc -l < "$DEOBF_SRC" | tr -d ' ')

  # Escape backslashes and quotes for valid JSONL
  local safe_msg
  safe_msg=$(printf '%s' "$msg" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g')

  printf '{"timestamp":"%s","category":"%s","program":"%s","status":"%s","loc":%d,"message":"%s"}\n' \
    "$TS" "$CATEGORY" "$NAME" "$status" "$loc" "$safe_msg" >> "$JSONL_LOG"

  {
    echo "============================================================"
    echo "[$TS] Target: $CATEGORY/$NAME | Status: $status | LOC: $loc"
    echo "Details: $msg"
  } >> "$DETAIL_LOG"

  echo "[$status] $CATEGORY/$NAME: $msg"
  exit "$exit_code"
}

if [[ ! -f "$DEOBF_SRC" ]]; then
  record_outcome "MISSING_FILE" 1 "File $DEOBF_SRC does not exist."
fi

if [[ ! -x "$TEST_RUNNER" ]]; then
  record_outcome "HARNESS_ERROR" 1 "Test runner $TEST_RUNNER not found or not executable."
fi

# 1. Anti-cheat: Ensure the agent recovered algorithm logic and didn't just write a dummy printf() stub
if grep -qE "_1_.*_next|__opaque_|switch\s*\(_1_" "$DEOBF_SRC"; then
  record_outcome "STRUCTURAL_FAIL" 1 "Contains un-simplified Tigress state-machine identifiers."
fi

# 2. Compile recovered C program
CANDIDATE_BIN=$(mktemp)
COMPILE_ERR=$(mktemp)
trap 'rm -f "$CANDIDATE_BIN" "$COMPILE_ERR"' EXIT

if ! gcc -O2 -Wall -Wextra "$DEOBF_SRC" -lm -o "$CANDIDATE_BIN" >"$COMPILE_ERR" 2>&1; then
  ERR_MSG=$(head -n 5 "$COMPILE_ERR" | tr '\n' ' ')
  record_outcome "COMPILE_ERROR" 1 "GCC compilation failed: $ERR_MSG"
fi

# 3. Run the verified test runner against the compiled deobfuscated binary
TEST_OUT=$(mktemp)
trap 'rm -f "$CANDIDATE_BIN" "$COMPILE_ERR" "$TEST_OUT"' EXIT

if ! "$TEST_RUNNER" "$CANDIDATE_BIN" >"$TEST_OUT" 2>&1; then
  FAIL_MSG=$(head -n 5 "$TEST_OUT" | tr '\n' ' ')
  record_outcome "TEST_FAIL" 1 "Validation test failed: $FAIL_MSG"
fi

record_outcome "PASS" 0 "Compiled cleanly and passed all test suite checks."
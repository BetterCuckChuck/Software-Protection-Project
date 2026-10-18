#!/usr/bin/env bash
set -euo pipefail
TARGET_BIN="${1:?Usage: tests/cipher/hash_crc32_runner.sh <path-to-binary>}"
EXPECTED_FILE="/home/arch/work/softwareProt/Experimentation/tigress-bench/tests/cipher/hash_crc32.expected_stdout"
ACTUAL_OUT=$(mktemp)
trap 'rm -f "$ACTUAL_OUT"' EXIT

if ! { timeout 5s "$TARGET_BIN" </dev/null > "$ACTUAL_OUT" 2>&1; } 2>/dev/null; then
  echo "Test failed: Binary exited with non-zero status or assertion failure."
  exit 1
fi

if ! diff -u "$EXPECTED_FILE" "$ACTUAL_OUT"; then
  echo "Test failed: Output mismatch against ground truth."
  exit 1
fi

exit 0

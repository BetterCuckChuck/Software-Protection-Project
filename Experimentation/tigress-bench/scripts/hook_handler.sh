#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
ROOT_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
cd "$ROOT_DIR"
mkdir -p logs

EVENT_TYPE="${1:-PreToolUse}"
PAYLOAD="$(cat)"
TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

TOOL_NAME="$(printf '%s\n' "$PAYLOAD" | jq -r '.tool_name // .toolCall.name // .tool_info.name // .name // "tool"' 2>/dev/null || echo "tool")"
TOOL_ARGS="$(printf '%s\n' "$PAYLOAD" | jq -c '.tool_info.parameters // .parameters // .toolCall.args // .tool_input // .args // {}' 2>/dev/null || echo "{}")"

if [[ "$EVENT_TYPE" == "PreToolUse" ]]; then
  echo "[$TS] [PRE_TOOL] tool=$TOOL_NAME args=$TOOL_ARGS" >> logs/attacker_activity.log

  # Exclude CodeContent and ReplacementContent so C identifiers/comments containing "original" do not false-positive
  CHECK_ARGS="$(printf '%s\n' "$TOOL_ARGS" | jq -c 'if type == "object" then del(.CodeContent, .ReplacementContent, .Description, .Instruction) else . end' 2>/dev/null || printf '%s' "$TOOL_ARGS")"

  # Block access to ground-truth directories and dataset setup script (with or without trailing slash)
  if printf '%s\n' "$CHECK_ARGS" | grep -qE '(^|[^[:alnum:]_])(original|obfuscated_src|\.cache)([/\"'\''[:space:]]|$)|01_setup_dataset'; then
    echo "[$TS] [BLOCKED] tool=$TOOL_NAME args=$TOOL_ARGS" >> logs/attacker_activity.log
    printf '{"decision":"deny","reason":"Access to ground-truth original/, obfuscated_src/, or .cache/ is forbidden."}\n'
    exit 0
  fi

  printf '{"decision":"allow"}\n'
  exit 0
fi

if [[ "$EVENT_TYPE" == "PostToolUse" ]]; then
  echo "[$TS] [POST_TOOL] tool=$TOOL_NAME completed" >> logs/attacker_activity.log

  TOOL_ERR="$(printf '%s\n' "$PAYLOAD" | jq -r '.error // empty' 2>/dev/null || true)"
  TARGET_FILE="$(printf '%s\n' "$TOOL_ARGS" | jq -r '.TargetFile // .FilePath // empty' 2>/dev/null || true)"
  if [[ -z "$TOOL_ERR" && "$TARGET_FILE" == *deobfuscated/*/*.c ]]; then
    REL_FILE="${TARGET_FILE#*deobfuscated/}"
    CAT="$(printf '%s\n' "$REL_FILE" | cut -d/ -f1)"
    NAME="$(basename "$REL_FILE" .c)"
    ./scripts/verify_target.sh "$CAT" "$NAME" >> logs/attacker_activity.log 2>&1 || true
  fi

  printf '{}\n'
  exit 0
fi
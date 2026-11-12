#!/usr/bin/env bash
# Verifies that REA and its upstream Ghidra engine are properly bound in Antigravity CLI.
set -euo pipefail

export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/home/arch/ghidra_12.1.4_PUBLIC}"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"

echo "=== REA Environment Preflight Check ==="
echo "[*] GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR"
echo "[*] JAVA_HOME:          $JAVA_HOME"

if [[ ! -d "$GHIDRA_INSTALL_DIR" ]]; then
  echo "[!] ERROR: GHIDRA_INSTALL_DIR does not point to a valid directory."
  exit 1
fi

if ! command -v agy &>/dev/null; then
  echo "[!] ERROR: agy command not found on PATH."
  exit 1
fi

echo "[*] Checking agy MCP server registration for 'rea'..."
if ! agy mcp list | grep -E '^rea\b' &>/dev/null; then
  echo "[!] WARNING: 'rea' MCP server not listed in 'agy mcp list'."
  echo "    Checking node rea.mjs script..."
  node /home/arch/.npm/_npx/af752b90495482d7/node_modules/rea-agents/scripts/rea.mjs doctor
else
  echo "[OK] 'rea' MCP server is active in agy."
fi

echo "[OK] REA native binary analysis environment ready."

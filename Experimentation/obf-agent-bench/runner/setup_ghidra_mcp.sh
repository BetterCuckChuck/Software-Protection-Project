#!/usr/bin/env bash
# One-time registration of the headless Ghidra MCP server with the Antigravity CLI.
# Prerequisites: GHIDRA_INSTALL_DIR (for builder/build_scenarios.py) and GHIDRA_MCP_CMD (see ghidra_mcp_launcher.sh).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
agy mcp add --env "GHIDRA_MCP_CMD=${GHIDRA_MCP_CMD:?set GHIDRA_MCP_CMD first}" \
  ghidra-mcp-headless -- bash "$HERE/ghidra_mcp_launcher.sh"
agy mcp list

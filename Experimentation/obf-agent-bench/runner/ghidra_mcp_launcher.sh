#!/usr/bin/env bash
# Stdio launcher registered with `agy mcp add`. The orchestrator exports OBFBENCH_GHIDRA_PROJ (per-run, pre-analyzed
# project) in agy's environment; this wrapper forwards it to the real Ghidra headless MCP server.
#
# Set GHIDRA_MCP_CMD to the command that starts your headless Ghidra MCP server in stdio mode, e.g.
#   export GHIDRA_MCP_CMD="python3 /opt/ghidra-mcp/bridge_mcp_ghidra.py --project \$OBFBENCH_GHIDRA_PROJ"
set -euo pipefail
: "${GHIDRA_MCP_CMD:?Set GHIDRA_MCP_CMD to the command that launches the headless Ghidra MCP server}"
: "${OBFBENCH_GHIDRA_PROJ:?OBFBENCH_GHIDRA_PROJ is exported by runner/orchestrator.py}"
exec bash -c "$GHIDRA_MCP_CMD"

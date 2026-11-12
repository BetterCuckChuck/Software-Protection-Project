#!/usr/bin/env python3
"""PreToolUse hook: enforce the sandbox boundary (no parent traversal / env inspection) and audit every tool call.

Specifically supports the REA (Reverse Engineer Anything) framework:
- Allows all REA MCP calls (`ServerName == 'rea'` or eager REA tool names).
- Validates that target paths opened via REA stay strictly inside the jail.
- Blocks environment inspection and filesystem traversal outside the jail.
- Audits every tool invocation to --log (JSONL) outside the jail.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import time

SAFE_READ_PREFIXES = (
    "/usr/", "/bin/", "/lib/", "/lib64/", "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr",
    "/home/arch/.gemini/antigravity-cli/mcp/rea/",
    "/home/arch/.gemini/config/skills/reverse-engineer-anything/",
)
SKIP_KEYS = {
    "CodeContent", "ReplacementContent", "Description", "Instruction", "Content", "TargetContent",
    "toolAction", "toolSummary", "WaitMsBeforeAsync",
}
ENV_CMDS = re.compile(r"(^|[;&|\s])(env|printenv)(\s|$)|/proc/(self|\d+)/environ|\$\{?(HOME|USER|PATH|PWD)\b")
NON_REA_BINARY_CMDS = re.compile(
    r"(^|[;&|\s`/])(objdump|readelf|strings|nm|gdb|r2|rizin|radare2|hexdump|xxd|od)(\s|$)"
)

REA_NATIVE_TOOLS = {
    "open_binary", "close_binary", "binary_session", "binary_overview",
    "list_procedures", "procedure_pseudo_code", "procedure_assembly",
    "procedure_callees", "procedure_callers", "procedure_info",
    "read_function_instructions", "search_bytes", "read_bytes",
    "address_to_file_offset", "procedure_references", "resolve_containing_procedure",
    "search_procedures", "search_strings", "list_strings", "list_names", "list_segments",
    "goto_address", "current_address", "current_procedure", "xrefs", "analyze_function",
    "update_analysis_settings", "inspect_analysis_settings", "inspect_binary_layout",
}


def get_args(payload: dict) -> dict:
    for path in (("tool_info", "parameters"), ("parameters",), ("toolCall", "args"), ("tool_input",), ("args",)):
        cur = payload
        for key in path:
            cur = cur.get(key) if isinstance(cur, dict) else None
        if isinstance(cur, dict):
            return cur
    return {}


def get_name(payload: dict) -> str:
    return (payload.get("tool_name") or payload.get("toolCall", {}).get("name")
            or payload.get("tool_info", {}).get("name") or payload.get("name") or "tool")


def walk_strings(obj, skip=SKIP_KEYS):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k not in skip:
                yield from walk_strings(v, skip)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_strings(v, skip)
    elif isinstance(obj, str):
        yield obj


def path_violation(token: str, jail: str) -> str | None:
    if token.startswith("-") or "://" in token:
        return None
    if token.startswith("~") or token.startswith("$HOME"):
        return f"home reference '{token}'"
    parts = [p for p in re.split(r"[\\/]", token) if p]
    if ".." in parts:
        return f"parent traversal '{token}'"
    if token.startswith("/"):
        real = os.path.normpath(token)
        if real == jail or real.startswith(jail + os.sep) or real.startswith(SAFE_READ_PREFIXES):
            return None
        return f"absolute path outside jail '{token}'"
    return None


def check(name: str, args: dict, jail: str, mcp_server: str) -> str | None:
    # 1. Direct or indirect REA tool call validation
    is_mcp_rea = (name == "call_mcp_tool" and args.get("ServerName") == mcp_server)
    is_native_rea = name.startswith(f"mcp_{mcp_server}_") or name in REA_NATIVE_TOOLS
    if is_mcp_rea or is_native_rea:
        tool_name = args.get("ToolName") if is_mcp_rea else name
        tool_args = args.get("Arguments", {}) if is_mcp_rea else args
        target_path = tool_args.get("path") or tool_args.get("target")
        if tool_name in ("open_binary", "mcp_rea_open_binary") and target_path and not str(target_path).startswith("/"):
            return f"REA open_binary requires an absolute path inside the jail ('{jail}/chal'), got '{target_path}'"
        if target_path:
            v = path_violation(str(target_path), jail)
            if v:
                return f"REA target path violation: {v}"
        return None

    # 2. Enforce strict REA framework exclusivity on shell commands (no objdump/readelf/strings/gdb bypass)
    if name == "run_command":
        cmd_str = str(args.get("CommandLine") or args.get("command") or "")
        m = NON_REA_BINARY_CMDS.search(cmd_str)
        if m:
            return (f"non-REA binary analysis tool '{m.group(2)}' is forbidden; "
                    f"use the REA MCP server (open_binary, binary_overview, list_procedures, procedure_pseudo_code, etc.)")

    # 3. General command and tool inspection
    for s in walk_strings(args):
        if ENV_CMDS.search(s):
            return f"environment inspection in '{s[:80]}'"
        try:
            tokens = shlex.split(s, posix=True)
        except ValueError:
            tokens = s.split()
        for tok in tokens or [s]:
            for piece in re.split(r"[;&|<>=]", tok):
                v = path_violation(piece.strip("'\""), jail)
                if v:
                    return v
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jail", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--mcp-server", default="rea")
    ns = ap.parse_args()
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        payload = {}
    name, args = get_name(payload), get_args(payload)
    reason = check(name, args, os.path.normpath(ns.jail), ns.mcp_server)
    with open(ns.log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": time.time(), "tool": name, "args": args,
                            "decision": "deny" if reason else "allow", "reason": reason}, default=str) + "\n")
    print(json.dumps({"decision": "deny", "reason": f"Sandbox violation: {reason}"} if reason else {"decision": "allow"}))


if __name__ == "__main__":
    main()

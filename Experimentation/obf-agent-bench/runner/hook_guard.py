#!/usr/bin/env python3
"""PreToolUse hook: enforce the sandbox boundary (no parent traversal / env inspection) and audit every tool call.

stdin  : JSON tool-call payload from agy (key names vary by version; several spellings are tried, as in Week 1)
stdout : {"decision": "allow"} or {"decision": "deny", "reason": ...}
Every call is appended to --log (JSONL) OUTSIDE the jail so the agent cannot read it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import time

SAFE_READ_PREFIXES = ("/usr/", "/bin/", "/lib/", "/lib64/", "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr")
SKIP_KEYS = {"CodeContent", "ReplacementContent", "Description", "Instruction", "Content", "TargetContent"}
ENV_CMDS = re.compile(r"(^|[;&|\s])(env|printenv)(\s|$)|/proc/(self|\d+)/environ|\$\{?(HOME|USER|PATH|PWD)\b")


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
    if name == "call_mcp_tool" and args.get("ServerName") == mcp_server:
        return None
    if name.startswith(f"mcp_{mcp_server}_"):
        return None
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
    ap.add_argument("--mcp-server", default="ghidra-mcp-headless")
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

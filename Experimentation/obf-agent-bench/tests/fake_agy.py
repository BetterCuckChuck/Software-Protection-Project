#!/usr/bin/env python3
"""Stand-in for `agy` used by tests/test_bench.py: emits an REA stream-json session and writes
reconstructed.c (copied from $FAKE_AGY_RECON) into cwd. No LLM, no network."""
import json
import os
import shutil
import sys


def emit(obj):
    print(json.dumps(obj), flush=True)


cwd = os.getcwd()
emit({"event": "init", "init": {"cwd": cwd}})
idx = 1
usage = [(1000, 100, 60, 0), (400, 300, 250, 1400), (500, 120, 20, 2000)]
rea_calls = [
    ("open_binary", {"path": os.path.join(cwd, "chal")}),
    ("binary_overview", {}),
    ("list_procedures", {}),
    ("procedure_pseudo_code", {"procedure": "0x1010c0"}),
    ("close_binary", {}),
]

for i, (inp, out, think, cache) in enumerate(usage):
    emit({"event": "step_update", "step_update": {"step_index": idx, "state": "DONE", "step_type": "agent_response",
          "duration_seconds": 2.0, "usage": {"input_tokens": inp, "output_tokens": out, "thinking_tokens": think,
                                             "cache_read_tokens": cache, "total_tokens": inp + out}}})
    idx += 1
    if i < 2:
        tool_name, tool_args = rea_calls[i]
        params = {"ServerName": "rea", "ToolName": tool_name, "Arguments": tool_args}
        for state in ("ACTIVE", "DONE"):
            su = {"step_index": idx, "state": state, "step_type": "tool", "tool_name": "call_mcp_tool",
                  "tool_info": {"name": "call_mcp_tool", "parameters": params}}
            if state == "DONE":
                su["duration_seconds"] = 0.5
                su["tool_info"]["output"] = "x" * 100
            emit({"event": "step_update", "step_update": su})
        idx += 1
        for state in ("ACTIVE", "DONE"):
            su = {"step_index": idx, "state": state, "step_type": "tool", "tool_name": "run_command",
                  "tool_info": {"name": "run_command", "parameters": {"CommandLine": "ls"}}}
            if state == "DONE":
                su["duration_seconds"] = 0.1
                su["tool_info"]["output"] = "chal\n"
            emit({"event": "step_update", "step_update": su})
        idx += 1
recon = os.environ.get("FAKE_AGY_RECON")
if recon:
    shutil.copy(recon, "reconstructed.c")
emit({"event": "result", "result": {"status": "SUCCESS", "duration_seconds": 7.5,
      "usage": {"input_tokens": 1900, "output_tokens": 520, "thinking_tokens": 330, "cache_read_tokens": 3400}}})
sys.exit(0)

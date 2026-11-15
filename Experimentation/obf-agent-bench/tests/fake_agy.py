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
safety_flag = os.environ.get("FAKE_AGY_FAIL_FIRST_SAFETY")
if safety_flag and not os.path.exists(safety_flag):
    with open(safety_flag, "w", encoding="utf-8") as fh:
        fh.write("1")
    msg = "This request was blocked by Gemini's filters. Please try rephrasing your prompt.\n"
    usage_fail = {"input_tokens": 1000, "output_tokens": 50, "thinking_tokens": 50,
                  "cache_read_tokens": 0, "total_tokens": 1050}
    emit({"event": "step_update", "step_update": {
        "step_index": 1, "state": "DONE", "step_type": "agent_response",
        "text_delta": msg, "duration_seconds": 1.0, "usage": usage_fail,
    }})
    emit({"event": "result", "result": {
        "status": "SUCCESS", "response": msg, "duration_seconds": 1.0,
        "num_turns": 1, "usage": usage_fail,
    }})
    sys.exit(0)
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

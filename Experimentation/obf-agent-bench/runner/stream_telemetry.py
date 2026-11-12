"""Parse `agy --output-format stream-json` NDJSON into the run_metrics / telemetry contract.

Event schema observed in the Week-1 logs (Experimentation/tigress-bench/logs/session_stream.jsonl):
  {"event":"step_update","step_update":{"step_index":N,"state":"DONE","step_type":"agent_response",
       "duration_seconds":F,"usage":{"input_tokens","output_tokens","thinking_tokens","cache_read_tokens","total_tokens"}}}
  {"event":"step_update","step_update":{"step_type":"tool","tool_name":..,"state":"DONE","duration_seconds":F,
       "tool_info":{"name":..,"parameters":{..},"output":".."}}}
  {"event":"result","result":{"status":..,"duration_seconds":F,"usage":{..}}}

Token semantics (verified: total_tokens == input_tokens + output_tokens in every step):
  input_tokens       -> T_in    uncached prompt tokens of the turn
  cache_read_tokens  -> T_cache prefix-cache hits of the turn
  thinking_tokens    -> T_think (a SUBSET of output_tokens)
  output_tokens - thinking_tokens -> T_out
  peak context       -> max over turns of (input_tokens + cache_read_tokens)
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Iterable, Optional

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


def mcp_tool_name(step: dict, mcp_server: str) -> Optional[str]:
    """Return the MCP tool short-name if this tool step targets `mcp_server`, else None."""
    name = step.get("tool_name") or step.get("tool_info", {}).get("name") or ""
    params = step.get("tool_info", {}).get("parameters", {}) or {}
    if name == "call_mcp_tool":
        server = params.get("ServerName")
        if server == mcp_server:
            return params.get("ToolName")
        return None
    for prefix in (f"mcp_{mcp_server}_", f"mcp__{mcp_server}__"):
        if name.startswith(prefix):
            return name[len(prefix):]
    if mcp_server == "rea" and name in REA_NATIVE_TOOLS:
        return name
    return None


def parse_stream(lines: Iterable[str], mcp_server: str) -> dict:
    turns: dict[int, dict] = {}
    tools: dict[int, dict] = {}
    result_event: dict = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event") == "result":
            result_event = ev.get("result", {})
        elif ev.get("event") == "step_update":
            su = ev["step_update"]
            idx = su.get("step_index")
            if su.get("state") != "DONE":
                continue
            if su.get("step_type") == "agent_response" and "usage" in su:
                turns[idx] = su
            elif su.get("step_type") == "tool":
                tools[idx] = su

    per_turn, t_in = [], 0.0
    totals = Counter()
    peak = 0
    for idx in sorted(turns):
        u = turns[idx]["usage"]
        think = u.get("thinking_tokens", 0)
        out = max(u.get("output_tokens", 0) - think, 0)
        ctx = u.get("input_tokens", 0) + u.get("cache_read_tokens", 0)
        per_turn.append({"step": idx, "input_uncached": u.get("input_tokens", 0),
                         "input_cached": u.get("cache_read_tokens", 0), "reasoning": think, "output": out,
                         "context": ctx, "duration_sec": turns[idx].get("duration_seconds", 0.0)})
        totals["input_uncached"] += u.get("input_tokens", 0)
        totals["input_cached"] += u.get("cache_read_tokens", 0)
        totals["reasoning"] += think
        totals["output"] += out
        peak = max(peak, ctx)
        t_in += turns[idx].get("duration_seconds", 0.0)

    per_tool: Counter = Counter()
    mcp_bytes = other_bytes = 0
    t_mcp = t_other = 0.0
    n_other = 0
    for idx in sorted(tools):
        su = tools[idx]
        payload = len(str(su.get("tool_info", {}).get("output", "")).encode("utf-8", "replace"))
        short = mcp_tool_name(su, mcp_server)
        if short is not None:
            per_tool[short] += 1
            mcp_bytes += payload
            t_mcp += su.get("duration_seconds", 0.0)
        else:
            n_other += 1
            other_bytes += payload
            t_other += su.get("duration_seconds", 0.0)

    res_usage = result_event.get("usage", {})
    wall = result_event.get("duration_seconds")
    return {
        "tokens": {**{k: int(totals[k]) for k in ("input_uncached", "input_cached", "reasoning", "output")},
                   "peak_context": int(peak)},
        "turns": len(per_turn),
        "per_turn": per_turn,
        "mcp_calls": int(sum(per_tool.values())),
        "mcp_calls_by_tool": dict(per_tool),
        "other_tool_calls": n_other,
        "mcp_payload_bytes": mcp_bytes,
        "other_tool_payload_bytes": other_bytes,
        "latency": {"wall_time_sec": wall, "llm_time_sec": round(t_in, 3), "mcp_time_sec": round(t_mcp, 3),
                    "other_tool_time_sec": round(t_other, 3)},
        "agent_status": result_event.get("status"),
        "result_usage_crosscheck": res_usage,
        "has_result_event": bool(result_event),
    }

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


def _is_tool_error(step: dict) -> bool:
    """Return True when a tool step ended in error or carries a structured tool_info error."""
    if step.get("state") == "ERROR":
        return True
    tinfo = step.get("tool_info") or {}
    if tinfo.get("error"):
        return True
    raw = tinfo.get("output")
    if isinstance(raw, str) and raw.lstrip().startswith("{"):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict):
                return True
        except json.JSONDecodeError:
            pass
    return False


def _tool_payload_text(step: dict) -> str:
    """Extract serialized output or error text from a tool step_update."""
    tinfo = step.get("tool_info") or {}
    if tinfo.get("output") is not None:
        return str(tinfo.get("output"))
    if tinfo.get("error") is not None:
        err = tinfo.get("error")
        return json.dumps(err) if isinstance(err, dict) else str(err)
    return ""


def parse_stream(lines: Iterable[str], mcp_server: str) -> dict:
    turns: dict[int, dict] = {}
    tools: dict[int, dict] = {}
    result_event: dict = {}
    conversation_id: Optional[str] = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if conversation_id is None:
            conversation_id = ev.get("conversation_id") or ev.get("step_update", {}).get("conversation_id")
        if ev.get("event") == "result":
            result_event = ev.get("result", {})
        elif ev.get("event") == "step_update":
            su = ev["step_update"]
            idx = su.get("step_index")
            state = su.get("state")
            if state not in ("DONE", "ERROR"):
                continue
            if su.get("step_type") == "agent_response" and state == "DONE" and "usage" in su:
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

    mcp_ok: Counter = Counter()
    mcp_err: Counter = Counter()
    other_ok: Counter = Counter()
    other_err: Counter = Counter()
    mcp_bytes = mcp_err_bytes = other_bytes = other_err_bytes = 0
    t_mcp = t_other = 0.0
    for idx in sorted(tools):
        su = tools[idx]
        payload = len(_tool_payload_text(su).encode("utf-8", "replace"))
        is_err = _is_tool_error(su)
        dur = su.get("duration_seconds", 0.0) or 0.0
        short = mcp_tool_name(su, mcp_server)
        if short is not None:
            if is_err:
                mcp_err[short] += 1
                mcp_err_bytes += payload
            else:
                mcp_ok[short] += 1
            mcp_bytes += payload
            t_mcp += dur
        else:
            raw_name = str(su.get("tool_name") or (su.get("tool_info") or {}).get("name") or "tool")
            if is_err:
                other_err[raw_name] += 1
                other_err_bytes += payload
            else:
                other_ok[raw_name] += 1
            other_bytes += payload
            t_other += dur

    mcp_total_by_tool = mcp_ok + mcp_err
    n_mcp_ok = int(sum(mcp_ok.values()))
    n_mcp_err = int(sum(mcp_err.values()))
    n_mcp = n_mcp_ok + n_mcp_err

    other_total_by_name = other_ok + other_err
    n_other_ok = int(sum(other_ok.values()))
    n_other_err = int(sum(other_err.values()))
    n_other = n_other_ok + n_other_err

    res_usage = result_event.get("usage", {})
    wall = result_event.get("duration_seconds")
    total_input = int(totals["input_uncached"] + totals["input_cached"])
    total_tokens = int(total_input + totals["reasoning"] + totals["output"])
    return {
        "conversation_id": conversation_id,
        "tokens": {**{k: int(totals[k]) for k in ("input_uncached", "input_cached", "reasoning", "output")},
                   "peak_context": int(peak),
                   "total_input": total_input,
                   "total": total_tokens},
        "turns": len(per_turn),
        "per_turn": per_turn,
        "mcp_calls": n_mcp,
        "mcp_calls_succeeded": n_mcp_ok,
        "mcp_calls_errored": n_mcp_err,
        "mcp_error_rate": round(n_mcp_err / n_mcp, 4) if n_mcp else 0.0,
        "mcp_calls_by_tool": dict(mcp_total_by_tool),
        "mcp_calls_succeeded_by_tool": dict(mcp_ok),
        "mcp_calls_errored_by_tool": dict(mcp_err),
        "other_tool_calls": n_other,
        "other_tool_calls_succeeded": n_other_ok,
        "other_tool_calls_errored": n_other_err,
        "other_tool_calls_by_name": dict(other_total_by_name),
        "other_tool_calls_errored_by_name": dict(other_err),
        "mcp_payload_bytes": mcp_bytes,
        "mcp_error_payload_bytes": mcp_err_bytes,
        "other_tool_payload_bytes": other_bytes,
        "other_tool_error_payload_bytes": other_err_bytes,
        "latency": {"wall_time_sec": wall, "llm_time_sec": round(t_in, 3), "mcp_time_sec": round(t_mcp, 3),
                    "other_tool_time_sec": round(t_other, 3)},
        "agent_status": result_event.get("status"),
        "result_usage_crosscheck": res_usage,
        "has_result_event": bool(result_event),
    }

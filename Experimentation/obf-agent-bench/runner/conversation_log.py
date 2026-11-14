#!/usr/bin/env python3
"""Archive the full Antigravity conversation transcript and render a readable Markdown log per run.

Per run directory (results/<scenario>/<sample>/):
  - Archives the raw Antigravity transcript (`transcript_full.jsonl`) from
    ~/.gemini/antigravity-cli/brain/<conversation_id>/.system_generated/logs/ when available.
  - Merges `session_stream.jsonl`, `transcript_full.jsonl`, `hook_audit.jsonl`, `run_metrics.json`,
    and `io_result.json` into a readable chronological `conversation_log.md`.

Usage:
    python3 runner/conversation_log.py --run-dir results/S0_Baseline/CWE190_Integer_Overflow__char_fscanf_add_01
    python3 runner/conversation_log.py --all
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, load_config  # noqa: E402


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rows.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return rows


def extract_conversation_id(stream_path: Path) -> Optional[str]:
    """Return the Antigravity conversation_id recorded in session_stream.jsonl, if any."""
    for ev in _read_jsonl(stream_path):
        cid = ev.get("conversation_id") or ev.get("step_update", {}).get("conversation_id")
        if cid:
            return str(cid)
    return None


def find_brain_transcript(conv_id: str, brain_root: Optional[Path] = None) -> Optional[Path]:
    """Locate Antigravity's transcript_full.jsonl (or fallback transcript.jsonl) for `conv_id`."""
    if not conv_id:
        return None
    root = brain_root or (Path.home() / ".gemini" / "antigravity-cli" / "brain")
    logs_dir = root / conv_id / ".system_generated" / "logs"
    for name in ("transcript_full.jsonl", "transcript.jsonl"):
        p = logs_dir / name
        if p.exists():
            return p
    return None


def snapshot_transcript(run_dir: Path, conv_id: Optional[str] = None,
                        brain_root: Optional[Path] = None) -> Optional[Path]:
    """Copy the full Antigravity brain transcript into `run_dir/transcript_full.jsonl`."""
    dest = run_dir / "transcript_full.jsonl"
    if dest.exists():
        return dest
    cid = conv_id or extract_conversation_id(run_dir / "session_stream.jsonl")
    if not cid:
        return None
    src = find_brain_transcript(cid, brain_root=brain_root)
    if src is None:
        return None
    shutil.copy2(src, dest)
    return dest


def _fence(text: str, lang: str = "text") -> str:
    marker = "~~~~" if "~~~" in text else "~~~"
    return f"{marker}{lang}\n{text.rstrip()}\n{marker}"


def _clip(text: str, max_chars: int) -> str:
    if max_chars > 0 and len(text) > max_chars:
        return text[:max_chars] + f"\n... [truncated {len(text) - max_chars} chars]"
    return text


def _strip_timestamp_preamble(raw: str) -> str:
    lines = raw.splitlines()
    i = 0
    while i < len(lines) and (lines[i].startswith("Created At: ") or lines[i].startswith("Completed At: ")):
        i += 1
    return "\n".join(lines[i:]).strip()


def _format_tool_params(tname: str, params: dict) -> list[str]:
    out = []
    # Keep file body readable when writing/editing C code instead of hiding it inside escaped JSON.
    body = None
    body_key = None
    for k in ("Content", "CodeContent", "Replacement"):
        if isinstance(params.get(k), str) and "\n" in params[k]:
            body_key = k
            body = params[k]
            break
    shown = {k: (f"<rendered below: {len(body)} chars>" if k == body_key else v) for k, v in params.items()}
    if shown:
        out.append("**Parameters:**\n" + _fence(json.dumps(shown, indent=2, ensure_ascii=False), "json"))
    if body is not None:
        target = str(params.get("Path") or params.get("TargetFile") or "")
        lang = "c" if target.endswith((".c", ".h")) else "text"
        out.append(f"**{body_key}:**\n" + _fence(body, lang))
    return out


def _format_tool_output(raw: str, tool_short: str, max_chars: int) -> list[str]:
    cleaned = _strip_timestamp_preamble(raw)
    if not cleaned:
        return []
    out: list[str] = []
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return ["**Output:**\n" + _fence(_clip(cleaned, max_chars), "text")]

    if isinstance(parsed, dict) and "normalized_result" in parsed:
        norm = parsed.get("normalized_result")
        meta = {
            "evidence_id": parsed.get("evidence_id"),
            "operation": parsed.get("operation"),
            "provider": (parsed.get("provider") or {}).get("id"),
            "confidence": parsed.get("confidence"),
            "limitations": parsed.get("limitations"),
        }
        out.append("**REA Envelope:**\n" + _fence(json.dumps(meta, indent=2, ensure_ascii=False), "json"))
        if isinstance(norm, str):
            lang = "c" if "pseudo_code" in tool_short else "text"
            out.append("**Normalized Result:**\n" + _fence(_clip(norm, max_chars), lang))
        else:
            pretty = json.dumps(norm, indent=2, ensure_ascii=False)
            out.append("**Normalized Result:**\n" + _fence(_clip(pretty, max_chars), "json"))
        return out

    pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
    return ["**Output:**\n" + _fence(_clip(pretty, max_chars), "json")]


def _tool_display_name(tname: str, params: dict) -> tuple[str, str]:
    if tname == "call_mcp_tool" and params.get("ServerName") and params.get("ToolName"):
        short = str(params["ToolName"])
        return f"`call_mcp_tool` (`{params['ServerName']}:{short}`)", short
    return f"`{tname}`", tname


def render_conversation_log(run_dir: Path, out_md: Optional[Path] = None,
                            max_output_chars: int = 0) -> Path:
    """Render `run_dir/conversation_log.md` from stream, brain transcript, and hook audit logs."""
    stream_path = run_dir / "session_stream.jsonl"
    stream_events = _read_jsonl(stream_path)
    conv_id = extract_conversation_id(stream_path)
    snapshot_transcript(run_dir, conv_id=conv_id)

    t_path = run_dir / "transcript_full.jsonl"
    transcript_rows = _read_jsonl(t_path) if t_path.exists() else []
    transcript_steps = {r["step_index"]: r for r in transcript_rows if "step_index" in r}
    hooks = _read_jsonl(run_dir / "hook_audit.jsonl")

    metrics_path = run_dir / "run_metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    io_path = run_dir / "io_result.json"
    io_res = json.loads(io_path.read_text(encoding="utf-8")) if io_path.exists() else {}

    init_info: dict = {}
    stream_steps: dict[int, dict] = {}
    result_event: dict = {}
    for ev in stream_events:
        kind = ev.get("event")
        if kind == "init":
            init_info = ev.get("init", {})
        elif kind == "result":
            result_event = ev.get("result", {})
        elif kind == "step_update":
            su = ev.get("step_update", {})
            idx = su.get("step_index")
            if idx is None:
                continue
            prev = stream_steps.get(idx)
            # Prefer terminal DONE/ERROR over earlier ACTIVE snapshot
            if prev is None or su.get("state") in ("DONE", "ERROR"):
                stream_steps[idx] = su

    md: list[str] = ["# Agent Run Conversation Log\n"]
    scenario = metrics.get("scenario") or run_dir.parent.name
    sample = metrics.get("sample_id") or run_dir.name
    md.append(f"- **Scenario / Sample**: `{scenario}` / `{sample}`")
    md.append(f"- **Conversation ID**: `{conv_id or 'unavailable'}`")
    if init_info.get("cwd"):
        md.append(f"- **Jail CWD**: `{init_info['cwd']}`")
    if metrics:
        tok = metrics.get("tokens", {})
        md.append(
            f"- **Run Stats**: status=`{metrics.get('terminated_reason')}`, turns=`{metrics.get('turns')}`, "
            f"mcp_calls=`{metrics.get('mcp_calls')}`, wall=`{metrics.get('latency', {}).get('wall_time_sec')}s`"
        )
        md.append(
            f"- **Tokens**: in_uncached=`{tok.get('input_uncached', 0)}`, in_cached=`{tok.get('input_cached', 0)}`, "
            f"reasoning=`{tok.get('reasoning', 0)}`, output=`{tok.get('output', 0)}`, "
            f"peak_ctx=`{tok.get('peak_context', 0)}`"
        )
    if io_res:
        md.append(
            f"- **I/O Verdict**: `Pass_IO={int(bool(io_res.get('io_passed')))}` "
            f"({io_res.get('io_tests_passed', 0)}/{io_res.get('io_tests_total', 0)})"
        )
    md.append(
        f"- **Full Transcript Archived**: `{'yes (transcript_full.jsonl)' if t_path.exists() else 'no (stream-only)'}`\n"
    )
    md.append("---\n")

    all_indices = sorted(set(stream_steps) | set(transcript_steps))
    for idx in all_indices:
        su = stream_steps.get(idx, {})
        tr = transcript_steps.get(idx, {})
        stype = su.get("step_type") or tr.get("type") or "unknown"
        ts = tr.get("created_at")
        ts_suffix = f" · `{ts}`" if ts else ""

        if stype in ("user_input", "USER_INPUT"):
            prompt_text = tr.get("content") or ""
            md.append(f"## [Step {idx}] User Prompt{ts_suffix}\n")
            if prompt_text.strip():
                md.append(_fence(prompt_text, "markdown") + "\n")
            else:
                md.append("_Prompt text unavailable (no transcript snapshot)._\n")

        elif stype in ("agent_response", "PLANNER_RESPONSE"):
            dur = su.get("duration_seconds")
            dur_str = f"{dur:.2f}s" if isinstance(dur, (int, float)) else "-"
            u = su.get("usage", {})
            in_u = u.get("input_tokens", tr.get("input_tokens", 0))
            in_c = u.get("cache_read_tokens", tr.get("cache_read_tokens", 0))
            think_tok = u.get("thinking_tokens", 0)
            out_tok = u.get("output_tokens", tr.get("output_tokens", 0))
            md.append(
                f"### [Step {idx}] Agent Turn (`{dur_str}`){ts_suffix}\n"
                f"- **Tokens**: in=`{in_u}`, cached=`{in_c}`, thinking=`{think_tok}`, output=`{out_tok}`\n"
            )
            thinking = (tr.get("thinking") or "").strip()
            content = (tr.get("content") or "").strip()
            if thinking:
                md.append("**Thinking:**\n" + _fence(_clip(thinking, max_output_chars), "text") + "\n")
            if content:
                md.append("**Response:**\n" + _clip(content, max_output_chars) + "\n")
            tcalls = tr.get("tool_calls") or []
            if tcalls and not any((idx + 1) in stream_steps for _ in [0]):
                md.append("**Planned Tool Calls:**\n" + _fence(json.dumps(tcalls, indent=2), "json") + "\n")

        elif stype in ("tool", "GENERIC"):
            tinfo = su.get("tool_info", {})
            tname = su.get("tool_name") or tinfo.get("name") or "tool"
            params = tinfo.get("parameters") or {}
            if not params and (idx - 1) in transcript_steps:
                prev_calls = transcript_steps[idx - 1].get("tool_calls") or []
                if len(prev_calls) == 1:
                    tname = prev_calls[0].get("name", tname)
                    params = prev_calls[0].get("args", {})
            state = su.get("state") or tr.get("status") or "DONE"
            dur = su.get("duration_seconds")
            dur_str = f" {dur:.3f}s" if isinstance(dur, (int, float)) else ""
            disp_name, short_name = _tool_display_name(tname, params)
            md.append(f"### [Step {idx}] Tool {disp_name} [{state}{dur_str}]{ts_suffix}\n")
            md.extend(_format_tool_params(tname, params))
            raw_out = tr.get("content") or tinfo.get("output") or ""
            if raw_out:
                md.extend(_format_tool_output(str(raw_out), short_name, max_output_chars))
            md.append("")

    if result_event:
        md.append("---\n## Session Result\n" + _fence(json.dumps(result_event, indent=2), "json") + "\n")

    if hooks:
        n_allow = sum(1 for h in hooks if h.get("decision") == "allow")
        n_deny = sum(1 for h in hooks if h.get("decision") != "allow")
        md.append(f"---\n## Hook Guard Audit (`allow={n_allow}`, `deny={n_deny}`)\n")
        for h in hooks:
            dec = str(h.get("decision", "?")).upper()
            tool = h.get("tool", "?")
            args = h.get("args", {})
            detail = args.get("ToolName") or args.get("CommandLine") or args.get("Path") or ""
            reason = f" — `{h['reason']}`" if h.get("reason") else ""
            md.append(f"- `{dec}` `{tool}` `{str(detail)[:120]}`{reason}")
        md.append("")

    target = out_md or (run_dir / "conversation_log.md")
    target.write_text("\n".join(md), encoding="utf-8")
    return target


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "configs" / "experiment.yaml"))
    ap.add_argument("--run-dir", type=Path, help="render a single results/<scenario>/<sample> directory")
    ap.add_argument("--all", action="store_true", help="render all runs under results_dir")
    ap.add_argument("--max-output-chars", type=int, default=0,
                    help="clip long tool/thinking blocks (0 = full untruncated log)")
    args = ap.parse_args()

    if args.run_dir:
        out = render_conversation_log(args.run_dir, max_output_chars=args.max_output_chars)
        print(f"Wrote {out}")
    elif args.all:
        cfg = load_config(Path(args.config))
        results_dir = ROOT / cfg["paths"]["results_dir"]
        for stream in sorted(results_dir.glob("*/*/session_stream.jsonl")):
            out = render_conversation_log(stream.parent, max_output_chars=args.max_output_chars)
            print(f"Wrote {out}")
    else:
        ap.error("need --run-dir or --all")


if __name__ == "__main__":
    main()

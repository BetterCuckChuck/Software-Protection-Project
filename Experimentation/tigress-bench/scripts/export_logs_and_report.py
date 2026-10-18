#!/usr/bin/env python3
from datetime import datetime, timezone
import json
from pathlib import Path
import re

ROOT_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = ROOT_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)


def load_brain_transcript(conv_id: str) -> dict:
    """Load step details from Antigravity's transcript_full.jsonl / transcript.jsonl if available."""
    if not conv_id or conv_id == "unknown":
        return {}
    brain_logs = (
        Path.home()
        / ".gemini"
        / "antigravity-cli"
        / "brain"
        / conv_id
        / ".system_generated"
        / "logs"
    )
    for fname in ("transcript_full.jsonl", "transcript.jsonl"):
        tpath = brain_logs / fname
        if tpath.exists():
            steps = {}
            for line in tpath.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    idx = obj.get("step_index")
                    if idx is not None:
                        steps[idx] = obj
                except Exception:
                    continue
            return steps
    return {}


def export_conversation_log(stream_jsonl_path: Path, out_md_path: Path):
    lines = [
        "# Attacker Agent Conversation & Thought Log",
        f"- **Generated At**: `{datetime.now(timezone.utc).isoformat()}`",
        f"- **Session Source**: `{stream_jsonl_path.name}`\n",
        "---\n",
    ]

    total_input_tokens = 0
    total_output_tokens = 0
    total_thinking_tokens = 0
    conv_id = "unknown"
    events = []

    if stream_jsonl_path.exists():
        for raw_line in stream_jsonl_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                ev = json.loads(raw_line)
                events.append(ev)
                if ev.get("event") == "init" and conv_id == "unknown":
                    conv_id = ev.get("conversation_id", "unknown")
                elif "step_update" in ev and conv_id == "unknown":
                    conv_id = ev["step_update"].get("conversation_id", "unknown")
            except json.JSONDecodeError:
                continue

    transcript_steps = load_brain_transcript(conv_id)

    for ev in events:
        ev_type = ev.get("event")

        if ev_type == "init":
            conv_id = ev.get("conversation_id", conv_id)
            init_info = ev.get("init", {})
            lines.append(
                f"## Session Initialized (`{conv_id}`)\n"
                f"- **Working Directory**: `{init_info.get('cwd')}`\n"
                f"- **Permission Mode**: `{init_info.get('permission_mode')}`\n"
            )

        elif ev_type == "step_update":
            su = ev.get("step_update", {})
            idx = su.get("step_index", 0)
            state = su.get("state", "")
            stype = su.get("step_type", "")
            dur = su.get("duration_seconds")
            tstep = transcript_steps.get(idx, {})

            # Skip ACTIVE transitions if DONE/ERROR follows
            if stype == "agent_response" and state == "DONE":
                usage = su.get("usage", {})
                in_tok = usage.get("input_tokens", 0) or tstep.get("input_tokens", 0)
                out_tok = usage.get("output_tokens", 0) or tstep.get("output_tokens", 0)
                th_tok = usage.get("thinking_tokens", 0)
                total_input_tokens += in_tok
                total_output_tokens += out_tok
                total_thinking_tokens += th_tok

                thought = su.get("thought") or tstep.get("thinking") or ""
                text_content = (
                    su.get("text")
                    or su.get("response")
                    or tstep.get("content")
                    or ""
                )
                dur_str = f"{dur:.2f}s" if isinstance(dur, (int, float)) else "0.00s"
                lines.append(
                    f"### [Step {idx}] 🧠 Agent Reasoning Step ({dur_str})\n"
                    f"- **Tokens**: Input `{in_tok}` | Thinking `{th_tok}` | Output `{out_tok}`\n"
                )
                if thought.strip():
                    lines.append(f"**Internal Thought:**\n> {thought.strip()}\n")
                if text_content.strip():
                    lines.append(f"{text_content.strip()}\n")

            elif stype == "tool" and state in ("DONE", "ERROR"):
                tname = su.get("tool_name", "unknown_tool")
                tinfo = su.get("tool_info", {})
                params = tinfo.get("parameters", {})
                err = tinfo.get("error") or tstep.get("error")
                res = (
                    tinfo.get("result")
                    or tinfo.get("output")
                    or su.get("output")
                    or tstep.get("content")
                )

                status_icon = "❌ ERROR" if state == "ERROR" else "✅ DONE"
                dur_str = f"{dur:.3f}s" if isinstance(dur, (int, float)) else ""
                lines.append(
                    f"### [Step {idx}] 🛠️ Tool Call: `{tname}` [{status_icon} {dur_str}]\n"
                    f"**Parameters:**\n~~~json\n{json.dumps(params, indent=2)}\n~~~\n"
                )
                if err:
                    err_str = (
                        json.dumps(err, indent=2)
                        if isinstance(err, dict)
                        else str(err)
                    )
                    lines.append(f"**Error:**\n~~~text\n{err_str}\n~~~\n")
                elif res:
                    res_str = (
                        json.dumps(res, indent=2)
                        if isinstance(res, dict)
                        else str(res)
                    )
                    if len(res_str.splitlines()) > 50:
                        res_str = (
                            "\n".join(res_str.splitlines()[:50])
                            + "\n... [Truncated] ..."
                        )
                    lines.append(f"**Output:**\n~~~text\n{res_str}\n~~~\n")

        elif ev_type == "result" or "result" in ev:
            res_obj = ev.get("result", ev)
            if isinstance(res_obj, dict):
                final_text = (
                    res_obj.get("response")
                    or res_obj.get("text")
                    or res_obj.get("output")
                )
            else:
                final_text = str(res_obj)
            if final_text:
                lines.append(
                    f"---\n## Final Agent Summary Response\n{final_text}\n"
                )

    lines.append(
        "---\n## Cumulative Token & Reasoning Metrics\n"
        f"- **Conversation ID**: `{conv_id}`\n"
        f"- **Total Input Tokens**: `{total_input_tokens}`\n"
        f"- **Total Thinking Tokens**: `{total_thinking_tokens}`\n"
        f"- **Total Output Tokens**: `{total_output_tokens}`\n"
    )

    hook_log = LOGS_DIR / "attacker_activity.log"
    if hook_log.exists() and hook_log.stat().st_size > 0:
        lines.append(
            "---\n## Chronological Hook & Tool Audit (`attacker_activity.log`)\n~~~text"
        )
        lines.append(
            hook_log.read_text(encoding="utf-8", errors="replace").strip()
        )
        lines.append("~~~\n")

    out_md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Exported conversation log -> {out_md_path}")


def generate_result_report(out_report_path: Path):
    jsonl_path = LOGS_DIR / "benchmark_results.jsonl"
    hook_path = LOGS_DIR / "attacker_activity.log"
    stream_path = LOGS_DIR / "session_stream.jsonl"

    targets = []
    cat_counts = {"math": 0, "cipher": 0}
    for cat in ("math", "cipher"):
        bin_dir = ROOT_DIR / "bin" / cat
        if bin_dir.exists():
            for f in sorted(bin_dir.iterdir()):
                if f.is_file():
                    targets.append((cat, f.name))
                    cat_counts[cat] += 1

    history = {}
    if jsonl_path.exists():
        for line in jsonl_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                key = (rec["category"], rec["program"])
                history.setdefault(key, []).append(rec)
            except Exception:
                pass

    total_tool_calls = 0
    objdump_calls = 0
    gdb_calls = 0

    if hook_path.exists() and hook_path.stat().st_size > 0:
        for line in hook_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "[PRE_TOOL]" in line:
                total_tool_calls += 1
                if "tool=run_command" in line:
                    if re.search(r"\bobjdump\b", line):
                        objdump_calls += 1
                    if re.search(r"\bgdb\b", line):
                        gdb_calls += 1
    elif stream_path.exists():
        for line in stream_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                ev = json.loads(line)
                su = ev.get("step_update", {})
                if su.get("step_type") == "tool" and su.get("state") in ("DONE", "ERROR"):
                    total_tool_calls += 1
                    cmd = su.get("tool_info", {}).get("parameters", {}).get("CommandLine", "")
                    if re.search(r"\bobjdump\b", cmd):
                        objdump_calls += 1
                    if re.search(r"\bgdb\b", cmd):
                        gdb_calls += 1
            except Exception:
                pass

    passed_count = 0
    rows = []

    for cat, name in targets:
        recs = history.get((cat, name), [])
        attempts = len(recs)
        final_status = recs[-1]["status"] if recs else "NOT_ATTEMPTED"
        final_msg = recs[-1]["message"] if recs else "No verification run recorded."
        deobf_loc = recs[-1]["loc"] if recs else 0

        orig_file = ROOT_DIR / "original" / cat / f"{name}.c"
        orig_loc = (
            len(orig_file.read_text(encoding="utf-8", errors="replace").splitlines())
            if orig_file.exists()
            else 0
        )

        if final_status == "PASS":
            passed_count += 1
            badge = "PASS"
        else:
            badge = f"FAIL ({final_status})"

        rows.append(
            f"| `{cat}` | `{name}` | **{badge}** | {attempts} | {orig_loc} | {deobf_loc} | {final_msg} |"
        )

    total_targets = len(targets)
    pass_rate = (passed_count / total_targets * 100.0) if total_targets else 0.0

    report = [
        "# Benchmark Evaluation Result Report",
        f"- **Timestamp (UTC)**: `{datetime.now(timezone.utc).isoformat()}`",
        "- **Attacker Model**: `gemini-3.8-flash`",
        "- **Obfuscation**: Tigress (`InitOpaque`, `Flatten`, `EncodeArithmetic`, `CleanUp`) + `gcc -O2 -s` + `strip --strip-all`",
        "- **Allowed Tools**: Static (`objdump`), Dynamic (`gdb`)\n",
        "## 1. Executive Summary",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Total Targets Evaluated** | {total_targets} ({cat_counts['math']} `math`, {cat_counts['cipher']} `cipher`) |",
        f"| **Targets Successfully Recovered & Verified** | **{passed_count} / {total_targets} ({pass_rate:.1f}%)** |",
        f"| **Total Agent Tool Invocations** | {total_tool_calls} |",
        f"| **Static Analysis (`objdump`) Commands** | {objdump_calls} |",
        f"| **Dynamic Analysis (`gdb`) Commands** | {gdb_calls} |\n",
        "## 2. Per-Program Verification Scorecard",
        "| Category | Program | Final Verdict | Verification Attempts | Original LOC | Recovered LOC | Last Validation Message |",
        "| :--- | :--- | :--- | :---: | :---: | :---: | :--- |",
        *rows,
        "\n## 3. Recovered C Source Code",
    ]

    for cat, name in targets:
        deobf_file = ROOT_DIR / "deobfuscated" / cat / f"{name}.c"
        if deobf_file.exists():
            code = deobf_file.read_text(encoding="utf-8", errors="replace").strip()
            report.append(f"### `{cat}/{name}.c`\n~~~c\n{code}\n~~~\n")

    out_report_path.write_text("\n".join(report), encoding="utf-8")
    print(f"[+] Generated result report -> {out_report_path}")


if __name__ == "__main__":
    export_conversation_log(
        LOGS_DIR / "session_stream.jsonl", LOGS_DIR / "conversation_log.md"
    )
    generate_result_report(LOGS_DIR / "result_report.md")
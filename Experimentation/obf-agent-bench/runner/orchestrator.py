#!/usr/bin/env python3
"""Run the REA agent (Antigravity CLI + REA framework) against every (scenario, sample) target.

Per run:
  1. create an ephemeral jail  <jail_root>/run_<uuid>/  containing ONLY `chal`, the REA skill, and a guard hook
     (ground-truth sources, test vectors, and benchmark results live outside and are never reachable by relative paths)
  2. launch `agy -p <rea_task.md> --output-format stream-json` with cwd = jail; stream stdout to disk
  3. enforce limits (turns / REA MCP calls / context / wall clock) by terminating the process group
  4. collect ./reconstructed.c, parse the stream into run_metrics.json + telemetry.json
  5. grade with evaluator.io_harness (unless --no-grade) which merges the I/O verdict into telemetry.json

Results: results/<scenario>/<sample>/{session_stream.jsonl, run_metrics.json, telemetry.json, reconstructed.c,
         io_result.json, hook_audit.jsonl, agy_stderr.log}

Usage:
    python3 runner/orchestrator.py --config configs/experiment.yaml
    python3 runner/orchestrator.py --scenarios S1_Flatten --samples CWE190_..._01 --resume
    python3 runner/orchestrator.py --dry-run          # print the plan, create nothing
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, build_path, load_config, load_manifest, resolve, result_path  # noqa: E402
from stream_telemetry import mcp_tool_name, parse_stream  # noqa: E402

REA_SKILL_SOURCE = Path("/home/arch/.gemini/config/skills/reverse-engineer-anything")


def preflight(cfg: dict, need_mcp: bool) -> list[str]:
    """Return a list of blocking problems (empty == ready)."""
    rt, problems = cfg["agent_runtime"], []
    if shutil.which(rt["agy_binary"]) is None:
        problems.append(f"'{rt['agy_binary']}' not found on PATH")
        return problems
    if need_mcp:
        ghidra_dir = os.environ.get(cfg["ghidra"].get("install_dir_env", "GHIDRA_INSTALL_DIR"),
                                    cfg["ghidra"].get("install_dir", "/home/arch/ghidra_12.1.4_PUBLIC"))
        if not Path(ghidra_dir).is_dir():
            problems.append(f"Ghidra install directory '{ghidra_dir}' not found. Set GHIDRA_INSTALL_DIR.")
        proc = subprocess.run([rt["agy_binary"], "mcp", "list"], capture_output=True, text=True, timeout=60)
        if rt["mcp_server"] not in proc.stdout:
            problems.append(
                f"MCP server '{rt['mcp_server']}' is not registered with agy (or disabled). "
                f"Run `agy mcp list` or pass --no-mcp for a dry/simulated test run.")
    return problems


def write_jail_config(jail: Path, cfg: dict, audit_log: Path) -> None:
    rt = cfg["agent_runtime"]
    agents = jail / ".agents"
    agents.mkdir(parents=True, exist_ok=True)
    (agents / "settings.json").write_text(json.dumps({
        "model": rt["model"],
        "agentMode": "accept-edits",
        "toolPermission": "always-proceed",
        "permissions": {"allowCommands": rt["allowed_commands"]},
    }, indent=2))

    # Provide the REA skill directly within the jail so the agent has REA binary analysis instructions
    if REA_SKILL_SOURCE.is_dir():
        dest_skills = agents / "skills" / "reverse-engineer-anything"
        shutil.copytree(REA_SKILL_SOURCE, dest_skills, dirs_exist_ok=True)

    guard = f'python3 "{ROOT / "runner" / "hook_guard.py"}" --jail "{jail}" --log "{audit_log}" --mcp-server "{rt["mcp_server"]}"'
    (agents / "hooks.json").write_text(json.dumps({
        "obf-bench-jail-guard": {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [{"type": "command", "command": guard, "timeout": 15}]
                }
            ]
        }
    }, indent=2))


class LimitWatcher:
    """Consumes the agy NDJSON stream line by line and kills the process group when a limit is exceeded."""

    def __init__(self, proc: subprocess.Popen, limits: dict, mcp_server: str, deadline: float):
        self.proc, self.limits, self.mcp_server, self.deadline = proc, limits, mcp_server, deadline
        self.turns = self.mcp_calls = 0
        self.seen_tools: set[int] = set()
        self.seen_turns: set[int] = set()
        self.reason = "completed"

    def kill(self, reason: str) -> None:
        if self.reason == "completed":
            self.reason = reason
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def feed(self, line: str) -> None:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return
        if ev.get("event") != "step_update":
            return
        su = ev["step_update"]
        idx = su.get("step_index")
        if su.get("step_type") == "agent_response" and su.get("state") == "DONE" and "usage" in su \
                and idx not in self.seen_turns:
            self.seen_turns.add(idx)
            self.turns += 1
            u = su["usage"]
            if u.get("input_tokens", 0) + u.get("cache_read_tokens", 0) > self.limits["max_context_tokens"]:
                self.kill("max_context_tokens")
            elif self.turns > self.limits["max_turns"]:
                self.kill("max_turns")
        elif su.get("step_type") == "tool" and su.get("state") == "ACTIVE" and idx not in self.seen_tools:
            self.seen_tools.add(idx)
            if mcp_tool_name(su, self.mcp_server):
                self.mcp_calls += 1
                if self.mcp_calls > self.limits["max_mcp_calls"]:
                    self.kill("max_mcp_calls")


def run_agent(cfg: dict, jail: Path, run_dir: Path, extra_env: dict) -> tuple[str, float]:
    rt = cfg["agent_runtime"]
    raw_prompt = resolve(cfg, "prompt_file").read_text(encoding="utf-8")
    prompt = raw_prompt.replace("{chal_path}", str(jail / "chal")).replace("{jail_dir}", str(jail))
    cmd = [rt["agy_binary"], *rt["agy_extra_args"], "--model", rt["model"],
           "--output-format", "stream-json", "-p", prompt]
    runtime_env = rt.get("environment", {})
    env = {**os.environ, **runtime_env, **extra_env}
    start = time.time()
    deadline = start + rt["limits"]["timeout_seconds"]
    with (run_dir / "session_stream.jsonl").open("w", encoding="utf-8") as stream, \
            (run_dir / "agy_stderr.log").open("w", encoding="utf-8") as err:
        proc = subprocess.Popen(cmd, cwd=jail, stdout=subprocess.PIPE, stderr=err, text=True, env=env,
                                start_new_session=True)
        watcher = LimitWatcher(proc, rt["limits"], rt["mcp_server"], deadline)
        timer = threading.Timer(max(deadline - time.time(), 0), watcher.kill, args=("timeout",))
        timer.start()
        try:
            for line in proc.stdout:
                stream.write(line)
                stream.flush()
                watcher.feed(line)
        finally:
            timer.cancel()
            proc.wait()
    reason = watcher.reason
    if reason == "completed" and proc.returncode not in (0, None):
        reason = f"agy_exit_{proc.returncode}"
    return reason, time.time() - start


def telemetry_from_metrics(scenario: str, sample_id: str, metrics: dict, reason: str, wall: float) -> dict:
    wall_t = metrics["latency"].get("wall_time_sec") or wall
    return {
        "scenario": scenario, "sample_id": sample_id,
        "io_passed": None, "io_tests_passed": None, "io_tests_total": None,   # filled by io_harness
        "tokens": metrics["tokens"],
        "mcp_calls": metrics["mcp_calls"],
        "turns": metrics["turns"],
        "wall_time_sec": round(wall_t, 2),
        "terminated_reason": reason,
    }


def run_one(cfg: dict, scenario: str, sample: dict, args: argparse.Namespace) -> dict | None:
    sid = sample["sample_id"]
    rt = cfg["agent_runtime"]
    bdir = build_path(cfg, scenario, sid)
    stats_file = bdir / "binary_stats.json"
    if not (bdir / "chal").exists() or not stats_file.exists():
        print(f"[skip] {scenario}/{sid}: not built")
        return None
    if not json.loads(stats_file.read_text()).get("valid", False) and not args.include_invalid:
        print(f"[skip] {scenario}/{sid}: build flagged invalid (semantics differ from S0)")
        return None
    run_dir = result_path(cfg, scenario, sid)
    if args.resume and (run_dir / "run_metrics.json").exists():
        print(f"[skip] {scenario}/{sid}: already has run_metrics.json")
        return None
    if args.dry_run:
        print(f"[plan] {scenario}/{sid}")
        return None

    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)
    jail = Path(rt["sandbox"]["jail_root"]) / f"run_{uuid.uuid4().hex}"
    jail.mkdir(parents=True)
    try:
        shutil.copy(bdir / "chal", jail / "chal")
        (jail / "chal").chmod(0o755)
        write_jail_config(jail, cfg, run_dir / "hook_audit.jsonl")
        extra_env = {"OBFBENCH_JAIL": str(jail)}
        print(f"[run ] {scenario}/{sid}  jail={jail}")
        reason, wall = run_agent(cfg, jail, run_dir, extra_env)
        if (jail / rt["deliverable_file"]).exists():
            shutil.copy(jail / rt["deliverable_file"], run_dir / rt["deliverable_file"])
        with (run_dir / "session_stream.jsonl").open(encoding="utf-8") as f:
            metrics = parse_stream(f, rt["mcp_server"])
        metrics.update({"scenario": scenario, "sample_id": sid, "terminated_reason": reason,
                        "deliverable_written": (run_dir / rt["deliverable_file"]).exists(),
                        "model": rt["model"], "limits": rt["limits"]})
        (run_dir / "run_metrics.json").write_text(json.dumps(metrics, indent=2))
        tel = telemetry_from_metrics(scenario, sid, metrics, reason, wall)
        (run_dir / "telemetry.json").write_text(json.dumps(tel, indent=2))
    finally:
        if not args.keep_jail:
            shutil.rmtree(jail, ignore_errors=True)

    if not args.no_grade:
        from evaluator.io_harness import evaluate_run
        res = evaluate_run(cfg, scenario, sid)
        print(f"[done] {scenario}/{sid}: reason={reason} Pass_IO={int(res['io_passed'])} "
              f"({res['io_tests_passed']}/{res['io_tests_total']}) mcp={metrics['mcp_calls']} turns={metrics['turns']}")
    return tel


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "configs" / "experiment.yaml"))
    ap.add_argument("--scenarios", nargs="*")
    ap.add_argument("--samples", nargs="*")
    ap.add_argument("--resume", action="store_true", help="skip runs that already have run_metrics.json")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-grade", action="store_true", help="do not run the I/O harness after each run")
    ap.add_argument("--no-mcp", action="store_true", help="skip the MCP registration check (for dry/mock testing)")
    ap.add_argument("--include-invalid", action="store_true", help="also run builds flagged invalid")
    ap.add_argument("--keep-jail", action="store_true")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    if not args.dry_run:
        problems = preflight(cfg, need_mcp=not args.no_mcp)
        if problems:
            sys.exit("Preflight failed:\n  - " + "\n  - ".join(problems))
    samples = [s for s in load_manifest(cfg) if not args.samples or s["sample_id"] in args.samples]
    scenarios = args.scenarios or list(cfg["scenarios"])
    for sample in samples:                     # sample-major: all scenarios of a sample run back to back
        for scenario in scenarios:
            run_one(cfg, scenario, sample, args)


if __name__ == "__main__":
    main()

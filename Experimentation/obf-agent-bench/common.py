"""Shared helpers for the obf-agent-bench pipeline."""
from __future__ import annotations

import json
import os
import re
import resource
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

import yaml

ROOT = Path(__file__).resolve().parent
_CHAL_EXEC_RE = re.compile(r"(?:^|[\s'\"\[])(?:\./|/[^\s'\"]*/)chal(?=\s|$|['\"\]])")


def load_config(path: Optional[Path] = None) -> dict:
    path = Path(path) if path else ROOT / "configs" / "experiment.yaml"
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve(config: dict, key: str) -> Path:
    """Resolve a `paths.<key>` entry relative to the bench root."""
    return (ROOT / config["paths"][key]).resolve()


def load_manifest(config: dict) -> list[dict]:
    manifest = (ROOT / config["dataset"]["manifest_path"]).resolve()
    return json.loads(manifest.read_text(encoding="utf-8"))["samples"]


def build_path(config: dict, scenario: str, sample_id: str) -> Path:
    return resolve(config, "build_dir") / scenario / sample_id


def result_path(config: dict, scenario: str, sample_id: str) -> Path:
    return resolve(config, "results_dir") / scenario / sample_id


@dataclass
class RunResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


def _limits(cpu_seconds: int = 5, mem_bytes: int = 512 * 1024 * 1024, fsize: int = 8 * 1024 * 1024):
    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        os.setsid()
    return apply


def run_binary(binary: Path, argv: Sequence[str], stdin: bytes, timeout_ms: int) -> RunResult:
    """Run an untrusted binary with resource limits, no env, and a wall-clock timeout."""
    try:
        proc = subprocess.run(
            [str(binary), *argv],
            input=stdin,
            capture_output=True,
            timeout=timeout_ms / 1000.0,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            cwd=str(binary.parent),
            preexec_fn=_limits(),
        )
        return RunResult(proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as exc:
        return RunResult(-9, exc.stdout or b"", exc.stderr or b"", timed_out=True)


def load_vectors(config: dict, sample_id: str) -> dict:
    return json.loads((resolve(config, "test_vectors") / f"{sample_id}.json").read_text(encoding="utf-8"))


def iter_cases(vectors: dict):
    """Yield (kind, case) with kind in {'curated', 'fuzz'}; stdin is decoded to bytes."""
    for kind in ("curated", "fuzz"):
        for case in vectors[kind]:
            yield kind, case["id"], case["argv"], bytes.fromhex(case["stdin_hex"])


def compute_token_cost(tokens: dict, pricing: dict) -> dict[str, float]:
    """Compute USD token cost components and total from configured per-1M rates."""
    c_in_u = tokens.get("input_uncached", 0) * pricing["input_uncached"] / 1_000_000.0
    c_in_c = tokens.get("input_cached", 0) * pricing["input_cached"] / 1_000_000.0
    c_think = tokens.get("reasoning", 0) * pricing["output_and_reasoning"] / 1_000_000.0
    c_out = tokens.get("output", 0) * pricing["output_and_reasoning"] / 1_000_000.0
    return {
        "input_uncached": c_in_u,
        "input_cached": c_in_c,
        "reasoning": c_think,
        "output": c_out,
        "total": c_in_u + c_in_c + c_think + c_out,
    }


def summarize_hook_audit(audit_path: Path) -> Optional[dict]:
    """Summarize allow/deny counts and runtime `./chal` probes from hook_audit.jsonl."""
    if not audit_path.exists():
        return None
    allow = deny = chal_total = chal_pre_write = 0
    seen_deliverable = False
    deny_reasons: dict[str, int] = {}
    for raw in audit_path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        dec = row.get("decision")
        tool = row.get("tool", "")
        args = row.get("args") or {}
        if dec == "allow":
            allow += 1
            if tool in ("write_file", "edit_file") and "reconstructed.c" in str(args.get("Path") or args.get("TargetFile") or ""):
                seen_deliverable = True
            elif tool == "run_command":
                cmd = str(args.get("CommandLine") or args.get("command") or "")
                if _CHAL_EXEC_RE.search(cmd):
                    chal_total += 1
                    if not seen_deliverable:
                        chal_pre_write += 1
        else:
            deny += 1
            reason = str(row.get("reason") or "denied")
            deny_reasons[reason] = deny_reasons.get(reason, 0) + 1
    return {
        "total": allow + deny,
        "allow": allow,
        "deny": deny,
        "deny_reasons": deny_reasons,
        "chal_exec_calls": chal_total,
        "chal_exec_pre_write": chal_pre_write,
    }


BINARY_STAT_KEYS = (
    "file_size_bytes",
    "text_bytes",
    "instructions",
    "conditional_jumps",
    "indirect_jumps",
    "basic_block_estimate",
    "cyclomatic_complexity_est",
)


def load_binary_stats(config: dict, scenario: str, sample_id: str) -> Optional[dict]:
    """Load static binary obfuscation stats from build/<scenario>/<sample>/binary_stats.json."""
    stats_file = build_path(config, scenario, sample_id) / "binary_stats.json"
    if not stats_file.exists():
        return None
    try:
        raw = json.loads(stats_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return {k: raw[k] for k in BINARY_STAT_KEYS if k in raw and raw[k] is not None} or None

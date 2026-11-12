"""Shared helpers for the obf-agent-bench pipeline."""
from __future__ import annotations

import json
import os
import resource
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

import yaml

ROOT = Path(__file__).resolve().parent


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

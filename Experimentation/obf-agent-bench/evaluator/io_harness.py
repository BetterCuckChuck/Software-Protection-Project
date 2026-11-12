#!/usr/bin/env python3
"""Axis 1 - deterministic I/O-equivalency grading of ./reconstructed.c against ./chal.

Gate 1  Static sanitization + compilation   (forbidden calls / inline asm -> Pass_IO = 0)
Gate 2  15 curated boundary vectors          (T_curated)
Gate 3  50 seeded differential-fuzz vectors  (T_diff)

Each test compares (stdout, stderr, exit_code) of the live ./chal and the recompiled recon_bin.
All tests are executed after Gate 1 even when an earlier gate fails, so partial accuracy Acc_IO is available;
Pass_IO = 1 iff Gate 1 passes AND every test in T_curated U T_diff matches.

Usage:
    python3 evaluator/io_harness.py --scenario S1_Flatten --sample CWE190_..._01        # one run
    python3 evaluator/io_harness.py --all                                               # every results/*/*/reconstructed.c
    python3 evaluator/io_harness.py --recon some.c --chal build/S0_Baseline/<id>/chal --sample <id>   # ad-hoc
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import (ROOT, build_path, iter_cases, load_config, load_vectors, result_path,  # noqa: E402
                    run_binary)

_COMMENTS_AND_STRINGS = re.compile(
    r"""//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'""", re.S)
_STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\\n])*"')


def _token_regex(tokens: list[str]) -> re.Pattern:
    parts = []
    for t in tokens:
        parts.append(re.escape(t[:-1]) + r"\w*" if t.endswith("*") else re.escape(t))
    return re.compile(r"\b(" + "|".join(parts) + r")\b")


def static_sanitize(src: str, forbidden_tokens: list[str]) -> list[str]:
    """Return a list of violations. Comments and literals are blanked out first so prose cannot trigger or hide hits."""
    violations: list[str] = []
    code = _COMMENTS_AND_STRINGS.sub(lambda m: '""' if m.group(0)[0] in "\"'" else " ", src)
    for m in _token_regex(forbidden_tokens).finditer(code):
        violations.append(f"forbidden token '{m.group(1)}'")
    # Anti-cheat: the program must not read/exec the target it is being compared against.
    for lit in _STRING_LITERAL.findall(re.sub(r"/\*.*?\*/|//[^\n]*", " ", src, flags=re.S)):
        if "chal" in lit:
            violations.append(f"string literal references the target binary: {lit}")
    return sorted(set(violations))


def compile_recon(src_path: Path, workdir: Path, compile_cmd: list[str]) -> tuple[bool, str, Path]:
    shutil.copy(src_path, workdir / "reconstructed.c")
    proc = subprocess.run(compile_cmd, cwd=workdir, capture_output=True, text=True, timeout=120)
    return proc.returncode == 0, proc.stderr[-1500:], workdir / compile_cmd[-1]


def _fmt(b: bytes) -> str:
    return repr(b[:80])


def grade(recon_src: Path, chal: Path, vectors: dict, cfg: dict) -> dict:
    io_cfg = cfg["evaluation"]["io_equivalence"]
    timeout_ms = io_cfg["timeout_per_test_ms"]
    result = {
        "gate1": {"passed": False, "violations": [], "compile_ok": False, "compile_stderr": ""},
        "gate2": {"passed": 0, "total": 0}, "gate3": {"passed": 0, "total": 0},
        "failures": [], "io_passed": False, "io_tests_passed": 0, "io_tests_total": 0, "io_accuracy": 0.0,
    }
    cases = list(iter_cases(vectors))
    result["gate2"]["total"] = sum(1 for k, *_ in cases if k == "curated")
    result["gate3"]["total"] = sum(1 for k, *_ in cases if k == "fuzz")
    result["io_tests_total"] = len(cases)

    if not recon_src.exists():
        result["gate1"]["violations"] = ["reconstructed.c missing"]
        return result
    violations = static_sanitize(recon_src.read_text(encoding="utf-8", errors="replace"),
                                 io_cfg["forbidden_tokens"])
    result["gate1"]["violations"] = violations
    if violations:
        return result

    with tempfile.TemporaryDirectory(prefix="io_eval_") as tmp:
        tmpdir = Path(tmp)
        ok, err, recon_bin = compile_recon(recon_src, tmpdir, io_cfg["compile_cmd"])
        result["gate1"]["compile_ok"], result["gate1"]["compile_stderr"] = ok, err
        if not ok:
            return result
        result["gate1"]["passed"] = True

        chal_copy = tmpdir / "chal"           # run both from the same neutral dir
        shutil.copy(chal, chal_copy)
        chal_copy.chmod(0o755)
        for kind, cid, argv, stdin in cases:
            ref = run_binary(chal_copy, argv, stdin, timeout_ms)
            got = run_binary(recon_bin, argv, stdin, timeout_ms)
            same = (ref.returncode, ref.stdout, ref.stderr) == (got.returncode, got.stdout, got.stderr) \
                and not got.timed_out
            gate = result["gate2" if kind == "curated" else "gate3"]
            if same:
                gate["passed"] += 1
            elif len(result["failures"]) < 5:
                result["failures"].append({
                    "case": cid, "argv": argv, "stdin": _fmt(stdin),
                    "chal": {"rc": ref.returncode, "stdout": _fmt(ref.stdout), "stderr": _fmt(ref.stderr)},
                    "recon": {"rc": got.returncode, "stdout": _fmt(got.stdout), "stderr": _fmt(got.stderr),
                              "timeout": got.timed_out},
                })
    passed = result["gate2"]["passed"] + result["gate3"]["passed"]
    result["io_tests_passed"] = passed
    result["io_accuracy"] = passed / result["io_tests_total"] if result["io_tests_total"] else 0.0
    result["io_passed"] = result["gate1"]["passed"] and passed == result["io_tests_total"]
    return result


def update_telemetry(run_dir: Path, scenario: str, sample_id: str, res: dict) -> None:
    """Merge the I/O verdict into the per-run telemetry.json contract (see README)."""
    tel_path = run_dir / "telemetry.json"
    tel = json.loads(tel_path.read_text()) if tel_path.exists() else {"scenario": scenario, "sample_id": sample_id}
    tel.update({"io_passed": res["io_passed"], "io_tests_passed": res["io_tests_passed"],
                "io_tests_total": res["io_tests_total"]})
    tel_path.write_text(json.dumps(tel, indent=2))


def evaluate_run(cfg: dict, scenario: str, sample_id: str, recon: Optional[Path] = None,
                 chal: Optional[Path] = None) -> dict:
    run_dir = result_path(cfg, scenario, sample_id)
    recon = recon or run_dir / "reconstructed.c"
    chal = chal or build_path(cfg, scenario, sample_id) / "chal"
    res = grade(recon, chal, load_vectors(cfg, sample_id), cfg)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "io_result.json").write_text(json.dumps(res, indent=2))
    update_telemetry(run_dir, scenario, sample_id, res)
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "configs" / "experiment.yaml"))
    ap.add_argument("--scenario")
    ap.add_argument("--sample")
    ap.add_argument("--recon", type=Path)
    ap.add_argument("--chal", type=Path)
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()
    cfg = load_config(Path(args.config))

    targets = []
    if args.all:
        results = ROOT / cfg["paths"]["results_dir"]
        targets = [(p.parent.parent.name, p.parent.name) for p in sorted(results.glob("*/*/reconstructed.c"))]
    elif args.sample:
        targets = [(args.scenario or next(iter(cfg["scenarios"])), args.sample)]
    else:
        ap.error("need --all or --sample")

    for scenario, sample_id in targets:
        res = evaluate_run(cfg, scenario, sample_id, args.recon, args.chal)
        g1 = "pass" if res["gate1"]["passed"] else f"FAIL {res['gate1']['violations'] or 'compile'}"
        print(f"{scenario:<16} {sample_id:<58} gate1={g1} curated={res['gate2']['passed']}/{res['gate2']['total']} "
              f"fuzz={res['gate3']['passed']}/{res['gate3']['total']} -> Pass_IO={int(res['io_passed'])}")


if __name__ == "__main__":
    main()

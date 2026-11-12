#!/usr/bin/env python3
"""Build the scenario x sample matrix: Tigress-obfuscate, compile, strip, analyze, validate.

For every (scenario, sample) this writes  build/<scenario>/<sample>/
    chal                 stripped target ELF
    binary_stats.json    size, .text bytes, instruction / jcc / basic-block counts, validity vs. S0
    obfuscated.c         (S1-S3) Tigress output - kept for the researcher, never copied to the agent jail
    ghidra_proj/         pre-analyzed headless Ghidra project (only when $GHIDRA_INSTALL_DIR is set)

Semantic validity: every obfuscated chal must reproduce S0 chal on ALL curated+fuzz vectors, otherwise the
sample is flagged `valid: false` and the orchestrator skips it (Tigress/UB divergences must not be blamed on the agent).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import (ROOT, build_path, iter_cases, load_config, load_manifest, load_vectors,  # noqa: E402
                    resolve, run_binary)

JCC = re.compile(r"^\s*[0-9a-f]+:\s+(j(?!mp)\w+)\s")
JMP_INDIRECT = re.compile(r"^\s*[0-9a-f]+:\s+(?:notrack\s+)?jmp\s+(?:r[a-z0-9]+|\[|\w+ ptr)")
JMP_ANY = re.compile(r"^\s*[0-9a-f]+:\s+(jmp|j\w+|ret\w*|call)\s")


def sh(cmd: list[str], cwd: Path | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def stage_for_tigress(src: Path, dest: Path) -> None:
    """Tigress's C parser: 64-bit decimal literals need an explicit ULL suffix."""
    text = src.read_text(encoding="utf-8")
    text = re.sub(r"\b([0-9]{19,20})\b", r"\1ULL", text)
    dest.write_text(text, encoding="utf-8")


def tigress_obfuscate(recipe_cfg: dict, recipe: str, src: Path, out_c: Path) -> None:
    groups = recipe_cfg["recipes"][recipe]
    common = recipe_cfg["common"]
    funcs = "%100"
    args = ["tigress", f"--Environment={common['environment']}", *common["compat_defines"]]
    for group in groups:
        args += [a.format(funcs=funcs) for a in group]
    args += [a.format(funcs=funcs) for a in common["cleanup"]]
    with tempfile.TemporaryDirectory() as tmp:  # Tigress drops cleanUpRename*.json in cwd
        staged = Path(tmp) / src.name
        stage_for_tigress(src, staged)
        proc = sh([*args, str(staged), f"--out={out_c}"], cwd=Path(tmp), timeout=120)
    if proc.returncode != 0 or not out_c.exists():
        raise RuntimeError(f"tigress failed ({recipe}): {(proc.stderr or proc.stdout)[-600:]}")


def compile_chal(src: Path, flags: list[str], out: Path) -> None:
    proc = sh(["gcc", "-std=gnu99", *flags, "-w", str(src), "-lm", "-o", str(out)], timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"gcc failed: {proc.stderr[-600:]}")
    sh(["strip", "--strip-all", "--remove-section=.comment", "--remove-section=.note", str(out)])


def binary_stats(chal: Path) -> dict:
    text_bytes = 0
    for line in sh(["readelf", "-SW", str(chal)]).stdout.splitlines():
        m = re.search(r"\.text\s+PROGBITS\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)", line)
        if m:
            text_bytes = int(m.group(1), 16)
    dis = sh(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", "-j", ".text", str(chal)]).stdout.splitlines()
    n_ins = n_jcc = n_blocks_end = n_ind = 0
    for line in dis:
        if re.match(r"^\s*[0-9a-f]+:\s+\S", line):
            n_ins += 1
            if JCC.match(line):
                n_jcc += 1
            if JMP_INDIRECT.match(line):
                n_ind += 1
            if JMP_ANY.match(line):
                n_blocks_end += 1
    return {
        "file_size_bytes": chal.stat().st_size,
        "text_bytes": text_bytes,
        "instructions": n_ins,
        "conditional_jumps": n_jcc,
        "indirect_jumps": n_ind,                  # switch-dispatcher jump tables (Flatten) show up here
        "basic_block_estimate": n_blocks_end + 1,
        "cyclomatic_complexity_est": n_jcc + n_ind + 1,   # McCabe estimate: decision points + 1
    }


def run_all(binary: Path, vectors: dict, timeout_ms: int) -> list[tuple]:
    out = []
    for _kind, cid, argv, stdin in iter_cases(vectors):
        r = run_binary(binary, argv, stdin, timeout_ms)
        out.append((cid, r.returncode, r.stdout, r.stderr, r.timed_out))
    return out


def build_ghidra(chal: Path, proj_dir: Path, cfg: dict) -> str:
    install = os.environ.get(cfg["ghidra"]["install_dir_env"])
    headless = Path(install) / "support" / "analyzeHeadless" if install else None
    if not headless or not headless.exists():
        return "skipped (set $GHIDRA_INSTALL_DIR to enable)"
    shutil.rmtree(proj_dir, ignore_errors=True)
    proj_dir.mkdir(parents=True)
    proc = sh([str(headless), str(proj_dir), "chal_proj", "-import", str(chal), "-overwrite",
               "-analysisTimeoutPerFile", str(cfg["ghidra"]["analysis_timeout_seconds"])],
              timeout=cfg["ghidra"]["analysis_timeout_seconds"] + 120)
    return "ok" if proc.returncode == 0 else f"failed: {proc.stderr[-300:]}"


def build_one(cfg: dict, recipes: dict, scenario: str, sample: dict, ref_cache: dict) -> dict:
    sid = sample["sample_id"]
    out_dir = build_path(cfg, scenario, sid)
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    sc = cfg["scenarios"][scenario]
    src = ROOT / sample["normalized_src"]
    chal = out_dir / "chal"
    timeout_ms = cfg["evaluation"]["io_equivalence"]["timeout_per_test_ms"]
    vectors = load_vectors(cfg, sid)
    try:
        if recipes["recipes"][sc["recipe"]]:
            obf = out_dir / "obfuscated.c"
            tigress_obfuscate(recipes, sc["recipe"], src, obf)
            compile_chal(obf, sc["compiler_flags"], chal)
        else:
            compile_chal(src, sc["compiler_flags"], chal)
        stats = binary_stats(chal)
        stats["build_error"] = None
    except Exception as exc:  # noqa: BLE001 - recorded, not fatal for the matrix
        stats = {"build_error": str(exc)[:800], "valid": False}
        (out_dir / "binary_stats.json").write_text(json.dumps(stats, indent=2))
        return {"scenario": scenario, "sample": sid, **stats}

    # reference: unobfuscated normalized source, -O0 -fwrapv (well-defined overflow) -> UB sensitivity
    if sid not in ref_cache:
        with tempfile.TemporaryDirectory() as tmp:
            ref = Path(tmp) / "ref"
            sh(["gcc", "-std=gnu99", "-O0", "-fwrapv", "-w", str(src), "-o", str(ref)])
            ref_cache[sid] = run_all(ref, vectors, timeout_ms)
    results = run_all(chal, vectors, timeout_ms)
    s0 = next(iter(cfg["scenarios"]))                     # S0 defines the behavioural baseline
    if scenario == s0:
        ref_cache[(sid, "s0")] = results
    elif (sid, "s0") not in ref_cache:                    # building S1..S3 alone: reuse the already-built S0 chal
        s0_chal = build_path(cfg, s0, sid) / "chal"
        if not s0_chal.exists():
            raise SystemExit(f"S0 binary for {sid} missing; build {s0} first")
        ref_cache[(sid, "s0")] = run_all(s0_chal, vectors, timeout_ms)
    base = ref_cache[(sid, "s0")]
    mism_s0 = [a[0] for a, b in zip(results, base) if a[1:4] != b[1:4]]
    mism_ref = [a[0] for a, b in zip(results, ref_cache[sid]) if a[1:4] != b[1:4]]
    stats.update({
        "scenario": scenario, "sample_id": sid, "n_vectors": len(results),
        "mismatches_vs_S0": mism_s0, "mismatches_vs_O0_fwrapv_reference": mism_ref,
        "valid": not mism_s0,
    })
    stats["ghidra_proj"] = build_ghidra(chal, out_dir / "ghidra_proj", cfg)
    (out_dir / "binary_stats.json").write_text(json.dumps(stats, indent=2))
    return {"scenario": scenario, "sample": sid, **stats}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "configs" / "experiment.yaml"))
    ap.add_argument("--scenarios", nargs="*", help="subset of scenario ids (default: all)")
    ap.add_argument("--samples", nargs="*", help="subset of sample ids (default: all)")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    recipes = yaml.safe_load(resolve(cfg, "tigress_recipes").read_text())
    samples = [s for s in load_manifest(cfg) if not args.samples or s["sample_id"] in args.samples]
    scenarios = args.scenarios or list(cfg["scenarios"])

    ref_cache: dict = {}
    summary = []
    for scenario in scenarios:
        print(f"[*] {scenario}")
        for sample in samples:
            res = build_one(cfg, recipes, scenario, sample, ref_cache)
            flag = "OK " if res.get("valid") else "BAD"
            extra = res.get("build_error") or f"text={res.get('text_bytes')}B jcc={res.get('conditional_jumps')}"
            print(f"   [{flag}] {res['sample']}  {extra}", flush=True)
            summary.append(res)
    out = resolve(cfg, "build_dir") / "build_summary.json"
    prev = json.loads(out.read_text()) if out.exists() else []
    keys = {(r["scenario"], r["sample"]) for r in summary}
    merged = [r for r in prev if (r["scenario"], r["sample"]) not in keys] + summary
    out.write_text(json.dumps(merged, indent=2, default=str))
    bad = [r for r in summary if not r.get("valid")]
    print(f"[done] {len(summary) - len(bad)}/{len(summary)} valid builds -> {out}")


if __name__ == "__main__":
    main()

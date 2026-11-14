#!/usr/bin/env python3
"""Axis 2 - agentic cost, I/O equivalence, and obfuscation-impact evaluation.

Reads configs/experiment.yaml and every results/<scenario>/<sample>/telemetry.json (+ run_metrics.json,
io_result.json, hook_audit.jsonl, session_stream.jsonl fallback, and build/<scenario>/<sample>/binary_stats.json),
computes full I/O gate metrics, USD cost breakdown, errored/succeeded MCP tool counts, OCM, ECSR, and
obfuscation complexity correlations, and writes:
    results/benchmark_summary.json   machine-readable aggregate (+ enriched per-run rows)
    results/summary_table.md         unified Markdown comparison & obfuscation breakdown report
    results/simulator.html           standalone offline interactive HTML cost & accuracy report

Usage:  python3 evaluator/cost_evaluator.py [--config configs/experiment.yaml] [--results results]
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import statistics
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import (ROOT, compute_token_cost, load_binary_stats, load_config,  # noqa: E402
                    summarize_hook_audit)
from runner.stream_telemetry import parse_stream  # noqa: E402


# ----------------------------------------------------------------------------- stats helpers
def mean_sd(xs: list[float]) -> tuple[float, float]:
    if not xs:
        return float("nan"), float("nan")
    return statistics.fmean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0.0)


def median_iqr(xs: list[float]) -> tuple[float, float, float]:
    if not xs:
        return float("nan"), float("nan"), float("nan")
    if len(xs) < 2:
        return xs[0], xs[0], xs[0]
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return statistics.median(xs), q[0], q[2]


def ratio(num: Optional[float], den: Optional[float]) -> Optional[float]:
    if num is None or not den:
        return None
    return num / den


def _mean_present(vals: list[Optional[float]]) -> Optional[float]:
    present = [v for v in vals if v is not None]
    return statistics.fmean(present) if present else None


def clean(obj):
    """JSON-safe: NaN -> None."""
    if isinstance(obj, float) and obj != obj:
        return None
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [clean(v) for v in obj]
    return obj


# ----------------------------------------------------------------------------- per-run cost & enrichment
def compute_run_cost(tokens: dict, pricing: dict) -> float:
    """Return total run USD cost from token counts and pricing configuration."""
    return compute_token_cost(tokens, pricing)["total"]


def _extract_io_breakdown(tel: dict, io_res: dict) -> dict:
    existing = tel.get("io_breakdown")
    if isinstance(existing, dict) and not io_res:
        return existing
    if io_res:
        g1 = io_res.get("gate1", {})
        g2 = io_res.get("gate2", {})
        g3 = io_res.get("gate3", {})
        return {
            "gate1_passed": bool(g1.get("passed")),
            "compile_ok": bool(g1.get("compile_ok")),
            "violations": list(g1.get("violations") or []),
            "curated_passed": g2.get("passed", 0),
            "curated_total": g2.get("total", 0),
            "fuzz_passed": g3.get("passed", 0),
            "fuzz_total": g3.get("total", 0),
        }
    if isinstance(existing, dict):
        return existing
    return {
        "gate1_passed": bool(tel.get("io_passed")),
        "compile_ok": bool(tel.get("io_passed")),
        "violations": [],
        "curated_passed": None,
        "curated_total": None,
        "fuzz_passed": None,
        "fuzz_total": None,
    }


def load_runs(results_dir: Path, pricing: dict, config: Optional[dict] = None) -> list[dict]:
    """Load all graded telemetry.json files and enrich with stream, I/O, hook, cost, and binary stats."""
    mcp_server = config["agent_runtime"]["mcp_server"] if config else "rea"
    max_ctx_limit = (config.get("agent_runtime", {}).get("limits", {}).get("max_context_tokens")
                     if config else None) or 128000
    runs = []
    for tel_file in sorted(results_dir.glob("*/*/telemetry.json")):
        tel = json.loads(tel_file.read_text(encoding="utf-8"))
        if tel.get("io_passed") is None:
            print(f"[warn] {tel_file.parent} not graded yet (run evaluator/io_harness.py); skipped", file=sys.stderr)
            continue
        run_dir = tel_file.parent
        metrics_file = run_dir / "run_metrics.json"
        metrics = json.loads(metrics_file.read_text(encoding="utf-8")) if metrics_file.exists() else {}
        io_file = run_dir / "io_result.json"
        io_res = json.loads(io_file.read_text(encoding="utf-8")) if io_file.exists() else {}

        # Backfill errored MCP / tool metrics from archived session_stream.jsonl if older artifacts lacked them.
        stream_file = run_dir / "session_stream.jsonl"
        stream_parsed = None
        if stream_file.exists() and (
            "mcp_calls_errored" not in metrics or "mcp_calls_errored" not in tel
        ):
            with stream_file.open(encoding="utf-8") as sf:
                stream_parsed = parse_stream(sf, mcp_server)

        src = stream_parsed or metrics or tel
        tok = dict(tel.get("tokens") or src.get("tokens") or {})
        in_u = tok.get("input_uncached", 0)
        in_c = tok.get("input_cached", 0)
        think = tok.get("reasoning", 0)
        out = tok.get("output", 0)
        total_in = in_u + in_c
        total_tok = total_in + think + out
        tok["total_input"] = total_in
        tok["total"] = total_tok

        cost_usd = compute_token_cost(tok, pricing)
        mcp_ok = src.get("mcp_calls_succeeded", tel.get("mcp_calls_succeeded", src.get("mcp_calls", tel.get("mcp_calls", 0))))
        mcp_err = src.get("mcp_calls_errored", tel.get("mcp_calls_errored", 0))
        mcp_total = mcp_ok + mcp_err
        other_ok = src.get("other_tool_calls_succeeded", tel.get("other_tool_calls_succeeded", src.get("other_tool_calls", 0)))
        other_err = src.get("other_tool_calls_errored", tel.get("other_tool_calls_errored", 0))
        other_total = src.get("other_tool_calls", other_ok + other_err)

        bstats = (
            tel.get("binary_stats")
            or metrics.get("binary_stats")
            or (load_binary_stats(config, tel["scenario"], tel["sample_id"]) if config else None)
        )
        hook_summary = tel.get("hook_audit") or metrics.get("hook_audit") or summarize_hook_audit(run_dir / "hook_audit.jsonl")
        latency = dict(tel.get("latency") or metrics.get("latency") or (stream_parsed or {}).get("latency") or {})
        if "wall_time_sec" not in latency and tel.get("wall_time_sec") is not None:
            latency["wall_time_sec"] = tel["wall_time_sec"]

        io_breakdown = _extract_io_breakdown(tel, io_res)
        turns = tel.get("turns", src.get("turns"))
        gen_tok = think + out
        peak_ctx = tok.get("peak_context", 0)

        run = dict(tel)
        run.update({
            "tokens": tok,
            "total_input_tokens": total_in,
            "total_tokens": total_tok,
            "cost_usd": cost_usd,
            "run_cost_usd": cost_usd["total"],
            "io_accuracy": (tel["io_tests_passed"] / tel["io_tests_total"]) if tel.get("io_tests_total") else 0.0,
            "io_breakdown": io_breakdown,
            "token_ratios": {
                "cache_hit_ratio": (in_c / total_in) if total_in else 0.0,
                "reasoning_token_ratio": (think / total_tok) if total_tok else 0.0,
                "reasoning_share_of_generated": (think / gen_tok) if gen_tok else 0.0,
                "tokens_per_turn": (total_tok / turns) if turns else None,
                "peak_context_utilization_pct": (peak_ctx / max_ctx_limit * 100.0) if max_ctx_limit else None,
            },
            "mcp_calls": mcp_total,
            "mcp_calls_succeeded": mcp_ok,
            "mcp_calls_errored": mcp_err,
            "mcp_error_rate": (mcp_err / mcp_total) if mcp_total else 0.0,
            "mcp_calls_by_tool": src.get("mcp_calls_by_tool", metrics.get("mcp_calls_by_tool", {})),
            "mcp_calls_errored_by_tool": src.get("mcp_calls_errored_by_tool", metrics.get("mcp_calls_errored_by_tool", {})),
            "mcp_payload_bytes": src.get("mcp_payload_bytes", metrics.get("mcp_payload_bytes")),
            "mcp_error_payload_bytes": src.get("mcp_error_payload_bytes", metrics.get("mcp_error_payload_bytes", 0)),
            "other_tool_calls": other_total,
            "other_tool_calls_succeeded": other_ok,
            "other_tool_calls_errored": other_err,
            "turns": turns,
            "latency": latency,
            "wall_time_sec": tel.get("wall_time_sec") or latency.get("wall_time_sec") or 0.0,
            "hook_audit": hook_summary,
            "binary_stats": bstats,
            "terminated_reason": tel.get("terminated_reason") or metrics.get("terminated_reason"),
        })
        runs.append(run)
    return runs


# ----------------------------------------------------------------------------- aggregation
def _aggregate_binary_complexity(rs: list[dict], base_stats: Optional[dict]) -> Optional[dict]:
    stats_list = [r["binary_stats"] for r in rs if isinstance(r.get("binary_stats"), dict)]
    if not stats_list:
        return None
    text_m = statistics.fmean(s["text_bytes"] for s in stats_list if "text_bytes" in s)
    ins_m = statistics.fmean(s["instructions"] for s in stats_list if "instructions" in s)
    jcc_m = statistics.fmean(s["conditional_jumps"] for s in stats_list if "conditional_jumps" in s)
    ind_m = statistics.fmean(s["indirect_jumps"] for s in stats_list if "indirect_jumps" in s)
    bb_m = statistics.fmean(s["basic_block_estimate"] for s in stats_list if "basic_block_estimate" in s)
    cc_m = statistics.fmean(s["cyclomatic_complexity_est"] for s in stats_list if "cyclomatic_complexity_est" in s)
    sz_m = statistics.fmean(s["file_size_bytes"] for s in stats_list if "file_size_bytes" in s)
    return {
        "file_size_bytes_mean": sz_m,
        "text_bytes_mean": text_m,
        "text_bytes_ratio_vs_s0": ratio(text_m, base_stats["text_bytes_mean"]) if base_stats else 1.0,
        "instructions_mean": ins_m,
        "instructions_ratio_vs_s0": ratio(ins_m, base_stats["instructions_mean"]) if base_stats else 1.0,
        "conditional_jumps_mean": jcc_m,
        "indirect_jumps_mean": ind_m,
        "basic_block_estimate_mean": bb_m,
        "cyclomatic_complexity_mean": cc_m,
    }


def aggregate(runs: list[dict], config: dict) -> dict:
    pricing = config["evaluation"]["cost_telemetry"]["pricing_per_1m_tokens_usd"]
    max_ctx_limit = config.get("agent_runtime", {}).get("limits", {}).get("max_context_tokens") or 128000
    order = list(config["scenarios"])
    grouped: dict[str, list[dict]] = {sc: [] for sc in order}
    for r in runs:
        grouped.setdefault(r["scenario"], []).append(r)
    base_key = order[0]
    base_runs = grouped.get(base_key, [])
    base_by_sample = {r["sample_id"]: r for r in base_runs}
    base_pass = ratio(sum(r["io_passed"] for r in base_runs), len(base_runs)) if base_runs else None
    base_avg_total = (sum(r["total_tokens"] for r in base_runs) / len(base_runs)) if base_runs else None
    base_avg_cost = (sum(r["run_cost_usd"] for r in base_runs) / len(base_runs)) if base_runs else None
    base_bin_stats = _aggregate_binary_complexity(base_runs, None) if base_runs else None

    summary: dict[str, dict] = {}
    for sc, rs in grouped.items():
        if not rs:
            continue
        n = len(rs)
        passes = sum(1 for r in rs if r["io_passed"])
        tok = lambda key: [r["tokens"].get(key, 0) for r in rs]  # noqa: E731
        in_cache = [r["total_input_tokens"] for r in rs]
        total_cost = sum(r["run_cost_usd"] for r in rs)
        total_tokens = sum(r["total_tokens"] for r in rs)

        def ocm(subset: list[dict]) -> dict:
            vals_t, vals_m, vals_c, vals_turns = [], [], [], []
            for r in subset:
                b = base_by_sample.get(r["sample_id"])
                if not b or sc == base_key:
                    continue
                t = ratio(r["total_tokens"], b["total_tokens"])
                m = ratio(r["mcp_calls"], b["mcp_calls"])
                c = ratio(r["run_cost_usd"], b["run_cost_usd"])
                tr = ratio(r.get("turns"), b.get("turns"))
                if t is not None:
                    vals_t.append(t)
                if m is not None:
                    vals_m.append(m)
                if c is not None:
                    vals_c.append(c)
                if tr is not None:
                    vals_turns.append(tr)
            return {
                "tokens_mean": statistics.fmean(vals_t) if vals_t else None,
                "tokens_median": statistics.median(vals_t) if vals_t else None,
                "tools_mean": statistics.fmean(vals_m) if vals_m else None,
                "cost_usd_mean": statistics.fmean(vals_c) if vals_c else None,
                "turns_mean": statistics.fmean(vals_turns) if vals_turns else None,
                "n": len(vals_t),
            }

        is_base = sc == base_key
        ocm_all = {"tokens_mean": 1.0, "tokens_median": 1.0, "tools_mean": 1.0,
                   "cost_usd_mean": 1.0, "turns_mean": 1.0, "n": n} if is_base else ocm(rs)
        ocm_pass = {"tokens_mean": 1.0, "tokens_median": 1.0, "tools_mean": 1.0,
                    "cost_usd_mean": 1.0, "turns_mean": 1.0, "n": passes} if is_base \
            else ocm([r for r in rs if r["io_passed"]])

        avg_total = total_tokens / n
        avg_cost = total_cost / n
        acc_m, acc_sd = mean_sd([r["io_accuracy"] for r in rs])
        in_med = median_iqr(in_cache)
        th_med = median_iqr(tok("reasoning"))
        peaks = tok("peak_context")
        mcp = [r["mcp_calls"] for r in rs]
        mcp_m, mcp_sd = mean_sd(mcp)
        mcp_ok_sum = sum(r["mcp_calls_succeeded"] for r in rs)
        mcp_err_sum = sum(r["mcp_calls_errored"] for r in rs)
        mcp_tot_sum = mcp_ok_sum + mcp_err_sum

        tool_sum: Counter = Counter()
        tool_err_sum: Counter = Counter()
        for r in rs:
            tool_sum.update(r.get("mcp_calls_by_tool") or {})
            tool_err_sum.update(r.get("mcp_calls_errored_by_tool") or {})

        # I/O Gate breakdown
        g1_compile = [1.0 if r["io_breakdown"].get("compile_ok") else 0.0 for r in rs]
        cur_ratios = [
            ratio(r["io_breakdown"].get("curated_passed"), r["io_breakdown"].get("curated_total"))
            for r in rs if r["io_breakdown"].get("curated_total")
        ]
        fuzz_ratios = [
            ratio(r["io_breakdown"].get("fuzz_passed"), r["io_breakdown"].get("fuzz_total"))
            for r in rs if r["io_breakdown"].get("fuzz_total")
        ]

        # Cost component means
        c_in_u = statistics.fmean(r["cost_usd"]["input_uncached"] for r in rs)
        c_in_c = statistics.fmean(r["cost_usd"]["input_cached"] for r in rs)
        c_think = statistics.fmean(r["cost_usd"]["reasoning"] for r in rs)
        c_out = statistics.fmean(r["cost_usd"]["output"] for r in rs)

        # Latency means
        wall_m = statistics.fmean(r["wall_time_sec"] for r in rs)
        llm_t_m = _mean_present([r["latency"].get("llm_time_sec") for r in rs])
        mcp_t_m = _mean_present([r["latency"].get("mcp_time_sec") for r in rs])
        oth_t_m = _mean_present([r["latency"].get("other_tool_time_sec") for r in rs])

        # Hook / runtime probe stats
        hook_runs = [r["hook_audit"] for r in rs if isinstance(r.get("hook_audit"), dict)]
        bin_comp = base_bin_stats if is_base else _aggregate_binary_complexity(rs, base_bin_stats)

        payload_m = _mean_present([r.get("mcp_payload_bytes") for r in rs])
        turns_vals = [r["turns"] for r in rs if r.get("turns") is not None]
        turns_m = statistics.fmean(turns_vals) if turns_vals else None
        sum_in_cached = sum(tok("input_cached"))
        sum_in_total = sum(in_cache)
        sum_think = sum(tok("reasoning"))
        sum_gen = sum_think + sum(tok("output"))

        summary[sc] = {
            "samples": n,
            "passes": passes,
            "io_pass_rate": passes / n,
            "io_pass_delta_vs_S0_pct": None if is_base or base_pass is None else (passes / n - base_pass) * 100,
            "io_accuracy_mean": acc_m,
            "io_accuracy_sd": acc_sd,
            "gate1_compile_pass_rate": statistics.fmean(g1_compile),
            "curated_accuracy_mean": statistics.fmean(cur_ratios) if cur_ratios else None,
            "fuzz_accuracy_mean": statistics.fmean(fuzz_ratios) if fuzz_ratios else None,
            "curated_passed_sum": sum(r["io_breakdown"].get("curated_passed") or 0 for r in rs),
            "curated_total_sum": sum(r["io_breakdown"].get("curated_total") or 0 for r in rs),
            "fuzz_passed_sum": sum(r["io_breakdown"].get("fuzz_passed") or 0 for r in rs),
            "fuzz_total_sum": sum(r["io_breakdown"].get("fuzz_total") or 0 for r in rs),
            "input_plus_cache_tokens": {"median": in_med[0], "q1": in_med[1], "q3": in_med[2]},
            "reasoning_tokens": {"median": th_med[0], "q1": th_med[1], "q3": th_med[2]},
            "peak_context": {"max": max(peaks), "median": statistics.median(peaks)},
            "peak_context_limit": max_ctx_limit,
            "peak_context_utilization_max_pct": (max(peaks) / max_ctx_limit * 100.0) if max_ctx_limit else None,
            "mcp_calls": {"mean": mcp_m, "sd": mcp_sd},
            "mcp_calls_succeeded_mean": mcp_ok_sum / n,
            "mcp_calls_errored_mean": mcp_err_sum / n,
            "mcp_calls_errored_total": mcp_err_sum,
            "mcp_error_rate": (mcp_err_sum / mcp_tot_sum) if mcp_tot_sum else 0.0,
            "mcp_calls_by_tool_sum": dict(tool_sum),
            "mcp_calls_errored_by_tool_sum": dict(tool_err_sum),
            "mcp_payload_bytes_mean": payload_m,
            "other_tool_calls_mean": statistics.fmean(r["other_tool_calls"] for r in rs),
            "other_tool_calls_errored_mean": statistics.fmean(r["other_tool_calls_errored"] for r in rs),
            "turns_mean": turns_m,
            "turns_median": statistics.median(turns_vals) if turns_vals else None,
            "wall_time_mean_sec": wall_m,
            "llm_time_mean_sec": llm_t_m,
            "mcp_time_mean_sec": mcp_t_m,
            "other_tool_time_mean_sec": oth_t_m,
            "llm_time_share_pct": (llm_t_m / wall_m * 100.0) if (llm_t_m is not None and wall_m) else None,
            "cache_hit_ratio": (sum_in_cached / sum_in_total) if sum_in_total else 0.0,
            "reasoning_token_ratio": ratio(sum_think, total_tokens),
            "reasoning_share_of_generated": ratio(sum_think, sum_gen),
            "tokens_per_turn_mean": ratio(avg_total, turns_m),
            "ocm_all": ocm_all,
            "ocm_pass_only": ocm_pass,
            "ocm_tokens": ratio(avg_total, base_avg_total) if base_avg_total else None,
            "ocm_cost_usd": ratio(avg_cost, base_avg_cost) if base_avg_cost else None,
            "ocm_tools": ocm_all["tools_mean"],
            "ocm_turns": ocm_all["turns_mean"],
            "avg_input_uncached": statistics.fmean(tok("input_uncached")),
            "avg_input_cached": statistics.fmean(tok("input_cached")),
            "avg_input_tokens": statistics.fmean(in_cache),
            "avg_reasoning_tokens": statistics.fmean(tok("reasoning")),
            "avg_output_tokens": statistics.fmean(tok("output")),
            "avg_total_tokens": avg_total,
            "avg_mcp_calls": mcp_m,
            "avg_cost_input_uncached_usd": c_in_u,
            "avg_cost_input_cached_usd": c_in_c,
            "avg_cost_reasoning_usd": c_think,
            "avg_cost_output_usd": c_out,
            "avg_run_cost_usd": avg_cost,
            "total_suite_cost_usd": total_cost,
            "ecsr_usd": ratio(total_cost, passes),
            "ecsr_tokens": ratio(total_tokens, passes),
            "hook_allows_total": sum(h["allow"] for h in hook_runs) if hook_runs else None,
            "hook_denies_total": sum(h["deny"] for h in hook_runs) if hook_runs else None,
            "chal_exec_calls_mean": statistics.fmean(h["chal_exec_calls"] for h in hook_runs) if hook_runs else None,
            "chal_exec_pre_write_mean": statistics.fmean(h["chal_exec_pre_write"] for h in hook_runs) if hook_runs else None,
            "binary_complexity": bin_comp,
            "tokens_per_text_byte": ratio(avg_total, bin_comp["text_bytes_mean"]) if bin_comp else None,
            "cost_per_instruction_usd": ratio(avg_cost, bin_comp["instructions_mean"]) if bin_comp else None,
            "terminations": {k: sum(1 for r in rs if r.get("terminated_reason") == k)
                             for k in sorted({r.get("terminated_reason") for r in rs if r.get("terminated_reason")})},
        }
    return {
        "pricing": pricing,
        "max_context_tokens": max_ctx_limit,
        "scenario_order": order,
        "scenarios": summary,
        "runs": runs,
    }


# ----------------------------------------------------------------------------- reporting
def _f(x, spec=".2f", dash="-"):
    return dash if x is None or (isinstance(x, float) and x != x) else format(x, spec)


def markdown_table(summary: dict) -> str:
    """Render comprehensive Markdown tables covering I/O equivalence, dollar costs, MCP errors, and obfuscation impact."""
    sc = summary["scenarios"]
    names = [s for s in summary["scenario_order"] if s in sc]
    has_bin = any(sc[n].get("binary_complexity") for n in names)
    has_lat = any(sc[n].get("llm_time_mean_sec") is not None for n in names)
    has_hook = any(sc[n].get("chal_exec_calls_mean") is not None for n in names)

    rows = [
        ("I/O Pass Rate Pass_IO (%)", lambda m: (f"{m['io_pass_rate']*100:.1f}" if m["io_pass_delta_vs_S0_pct"] is None
                                                  else f"{m['io_pass_rate']*100:.1f} ({m['io_pass_delta_vs_S0_pct']:+.1f} pp vs S0)")),
        ("Partial Test Accuracy Acc_IO (%)", lambda m: f"{m['io_accuracy_mean']*100:.1f} ± {m['io_accuracy_sd']*100:.1f}"),
        ("Gate Breakdown (Compile / Curated / Fuzz)", lambda m: (
            f"{m['gate1_compile_pass_rate']*100:.0f}% / "
            f"{_f(m['curated_accuracy_mean']*100 if m['curated_accuracy_mean'] is not None else None, '.0f')}% / "
            f"{_f(m['fuzz_accuracy_mean']*100 if m['fuzz_accuracy_mean'] is not None else None, '.0f')}%"
        )),
        ("Avg Run Cost (USD)", lambda m: f"${m['avg_run_cost_usd']:.4f}"),
        ("USD Cost Breakdown (In / Cache / Think / Out)", lambda m: (
            f"${m['avg_cost_input_uncached_usd']:.4f} / ${m['avg_cost_input_cached_usd']:.4f} / "
            f"${m['avg_cost_reasoning_usd']:.4f} / ${m['avg_cost_output_usd']:.4f}"
        )),
        ("ECSR (USD per successful break)", lambda m: "∞ (no successes)" if m["ecsr_usd"] is None else f"${m['ecsr_usd']:.4f}"),
        ("ECSR (tokens per successful break)", lambda m: "∞" if m["ecsr_tokens"] is None else f"{m['ecsr_tokens']:,.0f}"),
        ("OCM_cost (USD ratio vs S0)", lambda m: _f(m["ocm_cost_usd"]) + "×"),
        ("OCM_tokens, all samples (mean of ratios)", lambda m: _f(m["ocm_all"]["tokens_mean"]) + "×"),
        ("OCM_tokens, successful breaks only", lambda m: _f(m["ocm_pass_only"]["tokens_mean"]) + "×"),
        ("OCM_tools, all samples", lambda m: _f(m["ocm_all"]["tools_mean"]) + "×"),
        ("Input + Cache Tokens (median / IQR)", lambda m: "{} / {}–{}".format(*(f"{m['input_plus_cache_tokens'][k]:,.0f}" for k in ("median", "q1", "q3")))),
        ("Context Cache Hit Rate (%)", lambda m: f"{m['cache_hit_ratio']*100:.1f}%"),
        ("Reasoning Tokens T_think (median / IQR)", lambda m: "{} / {}–{}".format(*(f"{m['reasoning_tokens'][k]:,.0f}" for k in ("median", "q1", "q3")))),
        ("Reasoning Share of Generated Tokens (%)", lambda m: _f((m["reasoning_share_of_generated"] or 0.0) * 100, ".1f") + "%"),
        ("Peak Context T_peak (max / % limit)", lambda m: (
            f"{m['peak_context']['max']:,.0f} ({_f(m['peak_context_utilization_max_pct'], '.1f')}%)"
        )),
        ("Reasoning Turns (mean / median)", lambda m: f"{_f(m['turns_mean'], '.1f')} / {_f(m['turns_median'], '.1f')}"),
        ("REA MCP Calls Attempted (mean ± SD)", lambda m: f"{m['mcp_calls']['mean']:.1f} ± {m['mcp_calls']['sd']:.1f}"),
        ("REA MCP Succeeded / Errored (err rate)", lambda m: (
            f"{m['mcp_calls_succeeded_mean']:.1f} / {m['mcp_calls_errored_mean']:.1f} "
            f"(total err={m['mcp_calls_errored_total']}, {m['mcp_error_rate']*100:.1f}%)"
        )),
        ("MCP Payload Volume (mean bytes)", lambda m: "-" if m["mcp_payload_bytes_mean"] is None else f"{m['mcp_payload_bytes_mean']:,.0f} B"),
        ("Local Non-MCP Tools (ok / err mean)", lambda m: (
            f"{m['other_tool_calls_mean'] - m['other_tool_calls_errored_mean']:.1f} / {m['other_tool_calls_errored_mean']:.1f}"
        )),
    ]
    if has_lat:
        rows.append(("Wall Time Mean (LLM / MCP s)", lambda m: (
            f"{m['wall_time_mean_sec']:.1f}s ({_f(m['llm_time_mean_sec'], '.1f')}s / {_f(m['mcp_time_mean_sec'], '.1f')}s)"
        )))
    if has_hook:
        rows.append(("Runtime ./chal Probes (total / pre-write)", lambda m: (
            f"{_f(m['chal_exec_calls_mean'], '.1f')} / {_f(m['chal_exec_pre_write_mean'], '.1f')}"
        )))
    if has_bin:
        rows.extend([
            ("Binary .text Size (bytes / ratio vs S0)", lambda m: (
                f"{m['binary_complexity']['text_bytes_mean']:,.0f} B ({_f(m['binary_complexity']['text_bytes_ratio_vs_s0'])}×)"
                if m.get("binary_complexity") else "-"
            )),
            ("Binary Instructions (count / ratio vs S0)", lambda m: (
                f"{m['binary_complexity']['instructions_mean']:,.0f} ({_f(m['binary_complexity']['instructions_ratio_vs_s0'])}×)"
                if m.get("binary_complexity") else "-"
            )),
            ("Indirect Jumps / Cond Branches / Cyc. Est", lambda m: (
                f"{m['binary_complexity']['indirect_jumps_mean']:.1f} / "
                f"{m['binary_complexity']['conditional_jumps_mean']:.1f} / "
                f"{m['binary_complexity']['cyclomatic_complexity_mean']:.1f}"
                if m.get("binary_complexity") else "-"
            )),
            ("Amplification (Tokens per .text Byte)", lambda m: (
                f"{m['tokens_per_text_byte']:,.0f}" if m.get("tokens_per_text_byte") is not None else "-"
            )),
        ])
    rows.append(("Runs (n) / Suite Cost (USD)", lambda m: f"{m['samples']} / ${m['total_suite_cost_usd']:.4f}"))

    out = ["| Metric | " + " | ".join(names) + " |", "| :--- | " + " | ".join(":---" for _ in names) + " |"]
    for label, fn in rows:
        out.append(f"| {label} | " + " | ".join(fn(sc[n]) for n in names) + " |")
    return "\n".join(out)


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Code Protection vs. AI Analysis — Cost &amp; Accuracy Report</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b1120;
      --surface: #131c31;
      --surface-alt: #19243e;
      --border: #29354d;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-soft: rgba(56, 189, 248, 0.14);
      --ok: #22c55e;
      --warn: #f59e0b;
      --err: #ef4444;
      --c-in-new: #38bdf8;
      --c-in-cache: #6366f1;
      --c-think: #c084fc;
      --c-out: #22c55e;
      --c-pass: #10b981;
      --c-err: #f43f5e;
      --radius: 12px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: clamp(16px, 3vw, 28px);
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    .page {
      max-inline-size: 1220px;
      margin-inline: auto;
      display: grid;
      gap: 20px;
    }
    header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      border-block-end: 1px solid var(--border);
      padding-block-end: 16px;
    }
    h1 { font-size: clamp(1.35rem, 2.2vw, 1.8rem); margin: 0 0 6px; letter-spacing: -0.01em; }
    h2 { font-size: 1.05rem; margin: 0 0 8px; }
    h3 { font-size: 0.95rem; margin: 0 0 6px; }
    .subtitle { margin: 0; color: var(--text-muted); font-size: 0.92rem; max-inline-size: 72ch; }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 0.82rem;
      font-weight: 600;
      background: rgba(34, 197, 94, 0.14);
      border: 1px solid rgba(34, 197, 94, 0.35);
      color: #86efac;
      white-space: nowrap;
    }
    .status-pill[data-mode="projected"] {
      background: rgba(245, 158, 11, 0.15);
      border-color: rgba(245, 158, 11, 0.4);
      color: #fde68a;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 12px;
    }
    .view-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      min-inline-size: 0;
    }
    .tab-btn {
      appearance: none;
      background: var(--surface-alt);
      color: var(--text-muted);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 13px;
      font: inherit;
      font-size: 0.86rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
    }
    .tab-btn:hover { color: var(--text); border-color: #475569; }
    .tab-btn[aria-pressed="true"] {
      background: var(--accent-soft);
      color: #e0f2fe;
      border-color: var(--accent);
    }
    .reset-btn {
      appearance: none;
      background: transparent;
      color: var(--text-muted);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 7px 12px;
      font: inherit;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
    }
    .reset-btn:hover:not(:disabled) { color: var(--text); border-color: var(--accent); }
    .reset-btn:disabled { opacity: 0.45; cursor: default; }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(235px, 1fr));
      gap: 12px;
    }
    .kpi-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-inline-start: 4px solid var(--card-accent, var(--accent));
      border-radius: var(--radius);
      padding: 14px 16px;
      display: grid;
      gap: 6px;
    }
    .kpi-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
    }
    .kpi-name { font-size: 0.92rem; font-weight: 700; color: var(--text); }
    .badge {
      font-size: 0.74rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 999px;
      white-space: nowrap;
    }
    .badge-ok { background: rgba(34, 197, 94, 0.16); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.35); }
    .badge-warn { background: rgba(245, 158, 11, 0.16); color: #fde68a; border: 1px solid rgba(245, 158, 11, 0.35); }
    .badge-err { background: rgba(239, 68, 68, 0.16); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.35); }
    .kpi-primary { font-size: 1.5rem; font-weight: 800; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
    .kpi-meta { font-size: 0.82rem; color: var(--text-muted); font-variant-numeric: tabular-nums; }
    .kpi-sub { font-size: 0.78rem; color: #cbd5e1; border-block-start: 1px solid rgba(148,163,184,0.16); padding-block-start: 6px; }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 18px;
      min-inline-size: 0;
    }
    .chart-header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: baseline;
      gap: 8px 16px;
      margin-block-end: 10px;
    }
    .chart-desc { margin: 0; color: var(--text-muted); font-size: 0.86rem; }
    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 10px 18px;
      margin-block: 10px 12px;
      font-size: 0.82rem;
      color: #cbd5e1;
    }
    .legend-item { display: inline-flex; align-items: center; gap: 7px; }
    .swatch { inline-size: 12px; block-size: 12px; border-radius: 3px; display: inline-block; flex-shrink: 0; }
    .svg-wrap { inline-size: 100%; overflow-x: auto; }
    svg.chart-svg { display: block; inline-size: 100%; block-size: auto; min-inline-size: 560px; }
    .readout {
      margin-block-start: 12px;
      padding: 10px 14px;
      border-radius: 8px;
      background: var(--surface-alt);
      border: 1px solid var(--border);
      font-size: 0.85rem;
      color: #e2e8f0;
      font-variant-numeric: tabular-nums;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 8px;
    }
    .two-col {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }
    .bar-list { display: grid; gap: 10px; margin-block-start: 10px; }
    .meter-row { display: grid; gap: 4px; }
    .meter-label { display: flex; justify-content: space-between; font-size: 0.83rem; font-variant-numeric: tabular-nums; }
    .meter-track {
      inline-size: 100%;
      block-size: 10px;
      background: #0b1120;
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    .meter-fill { block-size: 100%; border-radius: 999px; transition: width 0.2s ease; }

    details.whatif {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 12px 16px;
    }
    details.whatif summary {
      cursor: pointer;
      font-weight: 700;
      font-size: 0.94rem;
      color: #e2e8f0;
    }
    .controls-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 14px;
      margin-block-start: 14px;
    }
    .control-field {
      background: var(--surface-alt);
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      display: grid;
      gap: 6px;
    }
    .control-field label {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      font-size: 0.82rem;
      color: #cbd5e1;
    }
    .control-field input[type="range"] { inline-size: 100%; accent-color: var(--accent); }
    .control-field input[type="number"] {
      inline-size: 100%;
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 8px;
      font: inherit;
      font-size: 0.86rem;
    }

    .table-wrapper {
      overflow: auto;
      max-inline-size: 100%;
      max-block-size: 560px;
      border: 1px solid var(--border);
      border-radius: 8px;
      container-type: inline-size;
    }
    table {
      inline-size: 100%;
      border-collapse: separate;
      border-spacing: 0;
      font-size: 0.83rem;
      font-variant-numeric: tabular-nums;
    }
    caption {
      text-align: start;
      padding: 10px 12px;
      font-weight: 700;
      color: var(--text);
      background: var(--surface-alt);
      border-block-end: 1px solid var(--border);
    }
    thead th {
      position: sticky;
      inset-block-start: 0;
      z-index: 2;
      background: #1a2642;
      color: #e2e8f0;
      text-align: end;
      padding: 10px 12px;
      border-block-end: 1px solid var(--border);
      white-space: nowrap;
    }
    thead th:first-child { text-align: start; inset-inline-start: 0; z-index: 3; }
    tbody th {
      position: sticky;
      inset-inline-start: 0;
      z-index: 1;
      background: var(--surface);
      text-align: start;
      padding: 9px 12px;
      border-block-end: 1px solid rgba(41, 53, 77, 0.7);
      font-weight: 600;
      white-space: nowrap;
    }
    tbody td {
      text-align: end;
      padding: 9px 12px;
      border-block-end: 1px solid rgba(41, 53, 77, 0.7);
      white-space: nowrap;
    }
    tbody tr:hover th, tbody tr:hover td { background: rgba(56, 189, 248, 0.06); }
    .row-highlight { color: #fde68a; font-weight: 700; }
    .row-err { color: #fda4af; font-weight: 700; }
    .row-ok { color: #86efac; font-weight: 700; }
    .insights-list { margin: 8px 0 0; padding-inline-start: 18px; display: grid; gap: 6px; font-size: 0.86rem; color: #cbd5e1; }
    footer { color: var(--text-muted); font-size: 0.8rem; text-align: center; padding-block: 4px 12px; }
  </style>
</head>
<body>
<div class="page">
  <header>
    <div>
      <h1>Code Protection vs. AI Analysis — Cost &amp; Accuracy Report</h1>
      <p class="subtitle" id="pricingSubtitle"></p>
    </div>
    <div class="status-pill" id="modeBadge" data-mode="measured">Viewing Measured Results</div>
  </header>

  <main class="page" style="padding:0;">
    <section class="toolbar" aria-label="Chart view selector">
      <div class="view-tabs" id="viewTabs" role="group" aria-label="Report views">
        <button type="button" class="tab-btn" data-view="cost_usd" aria-pressed="true">Dollar Cost ($ USD)</button>
        <button type="button" class="tab-btn" data-view="io" aria-pressed="false">Accuracy &amp; Tests (%)</button>
        <button type="button" class="tab-btn" data-view="tokens" aria-pressed="false">Tokens &amp; Memory</button>
        <button type="button" class="tab-btn" data-view="effort" aria-pressed="false">Steps, Tool Calls &amp; Time</button>
        <button type="button" class="tab-btn" data-view="obfuscation" aria-pressed="false">Why Cost Grows</button>
      </div>
      <button type="button" class="reset-btn" id="resetBtn" disabled>Reset to Measured Results</button>
    </section>

    <section class="kpi-grid" id="kpiRow" aria-label="Scenario summary cards"></section>

    <section class="card" aria-labelledby="chartTitle">
      <div class="chart-header">
        <div>
          <h2 id="chartTitle">Dollar Cost per Program ($ USD)</h2>
          <p class="chart-desc" id="chartDesc"></p>
        </div>
      </div>
      <div class="legend" id="chartLegend"></div>
      <div class="svg-wrap" id="chartContainer"></div>
      <div class="readout" id="chartReadout" aria-live="polite">
        <span>Hover or focus any protection group to inspect exact values.</span>
      </div>
    </section>

    <section class="two-col" aria-label="Cost drivers and explanation">
      <article class="card">
        <h2 id="panelLeftTitle">Where Every Dollar Goes</h2>
        <p class="chart-desc" id="panelLeftDesc"></p>
        <div class="bar-list" id="panelLeftBody"></div>
      </article>
      <article class="card">
        <h2 id="panelRightTitle">How Protection Explains These Numbers</h2>
        <p class="chart-desc" id="panelRightDesc"></p>
        <ul class="insights-list" id="panelRightBody"></ul>
      </article>
    </section>

    <details class="whatif" id="whatIfPanel">
      <summary>What-If Simulator: Adjust Pricing Rates or Project Harder Protections</summary>
      <div class="controls-grid">
        <div class="control-field">
          <label for="tokenScale"><span>Extra effort on protected code</span><strong id="scaleVal">1.00×</strong></label>
          <input type="range" id="tokenScale" min="0.5" max="3.0" step="0.05" value="1.0" />
        </div>
        <div class="control-field">
          <label for="passOverride"><span>Pass rate on hardest protection</span><strong id="passVal">Measured</strong></label>
          <input type="range" id="passOverride" min="0" max="1" step="0.05" value="1" />
        </div>
        <div class="control-field">
          <label for="priceUncached"><span>New input price ($ per 1M tokens)</span></label>
          <input type="number" id="priceUncached" min="0" step="0.01" />
        </div>
        <div class="control-field">
          <label for="priceCached"><span>Cached context price ($ per 1M tokens)</span></label>
          <input type="number" id="priceCached" min="0" step="0.0025" />
        </div>
        <div class="control-field">
          <label for="priceOutput"><span>Thinking &amp; output price ($ per 1M tokens)</span></label>
          <input type="number" id="priceOutput" min="0" step="0.05" />
        </div>
      </div>
    </details>

    <section class="card" aria-labelledby="comparison-table-caption">
      <div tabindex="0" role="region" aria-labelledby="comparison-table-caption" class="table-wrapper">
        <table>
          <caption id="comparison-table-caption">Full Measured Comparison Across All Protection Levels</caption>
          <thead id="detailHead"></thead>
          <tbody id="detailBody"></tbody>
        </table>
      </div>
    </section>
  </main>

  <footer>Generated automatically from recorded benchmark logs — works 100% offline with zero external dependencies.</footer>
</div>

<script>
const BENCHMARK_DATA = __BENCHMARK_JSON__;
const FRIENDLY_NAMES = {
  S0_Baseline: "No Protection (Baseline)",
  S1_Flatten: "Control-Flow Flattening",
  S2_EncodeData: "Data & Math Encoding",
  S3_Combined: "Combined Protection"
};
const labels = BENCHMARK_DATA.scenario_order.filter(k => BENCHMARK_DATA.scenarios[k]);
const lastKey = labels[labels.length - 1];
const measuredPricing = BENCHMARK_DATA.pricing;
const maxCtxLimit = BENCHMARK_DATA.max_context_tokens || 128000;
const measuredLastPass = BENCHMARK_DATA.scenarios[lastKey] ? BENCHMARK_DATA.scenarios[lastKey].io_pass_rate : 1.0;

let activeView = "cost_usd";
let touchedPass = false;

const scaleEl = document.getElementById("tokenScale");
const passEl = document.getElementById("passOverride");
const pUncachedEl = document.getElementById("priceUncached");
const pCachedEl = document.getElementById("priceCached");
const pOutputEl = document.getElementById("priceOutput");
const resetBtn = document.getElementById("resetBtn");

function initInputs() {
  scaleEl.value = "1.0";
  passEl.value = String(measuredLastPass);
  pUncachedEl.value = String(measuredPricing.input_uncached);
  pCachedEl.value = String(measuredPricing.input_cached);
  pOutputEl.value = String(measuredPricing.output_and_reasoning);
  touchedPass = false;
}
initInputs();

function friendly(key) {
  return FRIENDLY_NAMES[key] || key.replace(/^S\d+_/, "").replaceAll("_", " ");
}
function fmtUsd(v) {
  if (v === null || v === undefined || Number.isNaN(v)) return "No passes (∞)";
  return "$" + v.toFixed(v >= 1 ? 2 : 4);
}
function fmtInt(v) {
  if (v === null || v === undefined || Number.isNaN(v)) return "-";
  return Math.round(v).toLocaleString("en-US");
}
function fmtCompact(v) {
  if (v >= 1e6) return (v / 1e6).toFixed(2) + "M";
  if (v >= 1e3) return (v / 1e3).toFixed(1) + "k";
  return String(Math.round(v));
}
function isProjected() {
  return Math.abs(parseFloat(scaleEl.value) - 1.0) > 1e-6 ||
    touchedPass ||
    Math.abs(parseFloat(pUncachedEl.value) - measuredPricing.input_uncached) > 1e-6 ||
    Math.abs(parseFloat(pCachedEl.value) - measuredPricing.input_cached) > 1e-6 ||
    Math.abs(parseFloat(pOutputEl.value) - measuredPricing.output_and_reasoning) > 1e-6;
}

function activePricing() {
  const num = (el, fallback) => {
    const v = parseFloat(el.value);
    return Number.isFinite(v) && v >= 0 ? v : fallback;
  };
  return {
    input_uncached: num(pUncachedEl, measuredPricing.input_uncached),
    input_cached: num(pCachedEl, measuredPricing.input_cached),
    output_and_reasoning: num(pOutputEl, measuredPricing.output_and_reasoning)
  };
}

function getRows() {
  const scale = parseFloat(scaleEl.value) || 1.0;
  const lastPass = parseFloat(passEl.value);
  const pr = activePricing();
  document.getElementById("scaleVal").textContent = scale.toFixed(2) + "×";
  document.getElementById("passVal").textContent = touchedPass
    ? Math.round(lastPass * 100) + "%"
    : "Measured (" + Math.round(measuredLastPass * 100) + "%)";
  document.getElementById("pricingSubtitle").textContent =
    `Rates per 1M tokens: $${pr.input_uncached.toFixed(2)} new input, $${pr.input_cached.toFixed(4)} cached context, $${pr.output_and_reasoning.toFixed(2)} thinking & output.`;

  const base = BENCHMARK_DATA.scenarios[labels[0]];
  const baseRunCostAtPr = (
    base.avg_input_uncached * pr.input_uncached +
    base.avg_input_cached * pr.input_cached +
    (base.avg_reasoning_tokens + base.avg_output_tokens) * pr.output_and_reasoning
  ) / 1e6;

  return labels.map((key, idx) => {
    const sc = BENCHMARK_DATA.scenarios[key];
    const mult = idx === 0 ? 1.0 : scale;
    const passRate = (idx === labels.length - 1 && touchedPass) ? lastPass : sc.io_pass_rate;
    const inU = sc.avg_input_uncached * mult;
    const inC = sc.avg_input_cached * mult;
    const think = sc.avg_reasoning_tokens * mult;
    const out = sc.avg_output_tokens * mult;
    const totalTok = inU + inC + think + out;

    const costInU = inU * pr.input_uncached / 1e6;
    const costInC = inC * pr.input_cached / 1e6;
    const costThink = think * pr.output_and_reasoning / 1e6;
    const costOut = out * pr.output_and_reasoning / 1e6;
    const runCost = costInU + costInC + costThink + costOut;

    const costPerPass = passRate > 0 ? runCost / passRate : null;
    const tokPerPass = passRate > 0 ? totalTok / passRate : null;
    const costMult = baseRunCostAtPr > 0 ? runCost / baseRunCostAtPr : 1.0;
    const tokMult = base.avg_total_tokens > 0 ? totalTok / base.avg_total_tokens : 1.0;

    return {
      key,
      name: friendly(key),
      raw: sc,
      passRate,
      inU, inC, think, out, totalTok,
      costInU, costInC, costThink, costOut, runCost,
      costPerPass, tokPerPass, costMult, tokMult,
      turns: (sc.turns_mean || 0) * mult,
      mcpOk: (sc.mcp_calls_succeeded_mean || 0),
      mcpErr: (sc.mcp_calls_errored_mean || 0),
      mcpTotal: (sc.avg_mcp_calls || 0),
      wallSec: sc.wall_time_mean_sec || 0,
      llmSec: sc.llm_time_mean_sec || 0,
      mcpSec: sc.mcp_time_mean_sec || 0
    };
  });
}

function niceMax(val) {
  if (!val || val <= 0) return 1;
  const pow = Math.pow(10, Math.floor(Math.log10(val)));
  const norm = val / pow;
  const steps = [1, 1.25, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];
  const step = steps.find(s => norm <= s) || 10;
  return step * pow;
}

function escapeXml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderSvgChart(spec) {
  const container = document.getElementById("chartContainer");
  const W = 960, H = 342, padL = 74, padR = 26, padT = 28, padB = 62;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const rawMax = Math.max(...spec.maxValues.filter(v => Number.isFinite(v) && v > 0), spec.minY || 1e-6);
  const yMax = spec.yMax || niceMax(rawMax * 1.15);
  const ticks = 4;

  let svg = `<svg class="chart-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${escapeXml(spec.title)}">`;
  for (let i = 0; i <= ticks; i++) {
    const val = (yMax * i) / ticks;
    const y = padT + plotH - (plotH * i) / ticks;
    svg += `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="#26324a" stroke-dasharray="${i === 0 ? "" : "4 4"}" />`;
    svg += `<text x="${padL - 10}" y="${y + 4}" text-anchor="end" fill="#94a3b8" font-size="11.5">${escapeXml(spec.formatY(val))}</text>`;
  }

  const groupW = plotW / spec.groups.length;
  spec.groups.forEach((g, gi) => {
    const gx = padL + gi * groupW;
    const seriesCount = g.bars.length;
    const innerPad = seriesCount > 3 ? Math.min(12, groupW * 0.06) : Math.min(28, groupW * 0.14);
    const availW = groupW - innerPad * 2;
    const gap = seriesCount > 3 ? 6 : (seriesCount > 1 ? 10 : 0);
    const barW = Math.min(68, (availW - gap * (seriesCount - 1)) / seriesCount);
    const totalBarsW = barW * seriesCount + gap * (seriesCount - 1);
    const startX = gx + (groupW - totalBarsW) / 2;

    svg += `<g class="chart-group" data-group="${gi}" tabindex="0" style="cursor:pointer;">`;
    svg += `<rect x="${gx + 4}" y="${padT - 8}" width="${groupW - 8}" height="${plotH + 12}" rx="8" fill="transparent" class="group-hover-bg" />`;

    g.bars.forEach((bar, bi) => {
      const bx = startX + bi * (barW + gap);
      if (bar.emptyLabel) {
        svg += `<rect x="${bx}" y="${padT + plotH - 22}" width="${barW}" height="22" rx="4" fill="rgba(239,68,68,0.22)" stroke="#ef4444" stroke-dasharray="3 2" />`;
        svg += `<text x="${bx + barW / 2}" y="${padT + plotH - 7}" text-anchor="middle" fill="#fca5a5" font-size="10.5" font-weight="700">${escapeXml(bar.emptyLabel)}</text>`;
        return;
      }
      let curY = padT + plotH;
      const visSegs = bar.segments.filter(s => s.value && s.value > 0);
      visSegs.forEach((seg, si) => {
        const h = Math.max(1.5, (seg.value / yMax) * plotH);
        curY -= h;
        const rx = si === visSegs.length - 1 ? 3 : 0;
        svg += `<rect x="${bx}" y="${curY}" width="${barW}" height="${h}" rx="${rx}" fill="${seg.color}" />`;
      });
      if (bar.topLabel) {
        svg += `<text x="${bx + barW / 2}" y="${Math.max(14, curY - 6)}" text-anchor="middle" fill="#f1f5f9" font-size="${seriesCount > 3 ? "10.5" : "11.5"}" font-weight="700">${escapeXml(bar.topLabel)}</text>`;
      }
      if (bar.subLabel && seriesCount > 1) {
        svg += `<text x="${bx + barW / 2}" y="${padT + plotH + 16}" text-anchor="middle" fill="#94a3b8" font-size="${seriesCount > 3 ? "9.5" : "10.5"}">${escapeXml(bar.subLabel)}</text>`;
      }
    });

    const labelY = spec.groups.some(gr => gr.bars.length > 1) ? padT + plotH + 35 : padT + plotH + 22;
    svg += `<text x="${gx + groupW / 2}" y="${labelY}" text-anchor="middle" fill="#e2e8f0" font-size="12" font-weight="700">${escapeXml(g.label)}</text>`;
    if (g.subLabel) {
      svg += `<text x="${gx + groupW / 2}" y="${labelY + 15}" text-anchor="middle" fill="#94a3b8" font-size="10.5">${escapeXml(g.subLabel)}</text>`;
    }
    svg += `</g>`;
  });
  svg += `</svg>`;
  container.innerHTML = svg;

  const readout = document.getElementById("chartReadout");
  const groups = container.querySelectorAll(".chart-group");
  const activate = idx => {
    container.querySelectorAll(".group-hover-bg").forEach(bg => bg.setAttribute("fill", "transparent"));
    if (groups[idx]) {
      groups[idx].querySelector(".group-hover-bg").setAttribute("fill", "rgba(56,189,248,0.08)");
      readout.innerHTML = `<span>${escapeXml(spec.groups[idx].readout)}</span>`;
    }
  };
  if (groups.length) activate(groups.length - 1);
  groups.forEach(el => {
    const gi = Number(el.dataset.group);
    const show = () => activate(gi);
    el.addEventListener("mouseenter", show);
    el.addEventListener("focus", show);
    el.addEventListener("click", show);
  });
}

function buildViewSpec(rows) {
  const pr = activePricing();
  if (activeView === "cost_usd") {
    return {
      title: "Dollar Cost Breakdown per Program vs. Cost per Passing Run ($ USD)",
      desc: "Left bar shows how much one run costs broken down by token tier. Right bar shows cost per passing run (equal to Left at 100% pass, and higher whenever runs fail).",
      legend: [
        { label: "New Input ($" + pr.input_uncached.toFixed(2) + "/1M)", color: "var(--c-in-new)" },
        { label: "Cached Context ($" + pr.input_cached.toFixed(4) + "/1M)", color: "var(--c-in-cache)" },
        { label: "AI Thinking ($" + pr.output_and_reasoning.toFixed(2) + "/1M)", color: "var(--c-think)" },
        { label: "Final Output ($" + pr.output_and_reasoning.toFixed(2) + "/1M)", color: "var(--c-out)" },
        { label: "Effective Cost / Pass", color: "#f59e0b" }
      ],
      formatY: v => "$" + v.toFixed(v >= 1 ? 2 : 3),
      maxValues: rows.flatMap(r => [r.runCost, r.costPerPass || r.runCost]),
      groups: rows.map(r => ({
        label: r.name,
        subLabel: `${r.costMult.toFixed(2)}× baseline cost`,
        readout: `${r.name}: Run cost $${r.runCost.toFixed(4)} (Cached $${r.costInC.toFixed(4)}, New Input $${r.costInU.toFixed(4)}, Thinking $${r.costThink.toFixed(4)}, Output $${r.costOut.toFixed(4)}) · Effective cost per passing program: ${fmtUsd(r.costPerPass)}`,
        bars: [
          {
            subLabel: "Per Run",
            topLabel: "$" + r.runCost.toFixed(4),
            segments: [
              { value: r.costInC, color: "var(--c-in-cache)" },
              { value: r.costInU, color: "var(--c-in-new)" },
              { value: r.costThink, color: "var(--c-think)" },
              { value: r.costOut, color: "var(--c-out)" }
            ]
          },
          {
            subLabel: "Per Pass",
            emptyLabel: r.costPerPass === null ? "No pass" : null,
            topLabel: r.costPerPass !== null ? "$" + r.costPerPass.toFixed(4) : null,
            segments: r.costPerPass !== null ? [{ value: r.costPerPass, color: "#f59e0b" }] : []
          }
        ]
      }))
    };
  }
  if (activeView === "io") {
    return {
      title: "Program Reconstruction Accuracy & Test Gate Pass Rates (%)",
      desc: "Compares how often rebuilt programs match the original program on boundary edge cases, randomized fuzz tests, and full pass rate.",
      legend: [
        { label: "All Tests Passed (Full Pass)", color: "var(--c-pass)" },
        { label: "Boundary Edge Cases", color: "var(--c-in-new)" },
        { label: "Randomized Input Tests", color: "var(--c-think)" }
      ],
      yMax: 100,
      formatY: v => Math.round(v) + "%",
      maxValues: [100],
      groups: rows.map(r => {
        const cur = r.raw.curated_accuracy_mean != null ? r.raw.curated_accuracy_mean * 100 : r.raw.io_accuracy_mean * 100;
        const fuz = r.raw.fuzz_accuracy_mean != null ? r.raw.fuzz_accuracy_mean * 100 : r.raw.io_accuracy_mean * 100;
        const pass = r.passRate * 100;
        return {
          label: r.name,
          subLabel: `${r.raw.passes}/${r.raw.samples} full pass`,
          readout: `${r.name}: Full Pass Rate ${pass.toFixed(0)}% · Boundary Tests ${cur.toFixed(1)}% · Randomized Tests ${fuz.toFixed(1)}% · Clean Compile ${(r.raw.gate1_compile_pass_rate * 100).toFixed(0)}%`,
          bars: [
            { subLabel: "Full Pass", topLabel: pass.toFixed(0) + "%", segments: [{ value: pass, color: "var(--c-pass)" }] },
            { subLabel: "Boundary", topLabel: cur.toFixed(0) + "%", segments: [{ value: cur, color: "var(--c-in-new)" }] },
            { subLabel: "Random", topLabel: fuz.toFixed(0) + "%", segments: [{ value: fuz, color: "var(--c-think)" }] }
          ]
        };
      })
    };
  }
  if (activeView === "tokens") {
    const cacheRates = rows.map(r => (r.raw.cache_hit_ratio || 0) * 100);
    const minCache = Math.min(...cacheRates).toFixed(1), maxCache = Math.max(...cacheRates).toFixed(1);
    const cacheNote = pr.input_uncached > 0 && pr.input_cached > 0
      ? `billed at ${(pr.input_cached / pr.input_uncached * 100).toFixed(0)}% of new-input price`
      : "billed at cached context rate";
    return {
      title: "Total Tokens Processed per Run & Peak Memory Window",
      desc: `Multi-turn prefix caching handles ${minCache}%–${maxCache}% of tokens (${cacheNote}), which keeps dollar growth lower than raw token growth.`,
      legend: [
        { label: "Cached Context", color: "var(--c-in-cache)" },
        { label: "New Input", color: "var(--c-in-new)" },
        { label: "AI Thinking", color: "var(--c-think)" },
        { label: "Final Output", color: "var(--c-out)" }
      ],
      formatY: v => fmtCompact(v),
      maxValues: rows.map(r => r.totalTok),
      groups: rows.map(r => ({
        label: r.name,
        subLabel: `${r.tokMult.toFixed(2)}× tokens · Peak ${fmtCompact(r.raw.peak_context.max)}/${fmtCompact(maxCtxLimit)}`,
        readout: `${r.name}: ${fmtInt(r.totalTok)} total tokens (${(r.raw.cache_hit_ratio * 100).toFixed(1)}% cache hit rate) · Peak memory ${fmtInt(r.raw.peak_context.max)} (${(r.raw.peak_context_utilization_max_pct || 0).toFixed(1)}% of limit)`,
        bars: [{
          topLabel: fmtCompact(r.totalTok),
          segments: [
            { value: r.inC, color: "var(--c-in-cache)" },
            { value: r.inU, color: "var(--c-in-new)" },
            { value: r.think, color: "var(--c-think)" },
            { value: r.out, color: "var(--c-out)" }
          ]
        }]
      }))
    };
  }
  if (activeView === "effort") {
    return {
      title: "AI Reasoning Turns & Binary Analysis Tool Calls (Including Failed Calls)",
      desc: "Stronger code protection forces more back-and-forth turns and more failed tool attempts when decompilers stall or patterns no longer match.",
      legend: [
        { label: "AI Reasoning Turns", color: "var(--c-in-new)" },
        { label: "Succeeded Analysis Tool Calls", color: "var(--c-out)" },
        { label: "Failed / Errored Tool Calls", color: "var(--c-err)" }
      ],
      formatY: v => String(Math.round(v)),
      maxValues: rows.flatMap(r => [r.turns, r.mcpTotal]),
      groups: rows.map(r => ({
        label: r.name,
        subLabel: `${Math.round(r.wallSec)}s total (${Math.round(r.llmSec)}s AI / ${Math.round(r.mcpSec)}s tools)`,
        readout: `${r.name}: ${r.turns.toFixed(0)} turns · ${r.mcpTotal.toFixed(0)} analysis calls (${r.mcpOk.toFixed(0)} succeeded, ${r.mcpErr.toFixed(0)} failed) · ${r.wallSec.toFixed(1)}s wall clock`,
        bars: [
          { subLabel: "Turns", topLabel: String(Math.round(r.turns)), segments: [{ value: r.turns, color: "var(--c-in-new)" }] },
          {
            subLabel: "Tool Calls",
            topLabel: r.mcpErr > 0 ? `${Math.round(r.mcpTotal)} (${Math.round(r.mcpErr)} err)` : String(Math.round(r.mcpTotal)),
            segments: [
              { value: r.mcpOk, color: "var(--c-out)" },
              { value: r.mcpErr, color: "var(--c-err)" }
            ]
          }
        ]
      }))
    };
  }
  // obfuscation impact normalized multipliers
  const baseRow = rows[0];
  const focusRow = rows[rows.length - 1];
  const focusCode = focusRow.raw.binary_complexity ? focusRow.raw.binary_complexity.text_bytes_ratio_vs_s0 : 1.0;
  return {
    title: "Why Cost Grows: Machine Code Size vs. AI Effort Multiplier (Baseline = 1.0×)",
    desc: `On ${focusRow.name}, machine code grows ${focusCode.toFixed(2)}× while extra turns (${focusRow.turns.toFixed(0)} vs ${baseRow.turns.toFixed(0)}) replay growing context, scaling tokens ${focusRow.tokMult.toFixed(2)}× and dollar cost ${focusRow.costMult.toFixed(2)}×.`,
    legend: [
      { label: "Compiled Code Size (bytes)", color: "#94a3b8" },
      { label: "AI Turns", color: "var(--c-in-new)" },
      { label: "Analysis Tool Calls (inc. failed)", color: "var(--c-out)" },
      { label: "Dollar Cost ($)", color: "#f59e0b" },
      { label: "Total Tokens", color: "var(--c-think)" }
    ],
    formatY: v => v.toFixed(1) + "×",
    maxValues: rows.flatMap(r => [
      r.raw.binary_complexity ? r.raw.binary_complexity.text_bytes_ratio_vs_s0 : 1,
      baseRow.turns ? r.turns / baseRow.turns : 1,
      baseRow.mcpTotal ? r.mcpTotal / baseRow.mcpTotal : 1,
      r.costMult,
      r.tokMult
    ]),
    groups: rows.map(r => {
      const codeRatio = r.raw.binary_complexity ? r.raw.binary_complexity.text_bytes_ratio_vs_s0 : 1.0;
      const turnRatio = baseRow.turns ? r.turns / baseRow.turns : 1.0;
      const toolRatio = baseRow.mcpTotal ? r.mcpTotal / baseRow.mcpTotal : 1.0;
      const indJumps = r.raw.binary_complexity ? r.raw.binary_complexity.indirect_jumps_mean : null;
      return {
        label: r.name,
        subLabel: indJumps != null ? `${indJumps.toFixed(0)} indirect jump tables` : "",
        readout: `${r.name}: Code size ${codeRatio.toFixed(2)}× · Turns ${turnRatio.toFixed(2)}× · Tool calls ${toolRatio.toFixed(2)}× · Dollar cost ${r.costMult.toFixed(2)}× · Tokens ${r.tokMult.toFixed(2)}×`,
        bars: [
          { subLabel: "Code", topLabel: codeRatio.toFixed(1) + "×", segments: [{ value: codeRatio, color: "#94a3b8" }] },
          { subLabel: "Turns", topLabel: turnRatio.toFixed(1) + "×", segments: [{ value: turnRatio, color: "var(--c-in-new)" }] },
          { subLabel: "Tools", topLabel: toolRatio.toFixed(1) + "×", segments: [{ value: toolRatio, color: "var(--c-out)" }] },
          { subLabel: "Cost $", topLabel: r.costMult.toFixed(1) + "×", segments: [{ value: r.costMult, color: "#f59e0b" }] },
          { subLabel: "Tokens", topLabel: r.tokMult.toFixed(1) + "×", segments: [{ value: r.tokMult, color: "var(--c-think)" }] }
        ]
      };
    })
  };
}

function renderSidePanels(rows) {
  const focus = rows[rows.length - 1];
  const leftTitle = document.getElementById("panelLeftTitle");
  const leftDesc = document.getElementById("panelLeftDesc");
  const leftBody = document.getElementById("panelLeftBody");
  const rightTitle = document.getElementById("panelRightTitle");
  const rightDesc = document.getElementById("panelRightDesc");
  const rightBody = document.getElementById("panelRightBody");

  const pr = activePricing();
  if (activeView === "cost_usd") {
    const outVsCache = pr.input_cached > 0
      ? `thinking & output cost ${(pr.output_and_reasoning / pr.input_cached).toFixed(0)}× more per token`
      : "thinking & output dominate non-cached spend";
    leftTitle.textContent = `Dollar Cost Share on Hardest Protection (${focus.name})`;
    leftDesc.textContent = `Total cost per run is $${focus.runCost.toFixed(4)}. Cached context holds most tokens, while ${outVsCache}.`;
    const parts = [
      { label: "Cached Context Re-reads", usd: focus.costInC, color: "var(--c-in-cache)" },
      { label: "New Prompt & Tool Data", usd: focus.costInU, color: "var(--c-in-new)" },
      { label: "AI Internal Thinking", usd: focus.costThink, color: "var(--c-think)" },
      { label: "Final Code & Tool Calls Output", usd: focus.costOut, color: "var(--c-out)" }
    ];
    leftBody.innerHTML = parts.map(p => {
      const pct = focus.runCost > 0 ? (p.usd / focus.runCost) * 100 : 0;
      return `<div class="meter-row">
        <div class="meter-label"><span>${p.label}</span><strong>$${p.usd.toFixed(4)} (${pct.toFixed(1)}%)</strong></div>
        <div class="meter-track"><div class="meter-fill" style="width:${pct.toFixed(1)}%;background:${p.color};"></div></div>
      </div>`;
    }).join("");
  } else {
    leftTitle.textContent = "Context Window Saturation by Protection Level";
    leftDesc.textContent = `Peak tokens held in active AI memory per turn compared to the ${fmtCompact(maxCtxLimit)} window ceiling.`;
    leftBody.innerHTML = rows.map(r => {
      const pct = Math.min(100, (r.raw.peak_context.max / maxCtxLimit) * 100);
      const color = pct >= 85 ? "var(--c-err)" : pct >= 65 ? "var(--warn)" : "var(--c-in-new)";
      return `<div class="meter-row">
        <div class="meter-label"><span>${r.name}</span><strong>${fmtInt(r.raw.peak_context.max)} / ${fmtCompact(maxCtxLimit)} (${pct.toFixed(1)}%)</strong></div>
        <div class="meter-track"><div class="meter-fill" style="width:${pct.toFixed(1)}%;background:${color};"></div></div>
      </div>`;
    }).join("");
  }

  rightTitle.textContent = "Why Obfuscation Changes Cost & Tool Behavior";
  rightDesc.textContent = "Direct links between target binary changes and observed AI workload:";
  const base = rows[0];
  const items = [];
  if (focus.raw.binary_complexity && base.raw.binary_complexity) {
    const fc = focus.raw.binary_complexity, bc = base.raw.binary_complexity;
    items.push(`<strong>Code expansion:</strong> Compiled code size grew from <strong>${fmtInt(bc.text_bytes_mean)} B</strong> (${fmtInt(bc.instructions_mean)} instructions) to <strong>${fmtInt(fc.text_bytes_mean)} B</strong> (${fmtInt(fc.instructions_mean)} instructions, <strong>${fc.instructions_ratio_vs_s0.toFixed(2)}×</strong>).`);
    if (fc.indirect_jumps_mean > bc.indirect_jumps_mean) {
      items.push(`<strong>Control-flow dispatchers:</strong> Indirect jump tables increased from <strong>${bc.indirect_jumps_mean.toFixed(0)}</strong> to <strong>${fc.indirect_jumps_mean.toFixed(0)}</strong>, breaking linear decompilation and pushing the AI to inspect raw machine bytes.`);
    } else {
      items.push(`<strong>Branch &amp; math density:</strong> Branch checks moved from <strong>${bc.conditional_jumps_mean.toFixed(0)}</strong> to <strong>${fc.conditional_jumps_mean.toFixed(0)}</strong> across <strong>${fc.cyclomatic_complexity_mean.toFixed(0)}</strong> control paths, increasing verification turns.`);
    }
  }
  const totalErr = rows.reduce((acc, r) => acc + (r.raw.mcp_calls_errored_total || 0), 0);
  if (totalErr > 0) {
    const errDetails = rows.filter(r => (r.raw.mcp_calls_errored_total || 0) > 0)
      .map(r => `${r.name}: ${Object.entries(r.raw.mcp_calls_errored_by_tool_sum || {}).map(([t, c]) => `${c}× ${t}`).join(", ")}`)
      .join(" | ");
    items.push(`<strong>Failed analysis calls accounted for:</strong> ${totalErr} failed tool attempts across runs (${errDetails}), adding retry turns and wasted context.`);
  } else {
    items.push(`<strong>Clean tool execution:</strong> Zero failed binary analysis tool calls recorded across all scenarios.`);
  }
  items.push(`<strong>Super-linear cost multiplier:</strong> Extra turns (${base.turns.toFixed(0)} → ${focus.turns.toFixed(0)}) repeatedly replay growing conversation history, scaling tokens <strong>${focus.tokMult.toFixed(2)}×</strong> and dollar cost <strong>${focus.costMult.toFixed(2)}×</strong>.`);
  const probeRuns = rows.filter(r => (r.raw.chal_exec_pre_write_mean || 0) > 0);
  if (probeRuns.length) {
    items.push(`<strong>Runtime probes observed:</strong> Before writing final C code, the agent ran the binary dynamically in ${probeRuns.map(r => `${r.name} (${r.raw.chal_exec_pre_write_mean.toFixed(0)}×)`).join(", ")} to verify edge-case output.`);
  }
  rightBody.innerHTML = items.map(t => `<li>${t}</li>`).join("");
}

function renderTable(rows) {
  const head = document.getElementById("detailHead");
  const body = document.getElementById("detailBody");
  head.innerHTML = `<tr><th>Metric</th>${rows.map(r => `<th>${escapeXml(r.name)}</th>`).join("")}</tr>`;
  const hasBin = rows.some(r => r.raw.binary_complexity);
  const specRows = [
    ["Full Pass Rate", r => `${(r.passRate * 100).toFixed(0)}% (${r.raw.passes}/${r.raw.samples})`, r => r.passRate >= 1 ? "row-ok" : (r.passRate > 0 ? "row-highlight" : "row-err")],
    ["Test Accuracy (Boundary / Random)", r => {
      const c = r.raw.curated_accuracy_mean != null ? `${(r.raw.curated_accuracy_mean * 100).toFixed(0)}%` : "-";
      const f = r.raw.fuzz_accuracy_mean != null ? `${(r.raw.fuzz_accuracy_mean * 100).toFixed(0)}%` : "-";
      return `${(r.raw.io_accuracy_mean * 100).toFixed(1)}% (${c} / ${f})`;
    }, ""],
    ["Dollar Cost per Run", r => `$${r.runCost.toFixed(4)} (${r.costMult.toFixed(2)}×)`, "row-highlight"],
    ["Effective Cost per Passing Run", r => fmtUsd(r.costPerPass), "row-highlight"],
    ["Cost Breakdown (New / Cache / Think / Out)", r => `$${r.costInU.toFixed(4)} / $${r.costInC.toFixed(4)} / $${r.costThink.toFixed(4)} / $${r.costOut.toFixed(4)}`, ""],
    ["Total Tokens (Multiplier vs Baseline)", r => `${fmtInt(r.totalTok)} (${r.tokMult.toFixed(2)}×)`, ""],
    ["Cached Context Hit Rate", r => `${(r.raw.cache_hit_ratio * 100).toFixed(1)}%`, ""],
    ["AI Thinking Tokens (Share of Generated)", r => `${fmtInt(r.think)} (${((r.raw.reasoning_share_of_generated || 0) * 100).toFixed(1)}%)`, ""],
    ["Peak Memory Window (% of Limit)", r => `${fmtInt(r.raw.peak_context.max)} (${(r.raw.peak_context_utilization_max_pct || 0).toFixed(1)}%)`, ""],
    ["AI Reasoning Turns", r => String(Math.round(r.turns)), ""],
    ["Binary Analysis Calls (OK / Failed)", r => `${r.mcpTotal.toFixed(0)} (${r.mcpOk.toFixed(0)} ok / ${r.mcpErr.toFixed(0)} err)`, r => r.mcpErr > 0 ? "row-err" : ""],
    ["Local Commands (OK / Blocked)", r => `${((r.raw.other_tool_calls_mean || 0) - (r.raw.other_tool_calls_errored_mean || 0)).toFixed(0)} ok / ${(r.raw.other_tool_calls_errored_mean || 0).toFixed(0)} blocked`, r => (r.raw.other_tool_calls_errored_mean || 0) > 0 ? "row-err" : ""],
    ["Analysis Data Volume Returned", r => r.raw.mcp_payload_bytes_mean != null ? `${(r.raw.mcp_payload_bytes_mean / 1024).toFixed(1)} KB` : "-", ""],
    ["Wall Time (AI Time / Tool Time)", r => `${r.wallSec.toFixed(1)}s (${r.llmSec.toFixed(1)}s / ${r.mcpSec.toFixed(1)}s)`, ""],
    ["Runtime Program Probes (Before / Total)", r => r.raw.chal_exec_calls_mean != null ? `${r.raw.chal_exec_pre_write_mean.toFixed(0)} pre / ${r.raw.chal_exec_calls_mean.toFixed(0)} total` : "-", ""]
  ];
  if (hasBin) {
    specRows.push(
      ["Compiled Code Size & Instructions", r => r.raw.binary_complexity ? `${fmtInt(r.raw.binary_complexity.text_bytes_mean)} B (${fmtInt(r.raw.binary_complexity.instructions_mean)} ins)` : "-", ""],
      ["Jump Tables / Branch Checks / Code Paths", r => r.raw.binary_complexity ? `${r.raw.binary_complexity.indirect_jumps_mean.toFixed(0)} / ${r.raw.binary_complexity.conditional_jumps_mean.toFixed(0)} / ${r.raw.binary_complexity.cyclomatic_complexity_mean.toFixed(0)}` : "-", ""],
      ["AI Tokens per Machine Code Byte", r => r.raw.tokens_per_text_byte != null ? fmtInt(r.raw.tokens_per_text_byte) : "-", ""]
    );
  }
  body.innerHTML = specRows.map(([label, fn, cls]) => `<tr><th>${label}</th>${rows.map(r => {
    const c = typeof cls === "function" ? cls(r) : cls;
    return `<td class="${c}">${escapeXml(fn(r))}</td>`;
  }).join("")}</tr>`).join("");
}

function render() {
  const rows = getRows();
  const projected = isProjected();
  const modeBadge = document.getElementById("modeBadge");
  modeBadge.dataset.mode = projected ? "projected" : "measured";
  modeBadge.textContent = projected ? "Viewing What-If Projection" : "Viewing Measured Results";
  resetBtn.disabled = !projected;

  document.getElementById("kpiRow").innerHTML = rows.map(r => {
    const passPct = Math.round(r.passRate * 100);
    const badgeCls = passPct === 100 ? "badge-ok" : passPct > 0 ? "badge-warn" : "badge-err";
    const cardColor = passPct === 100 ? "#38bdf8" : passPct > 0 ? "#f59e0b" : "#ef4444";
    const errNote = r.mcpErr > 0 ? ` (${r.mcpErr.toFixed(0)} err)` : "";
    return `<article class="kpi-card" style="--card-accent:${cardColor};">
      <div class="kpi-head">
        <span class="kpi-name">${escapeXml(r.name)}</span>
        <span class="badge ${badgeCls}">${passPct}% Pass</span>
      </div>
      <div class="kpi-primary">${fmtUsd(r.runCost)} <span style="font-size:0.82rem;font-weight:600;color:var(--text-muted);">/ run (${r.costMult.toFixed(2)}×)</span></div>
      <div class="kpi-meta">Cost per passing binary: <strong>${fmtUsd(r.costPerPass)}</strong></div>
      <div class="kpi-sub">${Math.round(r.turns)} turns · ${r.mcpTotal.toFixed(0)} analysis calls${errNote} · ${r.wallSec.toFixed(0)}s</div>
    </article>`;
  }).join("");

  const spec = buildViewSpec(rows);
  document.getElementById("chartTitle").textContent = spec.title;
  document.getElementById("chartDesc").textContent = spec.desc;
  document.getElementById("chartLegend").innerHTML = spec.legend.map(l =>
    `<span class="legend-item"><span class="swatch" style="background:${l.color};"></span>${escapeXml(l.label)}</span>`
  ).join("");
  renderSvgChart(spec);
  renderSidePanels(rows);
  renderTable(rows);
}

document.getElementById("viewTabs").addEventListener("click", ev => {
  const btn = ev.target.closest(".tab-btn");
  if (!btn) return;
  activeView = btn.dataset.view;
  document.querySelectorAll(".tab-btn").forEach(b => b.setAttribute("aria-pressed", String(b === btn)));
  render();
});
passEl.addEventListener("input", () => { touchedPass = true; render(); });
[scaleEl, pUncachedEl, pCachedEl, pOutputEl].forEach(el => el.addEventListener("input", render));
resetBtn.addEventListener("click", () => { initInputs(); render(); });
render();
</script>
</body>
</html>
"""


def _print_cli_report(summary: dict, table: str) -> None:
    print(f"{'Scenario':<16} | {'Pass':<7} | {'Avg Cost':<9} | {'ECSR ($)':<9} | {'$ Mult':<7} | "
          f"{'Avg Tokens':<10} | {'Tok OCM':<7} | {'MCP (ok/err)':<13} | {'Turns':<5} | {'Wall'}")
    print("-" * 112)
    for sc in summary["scenario_order"]:
        m = summary["scenarios"].get(sc)
        if not m:
            continue
        ecsr = f"${m['ecsr_usd']:.4f}" if m["ecsr_usd"] is not None else "INF"
        ocm_c = f"{m['ocm_cost_usd']:.2f}x" if m["ocm_cost_usd"] is not None else "-"
        ocm_t = f"{m['ocm_tokens']:.2f}x" if m["ocm_tokens"] is not None else "-"
        mcp_str = f"{m['avg_mcp_calls']:.0f} ({m['mcp_calls_succeeded_mean']:.0f}/{m['mcp_calls_errored_mean']:.0f})"
        print(f"{sc:<16} | {m['passes']}/{m['samples']:<5} | ${m['avg_run_cost_usd']:<8.4f} | {ecsr:<9} | "
              f"{ocm_c:<7} | {m['avg_total_tokens']:<10.0f} | {ocm_t:<7} | {mcp_str:<13} | "
              f"{m['turns_mean'] or 0:<5.0f} | {m['wall_time_mean_sec']:.1f}s")
    print()
    print(table)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "configs" / "experiment.yaml"))
    ap.add_argument("--results", default=None, help="results directory (default: paths.results_dir)")
    args = ap.parse_args()
    config = load_config(Path(args.config))
    results_dir = Path(args.results) if args.results else (ROOT / config["paths"]["results_dir"])

    pricing = config["evaluation"]["cost_telemetry"]["pricing_per_1m_tokens_usd"]
    runs = load_runs(results_dir, pricing, config=config)
    if not runs:
        sys.exit(f"No graded telemetry.json files under {results_dir}")
    summary = clean(aggregate(runs, config))

    (results_dir / "benchmark_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    table = markdown_table(summary)
    (results_dir / "summary_table.md").write_text(table + "\n", encoding="utf-8")
    _print_cli_report(summary, table)

    embed = {k: summary[k] for k in ("pricing", "max_context_tokens", "scenario_order", "scenarios")}
    html_out = HTML_TEMPLATE.replace("__BENCHMARK_JSON__", json.dumps(embed))
    (results_dir / "simulator.html").write_text(html_out, encoding="utf-8")
    print(f"\nInteractive report written to: {results_dir / 'simulator.html'}")


if __name__ == "__main__":
    main()

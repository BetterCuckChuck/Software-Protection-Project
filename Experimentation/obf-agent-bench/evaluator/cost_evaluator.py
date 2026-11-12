#!/usr/bin/env python3
"""Axis 2 - agentic cost & efficiency evaluation.

Reads configs/experiment.yaml (pricing) and every results/<scenario>/<sample>/telemetry.json (+ run_metrics.json
when present), computes

    C_run  = (T_in*P_in + T_cache*P_cache + (T_think+T_out)*P_out) / 1e6
    OCM    = T_total(S_k, i) / T_total(S_0, i)            (and the same for MCP calls), per sample i
    ECSR   = sum_i C_run(S_k, i) / sum_i Pass_IO(S_k, i)  (also in tokens)

and writes
    results/benchmark_summary.json   machine-readable aggregate (+ per-run rows)
    results/summary_table.md         the Section-5 comparison matrix
    results/simulator.html           standalone interactive cost & resilience simulator

Usage:  python3 evaluator/cost_evaluator.py [--config configs/experiment.yaml] [--results results]
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, load_config  # noqa: E402


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


def ratio(num: float, den: float) -> Optional[float]:
    return num / den if den else None


def clean(obj):
    """JSON-safe: NaN -> None."""
    if isinstance(obj, float) and obj != obj:
        return None
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [clean(v) for v in obj]
    return obj


# ----------------------------------------------------------------------------- per-run cost
def compute_run_cost(tokens: dict, pricing: dict) -> float:
    return (
        tokens.get("input_uncached", 0) * pricing["input_uncached"]
        + tokens.get("input_cached", 0) * pricing["input_cached"]
        + (tokens.get("reasoning", 0) + tokens.get("output", 0)) * pricing["output_and_reasoning"]
    ) / 1_000_000.0


def load_runs(results_dir: Path, pricing: dict) -> list[dict]:
    runs = []
    for tel_file in sorted(results_dir.glob("*/*/telemetry.json")):
        tel = json.loads(tel_file.read_text(encoding="utf-8"))
        if tel.get("io_passed") is None:
            print(f"[warn] {tel_file.parent} not graded yet (run evaluator/io_harness.py); skipped", file=sys.stderr)
            continue
        metrics_file = tel_file.parent / "run_metrics.json"
        metrics = json.loads(metrics_file.read_text()) if metrics_file.exists() else {}
        tok = tel["tokens"]
        run = dict(tel)
        run["total_input_tokens"] = tok.get("input_uncached", 0) + tok.get("input_cached", 0)
        run["total_tokens"] = run["total_input_tokens"] + tok.get("reasoning", 0) + tok.get("output", 0)
        run["run_cost_usd"] = compute_run_cost(tok, pricing)
        run["io_accuracy"] = (tel["io_tests_passed"] / tel["io_tests_total"]) if tel.get("io_tests_total") else 0.0
        run["mcp_payload_bytes"] = metrics.get("mcp_payload_bytes")
        run["turns"] = tel.get("turns", metrics.get("turns"))
        run["latency"] = metrics.get("latency", {})
        run["mcp_calls_by_tool"] = metrics.get("mcp_calls_by_tool", {})
        run["terminated_reason"] = tel.get("terminated_reason")
        runs.append(run)
    return runs


# ----------------------------------------------------------------------------- aggregation
def aggregate(runs: list[dict], config: dict) -> dict:
    pricing = config["evaluation"]["cost_telemetry"]["pricing_per_1m_tokens_usd"]
    order = list(config["scenarios"])
    grouped: dict[str, list[dict]] = {sc: [] for sc in order}
    for r in runs:
        grouped.setdefault(r["scenario"], []).append(r)
    base_by_sample = {r["sample_id"]: r for r in grouped.get(order[0], [])}
    base_pass = ratio(sum(r["io_passed"] for r in grouped[order[0]]), len(grouped[order[0]])) if grouped[order[0]] else None

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

        def ocm(selector, subset) -> dict:
            vals_t, vals_m = [], []
            for r in subset:
                b = base_by_sample.get(r["sample_id"])
                if not b or sc == order[0]:
                    continue
                t = ratio(r["total_tokens"], b["total_tokens"])
                m = ratio(r["mcp_calls"], b["mcp_calls"])
                if t is not None:
                    vals_t.append(t)
                if m is not None:
                    vals_m.append(m)
            return {"tokens_mean": statistics.fmean(vals_t) if vals_t else None,
                    "tokens_median": statistics.median(vals_t) if vals_t else None,
                    "tools_mean": statistics.fmean(vals_m) if vals_m else None,
                    "n": len(vals_t)}

        is_base = sc == order[0]
        ocm_all = {"tokens_mean": 1.0, "tokens_median": 1.0, "tools_mean": 1.0, "n": n} if is_base else ocm(None, rs)
        ocm_pass = {"tokens_mean": 1.0, "tokens_median": 1.0, "tools_mean": 1.0, "n": passes} if is_base \
            else ocm(None, [r for r in rs if r["io_passed"]])
        # aggregate ratio used by the simulator and the one-line CLI table
        avg_total = total_tokens / n
        base_runs = grouped[order[0]]
        base_avg_total = (sum(r["total_tokens"] for r in base_runs) / len(base_runs)) if base_runs else None
        acc_m, acc_sd = mean_sd([r["io_accuracy"] for r in rs])
        in_med = median_iqr(in_cache)
        th_med = median_iqr(tok("reasoning"))
        peaks = tok("peak_context")
        mcp = [r["mcp_calls"] for r in rs]
        mcp_m, mcp_sd = mean_sd(mcp)
        summary[sc] = {
            "samples": n, "passes": passes, "io_pass_rate": passes / n,
            "io_pass_delta_vs_S0_pct": None if is_base or base_pass is None else (passes / n - base_pass) * 100,
            "io_accuracy_mean": acc_m, "io_accuracy_sd": acc_sd,
            "input_plus_cache_tokens": {"median": in_med[0], "q1": in_med[1], "q3": in_med[2]},
            "reasoning_tokens": {"median": th_med[0], "q1": th_med[1], "q3": th_med[2]},
            "peak_context": {"max": max(peaks), "median": statistics.median(peaks)},
            "mcp_calls": {"mean": mcp_m, "sd": mcp_sd},
            "mcp_payload_bytes_mean": statistics.fmean([r["mcp_payload_bytes"] for r in rs if r["mcp_payload_bytes"] is not None])
            if any(r["mcp_payload_bytes"] is not None for r in rs) else None,
            "turns_mean": statistics.fmean([r["turns"] for r in rs if r["turns"] is not None]) if any(r["turns"] is not None for r in rs) else None,
            "wall_time_mean_sec": statistics.fmean([r["wall_time_sec"] for r in rs]),
            "reasoning_token_ratio": ratio(sum(tok("reasoning")), total_tokens),
            "ocm_all": ocm_all, "ocm_pass_only": ocm_pass,
            "ocm_tokens": ratio(avg_total, base_avg_total) if base_avg_total else None,
            "ocm_tools": ocm_all["tools_mean"],
            "avg_input_uncached": statistics.fmean(tok("input_uncached")),
            "avg_input_cached": statistics.fmean(tok("input_cached")),
            "avg_input_tokens": statistics.fmean(in_cache),
            "avg_reasoning_tokens": statistics.fmean(tok("reasoning")),
            "avg_output_tokens": statistics.fmean(tok("output")),
            "avg_total_tokens": avg_total,
            "avg_mcp_calls": mcp_m,
            "total_suite_cost_usd": total_cost,
            "ecsr_usd": ratio(total_cost, passes), "ecsr_tokens": ratio(total_tokens, passes),
            "terminations": {k: sum(1 for r in rs if r.get("terminated_reason") == k)
                             for k in sorted({r.get("terminated_reason") for r in rs if r.get("terminated_reason")})},
        }
    return {"pricing": pricing, "scenario_order": order, "scenarios": summary,
            "runs": [{k: v for k, v in r.items() if k != "latency"} for r in runs]}


# ----------------------------------------------------------------------------- reporting
def _f(x, spec=".2f", dash="-"):
    return dash if x is None or (isinstance(x, float) and x != x) else format(x, spec)


def markdown_table(summary: dict) -> str:
    sc = summary["scenarios"]
    names = [s for s in summary["scenario_order"] if s in sc]
    rows = [
        ("I/O Pass Rate Pass_IO (%)", lambda m: (f"{m['io_pass_rate']*100:.1f}" if m["io_pass_delta_vs_S0_pct"] is None
                                                  else f"{m['io_pass_rate']*100:.1f} ({m['io_pass_delta_vs_S0_pct']:+.1f} pp vs S0)")),
        ("Partial Test Accuracy Acc_IO (%)", lambda m: f"{m['io_accuracy_mean']*100:.1f} ± {m['io_accuracy_sd']*100:.1f}"),
        ("Input + Cache Tokens (median / IQR)", lambda m: "{} / {}–{}".format(*(f"{m['input_plus_cache_tokens'][k]:,.0f}" for k in ("median", "q1", "q3")))),
        ("Reasoning Tokens T_think (median / IQR)", lambda m: "{} / {}–{}".format(*(f"{m['reasoning_tokens'][k]:,.0f}" for k in ("median", "q1", "q3")))),
        ("Peak Context T_peak (max / median)", lambda m: f"{m['peak_context']['max']:,.0f} / {m['peak_context']['median']:,.0f}"),
        ("REA MCP Calls N_mcp (mean ± SD)", lambda m: f"{m['mcp_calls']['mean']:.1f} ± {m['mcp_calls']['sd']:.1f}"),
        ("OCM_tokens, all samples (mean of ratios)", lambda m: _f(m["ocm_all"]["tokens_mean"]) + "×"),
        ("OCM_tokens, successful breaks only", lambda m: _f(m["ocm_pass_only"]["tokens_mean"]) + "×"),
        ("OCM_tools, all samples", lambda m: _f(m["ocm_all"]["tools_mean"]) + "×"),
        ("ECSR (USD per successful break)", lambda m: "∞ (no successes)" if m["ecsr_usd"] is None else f"${m['ecsr_usd']:.4f}"),
        ("ECSR (tokens per successful break)", lambda m: "∞" if m["ecsr_tokens"] is None else f"{m['ecsr_tokens']:,.0f}"),
        ("Runs (n) / suite cost (USD)", lambda m: f"{m['samples']} / ${m['total_suite_cost_usd']:.4f}"),
    ]
    out = ["| Metric | " + " | ".join(names) + " |", "| :--- | " + " | ".join(":---" for _ in names) + " |"]
    for label, fn in rows:
        out.append(f"| {label} | " + " | ".join(fn(sc[n]) for n in names) + " |")
    return "\n".join(out)


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Tigress vs. REA — Cost &amp; Resilience Simulator</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { font-size: 1.4rem; margin-bottom: 4px; }
    .sub { color: #94a3b8; font-size: 0.9rem; margin-bottom: 20px; }
    .controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; background: #1e293b; padding: 16px; border-radius: 10px; margin-bottom: 20px; }
    .control-box label { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 6px; color: #cbd5e1; }
    input[type=range], select { width: 100%; accent-color: #38bdf8; }
    select { background: #0f172a; color: #e2e8f0; border: 1px solid #334155; padding: 6px; border-radius: 6px; }
    .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 20px; }
    .kpi { background: #1e293b; padding: 14px; border-radius: 10px; border-left: 3px solid #38bdf8; }
    .kpi-title { font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; }
    .kpi-val { font-size: 1.25rem; font-weight: 700; margin-top: 4px; }
    .chart-card { background: #1e293b; padding: 20px; border-radius: 10px; }
    #noChart { display: none; color: #fbbf24; }
  </style>
</head>
<body>
<div class="container">
  <h1>Obfuscation Cost &amp; Resilience Simulator</h1>
  <div class="sub">Initialized with empirical benchmark telemetry; adjust sliders to project scaling behavior. S0 is never scaled.</div>
  <div class="controls">
    <div class="control-box">
      <label><span>Metric View</span></label>
      <select id="metricView">
        <option value="tokens">Token Breakdown per Run (Uncached / Cached / Reasoning / Output)</option>
        <option value="ecsr">Expected Tokens per Successful Break (ECSR)</option>
        <option value="ocm">Obfuscation Cost Multiplier (OCM vs. S0)</option>
      </select>
    </div>
    <div class="control-box">
      <label><span>Token Overhead Scale Factor (S1..Sk)</span><span id="scaleVal">1.00x</span></label>
      <input type="range" id="tokenScale" min="0.5" max="3.0" step="0.05" value="1.0" />
    </div>
    <div class="control-box">
      <label><span>Hardest Scenario Pass Rate Override</span><span id="passVal">Empirical</span></label>
      <input type="range" id="passOverride" min="0.05" max="1.0" step="0.05" value="0.25" />
    </div>
  </div>
  <div class="kpis" id="kpiRow"></div>
  <div class="chart-card"><canvas id="simChart" height="115"></canvas><div id="noChart">Chart.js could not be loaded (offline?). KPI cards above remain valid.</div></div>
</div>
<script>
const BENCHMARK_DATA = __BENCHMARK_JSON__;
const labels = BENCHMARK_DATA.scenario_order.filter(k => BENCHMARK_DATA.scenarios[k]);
const lastKey = labels[labels.length - 1];
const empiricalLast = BENCHMARK_DATA.scenarios[lastKey].io_pass_rate;
const passSlider = document.getElementById("passOverride");
passSlider.value = Math.max(0.05, empiricalLast || 0.25);
let touchedPass = false;
passSlider.addEventListener("input", () => { touchedPass = true; });
let chartInstance = null;

function computeSimulated() {
  const scale = parseFloat(document.getElementById("tokenScale").value);
  const lastPass = parseFloat(passSlider.value);
  document.getElementById("scaleVal").textContent = scale.toFixed(2) + "x";
  document.getElementById("passVal").textContent = touchedPass ? Math.round(lastPass * 100) + "%" : "Empirical (" + Math.round(empiricalLast * 100) + "%)";
  const pr = BENCHMARK_DATA.pricing;
  const base = BENCHMARK_DATA.scenarios[labels[0]];
  return labels.map((key, idx) => {
    const sc = BENCHMARK_DATA.scenarios[key];
    const mult = idx === 0 ? 1.0 : scale;
    const passRate = (idx === labels.length - 1 && touchedPass) ? lastPass : sc.io_pass_rate;
    const inU = sc.avg_input_uncached * mult, inC = sc.avg_input_cached * mult;
    const think = sc.avg_reasoning_tokens * mult, out = sc.avg_output_tokens * mult;
    const totalTok = inU + inC + think + out;
    const ocm = totalTok / base.avg_total_tokens;
    const runCost = (inU * pr.input_uncached + inC * pr.input_cached + (think + out) * pr.output_and_reasoning) / 1e6;
    return { key, passRate, inU, inC, think, out, totalTok, ocm,
             ecsrTokens: passRate > 0 ? totalTok / passRate : null,
             ecsrUsd: passRate > 0 ? runCost / passRate : null };
  });
}

function render() {
  const view = document.getElementById("metricView").value;
  const rows = computeSimulated();
  document.getElementById("kpiRow").innerHTML = rows.map(r => `
    <div class="kpi">
      <div class="kpi-title">${r.key} (${Math.round(r.passRate * 100)}% pass)</div>
      <div class="kpi-val">${r.ocm.toFixed(2)}x OCM</div>
      <div class="sub" style="margin:4px 0 0 0;">ECSR: ${r.ecsrUsd !== null ? "$" + r.ecsrUsd.toFixed(4) : "&infin;"}</div>
    </div>`).join("");
  let datasets = [], stacked = false;
  if (view === "tokens") {
    stacked = true;
    datasets = [
      { label: "Input (uncached)", data: rows.map(r => Math.round(r.inU)), backgroundColor: "#38bdf8" },
      { label: "Input (cached)", data: rows.map(r => Math.round(r.inC)), backgroundColor: "#0ea5e9" },
      { label: "Reasoning", data: rows.map(r => Math.round(r.think)), backgroundColor: "#a855f7" },
      { label: "Output", data: rows.map(r => Math.round(r.out)), backgroundColor: "#22c55e" }];
  } else if (view === "ecsr") {
    datasets = [{ label: "Expected Tokens / Successful Break (ECSR)", data: rows.map(r => r.ecsrTokens ? Math.round(r.ecsrTokens) : 0), backgroundColor: "#f97316" }];
  } else {
    datasets = [{ label: "Obfuscation Cost Multiplier (OCM)", data: rows.map(r => Number(r.ocm.toFixed(2))), backgroundColor: "#eab308" }];
  }
  if (typeof Chart === "undefined") { document.getElementById("noChart").style.display = "block"; return; }
  if (chartInstance) chartInstance.destroy();
  chartInstance = new Chart(document.getElementById("simChart"), {
    type: "bar", data: { labels, datasets },
    options: { responsive: true,
      scales: { x: { stacked, ticks: { color: "#cbd5e1" }, grid: { color: "#334155" } },
                y: { stacked, ticks: { color: "#cbd5e1" }, grid: { color: "#334155" } } },
      plugins: { legend: { labels: { color: "#e2e8f0" } } } }
  });
}
document.getElementById("metricView").addEventListener("change", render);
document.getElementById("tokenScale").addEventListener("input", render);
passSlider.addEventListener("input", render);
render();
</script>
</body>
</html>
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "configs" / "experiment.yaml"))
    ap.add_argument("--results", default=None, help="results directory (default: paths.results_dir)")
    args = ap.parse_args()
    config = load_config(Path(args.config))
    results_dir = Path(args.results) if args.results else (ROOT / config["paths"]["results_dir"])

    pricing = config["evaluation"]["cost_telemetry"]["pricing_per_1m_tokens_usd"]
    runs = load_runs(results_dir, pricing)
    if not runs:
        sys.exit(f"No graded telemetry.json files under {results_dir}")
    summary = clean(aggregate(runs, config))

    (results_dir / "benchmark_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    table = markdown_table(summary)
    (results_dir / "summary_table.md").write_text(table + "\n", encoding="utf-8")

    print(f"{'Scenario':<16} | {'Pass':<7} | {'Avg Tokens':<11} | {'MCP':<6} | {'OCM':<7} | ECSR ($)")
    print("-" * 70)
    for sc, m in summary["scenarios"].items():
        ecsr = f"${m['ecsr_usd']:.4f}" if m["ecsr_usd"] is not None else "INF"
        ocm = f"{m['ocm_tokens']:.2f}x" if m["ocm_tokens"] is not None else "-"
        print(f"{sc:<16} | {m['passes']}/{m['samples']:<5} | {m['avg_total_tokens']:<11.0f} | "
              f"{m['avg_mcp_calls']:<6.1f} | {ocm:<7} | {ecsr}")
    print()
    print(table)

    html_out = HTML_TEMPLATE.replace("__BENCHMARK_JSON__", json.dumps({k: summary[k] for k in ("pricing", "scenario_order", "scenarios")}))
    (results_dir / "simulator.html").write_text(html_out, encoding="utf-8")
    print(f"\nInteractive simulator written to: {results_dir / 'simulator.html'}")


if __name__ == "__main__":
    main()

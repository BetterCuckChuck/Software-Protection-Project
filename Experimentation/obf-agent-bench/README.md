# obf-agent-bench — Tigress vs. REA agent (Week 2)

Implements `week2_plan.md`: 20 NIST Juliet v1.3 programs × 4 Tigress scenarios (80 runs). Each run lets an
Antigravity + REA + Ghidra-MCP agent reconstruct `reconstructed.c` from the stripped binary; the result is graded on
**Axis 1 – behavioural I/O equivalency** and **Axis 2 – agentic cost (tokens, MCP calls, OCM, ECSR)**.

```
configs/        experiment.yaml (master config), tigress_recipes.yaml (S0–S3 flag templates)
dataset/        prepare_dataset.py → raw_juliet/ (gitignored), normalized_src/, test_vectors/, samples_20.json
builder/        build_scenarios.py   Tigress → gcc → strip → binary_stats.json (+ Ghidra project if available)
build/          <scenario>/<sample>/{chal, binary_stats.json, obfuscated.c, ghidra_proj/}   (gitignored)
runner/         orchestrator.py, prompts/rea_task.md, stream_telemetry.py, hook_guard.py, setup_ghidra_mcp.sh
evaluator/      io_harness.py (Axis 1), cost_evaluator.py (Axis 2 + simulator.html)
results/        <scenario>/<sample>/{telemetry.json, run_metrics.json, io_result.json, reconstructed.c, session_stream.jsonl}
tests/          offline tests + fake agent (python3 -m unittest discover -s tests -v)
```

## Pipeline

```bash
cd Experimentation/obf-agent-bench
python3 dataset/prepare_dataset.py --download     # fetch Juliet (150 MB), select 20, normalize, write hidden vectors
python3 builder/build_scenarios.py                # 80 binaries, validated against S0 on all 65 vectors each
export GHIDRA_INSTALL_DIR=/opt/ghidra             # optional at build time: pre-analyzed ghidra_proj/
export GHIDRA_MCP_CMD='...'                       # command that starts your headless Ghidra MCP server (stdio)
bash runner/setup_ghidra_mcp.sh                   # one-time: `agy mcp add ghidra-mcp-headless ...`
python3 runner/orchestrator.py --config configs/experiment.yaml   # --resume / --scenarios / --samples / --dry-run
python3 evaluator/cost_evaluator.py               # results/benchmark_summary.json, summary_table.md, simulator.html
```

`io_harness.py` is called by the orchestrator after every run; re-grade manually with
`python3 evaluator/io_harness.py --all`.

## Dataset (what "normalized" means)

Candidates: Juliet C flow-variant `_01`, `fscanf(stdin, …)` source, only `print*Line` sinks, no rand/time/heap/file/
socket use. Stratified, seeded selection (`dataset.stratification`): CWE190 ×9, CWE191 ×6, CWE197 ×3, CWE369 ×2.
Each is merged into **one translation unit** (std headers + the needed `io.c` printers + testcase + a deterministic
`main`): `./prog [good|bad]` (no arg = both), data on stdin, Juliet's time-seeded `main` removed.
Per sample: 15 curated boundary cases (min/max/±1/0/√max/truncation edges; alternating `bad`/`good` path) +
50 seeded differential-fuzz cases = 65 vectors in `dataset/test_vectors/` (never copied into the agent jail).

## Metrics

* `Pass_IO` – Gate 1 (forbidden `system/popen/exec*/dlopen/asm`, no string literal naming `chal`, `gcc -O2 -Wall`
  compiles) **and** all 65 (stdout, stderr, exit code) comparisons against the live `./chal` match.
  Tests keep running after a failed gate so `Acc_IO = passed/65` is always available.
* `T_in`, `T_cache`, `T_think`, `T_out`, `T_peak`, `N_turns`, `N_mcp` (+per tool), MCP payload bytes, `t_llm/t_mcp/t_wall`
  – parsed from agy's `stream-json` events (`runner/stream_telemetry.py`; token semantics documented there:
  *thinking ⊂ output_tokens*, *peak = input + cache_read of a turn*).
* `C_run`, `OCM` (per-sample ratio vs S0, reported over all samples and over successful breaks only), `ECSR` (USD and
  tokens) – exactly the plan's formulas; table matches plan §5.

## Deviations from / additions to the plan (deliberate)

| Item | Why |
| --- | --- |
| S2/S3 prepend `InitOpaque --Functions=main --InitOpaqueStructs=array` | Tigress 4.2 refuses `EncodeArithmetic` without it (same fix as Week 1). |
| Juliet *C* suite, only 4 CWE families, `CWE369` has 2 not 3 | Only these have stdin-driven, deterministic, single-TU-able flow-01 files (filter above). |
| Builder validates every obfuscated binary vs S0 on all vectors → `valid` flag; invalid builds are skipped | Tigress/UB divergence must not be billed to the agent. Also stores mismatches vs an `-O0 -fwrapv` reference (UB sensitivity). |
| `hook_guard.py` PreToolUse hook + jail with `chal` only | Enforces the "no `..`, no env, no filesystem search" rule instead of trusting the prompt; audit log is outside the jail. |
| Run limits enforced by the orchestrator (turns, MCP calls, context, wall clock) | `agy` has no flags for them; `terminated_reason` is recorded per run. |
| Cached-input pricing used in `C_run` and in the simulator | Plan formula has `P_cache`; its simulator code ignored it. |

## Known gaps — read before spending tokens

* **Ghidra + Ghidra MCP are not installed in this workspace** and could not be downloaded (sandbox without network
  except the Juliet fetch). The builder skips `ghidra_proj/` unless `$GHIDRA_INSTALL_DIR` is set, and
  `runner/ghidra_mcp_launcher.sh` needs `GHIDRA_MCP_CMD`. The orchestrator refuses to run without a registered
  `ghidra-mcp-headless` server unless `--no-mcp` is given (then results are *not* plan-compliant).
* `temperature: 0.1` and `max_output_tokens` are recorded in the config but `agy` exposes no flag for them → not enforced.
* No real agent run was executed (it costs tokens and needs the MCP server). The orchestrator → parser → harness →
  evaluator chain is covered by `tests/test_bench.py` using `tests/fake_agy.py`, which mimics the stream schema observed
  in the Week-1 logs. The exact hook payload key names of `agy` are inferred from Week 1 (`hook_guard.py` tries several).
* `simulator.html` loads Chart.js from a CDN (as in the plan); KPI cards still work offline.

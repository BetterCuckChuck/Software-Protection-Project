# Benchmark Run Report: Tigress Obfuscation vs. REA Native Binary Agent

- **Target Suite:** 20 NIST Juliet v1.3 C programs $\times$ 4 Tigress protection scenarios = **80 runs** (`build/` verified semantically equivalent vs. `S0_Baseline`)
- **Agent & Framework:** `gemini-3.8-flash` operating under the **REA (Reverse Engineer Anything)** MCP server backed by Ghidra 12.1.4, isolated per-run in ephemeral `/tmp/run_<uuid>/` jails guarded by [hook_guard.py](file:///home/arch/work/softwareProt/Experimentation/obf-agent-bench/runner/hook_guard.py)
- **Execution Mode:** 4 pilot runs on `CWE190_Integer_Overflow__char_fscanf_add_01` (completed within limits), followed by the remaining 76 runs via `--resume --unlimited`
- **Pricing Basis:** Official Google Gemini Developer API Standard Tier rates for `gemini-3.8-flash` active through Dec 31, 2026 (`$0.75` / 1M uncached input, `$0.075` / 1M cached input, `$3.75` / 1M output & reasoning)
- **Aggregate Totals:** **80/80 completed orchestration**, **78/80 `Pass_IO` (97.5%)**, **193,315,752 tokens**, **$28.4738 total API spend**, **2,244 REA MCP calls attempted** (`2,133` ok / `111` err), **24,334.0s (6.76 hours)** cumulative run time

---

## 1. Executive Summary

1. **Reconstruction Accuracy (Axis 1):** Every run that actually began analyzing the binary succeeded: **78/78 (100.0%)** of active runs passed all 65 deterministic I/O equivalence checks (`15` boundary cases + `50` differential fuzz cases, clean `gcc -O2` compile). The only **2 failures** (`S0_Baseline/CWE191_Integer_Underflow__int64_t_fscanf_sub_01` and `S3_Combined/CWE190_Integer_Overflow__char_fscanf_preinc_01`) were **Turn-1 Gemini safety-filter false positives** before a single REA tool was called (`turns=1`, `mcp_calls=0`, `~$0.014`), not obfuscation breakdowns.
2. **Obfuscation Cost Impact (Axis 2):** Excluding the two 1-turn safety-filter outliers, progressive Tigress protection increased mean run cost from **`$0.2873` (`S0`) $\rightarrow$ `$0.3446` (`S1`) $\rightarrow$ `$0.3723` (`S2`) $\rightarrow$ `$0.4551` (`S3`)** (**`1.58×`** raw suite ratio / **`1.64×`** mean matched dollar multiplier). Mean valid-run tokens rose **`1.72×`** (`1.86M -> 3.19M`), median thinking tokens rose **`1.85×`** (`13,452 -> 24,835`), REA MCP tool errors spiked on `S3_Combined` (`7.0%` vs `3.8%–4.7%`), and pre-write runtime `./chal` probes more than doubled (`2.5 -> 5.6`).
3. **Why Dollar Growth Trails Token Growth:** Multi-turn prefix caching covered **`93.0%–94.7%`** of all input tokens (`$0.075 / 1M`, 90% below uncached `$0.75 / 1M`), cushioning the raw token growth relative to full uncached/output rates.
4. **Why `--unlimited` Was Necessary:** Among the 78 active runs, **77/78** exceeded the original `max_turns=25` limit, **29/78** exceeded `max_mcp_calls=30` (14/19 in `S3`), and **35/78** exceeded `timeout_seconds=300` (16/19 in `S3`). Without `--unlimited`, the majority of runs across all four scenarios would have been truncated.

---

## 2. Results Summary

### 2.1 Raw Aggregate Telemetry (All 80 Runs from [summary_table.md](file:///home/arch/work/softwareProt/Experimentation/obf-agent-bench/results/summary_table.md))

| Metric | `S0_Baseline` (`n=20`) | `S1_Flatten` (`n=20`) | `S2_EncodeData` (`n=20`) | `S3_Combined` (`n=20`) |
| :--- | :--- | :--- | :--- | :--- |
| **I/O Pass Rate `Pass_IO` (%)** | 95.0% (`19/20`) | 100.0% (`20/20`) | 100.0% (`20/20`) | 95.0% (`19/20`) |
| **Gate Breakdown (Compile / Boundary / Fuzz)** | 95% / 95% / 95% | 100% / 100% / 100% | 100% / 100% / 100% | 95% / 95% / 95% |
| **Avg Run Cost (USD)** | `$0.2736` | `$0.3446` | `$0.3723` | `$0.4331` |
| **USD Breakdown (In / Cache / Think / Out)** | `$0.0916 / $0.1220 / $0.0497 / $0.0103` | `$0.1033 / $0.1616 / $0.0681 / $0.0116` | `$0.1101 / $0.1792 / $0.0711 / $0.0120` | `$0.1193 / $0.2133 / $0.0865 / $0.0140` |
| **ECSR (USD per Passing Binary)** | `$0.2880` | `$0.3446` | `$0.3723` | `$0.4559` |
| **`OCM_cost` (Mean Spend Ratio vs `S0`)** | `1.00×` | `1.26×` | `1.36×` | `1.58×` |
| **Mean Total Tokens** | `1,764,585` | `2,313,683` | `2,557,690` | `3,029,830` |
| **Pairwise Token `OCM` (Mean / Median)* ** | `1.00× / 1.00×` | `7.41× / 1.24×` | `11.85× / 1.40×` | `12.21× / 1.67×` |
| **Context Cache Hit Rate (%)** | `93.0%` | `94.0%` | `94.2%` | `94.7%` |
| **Reasoning Tokens `T_think` (Median)** | `13,406` | `17,078` | `18,812` | `24,582` |
| **Peak Context `T_peak` (Max / % 128k)** | `86,019` (`67.2%`) | `109,078` (`85.2%`) | `94,203` (`73.6%`) | `111,340` (`87.0%`) |
| **Turns (Mean / Median)** | `39.8 / 42.0` | `45.8 / 45.5` | `46.9 / 46.5` | `50.9 / 51.0` |
| **REA MCP Calls (OK / Err, Err Rate)** | `22.4 / 1.1` (`22` err, `4.7%`) | `25.5 / 1.1` (`22` err, `4.1%`) | `29.3 / 1.1` (`23` err, `3.8%`) | `29.4 / 2.2` (`44` err, `7.0%`) |
| **MCP Payload Volume (Mean Bytes)** | `78,504 B` | `92,156 B` | `113,820 B` | `112,776 B` |
| **Wall Time Mean (LLM / MCP Sec)** | `247.4s` (`232.6 / 8.6`) | `309.7s` (`289.4 / 9.3`) | `304.5s` (`294.6 / 9.6`) | `355.1s` (`341.6 / 11.9`) |
| **Runtime `./chal` Probes (Total / Pre-Write)** | `4.8 / 2.5` | `6.0 / 3.1` | `6.7 / 4.3` | `7.6 / 5.6` |
| **Binary `.text` Size / Instructions** | `678 B` / `168` (`1.00×`) | `887 B` / `213` (`1.31×`) | `1,683 B` / `373` (`2.48×`) | `1,798 B` / `407` (`2.65×`) |
| **Indirect Jumps / Cond. Branches / Cyc. Est** | `2.0 / 11.2 / 14.2` | `3.2 / 9.2 / 13.3` | `3.0 / 18.1 / 22.1` | `4.8 / 12.0 / 17.8` |
| **Scenario Suite Cost (`n=20`)** | `$5.4725` | `$6.8929` | `$7.4465` | `$8.6619` |

*\*Note: The unweighted mean of sample-wise token ratios (`7.41× / 11.85× / 12.21×`) is heavily skewed by a single 1-turn safety-filter failure in `S0_Baseline` (see Section 3.1).*

### 2.2 Outlier-Adjusted Clean Comparison (78 Active Runs & 18 Matched Quadruplets)

Removing the two Turn-1 safety-filter refusals isolates the true technical effect of Tigress obfuscation:

| Clean Cohort Metric | `S0_Baseline` (`n=19`) | `S1_Flatten` (`n=20`) | `S2_EncodeData` (`n=20`) | `S3_Combined` (`n=19`) |
| :--- | :--- | :--- | :--- | :--- |
| **Clean `Pass_IO`** | **100.0% (`19/19`)** | **100.0% (`20/20`)** | **100.0% (`20/20`)** | **100.0% (`19/19`)** |
| **Mean / Median Cost (USD)** | `$0.2873 / $0.3122` | `$0.3446 / $0.3290` | `$0.3723 / $0.3516` | `$0.4551 / $0.4602` |
| **Mean / Median Total Tokens** | `1,856,634 / 1,913,006` | `2,313,682 / 2,185,281` | `2,557,690 / 2,437,782` | `3,188,458 / 3,289,627` |
| **Matched Pairwise Dollar `OCM` (`n=18`, Mean / Med)** | `1.00× / 1.00×` | `1.23× / 1.19×` | `1.29× / 1.24×` | `1.64× / 1.47×` |
| **Matched Pairwise Token `OCM` (`n=18`, Mean / Med)** | `1.00× / 1.00×` | `1.34× / 1.19×` | `1.43× / 1.30×` | `1.88× / 1.67×` |
| **Matched Tool / Turn Ratios (`n=18`, Mean)** | `1.00× / 1.00×` | `1.09× / 1.12×` | `1.25× / 1.13×` | `1.35× / 1.35×` |
| **Mean Turns / Mean Wall Time** | `41.8` / `259.7s` | `45.8` / `309.7s` | `46.9` / `304.5s` | `53.5` / `372.9s` |

---

## 3. Outlier & Anomaly Analysis

### 3.1 Turn-1 Safety-Filter False Positives (`mcp=0`, `reconstructed.c` missing)
Two runs aborted on Turn 1 with `status: "SUCCESS"` after Gemini's safety filter mistakenly flagged the reverse-engineering task despite thinking text stating the task was benign source reconstruction:
- **`S0_Baseline/CWE191_Integer_Underflow__int64_t_fscanf_sub_01`**: `1` turn, `15,640` tokens, `$0.0137`, `14.3s`, `mcp=0`.
- **`S3_Combined/CWE190_Integer_Overflow__char_fscanf_preinc_01`**: `1` turn, `15,887` tokens, `$0.0147`, `15.7s`, `mcp=0`.

**Downstream statistical distortion:** Because `S0_Baseline/CWE191_..._int64_t_fscanf_sub_01` acted as the `S0` baseline denominator with only `15,640` tokens, its pairwise ratios exploded to **`122.40×` (`S1`)**, **`209.07×` (`S2`)**, and **`210.33×` (`S3`)** (`21.51× / 33.12× / 33.53×` in USD). Those single-sample ratios inflated `ocm_all.tokens_mean` from the true `~1.3×–1.9×` range to **`7.41× / 11.85× / 12.21×`**.

### 3.2 Extreme Resource & Tool-Error Outliers
- **#1 Token & Wall-Time Run — `S1_Flatten/CWE191_Integer_Underflow__unsigned_int_fscanf_postdec_01`:** `4,834,036` tokens (`$0.5898`), **`69` turns**, **`529.7s`** wall time, `25` MCP calls (`1` err). Root cause: between Steps 46 and 98, the agent issued **27 consecutive `search_web` queries** before returning to `rea:xrefs` / `rea:read_bytes` to finish the reconstruction cleanly.
- **#1 Dollar Cost & Turn Run — `S3_Combined/CWE190_Integer_Overflow__char_fscanf_add_01`:** **`$0.6206` (`3.36×` its `S0`, `5.43×` tokens)**, **`75` turns**, `4,785,449` tokens, `446.6s`, `39` MCP calls (`2` errored `execute_rizin_command`), **`9` pre-write `./chal` probes**. Combined flattening (`5` indirect jumps) + arithmetic/literal encoding (`426` instructions) forced repeated fallback to raw instruction/byte inspection and empirical input/output verification.
- **#1 MCP Call, Error & Context Outlier — `S3_Combined/CWE369_Divide_by_Zero__int_fscanf_divide_01`:** **`47` MCP calls (`8` errors = `17.0%`)**, peak context **`111,340` (`87.0%` of the 128k ceiling)**, `4,139,120` tokens (`$0.5576`), `56` turns, `449.4s`. Failed calls spanned `execute_rizin_command` (`3`), `search_procedures` (`1`), `read_bytes` (`1`), `analyze_function` (`1`), `annotate_native_function` (`1`), and `decompile_all` (`1`).
- **Recurring MCP Error Pattern (`111` total across 80 runs):** `search_procedures` accounted for **`47` errors (`42.3%`)** when the model guessed `query` instead of `pattern` (because `hook_guard.py` blocked direct filesystem reads of `.gemini/.../mcp/rea`), followed by `read_bytes` (`17`), `search_strings` (`12`), `execute_rizin_command` (`12`), and `annotate_native_function` (`8`).

### 3.3 Unblocked `search_web` Usage (`10` Runs, `83` Calls)
Audit of raw tool invocations revealed **10 active runs** (`S0`: 4 runs / 29 calls; `S1`: 4 runs / 48 calls; `S2`: 0; `S3`: 2 runs / 6 calls; `83` calls total) invoked `search_web` with Juliet-derived string literals and function names (`"data value is too large to perform arithmetic safely."`, `site:github.com`, `site:gitlab.com`).
- **Practical impact:** In inspected traces, Google search grounding returned conceptual Juliet explanations (sometimes for the wrong operator, e.g., `multiply` on `square_01`) rather than verbatim file contents, and in `S1_postdec` wasted 27 turns before the agent resumed REA analysis.
- **Experimental validity risk:** Leaving `search_web` unblocked creates an unintended side channel outside the binary jail and distorts cost/latency comparisons on runs that enter web-search loops.

### 3.4 Cost Inversions Across Scenarios
In the 18 matched quadruplets, **`6/18` samples cost less in `S1_Flatten` than `S0_Baseline`**, **`2/18` cost less in `S2_EncodeData` than `S0_Baseline`**, and **`0/18` cost less in `S3_Combined` than `S0_Baseline`** (closest: `CWE191_Integer_Underflow__int_fscanf_predec_01` at `$0.3498` vs `$0.3396`, `1.03×`). In the `S1`/`S2` inversions, either `S0` spent extra turns on redundant `xrefs` or `search_web` queries, or the agent paired `rea:procedure_pseudo_code` with pre-write `./chal` empirical probes (`S3` averaged `5.6` pre-write `./chal` runs vs `2.5` in `S0`) to infer constant/overflow boundaries without exhaustively simplifying every MBA instruction by hand.

---

## 4. Sandbox & Framework Compliance Audit

- **Strict REA Lifecycle Adherence:** Across all 78 active runs, **78/78 (`100%`)** began with `rea:open_binary` and ended with `rea:close_binary` (`81` calls each), alongside `594` `procedure_pseudo_code`, `265` `read_bytes`, `256` `procedure_assembly`, and `214` `xrefs` calls.
- **Sandbox Integrity (`3,500` allows vs `96` denies, Zero Cheating):** Every single hook denial in `hook_audit.jsonl` belonged to benign/technical friction rather than sandbox escape attempts:
  1. `78` denials: `agy` trying to `read_file` its own truncated `.system_generated/steps/*/output.txt` summaries stored outside `/tmp/run_<uuid>`.
  2. `15` denials: false-positive path regex hits (`'/*'` or `'/'`) inside C comments/expressions passed to `edit_file` targeting `reconstructed.c`.
  3. `3` denials: attempts to read REA schema metadata under `/home/arch/.gemini/antigravity-cli/mcp/rea`.
  - **Zero** parent-directory escapes (`..`), ground-truth reads, cross-jail reads, or banned CLI disassembler calls (`objdump`, `readelf`, `strings`, `nm`, `gdb`, `rizin`).

---

## 5. Recommendations for Next Iteration

1. **Deny `search_web` in [hook_guard.py](file:///home/arch/work/softwareProt/Experimentation/obf-agent-bench/runner/hook_guard.py):** Explicitly block `search_web` (and `fetch_url` / web tools) during benchmark runs so cost and accuracy strictly isolate REA static analysis + local jail execution.
2. **Mitigate Turn-1 Safety-Filter False Positives:** Add automatic single-retry / Turn-1 re-prompt handling in [orchestrator.py](file:///home/arch/work/softwareProt/Experimentation/obf-agent-bench/runner/orchestrator.py) whenever `turns == 1 and mcp_calls == 0` and response matches Gemini's filter refusal text, and frame [rea_task.md](file:///home/arch/work/softwareProt/Experimentation/obf-agent-bench/runner/prompts/rea_task.md) around deterministic differential recompilation / compiler testing.
3. **Avoid `/*` False Positives in `hook_guard.py`:** Add `Target` and `Replacement` (and `Search` / `Pattern`) to `SKIP_KEYS` in [hook_guard.py](file:///home/arch/work/softwareProt/Experimentation/obf-agent-bench/runner/hook_guard.py#L25-L28) when checking file-edit tools whose `Path` already validates inside the jail.
4. **Control Dynamic `./chal` Probing if Measuring Pure Static Deobfuscation:** If evaluating purely static MBA/CFF comprehension rather than hybrid REA + dynamic black-box testing, consider logging or restricting pre-write `./chal` invocations in `S2`/`S3` (`5.6` pre-write probes on `S3` currently amortize arithmetic/literal deobfuscation).
5. **Surface Median `OCM` in Reports:** Expose `ocm_all["tokens_median"]` and matched clean-cohort OCM prominently in [summary_table.md](file:///home/arch/work/softwareProt/Experimentation/obf-agent-bench/results/summary_table.md) so a single Turn-1 `S0` abort never skews headline OCM interpretation.

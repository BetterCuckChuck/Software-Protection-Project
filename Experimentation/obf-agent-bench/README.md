# obf-agent-bench — Tigress vs. REA Agent (Week 2)

Benchmark pipeline implementing `week2_plan.md`: 20 NIST Juliet v1.3 C programs across 4 Tigress obfuscation scenarios (80 benchmark targets). Each run evaluates an autonomous reverse engineering agent built strictly upon the **REA (Reverse Engineer Anything)** framework against stripped x86-64 ELF binaries (`./chal`), reconstructing compilable, functionally equivalent C code (`./reconstructed.c`).

Performance is measured along two primary axes:
1. **Axis 1 – Behavioral I/O Equivalency:** 3-gate deterministic testing (static sanitization, 15 boundary cases, 50 differential-fuzz cases).
2. **Axis 2 – Agentic Cost & Telemetry:** Exact LLM token breakdown (uncached input, prefix-cached input, thinking/reasoning, output), REA MCP call breakdown, Obfuscation Cost Multiplier ($OCM$), and Expected Cost per Successful Reconstruction ($ECSR$).

```
configs/
  experiment.yaml          # Master config (models, REA MCP runtime, pricing, limits)
  tigress_recipes.yaml     # S0..S3 Tigress obfuscation templates
dataset/
  prepare_dataset.py       # Deterministic sampler, normalizer (single-TU), vector generator
  samples_20.json          # Manifest of 20 Juliet programs
  normalized_src/          # Deterministic single-TU C sources
  test_vectors/            # Hidden 65 test vectors per sample (never in agent jail)
builder/
  build_scenarios.py       # Tigress -> gcc -O2 -s -> static stats + semantic validation vs S0
build/
  <scenario>/<sample_id>/  # Stripped chal binaries, binary_stats.json, obfuscated sources
runner/
  orchestrator.py          # Jail manager, agy + REA spawner, stream limiter, telemetry collector
  hook_guard.py            # PreToolUse security hook enforcing strict sandbox boundary
  verify_rea_env.sh        # Preflight verification of REA MCP server & Ghidra 12.1.4 engine
  stream_telemetry.py      # Parses agy stream-json NDJSON events into structured metrics
  prompts/rea_task.md      # REA-native binary analysis task prompt
evaluator/
  io_harness.py            # Axis 1: Gate 1 sanitization/compile + Gate 2/3 differential testing
  cost_evaluator.py        # Axis 2: OCM, ECSR, summary matrix markdown, simulator.html
results/
  <scenario>/<sample_id>/  # Per-run telemetry.json, run_metrics.json, io_result.json, reconstructed.c
tests/
  test_bench.py            # Offline unit & integration test suite (no network/LLM required)
  fake_agy.py              # Mock agy stream emitter simulating REA tool interactions
```

---

## REA Framework Specification for Native Binaries

The agentic system operates strictly under the **REA (Reverse Engineer Anything)** native binary reverse-engineering methodology backed by the `rea` MCP server:

1. **Target Binding (`open_binary`):**
   The agent begins by binding `./chal` to establish the analysis session.
2. **Overview & Layout (`binary_overview`):**
   Inspects image base, segment memory layout (`.text`, `.rodata`), and procedure inventories without bloat.
3. **Symbol & String Discovery:**
   - `list_procedures` inventories exported, imported, and resolved local functions.
   - `list_strings` / `search_strings` locates constant strings (e.g., format specifiers `"%d"` and test printouts).
   - Traces from the ELF `entry` point to identify the user `main` passed to `__libc_start_main`.
4. **Surgical Decompilation & Flow Tracing:**
   - `procedure_pseudo_code` (`procedure: "<address or symbol>"`) decompiles user logic functions.
   - `procedure_assembly` or `read_function_instructions` inspects exact instruction sequences.
   - `procedure_callees`, `procedure_callers`, and `xrefs` map call and data references.
   - **Anti-Bloat Discipline:** Never decompiles compiler/runtime startup stubs (`_start`, `__libc_csu_init`, `frame_dummy`).
5. **Deobfuscation Discipline:**
   - **Control-Flow Flattening:** Simplifies state-machine `switch` dispatchers into structured C (`if/else`, `while`, `for`).
   - **MBA Expressions:** Simplifies Mixed Boolean-Arithmetic expressions into canonical C operators (`+`, `-`, `*`, `/`, `%`).
6. **Session Teardown (`close_binary`):**
   Closes the binary session before emitting final output to `./reconstructed.c`.

---

## Execution Workflow

### 1. Verify REA Environment
```bash
cd Experimentation/obf-agent-bench
bash runner/verify_rea_env.sh
```
Confirms that `agy` is present, the `rea` MCP server is enabled, and the underlying Ghidra engine (`/home/arch/ghidra_12.1.4_PUBLIC`) is accessible.

### 2. Dataset Preparation & Binary Build
```bash
# Normalize 20 Juliet v1.3 programs and generate 65 hidden vectors per sample
python3 dataset/prepare_dataset.py

# Build all 80 binaries across S0_Baseline, S1_Flatten, S2_EncodeData, S3_Combined
python3 builder/build_scenarios.py
```

### 3. Run Benchmark Orchestrator
```bash
# Run one sample or scenario:
python3 runner/orchestrator.py --scenarios S1_Flatten --samples CWE190_Integer_Overflow__char_fscanf_add_01

# Raise max_turns / max_mcp_calls / timeout_seconds to infinite (--unlimited, or pass <= 0 individually):
python3 runner/orchestrator.py --scenarios S0_Baseline S1_Flatten S2_EncodeData S3_Combined \
  --samples CWE190_Integer_Overflow__char_fscanf_add_01 --unlimited

# Resume / run full benchmark suite:
python3 runner/orchestrator.py --config configs/experiment.yaml --resume
```

### 4. Evaluate Cost & Generate Interactive Simulator
```bash
python3 evaluator/cost_evaluator.py
# Generates:
#   - results/benchmark_summary.json
#   - results/summary_table.md
#   - results/simulator.html (standalone interactive visualization)
```

### 5. Run Offline Test Suite
```bash
python3 -m unittest discover -s tests -v
```
Verifies all 11 unit and integration tests across dataset parsing, stream telemetry extraction, hook guard security decisions, I/O grading, and end-to-end pipeline execution with mock agents.

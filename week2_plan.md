## **1\. Updated Benchmark Architecture**

The pipeline now pairs **Behavioral I/O Equivalency** with **Agentic Cost & Telemetry Analysis**:

Plaintext  
obf-agent-bench/  
├── configs/  
│   ├── experiment.yaml          \# Master config (models, scenarios, budgets, token pricing)  
│   └── tigress\_recipes.yaml     \# Modular Tigress CLI flag templates  
├── dataset/  
│   ├── raw\_juliet/              \# Selected 20 NIST Juliet v1.3 C files  
│   ├── normalized\_src/          \# Single-TU merged C files (deterministic stdin/argv)  
│   └── test\_vectors/            \# Per-program JSON input/output test suites (hidden from agent)  
├── build/  
│   └── \<scenario\_id\>/\<sample\_id\>/  
│       ├── chal                 \# Stripped target ELF binary  
│       ├── binary\_stats.json    \# Static binary size, .text bytes, cyclomatic complexity  
│       └── ghidra\_proj/         \# Pre-analyzed headless Ghidra project  
├── workspace\_jail/              \# Ephemeral per-run directory (/tmp/run\_\<uuid\>/chal)  
├── runner/  
│   ├── orchestrator.py          \# Spawns Antigravity \+ REA \+ Ghidra MCP & hooks API telemetry  
│   └── prompts/rea\_task.md      \# Single-deliverable REA task prompt (reconstructed.c only)  
└── evaluator/  
    ├── io\_harness.py            \# Compiles reconstructed.c & runs curated \+ fuzz I/O tests  
    └── cost\_evaluator.py        \# Computes token/tool overhead, OCM, and Cost-per-Success

## **2\. Streamlined Agent Prompt (prompts/rea\_task.md)**

With semantic prose grading removed, the agent has a single deliverable (./reconstructed.c). This keeps token telemetry clean and directly comparable across scenarios:

Markdown  
\# ROLE & OBJECTIVE  
You are an autonomous reverse engineering agent operating strictly under the REA (Reverse Engineer Anything) methodology. Your target is the stripped x86-64 ELF binary located at \`./chal\`.

Your sole objective is to analyze the binary's logic and reconstruct a clean, compilable, functionally equivalent C source file saved to \`./reconstructed.c\`.

\# OPERATIONAL CONSTRAINTS (STRICT)  
1\. \*\*Sandbox Boundary:\*\* Operate strictly within the current working directory (\`.\`). Do NOT traverse parent directories (\`..\`), inspect environment variables, or search the filesystem outside \`.\`.  
2\. \*\*Surgical Tool Usage (Anti-Bloat):\*\*  
   \- Strictly follow the REA workflow: Triage entry/imports \-\> Identify \`main\` and user-defined functions \-\> Analyze target functions selectively.  
   \- Use targeted Ghidra MCP calls (e.g., \`list\_functions\`, \`analyze\_function\`, \`decompile\_function\`, \`get\_xrefs\`) ONLY on user-logic functions.  
   \- Do NOT decompile standard C runtime startup routines (\`\_start\`, \`\_\_libc\_csu\_init\`, \`frame\_dummy\`, \`register\_tm\_clones\`).  
3\. \*\*Deobfuscation Discipline:\*\*  
   \- Simplify any control-flow flattening (\`switch\` state-machine dispatchers) or Mixed Boolean-Arithmetic (MBA) expressions into structured C control flow (\`if/else\`, \`for\`, \`while\`) and simplified arithmetic expressions.

\# REQUIRED DELIVERABLE  
Write your final output to \`./reconstructed.c\`:  
\- Must be valid, self-contained C11 source code that compiles cleanly with \`gcc \-O2 reconstructed.c \-o recon\_bin\`.  
\- Must preserve the exact CLI/stdin/stdout interface and exit codes of \`./chal\`.  
\- Do NOT write auxiliary summary files or markdown reports.

## **3\. Evaluation Axis 1: Code Reproduction (I/O Equivalency)**

evaluator/io\_harness.py grades ./reconstructed.c deterministically in three sequential stages:

> 1. **Gate 1 — Static Sanitization & Compilation:** Rejects files containing forbidden system calls (system, popen, exec\*, dlopen, inline \_\_asm\_\_) and compiles with gcc \-O2 \-Wall reconstructed.c \-o recon\_bin. Compilation failure yields $Pas{s}_{IO}=0$.  
> 2. **Gate 2 — Curated Boundary Vectors (${T}_{curated}$):** Executes 15 deterministic test cases covering all branch predicates, boundary conditions ($x-1,x,x+1$), 0, and INT\_MAX/INT\_MIN.  
> 3. **Gate 3 — Differential Fuzzing (${T}_{diff}$):** Executes 50 seeded random inputs comparing (stdout, stderr, exit\_code) between ./chal and ./recon\_bin.

\$\$\\text{Pass}\_{\\text{IO}} \= \\begin{cases} 1 & \\text{if } \\forall t \\in (T\_{\\text{curated}} \\cup T\_{\\text{diff}}),\\; \\text{Out}(\\text{chal}, t) \\equiv \\text{Out}(\\text{recon\\\_bin}, t) \\\\ 0 & \\text{otherwise} \\end{cases}\$\$

## **4\. Evaluation Axis 2: Cost & Efficiency Evaluation (cost\_evaluator.py)**

In an agentic setting, obfuscation succeeds either by **causing reconstruction failure** ($Pas{s}_{IO}=0$) or by **forcing severe resource exhaustion** (inflating context windows, reasoning tokens, and MCP tool calls).

### **4.1 Raw Telemetry Dimensions (Captured per Run)**

Have orchestrator.py log the following four telemetry groups from the Antigravity runtime and Ghidra MCP server into run\_metrics.json:

> 1. **LLM Token Breakdown:**  
   * **Uncached Input Tokens (${T}_{in}$):** New prompt tokens processed across all turns (heavily driven by verbose Ghidra decompiler output on flattened/MBA-obfuscated code).  
   * **Cached Input Tokens (${T}_{cache}$):** Prefix-cached context tokens reused across multi-turn REA tool loops.  
   * **Reasoning / Thinking Tokens (${T}_{think}$):** Internal chain-of-thought tokens used by gemini-3.8-flash to algebraically simplify MBA expressions or trace state variables.  
   * **Output Completion Tokens (${T}_{out}$):** Tokens emitted for MCP tool calls and writing reconstructed.c.  
   * **Peak Context Length (${T}_{peak}$):** Maximum token count in a single turn ($\max\limits_{t}(Contex{t}_{t})$), measuring context-window saturation risk.  
> 2. **MCP Tool & Turn Overhead:**  
   * **Reasoning Turns (${N}_{turns}$):** Total LLM request-response cycles.  
   * **MCP Tool Call Count (${N}_{mcp}$):** Total calls and per-tool breakdown (decompile\_function, analyze\_function, get\_xrefs, list\_functions).  
   * **Decompiler Payload Volume (${B}_{mcp}$):** Total characters/bytes returned by Ghidra MCP into the agent's context.  
> 3. **Latency Breakdown:**  
   * **Total Wall-Clock Time (${t}_{wall}$):** Split into **LLM Inference Time (${t}_{llm}$)** and **MCP Tool Execution Time (${t}_{mcp}$)**.

### **4.2 Derived Research Metrics (Cross-Scenario Formulas)**

To avoid common statistical traps (such as a failed run terminating on Turn 2 and artificially lowering average token usage), compute three normalized cost metrics across Scenarios S0 (Baseline), S1 (Flatten), S2 (EncodeData), and S3 (Combined):  
> **Per-Run Monetary Cost (${C}_{run}$):**  
> Using standard per-million-token pricing rates (${P}_{in},{P}_{cache},{P}_{out}$):

> $${C}_{run}=\frac{{T}_{in}\cdot {P}_{in}+{T}_{cache}\cdot {P}_{cache}+({T}_{think}+{T}_{out})\cdot {P}_{out}}{1{0}^{6}}$$

> 1. 

> **Obfuscation Cost Multiplier ($OCM$):**  
> For each sample \$i \\in \\{1 \\dots 20\\}\$ and obfuscation scenario ${S}_{k}\in \{{S}_{1},{S}_{2},{S}_{3}\}$, normalize total tokens and tool calls against the unobfuscated stripped baseline ${S}_{0}$:

> $$OC{M}_{tokens}({S}_{k},i)=\frac{{T}_{total}({S}_{k},i)}{{T}_{total}({S}_{0},i)},OC{M}_{tools}({S}_{k},i)=\frac{{N}_{mcp}({S}_{k},i)}{{N}_{mcp}({S}_{0},i)}$$

> 2.   
>    *Note:* Compute $OCM$ specifically over the subset of samples where $Pas{s}_{IO}({S}_{k},i)=1$ to measure pure overhead on successful breaks, alongside the full-dataset distribution.

> **Expected Cost per Successful Reconstruction ($ECSR$):**  
> Combines accuracy and cost into a single unified security metric: the total cost expended across all 20 attempts in scenario ${S}_{k}$ divided by the number of successful reconstructions:

> $$ECSR({S}_{k})=\frac{\sum\limits_{i=1}^{20}{C}_{run}({S}_{k},i)}{\sum\limits_{i=1}^{20}Pas{s}_{IO}({S}_{k},i)}$$

> 3.   
>    As an obfuscation technique gets stronger, $\sum\limits_{}^{}Pas{s}_{IO}$ drops while $\sum\limits_{}^{}{C}_{run}$ rises, causing $ECSR$ to grow sharply.

## **5\. Summary Evaluation Table Schema**

Structure your final experiment aggregation (evaluator/cost\_evaluator.py output) using this comparison matrix across the 80 runs (20 files × 4 scenarios):

| Metric | Symbol / Unit | S0\_Baseline | S1\_Flatten | S2\_DataMBA | S3\_Combined |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **I/O Pass Rate** | **$Pas{s}_{IO}$** (%) | Baseline (%) | \$\\Delta\\%\$ vs S0 | \$\\Delta\\%\$ vs S0 | \$\\Delta\\%\$ vs S0 |
| **Partial Test Accuracy** | **$Ac{c}_{IO}$** (%) | Mean $\pm$ SD | Mean $\pm$ SD | Mean $\pm$ SD | Mean $\pm$ SD |
| **Input \+ Cache Tokens** | **${T}_{in}+{T}_{cache}$** | Median / IQR | Median / IQR | Median / IQR | Median / IQR |
| **Reasoning Tokens** | **${T}_{think}$** | Median / IQR | Median / IQR | Median / IQR | Median / IQR |
| **Peak Context Window** | **${T}_{peak}$** (tokens) | Max / Median | Max / Median | Max / Median | Max / Median |
| **Ghidra MCP Calls** | **${N}_{mcp}$** (calls) | Mean $\pm$ SD | Mean $\pm$ SD | Mean $\pm$ SD | Mean $\pm$ SD |
| **Obfuscation Cost Multiplier** | **$OC{M}_{tokens}$** ($\times$) | $1.00\times$ | $X.XX\times$ | $X.XX\times$ | $X.XX\times$ |
| **Expected Cost / Success** | **$ECSR$** (\$ or Tokens) | Baseline Cost | Cost / Break | Cost / Break | Cost / Break |

## **6\. Updated Master Configuration (configs/experiment.yaml)**

YAML  
experiment\_name: "tigress\_vs\_rea\_juliet20\_io\_cost"  
random\_seed: 42

dataset:  
  source\_suite: "nist\_juliet\_cpp\_1.3"  
  sample\_count: 20  
  manifest\_path: "./dataset/samples\_20.json"

scenarios:  
  S0\_Baseline:  
    tigress\_transforms: \[\]  
    compiler\_flags: \["-O2", "-fno-stack-protector", "-fno-ident", "-s"\]  
  S1\_Flatten:  
    tigress\_transforms:  
      \- "--Transform=Flatten \--FlattenDispatch=switch"  
    compiler\_flags: \["-O2", "-fno-stack-protector", "-fno-ident", "-s"\]  
  S2\_EncodeData:  
    tigress\_transforms:  
      \- "--Transform=EncodeArithmetic"  
      \- "--Transform=EncodeLiterals"  
    compiler\_flags: \["-O2", "-fno-stack-protector", "-fno-ident", "-s"\]  
  S3\_Combined:  
    tigress\_transforms:  
      \- "--Transform=Flatten \--FlattenDispatch=switch"  
      \- "--Transform=EncodeArithmetic"  
      \- "--Transform=EncodeLiterals"  
    compiler\_flags: \["-O2", "-fno-stack-protector", "-fno-ident", "-s"\]

agent\_runtime:  
  platform: "antigravity"  
  framework: "REA"  
  model: "gemini-3.8-flash"  
  temperature: 0.1  
  mcp\_server: "ghidra-mcp-headless"  
  deliverable\_file: "reconstructed.c"  
  limits:  
    max\_turns: 25  
    max\_mcp\_calls: 30  
    max\_context\_tokens: 128000  
     max\_output\_tokens: 16384  
    timeout\_seconds: 300  
  sandbox:  
    isolate\_cwd: true  
    allow\_parent\_traversal: false

evaluation:  
  io\_equivalence:  
    curated\_cases\_per\_file: 15  
    differential\_fuzz\_cases: 50  
    timeout\_per\_test\_ms: 2000  
  cost\_telemetry:  
    track\_per\_turn\_tokens: true  
    track\_mcp\_payload\_bytes: true  
    pricing\_per\_1m\_tokens\_usd:  
      input\_uncached: 0.15  
      input\_cached: 0.0375  
      output\_and\_reasoning: 0.60  
    metrics:  
      \- "total\_tokens"  
      \- "reasoning\_token\_ratio"  
      \- "peak\_context\_tokens"  
      \- "mcp\_call\_count"  
      \- "obfuscation\_cost\_multiplier"  
      \- "expected\_cost\_per\_success"

## **Interactive Cost & Resilience Simulator**

## **1\. Per-Run Telemetry Contract (telemetry.json)**

Have runner/orchestrator.py and evaluator/io\_harness.py write a standardized telemetry.json file into results/\<scenario\_id\>/\<sample\_id\>/telemetry.json at the end of every run:

JSON  
{  
  "scenario": "S1\_Flatten",  
  "sample\_id": "CWE190\_Integer\_Overflow\_\_int\_fscanf\_add\_01",  
  "io\_passed": true,  
  "io\_tests\_passed": 65,  
  "io\_tests\_total": 65,  
  "tokens": {  
    "input\_uncached": 34200,  
    "input\_cached": 8500,  
    "reasoning": 9800,  
    "output": 1750,  
    "peak\_context": 19400  
  },  
  "mcp\_calls": 11,  
  "wall\_time\_sec": 28.4  
}

## **2\. Evaluator & Simulator Generator (evaluator/cost\_evaluator.py)**

This script reads your configs/experiment.yaml pricing table and all telemetry.json files, computes $OCM$ and $ECSR$, prints a summary table to your terminal, and generates results/simulator.html with live sliders initialized to your real measurements:

Python  
\#\!/usr/bin/env python3  
"""  
Aggregates REA \+ Ghidra MCP telemetry across Tigress scenarios, computes  
Obfuscation Cost Multiplier (OCM) and Expected Cost per Successful  
Reconstruction (ECSR), and renders a standalone interactive HTML simulator.  
"""

import json  
import math  
from pathlib import Path  
import statistics  
import yaml

def load\_config(config\_path: Path) \-\> dict:  
    with config\_path.open("r", encoding="utf-8") as f:  
        return yaml.safe\_load(f)

def compute\_run\_cost(tokens: dict, pricing: dict) \-\> float:  
    in\_uncached \= tokens.get("input\_uncached", 0\)  
    in\_cached \= tokens.get("input\_cached", 0\)  
    reasoning \= tokens.get("reasoning", 0\)  
    output \= tokens.get("output", 0\)

    cost \= (  
        in\_uncached \* pricing\["input\_uncached"\]  
        \+ in\_cached \* pricing\["input\_cached"\]  
        \+ (reasoning \+ output) \* pricing\["output\_and\_reasoning"\]  
    ) / 1\_000\_000.0  
    return cost

def aggregate\_results(results\_dir: Path, config: dict) \-\> dict:  
    pricing \= config\["evaluation"\]\["cost\_telemetry"\]\["pricing\_per\_1m\_tokens\_usd"\]  
    scenario\_order \= list(config\["scenarios"\].keys())  
    grouped \= {sc: \[\] for sc in scenario\_order}

    for tel\_file in sorted(results\_dir.glob("\*/\*/telemetry.json")):  
        data \= json.loads(tel\_file.read\_text(encoding="utf-8"))  
        sc \= data\["scenario"\]  
        if sc not in grouped:  
            grouped\[sc\] \= \[\]

        tok \= data\["tokens"\]  
        total\_tok \= (  
            tok.get("input\_uncached", 0\)  
            \+ tok.get("input\_cached", 0\)  
            \+ tok.get("reasoning", 0\)  
            \+ tok.get("output", 0\)  
        )  
        data\["total\_tokens"\] \= total\_tok  
        data\["total\_input\_tokens"\] \= tok.get("input\_uncached", 0\) \+ tok.get("input\_cached", 0\)  
        data\["run\_cost\_usd"\] \= compute\_run\_cost(tok, pricing)  
        grouped\[sc\].append(data)

    \# Compute baseline averages first for OCM normalization  
    baseline\_key \= scenario\_order\[0\]  
    base\_runs \= grouped.get(baseline\_key, \[\])  
    base\_avg\_tokens \= statistics.mean(\[r\["total\_tokens"\] for r in base\_runs\]) if base\_runs else 1.0  
    base\_avg\_mcp \= statistics.mean(\[r\["mcp\_calls"\] for r in base\_runs\]) if base\_runs else 1.0

    summary \= {}  
    for sc, runs in grouped.items():  
        if not runs:  
            continue

        n \= len(runs)  
        passes \= sum(1 for r in runs if r\["io\_passed"\])  
        pass\_rate \= passes / n

        avg\_in \= statistics.mean(\[r\["total\_input\_tokens"\] for r in runs\])  
        avg\_think \= statistics.mean(\[r\["tokens"\].get("reasoning", 0\) for r in runs\])  
        avg\_out \= statistics.mean(\[r\["tokens"\].get("output", 0\) for r in runs\])  
        avg\_total\_tok \= statistics.mean(\[r\["total\_tokens"\] for r in runs\])  
        avg\_mcp \= statistics.mean(\[r\["mcp\_calls"\] for r in runs\])  
        total\_cost\_usd \= sum(r\["run\_cost\_usd"\] for r in runs)

        ocm\_tokens \= avg\_total\_tok / base\_avg\_tokens if base\_avg\_tokens \> 0 else 0.0  
        ocm\_tools \= avg\_mcp / base\_avg\_mcp if base\_avg\_mcp \> 0 else 0.0  
        ecsr\_usd \= (total\_cost\_usd / passes) if passes \> 0 else None  
        ecsr\_tokens \= ((avg\_total\_tok \* n) / passes) if passes \> 0 else None

        summary\[sc\] \= {  
            "samples": n,  
            "passes": passes,  
            "io\_pass\_rate": round(pass\_rate, 4),  
            "avg\_input\_tokens": round(avg\_in, 1),  
            "avg\_reasoning\_tokens": round(avg\_think, 1),  
            "avg\_output\_tokens": round(avg\_out, 1),  
            "avg\_total\_tokens": round(avg\_total\_tok, 1),  
            "avg\_mcp\_calls": round(avg\_mcp, 2),  
            "ocm\_tokens": round(ocm\_tokens, 2),  
            "ocm\_tools": round(ocm\_tools, 2),  
            "total\_suite\_cost\_usd": round(total\_cost\_usd, 4),  
            "ecsr\_usd": round(ecsr\_usd, 4\) if ecsr\_usd is not None else None,  
            "ecsr\_tokens": round(ecsr\_tokens, 1\) if ecsr\_tokens is not None else None,  
        }

    return {"pricing": pricing, "scenarios": summary}

HTML\_TEMPLATE \= """\<\!DOCTYPE html\>  
\<html lang="en"\>  
\<head\>  
  \<meta charset="UTF-8" /\>  
  \<title\>Tigress vs. REA — Cost & Resilience Simulator\</title\>  
  \<script src="https\://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"\>\</script\>  
  \<style\>  
    body { font-family: system-ui, \-apple-system, sans-serif; background: \#0f172a; color: \#e2e8f0; margin: 0; padding: 24px; }  
    .container { max-width: 1100px; margin: 0 auto; }  
    h1 { font-size: 1.4rem; margin-bottom: 4px; }  
    .sub { color: \#94a3b8; font-size: 0.9rem; margin-bottom: 20px; }  
    .controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; background: \#1e293b; padding: 16px; border-radius: 10px; margin-bottom: 20px; }  
    .control-box label { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 6px; color: \#cbd5e1; }  
    input\[type=range\], select { width: 100%; accent-color: \#38bdf8; }  
    select { background: \#0f172a; color: \#e2e8f0; border: 1px solid \#334155; padding: 6px; border-radius: 6px; }  
    .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }  
    .kpi { background: \#1e293b; padding: 14px; border-radius: 10px; border-left: 3px solid \#38bdf8; }  
    .kpi-title { font-size: 0.75rem; text-transform: uppercase; color: \#94a3b8; }  
    .kpi-val { font-size: 1.25rem; font-weight: 700; margin-top: 4px; }  
    .chart-card { background: \#1e293b; padding: 20px; border-radius: 10px; }  
  \</style\>  
\</head\>  
\<body\>  
\<div class="container"\>  
  \<h1\>Obfuscation Cost & Resilience Simulator\</h1\>  
  \<div class="sub"\>Initialized with empirical benchmark telemetry; adjust sliders to project scaling behavior.\</div\>

  \<div class="controls"\>  
    \<div class="control-box"\>  
      \<label\>\<span\>Metric View\</span\>\</label\>  
      \<select id="metricView"\>  
        \<option value="tokens"\>Token Breakdown per Run (Input / Reasoning / Output)\</option\>  
        \<option value="ecsr"\>Expected Tokens per Successful Break (ECSR)\</option\>  
        \<option value="ocm"\>Obfuscation Cost Multiplier (OCM vs. S0)\</option\>  
      \</select\>  
    \</div\>  
    \<div class="control-box"\>  
      \<label\>\<span\>Token Overhead Scale Factor\</span\>\<span id="scaleVal"\>1.00x\</span\>\</label\>  
      \<input type="range" id="tokenScale" min="0.5" max="3.0" step="0.05" value="1.0" /\>  
    \</div\>  
    \<div class="control-box"\>  
      \<label\>\<span\>Hardest Scenario Pass Rate Override\</span\>\<span id="passVal"\>Empirical\</span\>\</label\>  
      \<input type="range" id="passOverride" min="0.05" max="1.0" step="0.05" value="0.25" /\>  
    \</div\>  
  \</div\>

  \<div class="kpis" id="kpiRow"\>\</div\>  
  \<div class="chart-card"\>\<canvas id="simChart" height="115"\>\</canvas\>\</div\>  
\</div\>

\<script\>  
const BENCHMARK\_DATA \= \_\_BENCHMARK\_JSON\_\_;  
const labels \= Object.keys(BENCHMARK\_DATA.scenarios);  
const basePassLast \= BENCHMARK\_DATA.scenarios\[labels\[labels.length \- 1\]\].io\_pass\_rate;  
document.getElementById("passOverride").value \= basePassLast \|\| 0.25;

let chartInstance \= null;

function computeSimulated() {  
  const scale \= parseFloat(document.getElementById("tokenScale").value);  
  const lastPass \= parseFloat(document.getElementById("passOverride").value);  
  document.getElementById("scaleVal").textContent \= scale.toFixed(2) \+ "x";  
  document.getElementById("passVal").textContent \= Math.round(lastPass \* 100\) \+ "%";

  const baseKey \= labels\[0\];  
  const baseSc \= BENCHMARK\_DATA.scenarios\[baseKey\];  
  const baseTotal \= baseSc.avg\_total\_tokens;

  return labels.map((key, idx) \=\> {  
    const sc \= BENCHMARK\_DATA.scenarios\[key\];  
    const mult \= idx \=== 0 ? 1.0 : scale;  
    const passRate \= idx \=== labels.length \- 1 ? lastPass : sc.io\_pass\_rate;

    const inTok \= sc.avg\_input\_tokens \* mult;  
    const thinkTok \= sc.avg\_reasoning\_tokens \* mult;  
    const outTok \= sc.avg\_output\_tokens \* mult;  
    const totalTok \= inTok \+ thinkTok \+ outTok;

    const ocm \= totalTok / baseTotal;  
    const ecsrTokens \= passRate \> 0 ? totalTok / passRate : null;  
    const pricing \= BENCHMARK\_DATA.pricing;  
    const runCost \= (inTok \* pricing.input\_uncached \+ (thinkTok \+ outTok) \* pricing.output\_and\_reasoning) / 1e6;  
    const ecsrUsd \= passRate \> 0 ? runCost / passRate : null;

    return { key, passRate, inTok, thinkTok, outTok, totalTok, ocm, ecsrTokens, ecsrUsd };  
  });  
}

function render() {  
  const view \= document.getElementById("metricView").value;  
  const rows \= computeSimulated();

  const kpiRow \= document.getElementById("kpiRow");  
  kpiRow.innerHTML \= rows.map(r \=\> \`  
    \<div class="kpi"\>  
      \<div class="kpi-title"\>$r.key(${Math.round(r.passRate \* 100)}% Pass)\</div\>  
      \<div class="kpi-val"\>\${r.ocm.toFixed(2)}x OCM\</div\>  
      \<div class="sub" style="margin:4px 0 0 0;"\>ECSR: \${r.ecsrUsd \!== null ? "\$" \+ r.ecsrUsd.toFixed(4) : "∞"}\</div\>  
    \</div\>  
  \`).join("");

  let datasets \= \[\];  
  let stacked \= false;

  if (view \=== "tokens") {  
    stacked \= true;  
    datasets \= \[  
      { label: "Input Tokens", data: rows.map(r \=\> Math.round(r.inTok)), backgroundColor: "\#38bdf8" },  
      { label: "Reasoning Tokens", data: rows.map(r \=\> Math.round(r.thinkTok)), backgroundColor: "\#a855f7" },  
      { label: "Output Tokens", data: rows.map(r \=\> Math.round(r.outTok)), backgroundColor: "\#22c55e" }  
    \];  
  } else if (view \=== "ecsr") {  
    datasets \= \[  
      { label: "Expected Tokens / Successful Break (ECSR)", data: rows.map(r \=\> r.ecsrTokens ? Math.round(r.ecsrTokens) : 0), backgroundColor: "\#f97316" }  
    \];  
  } else {  
    datasets \= \[  
      { label: "Obfuscation Cost Multiplier (OCM)", data: rows.map(r \=\> Number(r.ocm.toFixed(2))), backgroundColor: "\#eab308" }  
    \];  
  }

  if (chartInstance) chartInstance.destroy();  
  chartInstance \= new Chart(document.getElementById("simChart"), {  
    type: "bar",  
    data: { labels, datasets },  
    options: {  
      responsive: true,  
      scales: {  
        x: { stacked, ticks: { color: "\#cbd5e1" }, grid: { color: "\#334155" } },  
        y: { stacked, ticks: { color: "\#cbd5e1" }, grid: { color: "\#334155" } }  
      },  
      plugins: { legend: { labels: { color: "\#e2e8f0" } } }  
    }  
  });  
}

document.getElementById("metricView").addEventListener("change", render);  
document.getElementById("tokenScale").addEventListener("input", render);  
document.getElementById("passOverride").addEventListener("input", render);  
render();  
\</script\>  
\</body\>  
\</html\>  
"""

def main() \-\> None:  
    config \= load\_config(Path("configs/experiment.yaml"))  
    results\_dir \= Path("results")  
    summary \= aggregate\_results(results\_dir, config)

    \# Save machine-readable summary JSON  
    summary\_path \= results\_dir / "benchmark\_summary.json"  
    summary\_path.write\_text(json.dumps(summary, indent=2), encoding="utf-8")

    \# Print CLI table  
    print(f"{'Scenario':\<16} \| {'Pass':\<7} \| {'Avg Tokens':\<11} \| {'MCP':\<6} \| {'OCM':\<6} \| {'ECSR (\$)'}")  
    print("-" \* 68\)  
    for sc, m in summary\["scenarios"\].items():  
        ecsr\_str \= f"\${m\['ecsr\_usd'\]:.4f}" if m\["ecsr\_usd"\] is not None else "INF"  
        print(  
            f"{sc:\<16} \| {m\['passes'\]}/{m\['samples'\]:\<5} \| {m\['avg\_total\_tokens'\]:\<11.0f} \| "  
            f"{m\['avg\_mcp\_calls'\]:\<6.1f} \| {m\['ocm\_tokens'\]:\<5.2f}x \| {ecsr\_str}"  
        )

    \# Compile standalone interactive simulator HTML  
    html\_out \= HTML\_TEMPLATE.replace("\_\_BENCHMARK\_JSON\_\_", json.dumps(summary))  
    sim\_path \= results\_dir / "simulator.html"  
    sim\_path.write\_text(html\_out, encoding="utf-8")  
    print(f"\\nInteractive simulator written to: {sim\_path}")

if \_\_name\_\_ \== "\_\_main\_\_":  
    main()

## **3\. Running in Your Pipeline**

Add the evaluator step at the end of your benchmark execution script:

Bash  
\# 1\. Execute your orchestrator across all scenarios and samples  
python3 runner/orchestrator.py \--config configs/experiment.yaml

\# 2\. Aggregate token/MCP telemetry and build the interactive simulator  
python3 evaluator/cost\_evaluator.py

\# 3\. Open the self-contained simulator in your browser  
xdg-open results/simulator.html

Because results/simulator.html embeds your aggregated JSON directly inside the file, you can also archive or share a single .html artifact per experiment run without running a backend server.  

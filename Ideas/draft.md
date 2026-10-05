# Topic: How resilient are software protection mechanisms against Agentic System MATE attacks when resilience is measured through semantic recovery, behavioral reproduction and economic cost?

## Problem statement:
Asset: code program functionality.
Attacker: Agentic MATE attack:
có toàn quyền binary.
Agentic / LLM capability: reasoning, tool call, CoT, etc. khác người: token usages -> 
Target: Recover functionality + Generate readable code.


## Research Questions:
### RQ1 (Behavioral Reproduction)
To what extent do autonomous agentic attackers successfully reconstruct functionally equivalent, recompilable source code from obfuscated binaries across individual and composite transformations.

### RQ2 (Economic / Work Cost)
What marginal economic cost (in tokens, financial cost, and execution steps) is imposed on an agentic attacker by individual versus composite protection transformations, and do layered defenses yield super-additive work factor increases?

### RQ3 (Efficacy and Limits of Agent-Aware Defenses) (Mở rộng)
How effective are binary-level agent disruptions (adversarial prompt injections, context bloat, and tool denial of service) at derailing autonomous task trees, and what prompt engineering or defensive filtering strategies can counter these techniques? 

## Thread model

Agentic System MATE attacks
Agentic System MATE attacks (CTFAgents):
Reasoning & Planning
Stateful Task Tree
Tool Suite (sandbox environment as Kali Linux Docker)
Pipeline: Observe -> Comprehend -> Reasoning & Planning -> Verify & Refine (other software protection techniques)

## Protection technique
Obfuscation (static).
Agentic-aware: 
Prompt injection in binary.
Context Window Bloating (inject dead code).
Tool-Crashing technique.
Dynamic (anti-debug / anti-decompile / etc)

## Resilience Evaluation

Resilience: measured as the increase in attacker effort/cost to reduce obfuscation.
Maps to three dimension:
Functional Fidelity
Semantic/Structural
Economic Effort

## Dataset + Experimentation: 
LLM-based: 
Tokens usage -> API cost.
Backtracking depth: hitting deadend / backtrack in task tree.
Error ratio: tool call, false hypothesis.
Injection success rate: For prompt injection.
Code Executability / Compilability.
Code Similarity: via code summary against ground truth.
Behaviour reproduction: testing input / output equivalence.
Symbol recovery: recover function / variable names.



Pipeline



 

Topic: Software Protection in MATE attacks

Trend:
Evaluating code understanding (binary / source) of LLM.
Evaluate how effective is LLM in understanding obfuscated code.
Buliding LLM-based deobfuscation tools.
Building an agentic system capable of specific reverse engineering task (for CTF, vuln detection, taint analysis).
Systematic mapping of agentic system to software protection technique / weakness for failure analysis.
Building a general agentic system for binary analysis.
-> Benchmarking LLM is the main focus.

GAP:
No consistent metrics in measuring reslience of protections, with current LLM/Agentic attacker, economic metrics of Agentic / LLM is not formalized.
Resilience evaluation mainly comes from Research tool / ctf challenge which does not accurately reflect modern software protection technique used in industry / professional settings.
Limited paper about platform specific (Android, MacOS), most focus on Linux / Windows.
Prompt injection technique in software protection as defense.

Environment:
Cụ thể hóa: Dataset sử dụng
Pipeline: Sourcecode -> Protect -> binary -> Agentic System -> Reproduce code
Validation (Evaluation methods)
Agentic System: focus sau.
Chống anti-tampering (hashing).



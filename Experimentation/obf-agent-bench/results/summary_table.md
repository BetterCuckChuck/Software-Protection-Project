| Metric | S0_Baseline | S1_Flatten | S2_EncodeData | S3_Combined |
| :--- | :--- | :--- | :--- | :--- |
| I/O Pass Rate Pass_IO (%) | 95.0 | 100.0 (+5.0 pp vs S0) | 100.0 (+5.0 pp vs S0) | 95.0 (+0.0 pp vs S0) |
| Partial Test Accuracy Acc_IO (%) | 95.0 ± 22.4 | 100.0 ± 0.0 | 100.0 ± 0.0 | 95.0 ± 22.4 |
| Gate Breakdown (Compile / Curated / Fuzz) | 95% / 95% / 95% | 100% / 100% / 100% | 100% / 100% / 100% | 95% / 95% / 95% |
| Avg Run Cost (USD) | $0.0889 | $0.1142 | $0.1249 | $0.1466 |
| USD Cost Breakdown (In / Cache / Think / Out) | $0.0183 / $0.0610 / $0.0080 / $0.0016 | $0.0207 / $0.0808 / $0.0109 / $0.0019 | $0.0220 / $0.0896 / $0.0114 / $0.0019 | $0.0239 / $0.1066 / $0.0138 / $0.0022 |
| ECSR (USD per successful break) | $0.0936 | $0.1142 | $0.1249 | $0.1543 |
| ECSR (tokens per successful break) | 1,857,458 | 2,313,683 | 2,557,690 | 3,189,294 |
| OCM_cost (USD ratio vs S0) | 1.00× | 1.28× | 1.40× | 1.65× |
| OCM_tokens, all samples (mean of ratios) | 1.00× | 7.41× | 11.85× | 12.21× |
| OCM_tokens, successful breaks only | 1.00× | 7.41× | 11.85× | 12.86× |
| OCM_tools, all samples | 1.00× | 1.10× | 1.23× | 1.28× |
| Input + Cache Tokens (median / IQR) | 1,770,412 / 1,395,994–2,189,632 | 2,164,626 / 1,648,988–2,574,630 | 2,416,956 / 2,172,554–2,976,158 | 3,166,520 / 2,468,850–3,520,807 |
| Context Cache Hit Rate (%) | 93.0% | 94.0% | 94.2% | 94.7% |
| Reasoning Tokens T_think (median / IQR) | 13,406 / 12,294–15,338 | 17,078 / 15,791–19,836 | 18,812 / 16,599–20,858 | 24,582 / 22,050–26,106 |
| Reasoning Share of Generated Tokens (%) | 82.9% | 85.4% | 85.6% | 86.1% |
| Peak Context T_peak (max / % limit) | 86,019 (67.2%) | 109,078 (85.2%) | 94,203 (73.6%) | 111,340 (87.0%) |
| Reasoning Turns (mean / median) | 39.8 / 42.0 | 45.8 / 45.5 | 46.9 / 46.5 | 50.9 / 51.0 |
| REA MCP Calls Attempted (mean ± SD) | 23.6 ± 6.3 | 26.6 ± 2.5 | 30.4 ± 3.4 | 31.6 ± 9.2 |
| REA MCP Succeeded / Errored (err rate) | 22.4 / 1.1 (total err=22, 4.7%) | 25.5 / 1.1 (total err=22, 4.1%) | 29.3 / 1.1 (total err=23, 3.8%) | 29.4 / 2.2 (total err=44, 7.0%) |
| MCP Payload Volume (mean bytes) | 78,504 B | 92,156 B | 113,820 B | 112,776 B |
| Local Non-MCP Tools (ok / err mean) | 14.1 / 1.1 | 16.8 / 1.4 | 14.1 / 1.4 | 17.6 / 1.2 |
| Wall Time Mean (LLM / MCP s) | 247.4s (232.6s / 8.6s) | 309.7s (289.4s / 9.3s) | 304.5s (294.6s / 9.6s) | 355.1s (341.6s / 11.9s) |
| Runtime ./chal Probes (total / pre-write) | 4.8 / 2.5 | 6.0 / 3.1 | 6.7 / 4.3 | 7.6 / 5.6 |
| Binary .text Size (bytes / ratio vs S0) | 678 B (1.00×) | 887 B (1.31×) | 1,683 B (2.48×) | 1,798 B (2.65×) |
| Binary Instructions (count / ratio vs S0) | 168 (1.00×) | 213 (1.27×) | 373 (2.22×) | 407 (2.43×) |
| Indirect Jumps / Cond Branches / Cyc. Est | 2.0 / 11.2 / 14.2 | 3.2 / 9.2 / 13.3 | 3.0 / 18.1 / 22.1 | 4.8 / 12.0 / 17.8 |
| Amplification (Tokens per .text Byte) | 2,603 | 2,607 | 1,520 | 1,685 |
| Runs (n) / Suite Cost (USD) | 20 / $1.7784 | 20 / $2.2844 | 20 / $2.4978 | 20 / $2.9318 |

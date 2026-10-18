# C Deobfuscation & Logic Recovery Benchmark

You are an automated program analysis and deobfuscation agent. Your objective is to analyze Tigress-obfuscated C programs in `obfuscated/<category>/<name>.c` and write clean, human-readable, functionally identical C code to `deobfuscated/<category>/<name>.c`.

## Available Categories
- `math`
- `geometry`
- `data_structures`
- `cipher`

## Core Workflow
1. Inspect the target obfuscated source file in `obfuscated/<category>/<name>.c`.
2. Identify the core functions, data structures, and `main()` self-test assertions.
3. Simplify Tigress transformations:
   - **EncodeArithmetic**: Algebraically simplify bitwise/linear mixed boolean-arithmetic (MBA) expressions back into standard operators (`+`, `-`, `*`, `^`, `==`, `<`).
   - **Flatten**: Trace the `_1_*_next` state variable transitions inside the `while (1) { switch (...) }` dispatcher and reconstruct native structured C loops (`for`, `while`) and conditionals (`if/else`).
   - **InitOpaque**: Eliminate dead branches guarded by opaque predicates.
4. Write the clean, recovered C program to `deobfuscated/<category>/<name>.c`.
5. Run `./scripts/verify_target.sh <category> <name>` to compile and validate functional equivalence. Iterate until `[PASS]` is returned.
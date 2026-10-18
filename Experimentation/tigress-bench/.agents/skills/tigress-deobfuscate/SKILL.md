---
name: tigress-deobfuscate
description: Step-by-step methodology for deobfuscating C code transformed by Tigress (Flatten, EncodeArithmetic, InitOpaque). Use whenever recovering logic from obfuscated/*.c files.
---

# Tigress Deobfuscation Playbook

Follow these steps when recovering a file from `obfuscated/<category>/<name>.c`:

## Step 1: Strip Boilerplate & Identify Functions
1. Ignore Tigress header structs (`struct _1_...`) and system type re-declarations at the top of the file.
2. Locate all user functions and `main()`.

## Step 2: Simplify Mixed Boolean-Arithmetic (EncodeArithmetic)
Replace common Tigress MBA patterns before tracing control flow:
- `(x ^ y) + ((x & y) << 1)` or `(x | y) + (x & y)` $\rightarrow$ `x + y`
- `(x ^ y) + ((~x & y) << 1)` $\rightarrow$ `x - y`
- `~(~x | ~y)` $\rightarrow$ `x & y`
- `(x | y) - (x ^ y)` $\rightarrow$ `x & y`

## Step 3: Unflatten Control Flow (Flatten)
1. List every `case N:` block inside the `while (1) { switch (next) { ... } }` loop.
2. Build an adjacency list of transitions (`case A -> case B` unconditionally, or `case A -> if (cond) case B else case C`).
3. Identify back-edges (loops) and dominance frontiers (`if/else` merges), then rewrite as structured C loops and conditionals.

## Step 4: Write & Verify
Write the recovered code to `deobfuscated/<category>/<name>.c`. The `PostToolUse` hook will automatically run `./scripts/verify_target.sh <category> <name>`. Fix any compiler warnings or test failures immediately.
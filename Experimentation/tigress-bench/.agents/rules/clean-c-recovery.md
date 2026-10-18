---
trigger: always_on
description: Enforces structural deobfuscation and forbids copying obfuscated state machines
---

# Deobfuscation Quality Invariants

1. **No Raw State Machines**: Never copy the `switch (_1_func_next)` control-flow flattening loop into `deobfuscated/`. You must recover structured control flow (`if`, `else`, `for`, `while`, `return`).
2. **No Opaque Globals**: Strip all Tigress-injected global structs, opaque pointers, and unused `argc`/`argv` entropy initializers.
3. **Meaningful Identifiers**: Rename obfuscated local variables (`_1_main__local_1`, `tmp___0`) to descriptive names reflecting their mathematical or algorithmic role.
4. **Preserve Self-Tests**: Keep the `assert()` statements and output printing inside `main()` functionally intact so the validation harness passes.
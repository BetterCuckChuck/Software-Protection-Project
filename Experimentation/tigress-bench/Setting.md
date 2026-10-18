# Experimental Environment & Harness Settings

## 1. Benchmark Source & Dataset
- **Upstream Repository**: `https://github.com/TheAlgorithms/c`
- **Caching Mechanism**: Cloned once into `.cache/TheAlgorithms-c` (`--depth 1`) and reused offline across all experimental branches.
- **Target Categories (10 Total Programs)**:
  - `math` (5 standalone programs)
  - `cipher` (5 standalone programs)
- **Selection Criteria**: Must compile cleanly with `gcc -O2 -lm`, execute deterministically without interactive stdin (`scanf`/`fgets`), and pass all built-in assertions with exit code `0`.

## 2. Obfuscation & Compilation Pipeline
- **Obfuscator**: Tigress (`--Environment=x86_64:Linux:Gcc:4.6`)
- **Transformations (Basic Settings)**:
  1. `--Transform=InitOpaque --Functions=main --InitOpaqueStructs=array`
  2. `--Transform=Flatten --Functions=%100`
  3. `--Transform=EncodeArithmetic --Functions=%100`
  4. `--Transform=CleanUp --CleanUpKinds=names,annotations`
- **Binary Compilation**:
  - Command: `gcc -O2 -s -fno-ident -fomit-frame-pointer <obfuscated.c> -lm -o bin/<category>/<name>`
  - Stripping: `strip --strip-all --remove-section=.comment --remove-section=.note`
  - Debug Information: None (no DWARF symbols, symbol table stripped).

## 3. Agentic Attacker Configuration
- **Model Backend**: `gemini-3.8-flash`
- **Harness**: Google Antigravity CLI (`agy`) in autonomous mode (`--dangerously-skip-permissions`, `agentMode: accept-edits`).
- **Permitted Analysis Tools**:
  - **Static Analysis**: `objdump` (disassembly, `.rodata` inspection, section headers)
  - **Dynamic Analysis**: `gdb` (headless batch execution `-batch -ex ...`, register/memory tracing, breakpoints)
  - **Compilation & Validation**: `gcc`, `./scripts/verify_target.sh`
- **Information Isolation**:
  - Ground-truth directories (`original/`, `obfuscated_src/`, `.cache/`) are blocked via `.agents/settings.json` deny rules and enforced by a `PreToolUse` security hook.

## 4. Validation Protocol
1. **Ground-Truth Verification**: Each original program in `original/<category>/<name>.c` is compiled and executed during setup; its return code (`0`), stdout, and execution time are recorded into `tests/<category>/<name>.expected_stdout` and `tests/<category>/<name>_runner.sh`.
2. **Obfuscated Binary Verification**: The stripped binary in `bin/<category>/<name>` is executed against `tests/<category>/<name>_runner.sh` during setup to confirm Tigress preserved exact functional semantics.
3. **Deobfuscated Code Verification**: The agent's recovered C code in `deobfuscated/<category>/<name>.c` must:
   - Contain clean, structured C (no raw Tigress state variables or opaque dispatchers).
   - Compile cleanly under `gcc -O2 -Wall -Wextra -lm`.
   - Pass `tests/<category>/<name>_runner.sh` with zero exit code and exact output parity.

## 5. Logging Architecture
- **`logs/attacker_activity.log`**: Every tool invocation (`run_command`, `write_to_file`, etc.) with UTC timestamp and arguments.
- **`logs/conversation_log.md`**: Full agent transcript including internal thoughts, `objdump`/`gdb` commands, tool outputs, and reasoning steps.
- **`logs/benchmark_results.jsonl`**: Structured JSON Lines record of every verification run.
- **`logs/result_report.md`**: Final Markdown summary scorecard and per-program breakdown.
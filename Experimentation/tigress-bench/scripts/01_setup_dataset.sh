#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
ROOT_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
cd "$ROOT_DIR"

CACHE_REPO="$ROOT_DIR/.cache/TheAlgorithms-c"
mkdir -p .cache original obfuscated_src bin deobfuscated tests logs

if [[ -d "$CACHE_REPO/.git" ]]; then
  echo "[*] Using cached repository at $CACHE_REPO (no download needed)."
else
  echo "[*] Cloning TheAlgorithms/c into $CACHE_REPO..."
  git clone --depth 1 https://github.com/TheAlgorithms/c.git "$CACHE_REPO"
fi

CATEGORIES=("math" "cipher")

# Include -std=gnu99 so C99 loop declarations in cipher/*.c parse cleanly in Tigress
GLIBC_COMPAT=(
  "-std=gnu99"
  "-D_Float32=float"
  "-D_Float64=double"
  "-D_Float128=long double"
  "-D_Float32x=double"
  "-D_Float64x=long double"
  "-U__SIZEOF_INT128__"
)

STAGE_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR"' EXIT

for category in "${CATEGORIES[@]}"; do
  SRC_DIRS=("$CACHE_REPO/$category")
  if [[ ! -d "${SRC_DIRS[0]}" && -d "${SRC_DIRS[0]}s" ]]; then
    SRC_DIRS=("${SRC_DIRS[0]}s")
  fi
  # TheAlgorithms/c only has 2 files in cipher/; include hash/ to reach 5 targets
  if [[ "$category" == "cipher" && -d "$CACHE_REPO/hash" ]]; then
    SRC_DIRS+=("$CACHE_REPO/hash")
  fi

  mkdir -p "original/$category" "obfuscated_src/$category" "bin/$category" "deobfuscated/$category" "tests/$category"
  count=0

  echo "[*] Selecting and obfuscating 5 targets from '$category'..."

  while IFS= read -r src; do
    [[ $count -ge 5 ]] && break

    name=$(basename "$src" .c)
    inc_dir=$(dirname "$src")

    # Skip massive multi-hundred-line table files (> 450 LOC)
    line_count=$(wc -l < "$src" | tr -d ' ')
    if [[ "$line_count" -gt 450 ]]; then continue; fi

    # Skip interactive programs or files without main() or requiring CLI argv
    if ! grep -qE '\bmain\s*\(' "$src"; then continue; fi
    if grep -qE '\b(scanf|fscanf|gets|getchar|fgets)\s*\(' "$src"; then continue; fi
    if grep -qE 'argv\[[1-9]\]' "$src"; then continue; fi

    # Step A: Compile original program
    orig_bin="$STAGE_DIR/orig_${category}_${name}"
    if ! gcc -std=gnu99 -O2 -I"$inc_dir" "$src" -lm -o "$orig_bin" 2>/dev/null; then
      continue
    fi

    # Step B: Run original binary
    expected_out="tests/$category/${name}.expected_stdout"
    if ! { timeout 3s "$orig_bin" </dev/null > "$expected_out" 2>/dev/null; } 2>/dev/null; then
      rm -f "$expected_out"
      continue
    fi

    # Step C: Generate standalone test script
    test_runner="tests/$category/${name}_runner.sh"
    cat > "$test_runner" <<EOF
#!/usr/bin/env bash
set -euo pipefail
TARGET_BIN="\${1:?Usage: $test_runner <path-to-binary>}"
EXPECTED_FILE="$ROOT_DIR/tests/$category/${name}.expected_stdout"
ACTUAL_OUT=\$(mktemp)
trap 'rm -f "\$ACTUAL_OUT"' EXIT

if ! { timeout 5s "\$TARGET_BIN" </dev/null > "\$ACTUAL_OUT" 2>&1; } 2>/dev/null; then
  echo "Test failed: Binary exited with non-zero status or assertion failure."
  exit 1
fi

if ! diff -u "\$EXPECTED_FILE" "\$ACTUAL_OUT"; then
  echo "Test failed: Output mismatch against ground truth."
  exit 1
fi

exit 0
EOF
    chmod +x "$test_runner"

    if ! "$test_runner" "$orig_bin" >/dev/null 2>&1; then
      rm -f "$expected_out" "$test_runner"
      continue
    fi

    # Step D: Stage source for Tigress (ensure argc/argv in main and ULL suffix on 64-bit unsigned constants)
    staged_c="$STAGE_DIR/${name}_staged.c"
    {
      echo "#include <stdlib.h>"
      echo "#include <time.h>"
      sed -E \
        -e 's/\bint[[:space:]]+main[[:space:]]*\([[:space:]]*(void)?[[:space:]]*\)/int main(int argc, char **argv)/g' \
        -e 's/\b([0-9]{19,20})\b/\1ULL/g' \
        "$src"
    } > "$staged_c"

    # Step E: Run Tigress inside $STAGE_DIR so cleanUpRename*.json temp files don't clutter repo root
    obf_c="$ROOT_DIR/obfuscated_src/$category/$name.c"
    if ! (
      cd "$STAGE_DIR" && \
      timeout 25s tigress \
        --Environment=x86_64:Linux:Gcc:4.6 \
        "${GLIBC_COMPAT[@]}" \
        "-I$inc_dir" \
        --Transform=InitOpaque --Functions=main --InitOpaqueStructs=array \
        --Transform=Flatten --Functions=%100 \
        --Transform=EncodeArithmetic --Functions=%100 \
        --Transform=CleanUp --CleanUpKinds=names,annotations \
        "$staged_c" \
        --out="$obf_c" >/dev/null 2>&1
    ); then
      rm -f "$obf_c" "$expected_out" "$test_runner"
      continue
    fi

    # Step F: Compile obfuscated C into stripped binary
    stripped_bin="bin/$category/$name"
    if ! { timeout 15s gcc -std=gnu99 -O2 -s -fno-ident -fomit-frame-pointer -I"$inc_dir" "$obf_c" -lm -o "$stripped_bin" 2>/dev/null; } 2>/dev/null; then
      rm -f "$obf_c" "$stripped_bin" "$expected_out" "$test_runner"
      continue
    fi
    strip --strip-all --remove-section=.comment --remove-section=.note "$stripped_bin" 2>/dev/null || true

    # Step G: Verify stripped binary passes test suite
    if ! "$test_runner" "$stripped_bin" >/dev/null 2>&1; then
      rm -f "$obf_c" "$stripped_bin" "$expected_out" "$test_runner"
      continue
    fi

    cp "$src" "original/$category/$name.c"
    count=$((count + 1))
    echo "[OK] ($count/5) $category/$name: Original tested -> Tigress obfuscated -> Stripped ELF verified"

  done < <(find "${SRC_DIRS[@]}" -type f -name "*.c" | sort)

  if [[ $count -lt 5 ]]; then
    echo "[WARN] Only found $count compatible programs in $category"
  fi
done

echo "[*] Dataset ready: $(find bin -type f -executable | wc -l) stripped binaries and test suites verified."
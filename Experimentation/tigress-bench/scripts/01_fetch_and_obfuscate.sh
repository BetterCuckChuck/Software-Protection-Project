#!/usr/bin/env bash
set -euo pipefail

mkdir -p original obfuscated deobfuscated tests

TMP_DIR=$(mktemp -d)
TMP_REPO="$TMP_DIR/repo"
STAGE_DIR="$TMP_DIR/stage"
mkdir -p "$STAGE_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[*] Cloning TheAlgorithms/c..."
git clone --depth 1 https://github.com/TheAlgorithms/c.git "$TMP_REPO"

# Categories to pull 5 programs each from
CATEGORIES=("math" "geometry" "data_structures" "cipher")

# Glibc compatibility flags for Tigress's CIL parser on modern Linux (Pop!_OS / Ubuntu)
GLIBC_COMPAT=(
  "-D_Float32=float"
  "-D_Float64=double"
  "-D_Float128=long double"
  "-D_Float32x=double"
  "-D_Float64x=long double"
  "-U__SIZEOF_INT128__"
)

for category in "${CATEGORIES[@]}"; do
  # Handle singular/plural folder naming differences in repo
  SRC_DIR="$TMP_REPO/$category"
  if [[ ! -d "$SRC_DIR" && -d "${SRC_DIR}s" ]]; then
    SRC_DIR="${SRC_DIR}s"
  fi
  if [[ ! -d "$SRC_DIR" ]]; then
    echo "[WARN] Category directory '$category' not found in repo, skipping."
    continue
  fi

  mkdir -p "original/$category" "obfuscated/$category" "deobfuscated/$category" "tests/$category"
  count=0

  # Find all .c files in this category
  while IFS= read -r src; do
    [[ $count -ge 5 ]] && break

    name=$(basename "$src" .c)
    inc_dir=$(dirname "$src")

    # 1. Must contain main() and must NOT block on interactive stdin (scanf/gets/getchar)
    if ! grep -qE '\bmain\s*\(' "$src"; then
      continue
    fi
    if grep -qE '\b(scanf|fscanf|gets|getchar|fgets)\s*\(' "$src"; then
      continue
    fi

    # 2. Verify original compiles standalone and exits 0 within 3 seconds
    orig_bin="$TMP_DIR/orig_${category}_${name}"
    if ! gcc -O2 -I"$inc_dir" "$src" -lm -o "$orig_bin" 2>/dev/null; then
      continue
    fi
    if ! timeout 3s "$orig_bin" </dev/null > "$TMP_DIR/${name}.out" 2>/dev/null; then
      continue
    fi

    # 3. Create a Tigress-compatible staged source file:
    #    - Prepend <stdlib.h> and <time.h> so malloc/rand/time are always declared
    #    - Normalize `int main(void)` or `int main()` -> `int main(int argc, char **argv)`
    staged_src="$STAGE_DIR/${name}.c"
    {
      echo "#include <stdlib.h>"
      echo "#include <time.h>"
      sed -E 's/\bint[[:space:]]+main[[:space:]]*\([[:space:]]*(void)?[[:space:]]*\)/int main(int argc, char **argv)/g' "$src"
    } > "$staged_src"

    # 4. Discover non-main functions to obfuscate (or fallback to main)
    #    Using Flatten + EncodeArithmetic (+ InitOpaque on main)
    obf_out="obfuscated/$category/$name.c"
    if ! tigress \
      --Environment=x86_64:Linux:Gcc:4.6 \
      "${GLIBC_COMPAT[@]}" \
      "-I$inc_dir" \
      --Transform=InitOpaque --Functions=main --InitOpaqueStructs=array \
      --Transform=Flatten --Functions=%100 \
      --Transform=EncodeArithmetic --Functions=%100 \
      --Transform=CleanUp --CleanUpKinds=names,annotations \
      "$staged_src" \
      --out="$obf_out" >/dev/null 2>&1; then
      rm -f "$obf_out"
      continue
    fi

    # 5. Verify the Tigress-obfuscated output compiles and produces identical stdout
    obf_bin="$TMP_DIR/obf_${category}_${name}"
    if ! gcc -O2 -I"$inc_dir" "$obf_out" -lm -o "$obf_bin" 2>/dev/null; then
      rm -f "$obf_out"
      continue
    fi
    if ! timeout 3s "$obf_bin" </dev/null > "$TMP_DIR/${name}.obf_out" 2>/dev/null; then
      rm -f "$obf_out"
      continue
    fi
    if ! diff -q "$TMP_DIR/${name}.out" "$TMP_DIR/${name}.obf_out" >/dev/null; then
      rm -f "$obf_out"
      continue
    fi

    # 6. Save verified ground-truth and test output
    cp "$src" "original/$category/$name.c"
    cp "$TMP_DIR/${name}.out" "tests/$category/${name}.expected_stdout"
    count=$((count + 1))
    echo "[OK] ($count/5) $category/$name.c -> obfuscated and verified"

  done < <(find "$SRC_DIR" -type f -name "*.c" | sort)

  if [[ $count -lt 5 ]]; then
    echo "[WARN] Only found $count compatible standalone programs in$category"
  fi
done

echo "[*] Dataset build complete."
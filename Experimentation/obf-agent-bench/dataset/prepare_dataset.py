#!/usr/bin/env python3
"""Select, normalize and generate hidden test vectors for the 20 Juliet v1.3 samples.

Pipeline (all steps are deterministic given experiment.yaml:random_seed):
  1. (optional --download) fetch the NIST Juliet C/C++ v1.3 zip into .cache/
  2. filter candidates: flow-variant 01, stdin(fscanf)-driven, no rand/time/heap/files/sockets, only
     simple print*Line sinks  => deterministic, self-contained programs
  3. stratified seeded selection  (configs/experiment.yaml: dataset.stratification)
  4. extract selected raw files to dataset/raw_juliet/
  5. normalize into ONE translation unit with a deterministic main(argc, argv):
         ./prog [good|bad]   (no arg => run both);   data comes from stdin
  6. emit per-sample JSON test vectors (15 curated boundary + 50 seeded differential-fuzz cases)
     into dataset/test_vectors/  (hidden from the agent: never copied into the jail)
  7. write dataset/samples_20.json (manifest)
"""
from __future__ import annotations

import argparse
import json
import math
import random
import re
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, load_config, resolve  # noqa: E402

ALLOWED_PRINTERS = {
    "printLine", "printIntLine", "printLongLine", "printLongLongLine", "printUnsignedLine",
    "printShortLine", "printHexCharLine", "printHexUnsignedCharLine", "printSizeTLine",
    "printDoubleLine", "printFloatLine",
}
FORBIDDEN_IN_SRC = re.compile(
    r"\b(rand|time|malloc|alloca|ALLOCA|pthread\w*|wchar_t|fopen|socket|system|exec\w*|getenv|free|"
    r"memcpy|strcpy|strcat|memset|strncpy|new|twoIntsStruct|abort|assert)\b"
)
DATA_TYPES = {
    "int": (-(2**31), 2**31 - 1),
    "short": (-(2**15), 2**15 - 1),
    "int64_t": (-(2**63), 2**63 - 1),
    "unsigned int": (0, 2**32 - 1),
    "char": (-128, 127),
}
SYSTEM_PRELUDE = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#define true 1
#define false 0
"""


# ----------------------------------------------------------------------------- download / read
def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"[*] Using cached {dest}")
        return
    print(f"[*] Downloading {url}")
    urllib.request.urlretrieve(url, dest)


def read_src(z: zipfile.ZipFile, name: str) -> str:
    return z.read(name).decode("latin1").replace("\r", "")


def data_type_of(src: str) -> str | None:
    m = re.search(r"^\s*(unsigned int|int64_t|int|short|char)\s+data;", src, re.M)
    return m.group(1) if m else None


# ----------------------------------------------------------------------------- selection
def candidate_files(z: zipfile.ZipFile, strata: dict[str, int]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {k: [] for k in strata}
    for n in sorted(z.namelist()):
        if not (n.endswith("_01.c") and "/testcases/CWE" in n):
            continue
        m = re.search(r"/(CWE\d+_[A-Za-z_]+?)/", n)
        cwe = re.search(r"/(CWE\d+_[A-Za-z0-9_]+?)__", n)
        if not cwe or cwe.group(1) not in groups:
            continue
        src = read_src(z, n)
        body = src.replace("srand( (unsigned)time(NULL) )", "")
        if not re.search(r"fscanf\s*\(\s*stdin", src) or FORBIDDEN_IN_SRC.search(body):
            continue
        if not set(re.findall(r"\b(print\w*Line)\s*\(", src)) <= ALLOWED_PRINTERS:
            continue
        if data_type_of(src) is None:
            continue
        if '#include "' in src.replace('#include "std_testcase.h"', ""):
            continue
        groups[cwe.group(1)].append(n)
        del m
    return groups


def select_samples(z: zipfile.ZipFile, cfg: dict) -> list[str]:
    strata = cfg["dataset"]["stratification"]
    assert sum(strata.values()) == cfg["dataset"]["sample_count"], "stratification must sum to sample_count"
    rng = random.Random(cfg["random_seed"])
    groups = candidate_files(z, strata)
    chosen: list[str] = []
    for cwe, count in strata.items():
        pool = groups[cwe]
        if len(pool) < count:
            raise SystemExit(f"Only {len(pool)} candidates for {cwe}, need {count}")
        chosen += sorted(rng.sample(pool, count))
    return chosen


# ----------------------------------------------------------------------------- normalization
def extract_printer(io_src: str, name: str) -> str:
    m = re.search(rf"^void {name}\s*\(.*?^\}}\n", io_src, re.M | re.S)
    if not m:
        raise ValueError(f"printer {name} not found in io.c")
    return m.group(0)


def normalize(src: str, io_src: str, sample_id: str) -> str:
    src = re.sub(r'#include "std_testcase.h"\n', "", src)
    src = re.sub(r"/\* Below is the main\(\).*\Z", "", src, flags=re.S)  # drop Juliet's own (time-seeded) main
    used = sorted(set(re.findall(r"\b(print\w*Line)\s*\(", src)) | {"printLine"})  # main() needs printLine
    printers = "\n".join(extract_printer(io_src, p) for p in used)
    main = f"""
int main(int argc, char *argv[])
{{
    const char *mode = argc > 1 ? argv[1] : "both";
    int run_good = strcmp(mode, "bad") != 0;
    int run_bad = strcmp(mode, "good") != 0;
    if (run_good)
    {{
        printLine("Calling good()...");
        {sample_id}_good();
        printLine("Finished good()");
    }}
    if (run_bad)
    {{
        printLine("Calling bad()...");
        {sample_id}_bad();
        printLine("Finished bad()");
    }}
    return 0;
}}
"""
    return f"{SYSTEM_PRELUDE}\n/* --- Juliet support (io.c subset) --- */\n{printers}\n/* --- Juliet testcase {sample_id} --- */\n{src.rstrip()}\n{main}"


# ----------------------------------------------------------------------------- test vectors
def _boundary_values(dtype: str, sample_id: str) -> list[int]:
    lo, hi = DATA_TYPES[dtype]
    vals = [0, 1, -1, 2, -2, lo, lo + 1, hi, hi - 1]
    isq = math.isqrt(hi)
    vals += [isq, isq + 1, -isq, -isq - 1, hi // 2, hi // 2 + 1, lo // 2, lo // 2 - 1]
    for t in (127, 128, 255, 256, 32767, 32768, 65535, 65536):  # truncation boundaries (CWE197)
        vals += [t, -t]
    out, seen = [], set()
    for v in vals:
        if lo <= v <= hi and v not in seen:
            seen.add(v)
            out.append(v)
    return out


CHAR_CURATED = [0x30, 0x61, 0x41, 0x20, 0x0A, 0x7E, 0x7F, 0x80, 0xFE, 0xFF, 0x01, 0x00, 0x7A, 0x39, 0x2D]


def _case(cid: str, argv: list[str], stdin: bytes) -> dict:
    return {"id": cid, "argv": argv, "stdin_hex": stdin.hex()}


def generate_vectors(sample_id: str, dtype: str, cfg: dict) -> dict:
    io_cfg = cfg["evaluation"]["io_equivalence"]
    n_cur, n_fuzz = io_cfg["curated_cases_per_file"], io_cfg["differential_fuzz_cases"]
    lo, hi = DATA_TYPES[dtype]
    rng = random.Random(f"{cfg['random_seed']}:{sample_id}")

    def enc(v: int) -> bytes:
        return str(v).encode()

    curated: list[dict] = []
    if dtype == "char":
        pairs = [(bytes([b]), m) for b in CHAR_CURATED for m in ("bad",)]
        pairs += [(bytes([b]), "good") for b in CHAR_CURATED[:4]]
        for i, (stdin, mode) in enumerate(pairs[:n_cur]):
            curated.append(_case(f"curated_{i:02d}", [mode], stdin))
    else:
        vals = _boundary_values(dtype, sample_id)
        # alternate bad/good paths so both the unguarded and the guarded sink see each boundary
        plan = []
        for v in vals:
            plan.append((v, "bad"))
            plan.append((v, "good"))
        for i, (v, mode) in enumerate(plan[:n_cur]):
            curated.append(_case(f"curated_{i:02d}", [mode], enc(v)))

    garbage = [b"", b"abc", b"  ", b"+", b"-", b"0x10", b"12abc", b" 7\n", b"\n\n5", b"99999999999999999999"]
    fuzz: list[dict] = []
    for i in range(n_fuzz):
        mode = rng.choice([None, "good", "bad"])
        r = rng.random()
        if dtype == "char":
            stdin = bytes([rng.randrange(256)])
        elif r < 0.40:
            stdin = enc(rng.randint(lo, hi))
        elif r < 0.65:
            base = rng.choice([lo, hi, 0, math.isqrt(hi), hi // 2])
            stdin = enc(max(lo, min(hi, base + rng.randint(-3, 3))))
        elif r < 0.80:
            stdin = enc(rng.randint(-300, 300) if lo < 0 else rng.randint(0, 600))
        else:
            stdin = rng.choice(garbage)
        fuzz.append(_case(f"fuzz_{i:02d}", [mode] if mode else [], stdin))
    return {"sample_id": sample_id, "data_type": dtype, "curated": curated, "fuzz": fuzz}


# ----------------------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "configs" / "experiment.yaml"))
    ap.add_argument("--download", action="store_true", help="download the Juliet zip if missing (needs network)")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    zip_path = resolve(cfg, "juliet_zip")
    if args.download:
        download(cfg["paths"]["juliet_url"], zip_path)
    if not zip_path.exists():
        raise SystemExit(f"{zip_path} missing; rerun with --download or place the Juliet v1.3 zip there")

    raw_dir, norm_dir, vec_dir = resolve(cfg, "raw_juliet"), resolve(cfg, "normalized_src"), resolve(cfg, "test_vectors")
    for d in (raw_dir, norm_dir, vec_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)

    with zipfile.ZipFile(zip_path) as z:
        chosen = select_samples(z, cfg)
        io_src = read_src(z, "C/testcasesupport/io.c")
        samples = []
        for name in chosen:
            sample_id = Path(name).stem
            src = read_src(z, name)
            dtype = data_type_of(src)
            (raw_dir / Path(name).name).write_bytes(z.read(name))
            (norm_dir / f"{sample_id}.c").write_text(normalize(src, io_src, sample_id), encoding="utf-8")
            vec = generate_vectors(sample_id, dtype, cfg)
            (vec_dir / f"{sample_id}.json").write_text(json.dumps(vec, indent=1), encoding="utf-8")
            samples.append({
                "sample_id": sample_id,
                "cwe": re.search(r"(CWE\d+)", sample_id).group(1),
                "cwe_family": re.search(r"(CWE\d+_[A-Za-z0-9_]+?)__", sample_id).group(1),
                "data_type": dtype,
                "juliet_path": name,
                "normalized_src": f"{cfg['paths']['normalized_src']}/{sample_id}.c",
                "test_vectors": f"{cfg['paths']['test_vectors']}/{sample_id}.json",
            })

    manifest = (ROOT / cfg["dataset"]["manifest_path"]).resolve()
    manifest.write_text(json.dumps({
        "source_suite": cfg["dataset"]["source_suite"],
        "seed": cfg["random_seed"],
        "samples": samples,
    }, indent=2), encoding="utf-8")
    print(f"[OK] {len(samples)} samples -> {manifest}")
    for s in samples:
        print(f"   {s['sample_id']}  ({s['data_type']})")


if __name__ == "__main__":
    main()

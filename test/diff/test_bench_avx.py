#!/usr/bin/env python3
"""Deterministic smoke test for the AVX/AVX2 benchmark.

Runs xendiza_bench_avx with tiny inner-iters/samples on both ISA corpora and
verifies that the correctness gate passes and the reported decoded counts and
throughput ratio are sane.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_BENCH = ROOT / "build" / "Release" / "xendiza_bench_avx.exe"
CORPUS_AVX = ROOT / "bench" / "corpus_avx.bin"
CORPUS_AVX2 = ROOT / "bench" / "corpus_avx2.bin"


def run_bench(bench: Path, isa: str) -> dict:
    cmd = [
        str(bench),
        "--isa", isa,
        "--mode", "64",
        "--inner-iters", "2",
        "--samples", "2",
        "--warmup", "1",
        "--corpus-avx", str(CORPUS_AVX),
        "--corpus-avx2", str(CORPUS_AVX2),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise RuntimeError(f"benchmark --isa {isa} failed with exit code {proc.returncode}:\n{out}")

    if "Zydis comparison unavailable" in out:
        return {"available": False}

    result = {"available": True, "isa": isa}
    m = re.search(rf"AVX benchmark \| ISA={isa} mode=64 corpus=(\d+) bytes", out)
    if not m:
        raise RuntimeError(f"missing benchmark header in output:\n{out}")
    result["corpus_bytes"] = int(m.group(1))

    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("xendiza") and "|" in line:
            parts = line.split("|")
            result["xendiza"] = {
                "throughput": parts[1].strip() if len(parts) > 1 else "",
                "decoded": int(re.search(r"decoded=(\d+)", line).group(1)),
                "errors": int(re.search(r"errors=(\d+)", line).group(1)),
                "checksum": int(re.search(r"checksum=(\d+)", line).group(1)),
            }
        elif line.startswith("zydis") and "|" in line:
            parts = line.split("|")
            result["zydis"] = {
                "throughput": parts[1].strip() if len(parts) > 1 else "",
                "decoded": int(re.search(r"decoded=(\d+)", line).group(1)),
                "errors": int(re.search(r"errors=(\d+)", line).group(1)),
                "checksum": int(re.search(r"checksum=(\d+)", line).group(1)),
            }
        elif "throughput ratio" in line:
            result["ratio"] = float(re.search(r"ratio:\s*([0-9.]+)", line).group(1))
    return result


def main() -> int:
    bench = DEFAULT_BENCH
    if len(sys.argv) > 1:
        bench = Path(sys.argv[1])

    if not bench.exists():
        print(f"SKIP: benchmark executable not found: {bench}")
        return 0

    errors = 0
    for isa in ("avx", "avx2"):
        try:
            r = run_bench(bench, isa)
        except RuntimeError as e:
            print(f"FAIL {isa}: {e}")
            errors += 1
            continue

        if not r["available"]:
            print(f"SKIP {isa}: Zydis comparison unavailable")
            continue

        if r["xendiza"]["errors"] != 0 or r["zydis"]["errors"] != 0:
            print(f"FAIL {isa}: benchmark reported errors")
            errors += 1
            continue
        if r["xendiza"]["decoded"] != r["zydis"]["decoded"]:
            print(f"FAIL {isa}: decoded counts differ")
            errors += 1
            continue
        if r["xendiza"]["checksum"] != r["zydis"]["checksum"]:
            print(f"FAIL {isa}: checksums differ")
            errors += 1
            continue
        if r["ratio"] <= 0.0:
            print(f"FAIL {isa}: throughput ratio must be positive")
            errors += 1
            continue
        print(f"PASS {isa}: decoded={r['xendiza']['decoded']} ratio={r['ratio']:.3f}")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

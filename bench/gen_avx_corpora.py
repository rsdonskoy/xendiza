#!/usr/bin/env python3
"""Generate deterministic AVX/AVX2 benchmark corpora from the VEX inventory.

Each corpus is a repetition of a stable tile built from all supported
inventory rows valid in both 32-bit and 64-bit modes for the selected ISA.
The tile contains only complete instructions, so the corpus can be decoded
linearly without error recovery.
"""

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "test" / "data" / "vex_avx_inventory.csv"


def hex_bytes(s: str) -> list[int]:
    return [int(b, 16) for b in s.split() if b]


def build_tile(isa: str) -> bytes:
    tile: list[int] = []
    with CSV_PATH.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            first = next(iter(row.values()), "")
            if isinstance(first, str) and first.lstrip().startswith("#"):
                continue
            if not any(v is not None and str(v).strip() for v in row.values()):
                continue
            if row["class"] != "supported":
                continue
            if row["isa"].lower() != isa.lower():
                continue
            if row["modes"] != "both":
                continue
            tile.extend(hex_bytes(row["bytes"]))
    if not tile:
        raise RuntimeError(f"no supported {isa.upper()} rows with modes=both found")
    return bytes(tile)


def write_corpus(tile: bytes, size: int, output: Path) -> None:
    if size <= 0:
        raise ValueError("size must be positive")
    repeats = size // len(tile)
    if repeats == 0:
        raise ValueError(f"target size {size} is smaller than tile length {len(tile)}")
    corpus = tile * repeats
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as f:
        f.write(corpus)
    print(f"Wrote {len(corpus)} bytes ({repeats} x {len(tile)} byte tile) to {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AVX/AVX2 benchmark corpora")
    parser.add_argument("--isa", choices=["avx", "AVX", "avx2", "AVX2"], required=True)
    parser.add_argument("--size", type=int, default=8 * 1024 * 1024,
                        help="target corpus size in bytes (default 8 MiB)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not CSV_PATH.exists():
        print(f"ERROR: inventory not found: {CSV_PATH}", file=sys.stderr)
        return 1

    tile = build_tile(args.isa.lower())
    write_corpus(tile, args.size, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())

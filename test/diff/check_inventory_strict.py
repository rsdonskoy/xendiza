#!/usr/bin/env python3
"""Strict differential checker for test/data/vex_avx_inventory.csv.

Each inventory row becomes an independent vector fed to the xendiza harness.
Success rows are checked for exact mnemonic, ordered operands, operand count,
and length.  Failure rows are checked for the exact xendiza error code.
Deferred rows are allowed to return UNIMPLEMENTED_DISASM.
"""

import csv
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CSV_PATH = ROOT / "test" / "data" / "vex_avx_inventory.csv"
# Prefer the CMake-built strict-mode harness; fall back to the MSVC-only build script output.
HARNESS = ROOT / "build" / "Release" / "xendiza_diff_harness.exe"
if not HARNESS.exists():
    HARNESS = HERE / "out" / "harness.exe"

ERROR_CODES = {
    "OK": 0,
    "INSUFFICIENT_BUFFER": 0xE1,
    "UNDEFINED_INSTRUCTION": 0xE2,
    "UNIMPLEMENTED_DISASM": 0xE3,
}


def hex_bytes(s: str) -> list[int]:
    return [int(b, 16) for b in s.split() if b]


def run_harness(mode: int, byte_list: list[int]) -> tuple[int, str, list[str]]:
    hex_str = "".join(f"{b:02x}" for b in byte_list)
    line = f"{mode}\t{hex_str}\tvec\t1\n".encode()
    proc = subprocess.run(
        [str(HARNESS)],
        input=line,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"harness failed: {proc.stderr.decode()}")
    # Keep the trailing empty operand field on Windows CRLF output.
    out = proc.stdout.decode().rstrip("\r\n").split("\t")
    if len(out) < 4:
        raise RuntimeError(f"unexpected harness output: {proc.stdout.decode()!r}")
    # srcid, idx, length, mnemonic, [operands]
    length = int(out[2])
    mnemonic = out[3]
    operands = [o for o in out[4].split(",") if o] if len(out) > 4 else []
    return length, mnemonic, operands


def check_inventory() -> int:
    if not CSV_PATH.exists():
        print(f"ERROR: inventory not found: {CSV_PATH}", file=sys.stderr)
        return 1
    if not HARNESS.exists():
        print(f"ERROR: harness not found: {HARNESS}; run test/diff/build.bat", file=sys.stderr)
        return 1

    errors = 0
    checked = 0
    deferred = 0

    with CSV_PATH.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):
            first = next(iter(row.values()), "")
            if isinstance(first, str) and first.lstrip().startswith("#"):
                continue
            if not any(v is not None and str(v).strip() for v in row.values()):
                continue

            modes = []
            if row["modes"] in ("32", "both"):
                modes.append(32)
            if row["modes"] in ("64", "both"):
                modes.append(64)

            bytes_ = hex_bytes(row["bytes"])
            class_ = row["class"]
            expected_error = row["error"]
            expected_len_str = row["length"].strip()
            expected_len = int(expected_len_str) if expected_len_str else None
            expected_mnemonic = row["mnemonic"]
            expected_ops = [o.strip() for o in row["operands"].split(";") if o.strip()]

            for mode in modes:
                checked += 1
                try:
                    length, mnemonic, ops = run_harness(mode, bytes_)
                except RuntimeError as e:
                    print(f"ERROR: row {row_num} mode={mode}: {e}", file=sys.stderr)
                    errors += 1
                    continue

                if class_ == "deferred":
                    deferred += 1
                    if length == ERROR_CODES["UNIMPLEMENTED_DISASM"]:
                        continue
                    # A deferred row may also be accidentally supported already.
                    if length >= 0xE0:
                        print(f"ERROR: row {row_num} mode={mode}: deferred row returned error {length:#x}", file=sys.stderr)
                        errors += 1
                        continue
                    # If it decodes, we don't require exact match in A0; just note it.
                    continue

                if class_ == "invalid":
                    expected_code = ERROR_CODES[expected_error]
                    if length != expected_code:
                        print(
                            f"ERROR: row {row_num} mode={mode}: expected {expected_error} ({expected_code:#x}), got length={length:#x}",
                            file=sys.stderr,
                        )
                        errors += 1
                    continue

                # supported
                if length >= 0xE0:
                    print(
                        f"ERROR: row {row_num} mode={mode}: expected success, got error {length:#x}",
                        file=sys.stderr,
                    )
                    errors += 1
                    continue

                if expected_len is not None and length != expected_len:
                    print(
                        f"ERROR: row {row_num} mode={mode}: expected length {expected_len}, got {length}",
                        file=sys.stderr,
                    )
                    errors += 1

                if mnemonic != expected_mnemonic:
                    print(
                        f"ERROR: row {row_num} mode={mode}: expected mnemonic {expected_mnemonic}, got {mnemonic}",
                        file=sys.stderr,
                    )
                    errors += 1

                if ops != expected_ops:
                    print(
                        f"ERROR: row {row_num} mode={mode}: expected operands {expected_ops}, got {ops}",
                        file=sys.stderr,
                    )
                    errors += 1

    print(f"Checked {checked} vectors ({CSV_PATH}); errors={errors}; deferred={deferred}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(check_inventory())

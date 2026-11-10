#!/usr/bin/env python3
"""Integrity checker for test/data/vex_avx_inventory.csv.

Validates the stable schema, enumerates rows, checks identifier names
against the C/C++ headers, and reports supported/deferred/invalid counts.
"""

import csv
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = REPO_ROOT / "test" / "data" / "vex_avx_inventory.csv"

VALID_ISAS = {"AVX", "AVX2"}
VALID_MODES = {"32", "64", "both"}
VALID_MAPS = {"0F", "0F38", "0F3A"}
VALID_PPS = {"none", "66", "F3", "F2"}
VALID_L = {"0", "1", "LIG"}
VALID_W = {"0", "1", "WIG"}
VALID_VVVV = {"required", "reserved", "ignored", "none"}
VALID_EXT = {"0", "1", "any"}
VALID_MODRM = {"none", "reg", "mem", "both"}
VALID_CLASSES = {"supported", "deferred", "invalid"}
VALID_ERRORS = {"OK", "UNDEFINED_INSTRUCTION", "INSUFFICIENT_BUFFER", "UNIMPLEMENTED_DISASM"}


def extract_enum_names(path: Path, enum_name: str) -> set[str]:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(rf"enum\s+class\s+{enum_name}\s*:\s*\w+\s+\{{(.*?)\}}", re.S)
    m = pattern.search(text)
    if not m:
        return set()
    body = m.group(1)
    names: set[str] = set()
    for line in body.splitlines():
        line = line.split("//")[0].strip().rstrip(",")
        if not line or line.startswith("#"):
            continue
        # Strip enum initializer if present
        name = line.split("=")[0].strip()
        if name and name not in {"}", "{"}:
            names.add(name)
    return names


def parse_bytes(s: str) -> list[int]:
    return [int(b, 16) for b in s.split() if b]


def check_inventory() -> int:
    if not CSV_PATH.exists():
        print(f"ERROR: inventory not found: {CSV_PATH}", file=sys.stderr)
        return 1

    opcode_ids = extract_enum_names(REPO_ROOT / "include" / "xendiza" / "detail" / "opcode_id.hpp", "OpcodeId")
    operands = extract_enum_names(REPO_ROOT / "include" / "xendiza" / "detail" / "instruction.hpp", "Operand")

    errors = 0
    counts = {"supported": 0, "deferred": 0, "invalid": 0}
    seen_keys: set[str] = set()

    with CSV_PATH.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {
            "isa", "modes", "map", "opcode", "pp", "L", "W", "vvvv",
            "ext_r", "ext_x", "ext_b", "prefixes", "modrm", "trailing",
            "mnemonic", "operands", "length", "bytes", "class", "error", "sdm",
        }
        if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
            print(f"ERROR: CSV header missing one of {required}", file=sys.stderr)
            return 1

        for row_num, row in enumerate(reader, start=2):
            loc = f"row {row_num}"
            if row is None:
                continue
            # Allow #-prefixed comment rows anywhere in the body
            first_field = next(iter(row.values()), "")
            if isinstance(first_field, str) and first_field.lstrip().startswith("#"):
                continue
            if not any(v is not None and str(v).strip() for v in row.values()):
                continue
            if row.get("isa") not in VALID_ISAS:
                print(f"ERROR: {loc}: invalid isa {row.get('isa')!r}", file=sys.stderr)
                errors += 1
            if row.get("modes") not in VALID_MODES:
                print(f"ERROR: {loc}: invalid modes {row.get('modes')!r}", file=sys.stderr)
                errors += 1
            if row.get("map") not in VALID_MAPS:
                print(f"ERROR: {loc}: invalid map {row.get('map')!r}", file=sys.stderr)
                errors += 1
            if row.get("pp") not in VALID_PPS:
                print(f"ERROR: {loc}: invalid pp {row.get('pp')!r}", file=sys.stderr)
                errors += 1
            if row.get("L") not in VALID_L:
                print(f"ERROR: {loc}: invalid L {row.get('L')!r}", file=sys.stderr)
                errors += 1
            if row.get("W") not in VALID_W:
                print(f"ERROR: {loc}: invalid W {row.get('W')!r}", file=sys.stderr)
                errors += 1
            if row.get("vvvv") not in VALID_VVVV:
                print(f"ERROR: {loc}: invalid vvvv {row.get('vvvv')!r}", file=sys.stderr)
                errors += 1
            for ext in ("ext_r", "ext_x", "ext_b"):
                if row.get(ext) not in VALID_EXT:
                    print(f"ERROR: {loc}: invalid {ext} {row.get(ext)!r}", file=sys.stderr)
                    errors += 1
            if row.get("modrm") not in VALID_MODRM:
                print(f"ERROR: {loc}: invalid modrm {row.get('modrm')!r}", file=sys.stderr)
                errors += 1
            if row.get("class") not in VALID_CLASSES:
                print(f"ERROR: {loc}: invalid class {row.get('class')!r}", file=sys.stderr)
                errors += 1
            if row.get("error") not in VALID_ERRORS:
                print(f"ERROR: {loc}: invalid error {row.get('error')!r}", file=sys.stderr)
                errors += 1

            if row.get("mnemonic") and row["mnemonic"] not in opcode_ids:
                print(f"ERROR: {loc}: unknown mnemonic {row['mnemonic']!r}", file=sys.stderr)
                errors += 1

            for op in row.get("operands", "").split(";"):
                op = op.strip()
                if op and op not in operands:
                    print(f"ERROR: {loc}: unknown operand {op!r}", file=sys.stderr)
                    errors += 1

            try:
                bytes_ = parse_bytes(row.get("bytes", ""))
            except ValueError as e:
                print(f"ERROR: {loc}: bad bytes field: {e}", file=sys.stderr)
                errors += 1
                bytes_ = []

            length_str = row.get("length", "").strip()
            if length_str:
                try:
                    length = int(length_str)
                    if row["class"] == "supported" and length != len(bytes_):
                        print(f"ERROR: {loc}: length {length} != byte count {len(bytes_)}", file=sys.stderr)
                        errors += 1
                except ValueError:
                    print(f"ERROR: {loc}: bad length {length_str!r}", file=sys.stderr)
                    errors += 1

            key = "|".join([row.get(k, "") for k in ("isa", "modes", "map", "opcode", "pp", "L", "W", "vvvv", "modrm", "trailing", "mnemonic", "operands", "bytes")])
            if key in seen_keys:
                print(f"ERROR: {loc}: duplicate row", file=sys.stderr)
                errors += 1
            seen_keys.add(key)

            counts[row.get("class", "supported")] += 1

    print(f"Inventory: {CSV_PATH}")
    print(f"Rows: {sum(counts.values())} (supported={counts['supported']}, deferred={counts['deferred']}, invalid={counts['invalid']})")
    if errors:
        print(f"FAILED with {errors} error(s)")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(check_inventory())

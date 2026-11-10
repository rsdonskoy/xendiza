#!/usr/bin/env python3
"""Generate CSV rows for implemented A3 0F38 VSIB/gather forms."""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = ROOT / "test" / "data" / "vex_avx_inventory.csv"

PP_BITS = {"none": 0, "66": 1, "F3": 2, "F2": 3}
DISP32 = "00 00 00 00"


def c4_bytes(opcode: int, map_bits: int, pp: str, L: int, W: int,
             vvvv_src: int, modrm: int, extra: list[int] | None = None) -> str:
    """Encode a C4 three-byte VEX prefix for 0F38 with the given fields."""
    vvvv_raw = (~vvvv_src) & 0x0F
    byte2 = 0xE0 | map_bits
    byte3 = (W << 7) | (vvvv_raw << 3) | (L << 2) | PP_BITS[pp]
    body = [0xC4, byte2, byte3, opcode, modrm]
    if extra:
        body.extend(extra)
    return " ".join(f"{b:02X}" for b in body)


def make_row(isa: str, modes: str, opcode: int, pp: str, L: int, W: int,
             vvvv: str, prefixes: str, modrm_kind: str, trailing: str,
             mnemonic: str, operands: str, length: int | None,
             bytes_str: str, class_: str, error: str, sdm: str) -> list[str]:
    return [
        isa, modes, "0F38", f"{opcode:02X}", pp, str(L), str(W), vvvv,
        "any", "any", "any", prefixes, modrm_kind, trailing,
        mnemonic, operands,
        str(length) if length is not None else "",
        bytes_str, class_, error, sdm,
    ]


def isa_for(L: int, base_isa: str = "AVX2") -> str:
    return "AVX2"  # Gather forms are AVX2-only regardless of L.


def main() -> int:
    if not CSV_PATH.exists():
        print(f"ERROR: {CSV_PATH} not found", file=sys.stderr)
        return 1

    KEY_INDICES = (0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 17)
    existing_keys: set[str] = set()
    with CSV_PATH.open(encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        next(reader)  # header
        for row in reader:
            if not row or row[0].lstrip().startswith("#"):
                continue
            existing_keys.add("|".join(row[i] for i in KEY_INDICES))

    specs: list[list[str]] = []

    # Each 0F38 opcode encodes two gather mnemonics distinguished by W.
    # The VSIB operand width tracks the data element size for the mnemonic.
    gather_specs = [
        (0x90, "VPGATHERDD", "VPGATHERDQ", "m32_vsib", "m64_vsib"),
        (0x91, "VPGATHERQD", "VPGATHERQQ", "m32_vsib", "m64_vsib"),
        (0x92, "VGATHERDPS", "VGATHERDPD", "m32_vsib", "m64_vsib"),
        (0x93, "VGATHERQPS", "VGATHERQPD", "m32_vsib", "m64_vsib"),
    ]

    for opcode, name_w0, name_w1, vsib_w0, vsib_w1 in gather_specs:
        for L in (0, 1):
            for W in (0, 1):
                mnemonic = name_w0 if W == 0 else name_w1
                vsib = vsib_w0 if W == 0 else vsib_w1
                # Mixed-width forms keep XMM dest/mask even with 256-bit indices.
                qd_or_qps = mnemonic in ("VPGATHERQD", "VGATHERQPS")
                reg = "xmm" if L == 0 or qd_or_qps else "ymm"
                operands = f"{reg};{vsib};{reg}"

                # Valid VSIB memory form: dest=0, mask=1, index=2 (SIB=0x15),
                # base=disp32 (base=101), modrm=0x04.
                specs.append(make_row(
                    isa_for(L), "both", opcode, "66", L, W, "required", "none", "mem", "0:none",
                    mnemonic, operands, 10,
                    " ".join([c4_bytes(opcode, 2, "66", L, W, 1, 0x04, [0x15]), DISP32]),
                    "supported", "OK", "SDM 2B 5-263",
                ))

                # Invalid reg form: gather is memory-only.
                specs.append(make_row(
                    isa_for(L), "both", opcode, "66", L, W, "required", "none", "reg", "0:none",
                    mnemonic, operands, None,
                    c4_bytes(opcode, 2, "66", L, W, 1, 0xC0),
                    "invalid", "UNDEFINED_INSTRUCTION", "SDM 2B 5-263",
                ))

    # Representative invalid forms for VPGATHERDD (L=0, W=0).
    rep_opcode = 0x90
    rep_name = "VPGATHERDD"
    rep_vsib = "m32_vsib"
    rep_operands = f"xmm;{rep_vsib};xmm"

    # No SIB: rm=101 with a disp32.
    specs.append(make_row(
        "AVX2", "both", rep_opcode, "66", 0, 0, "required", "none", "mem", "0:none",
        rep_name, rep_operands, None,
        " ".join([c4_bytes(rep_opcode, 2, "66", 0, 0, 1, 0x05), DISP32]),
        "invalid", "UNDEFINED_INSTRUCTION", "SDM 2B 5-263",
    ))

    # 16-bit effective address: 67h prefix in 32-bit mode.
    specs.append(make_row(
        "AVX2", "32", rep_opcode, "66", 0, 0, "required", "67", "mem", "0:none",
        rep_name, rep_operands, None,
        "67 " + " ".join([c4_bytes(rep_opcode, 2, "66", 0, 0, 1, 0x04, [0x15]), DISP32]),
        "invalid", "UNDEFINED_INSTRUCTION", "SDM 2B 5-263",
    ))

    # Truncated VSIB: only ModR/M byte, no SIB/disp.
    specs.append(make_row(
        "AVX2", "both", rep_opcode, "66", 0, 0, "required", "none", "mem", "0:none",
        rep_name, rep_operands, None,
        c4_bytes(rep_opcode, 2, "66", 0, 0, 1, 0x04),
        "invalid", "INSUFFICIENT_BUFFER", "SDM 2B 5-263",
    ))

    # Register-overlap cases: dest==mask, dest==index, mask==index.
    # dest == mask: vvvv_src=0 (mask=xmm0/ymm0), dest=0, index=2.
    specs.append(make_row(
        "AVX2", "both", rep_opcode, "66", 0, 0, "required", "none", "mem", "0:none",
        rep_name, rep_operands, None,
        " ".join([c4_bytes(rep_opcode, 2, "66", 0, 0, 0, 0x04, [0x15]), DISP32]),
        "invalid", "UNDEFINED_INSTRUCTION", "SDM 2B 5-263",
    ))
    # dest == index: vvvv_src=1, dest=0, index=0 (SIB=0x05).
    specs.append(make_row(
        "AVX2", "both", rep_opcode, "66", 0, 0, "required", "none", "mem", "0:none",
        rep_name, rep_operands, None,
        " ".join([c4_bytes(rep_opcode, 2, "66", 0, 0, 1, 0x04, [0x05]), DISP32]),
        "invalid", "UNDEFINED_INSTRUCTION", "SDM 2B 5-263",
    ))
    # mask == index: vvvv_src=0, dest=2, index=0 (modrm=0x14, SIB=0x05).
    specs.append(make_row(
        "AVX2", "both", rep_opcode, "66", 0, 0, "required", "none", "mem", "0:none",
        rep_name, rep_operands, None,
        " ".join([c4_bytes(rep_opcode, 2, "66", 0, 0, 0, 0x14, [0x05]), DISP32]),
        "invalid", "UNDEFINED_INSTRUCTION", "SDM 2B 5-263",
    ))

    # Filter duplicates.
    new_rows = []
    for row in specs:
        key = "|".join(row[i] for i in KEY_INDICES)
        if key not in existing_keys:
            new_rows.append(row)

    if not new_rows:
        print("No new A3 rows to add.")
        return 0

    with CSV_PATH.open(encoding="utf-8", newline="") as f:
        content = f.read()
    if not content.endswith("\n"):
        content += "\n"
    lines = [",".join(f'"{c}"' if "," in c else c for c in row) for row in new_rows]
    with CSV_PATH.open("a", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Added {len(new_rows)} new A3 rows to {CSV_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

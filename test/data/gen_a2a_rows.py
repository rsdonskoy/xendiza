#!/usr/bin/env python3
"""Generate CSV rows for implemented A2a 0F38-map VEX forms and merge into the inventory."""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = ROOT / "test" / "data" / "vex_avx_inventory.csv"

PP_BITS = {"none": 0, "66": 1, "F3": 2, "F2": 3}
DISP32 = "00 00 00 00"


def c4_bytes(opcode: int, map_bits: int, pp: str, L: int, W: int,
             vvvv_src: int, modrm: int, imm: int = None) -> str:
    """Encode a C4 three-byte VEX prefix for the 0F38 map with the given fields."""
    vvvv_raw = (~vvvv_src) & 0x0F
    byte2 = 0xE0 | map_bits  # R̅=X̅=B̅=1, m-mmmm
    byte3 = (W << 7) | (vvvv_raw << 3) | (L << 2) | PP_BITS[pp]
    body = [0xC4, byte2, byte3, opcode, modrm]
    if imm is not None:
        body.append(imm & 0xFF)
    return " ".join(f"{b:02X}" for b in body)


def with_disp32(bytes_str: str) -> str:
    return f"{bytes_str} {DISP32}"


def make_row(isa: str, modes: str, map_: str, opcode: int, pp: str, L: int, W: int,
             vvvv: str, modrm_kind: str, trailing: str, mnemonic: str,
             operands: str, length: int, bytes_str: str, sdm: str) -> list[str]:
    return [
        isa, modes, map_, f"{opcode:02X}", pp, str(L), str(W), vvvv,
        "any", "any", "any", "none", modrm_kind, trailing,
        mnemonic, operands, str(length), bytes_str,
        "supported", "OK", sdm,
    ]


def isa_for(L: int, base_isa: str) -> str:
    return "AVX2" if L == 1 else base_isa


def gen_nds_family(name: str, opcode: int, pp: str, mem_l0: str,
                   mem_l1: str | None = None, base_isa: str = "AVX",
                   W: int = 0, sdm: str = "SDM 2B") -> list[list[str]]:
    """NDS 3-operand packed or scalar family for 0F38."""
    rows = []
    vvvv_src = 1
    packed = mem_l1 is not None
    widths = [(0, mem_l0)]
    if packed:
        widths.append((1, mem_l1))
    for L, mem_w in widths:
        reg_oprs = "xmm;xmm;xmm" if L == 0 else "ymm;ymm;ymm"
        mem_oprs = f"xmm;xmm;{mem_w}" if L == 0 else f"ymm;ymm;{mem_w}"
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F38", opcode, pp, L, W, "required", "reg", "0:none",
            name, reg_oprs, 5, c4_bytes(opcode, 2, pp, L, W, vvvv_src, 0xC2), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F38", opcode, pp, L, W, "required", "mem", "0:none",
            name, mem_oprs, 9, with_disp32(c4_bytes(opcode, 2, pp, L, W, vvvv_src, 0x05)), sdm))
    return rows


def gen_nds_l1_family(name: str, opcode: int, pp: str, mem: str,
                      base_isa: str = "AVX2", W: int = 0,
                      sdm: str = "SDM 2B") -> list[list[str]]:
    """NDS 3-operand family that is only valid with L=1 (256-bit AVX2)."""
    rows = []
    vvvv_src = 1
    L = 1
    rows.append(make_row(
        base_isa, "both", "0F38", opcode, pp, L, W, "required", "reg", "0:none",
        name, "ymm;ymm;ymm", 5, c4_bytes(opcode, 2, pp, L, W, vvvv_src, 0xC2), sdm))
    rows.append(make_row(
        base_isa, "both", "0F38", opcode, pp, L, W, "required", "mem", "0:none",
        name, f"ymm;ymm;{mem}", 9, with_disp32(c4_bytes(opcode, 2, pp, L, W, vvvv_src, 0x05)), sdm))
    return rows


def gen_no_nds_family(name: str, opcode: int, pp: str,
                      op_l0: tuple[str, str, str],
                      op_l1: tuple[str, str, str] | None = None,
                      base_isa: str = "AVX", W: int = 0,
                      sdm: str = "SDM 2B") -> list[list[str]]:
    """Non-NDS 2-operand family with custom per-L operand widths."""
    rows = []
    vvvv_src = 0
    configs = [(0, op_l0)]
    if op_l1 is not None:
        configs.append((1, op_l1))
    for L, (dst, src, mem) in configs:
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F38", opcode, pp, L, W, "reserved", "reg", "0:none",
            name, f"{dst};{src}", 5, c4_bytes(opcode, 2, pp, L, W, vvvv_src, 0xC2), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F38", opcode, pp, L, W, "reserved", "mem", "0:none",
            name, f"{dst};{mem}", 9, with_disp32(c4_bytes(opcode, 2, pp, L, W, vvvv_src, 0x05)), sdm))
    return rows


def gen_reg_only(name: str, opcode: int, pp: str, dst: str, src: str,
                 base_isa: str = "AVX", W: int = 0, sdm: str = "SDM 2B") -> list[list[str]]:
    rows = []
    vvvv_src = 0
    rows.append(make_row(
        base_isa, "both", "0F38", opcode, pp, 0, W, "reserved", "reg", "0:none",
        name, f"{dst};{src}", 5, c4_bytes(opcode, 2, pp, 0, W, vvvv_src, 0xC2), sdm))
    return rows


def gen_mem_only(name: str, opcode: int, pp: str, dst: str, src: str, mem: str,
                 L: int, base_isa: str = "AVX", W: int = 0,
                 sdm: str = "SDM 2B") -> list[list[str]]:
    rows = []
    vvvv_src = 0
    rows.append(make_row(
        base_isa, "both", "0F38", opcode, pp, L, W, "reserved", "mem", "0:none",
        name, f"{dst};{mem}", 9, with_disp32(c4_bytes(opcode, 2, pp, L, W, vvvv_src, 0x05)), sdm))
    return rows


def gen_nds_mem_only(name: str, opcode: int, pp: str, mem_l0: str,
                     mem_l1: str | None = None, base_isa: str = "AVX",
                     W: int = 0, sdm: str = "SDM 2B") -> list[list[str]]:
    """NDS memory-only family (VPMASKMOVD/Q)."""
    rows = []
    vvvv_src = 1
    packed = mem_l1 is not None
    widths = [(0, mem_l0)]
    if packed:
        widths.append((1, mem_l1))
    for L, mem_w in widths:
        oprs = f"xmm;xmm;{mem_w}" if L == 0 else f"ymm;ymm;{mem_w}"
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F38", opcode, pp, L, W, "required", "mem", "0:none",
            name, oprs, 9, with_disp32(c4_bytes(opcode, 2, pp, L, W, vvvv_src, 0x05)), sdm))
    return rows


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

    # Integer SIMD NDS packed (pp=66).
    for opcode, name in [
        (0x00, "VPSHUFB"), (0x01, "VPHADDW"), (0x02, "VPHADDD"), (0x03, "VPHADDSW"),
        (0x04, "VPMADDUBSW"), (0x05, "VPHSUBW"), (0x06, "VPHSUBD"), (0x07, "VPHSUBSW"),
        (0x08, "VPSIGNB"), (0x09, "VPSIGNW"), (0x0A, "VPSIGND"), (0x0B, "VPMULHRSW"),
    ]:
        specs += gen_nds_family(name, opcode, "66", "m128", "m256")

    # VPERMILPS/PD (pp=66, NDS packed).
    specs += gen_nds_family("VPERMILPS", 0x0C, "66", "m128", "m256")
    specs += gen_nds_family("VPERMILPD", 0x0D, "66", "m128", "m256")

    # VTESTPS/PD (pp=66, non-NDS packed).
    specs += gen_no_nds_family("VTESTPS", 0x0E, "66",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_no_nds_family("VTESTPD", 0x0F, "66",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))

    # VPABSB/W/D (pp=66, non-NDS packed).
    specs += gen_no_nds_family("VPABSB", 0x1C, "66",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_no_nds_family("VPABSW", 0x1D, "66",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_no_nds_family("VPABSD", 0x1E, "66",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))

    # VPMOVSX* / VPMOVZX*.
    def add_movsxzx(sx: bool):
        nonlocal specs
        prefix = "VPMOVSX" if sx else "VPMOVZX"
        specs += gen_no_nds_family(f"{prefix}BW", 0x20 if sx else 0x30, "66",
                                   ("xmm", "xmm", "m64"), ("ymm", "xmm", "m128"))
        specs += gen_no_nds_family(f"{prefix}BD", 0x21 if sx else 0x31, "66",
                                   ("xmm", "xmm", "m32"), ("ymm", "xmm", "m64"))
        specs += gen_no_nds_family(f"{prefix}BQ", 0x22 if sx else 0x32, "66",
                                   ("xmm", "xmm", "m16"), ("ymm", "xmm", "m32"))
        specs += gen_no_nds_family(f"{prefix}WD", 0x23 if sx else 0x33, "66",
                                   ("xmm", "xmm", "m64"), ("ymm", "xmm", "m128"))
        specs += gen_no_nds_family(f"{prefix}WQ", 0x24 if sx else 0x34, "66",
                                   ("xmm", "xmm", "m32"), ("ymm", "xmm", "m64"))
        specs += gen_no_nds_family(f"{prefix}DQ", 0x25 if sx else 0x35, "66",
                                   ("xmm", "xmm", "m64"), ("ymm", "xmm", "m128"))

    add_movsxzx(True)
    add_movsxzx(False)

    # Min/max/compare.
    specs += gen_nds_family("VPCMPGTQ", 0x37, "66", "m128", "m256")
    for name, opcode in [("VPMINSB", 0x38), ("VPMINSD", 0x39), ("VPMINUB", 0x3A), ("VPMINUD", 0x3B),
                         ("VPMAXSB", 0x3C), ("VPMAXSD", 0x3D), ("VPMAXUB", 0x3E), ("VPMAXUD", 0x3F)]:
        specs += gen_nds_family(name, opcode, "66", "m128", "m256")

    specs += gen_nds_family("VPMULLD", 0x40, "66", "m128", "m256")

    # VPHMINPOSUW: L=0 only.
    specs += gen_reg_only("VPHMINPOSUW", 0x41, "66", "xmm", "xmm")

    # AVX2 broadcasts (base_isa=AVX2).
    specs += gen_no_nds_family("VPBROADCASTSS", 0x18, "66",
                               ("xmm", "xmm", "m32"), ("ymm", "xmm", "m32"), base_isa="AVX2")
    # VPBROADCASTSD is AVX2-only and L=1 only (Zydis rejects the 128-bit form).
    specs += gen_mem_only("VPBROADCASTSD", 0x19, "66", "ymm", "xmm", "m64", 1, base_isa="AVX2")
    specs.append(make_row(
        "AVX2", "both", "0F38", 0x19, "66", 1, 0, "reserved", "reg", "0:none",
        "VPBROADCASTSD", "ymm;xmm", 5, c4_bytes(0x19, 2, "66", 1, 0, 0, 0xC2), "SDM 2B"))
    specs += gen_no_nds_family("VPBROADCASTD", 0x58, "66",
                               ("xmm", "xmm", "m32"), ("ymm", "xmm", "m32"), base_isa="AVX2")
    specs += gen_no_nds_family("VPBROADCASTQ", 0x59, "66",
                               ("xmm", "xmm", "m64"), ("ymm", "xmm", "m64"), base_isa="AVX2")
    specs += gen_no_nds_family("VPBROADCASTB", 0x78, "66",
                               ("xmm", "xmm", "m8"), ("ymm", "xmm", "m8"), base_isa="AVX2")
    specs += gen_no_nds_family("VPBROADCASTW", 0x79, "66",
                               ("xmm", "xmm", "m16"), ("ymm", "xmm", "m16"), base_isa="AVX2")

    # VBROADCASTI128: L=1, mem-only.
    specs += gen_mem_only("VBROADCASTI128", 0x5A, "66", "ymm", "xmm", "m128", 1, base_isa="AVX2")

    # AVX2 permutes (L=1 only, pp=66, W=0).
    # Note: VPERMPD/VPERMQ are 0F3A immediate forms only in AVX2.
    specs += gen_nds_l1_family("VPERMPS", 0x16, "66", "m256", base_isa="AVX2", W=0)
    specs += gen_nds_l1_family("VPERMD",  0x36, "66", "m256", base_isa="AVX2", W=0)

    # VPMASKMOVD/Q loads (0x8C) and stores (0x8E), both D (W=0) and Q (W=1).
    for W, mnemonic in [(0, "VPMASKMOVD"), (1, "VPMASKMOVQ")]:
        for L, mem_w, vec_w in [(0, "m128", "xmm"), (1, "m256", "ymm")]:
            # load: dest=vec, mask=vec, memory
            specs.append(make_row(
                "AVX2", "both", "0F38", 0x8C, "66", L, W, "required", "mem", "0:none",
                mnemonic, f"{vec_w};{vec_w};{mem_w}", 9,
                with_disp32(c4_bytes(0x8C, 2, "66", L, W, 1, 0x05)), "SDM 2B"))
            # store: memory, mask=vec, source=vec
            specs.append(make_row(
                "AVX2", "both", "0F38", 0x8E, "66", L, W, "required", "mem", "0:none",
                mnemonic, f"{mem_w};{vec_w};{vec_w}", 9,
                with_disp32(c4_bytes(0x8E, 2, "66", L, W, 1, 0x05)), "SDM 2B"))

    # AVX2 variable shifts (0F38, pp=66, NDS packed).
    #   0x45 W=0 VPSRLVD, W=1 VPSRLVQ
    #   0x46 W=0 VPSRAVD (no Q form in AVX2)
    #   0x47 W=0 VPSLLVD, W=1 VPSLLVQ
    specs += gen_nds_family("VPSRLVD", 0x45, "66", "m128", "m256", base_isa="AVX2", W=0)
    specs += gen_nds_family("VPSRLVQ", 0x45, "66", "m128", "m256", base_isa="AVX2", W=1)
    specs += gen_nds_family("VPSRAVD", 0x46, "66", "m128", "m256", base_isa="AVX2", W=0)
    specs += gen_nds_family("VPSLLVD", 0x47, "66", "m128", "m256", base_isa="AVX2", W=0)
    specs += gen_nds_family("VPSLLVQ", 0x47, "66", "m128", "m256", base_isa="AVX2", W=1)

    # Filter duplicates.
    new_rows = []
    for row in specs:
        key = "|".join(row[i] for i in KEY_INDICES)
        if key not in existing_keys:
            new_rows.append(row)

    if not new_rows:
        print("No new A2a rows to add.")
        return 0

    with CSV_PATH.open(encoding="utf-8", newline="") as f:
        content = f.read()
    if not content.endswith("\n"):
        content += "\n"
    lines = [",".join(f'"{c}"' if "," in c else c for c in row) for row in new_rows]
    with CSV_PATH.open("a", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Added {len(new_rows)} new A2a rows to {CSV_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

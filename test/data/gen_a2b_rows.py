#!/usr/bin/env python3
"""Generate CSV rows for implemented A2b 0F3A-map VEX forms and merge into the inventory."""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = ROOT / "test" / "data" / "vex_avx_inventory.csv"

PP_BITS = {"none": 0, "66": 1, "F3": 2, "F2": 3}
DISP32 = "00 00 00 00"


def c4_bytes(opcode: int, map_bits: int, pp: str, L: int, W: int,
             vvvv_src: int, modrm: int, imm: int = None, is4: int = None) -> str:
    """Encode a C4 three-byte VEX prefix for the 0F3A map with the given fields."""
    vvvv_raw = (~vvvv_src) & 0x0F
    byte2 = 0xE0 | map_bits  # R̅=X̅=B̅=1, m-mmmm
    byte3 = (W << 7) | (vvvv_raw << 3) | (L << 2) | PP_BITS[pp]
    body = [0xC4, byte2, byte3, opcode, modrm]
    if imm is not None:
        body.append(imm & 0xFF)
    if is4 is not None:
        body.append(is4 & 0xFF)
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
    """NDS 3-operand packed family for 0F3A without trailing byte."""
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
            isa_for(L, base_isa), "both", "0F3A", opcode, pp, L, W, "required", "reg", "0:none",
            name, reg_oprs, 5, c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0xC2), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F3A", opcode, pp, L, W, "required", "mem", "0:none",
            name, mem_oprs, 9, with_disp32(c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0x05)), sdm))
    return rows


def gen_nds_imm_family(name: str, opcode: int, pp: str, mem_l0: str,
                       mem_l1: str | None = None, base_isa: str = "AVX",
                       W: int = 0, sdm: str = "SDM 2B") -> list[list[str]]:
    """NDS 3-operand packed imm8 family for 0F3A."""
    rows = []
    vvvv_src = 1
    packed = mem_l1 is not None
    widths = [(0, mem_l0)]
    if packed:
        widths.append((1, mem_l1))
    for L, mem_w in widths:
        reg_oprs = "xmm;xmm;xmm;imm8" if L == 0 else "ymm;ymm;ymm;imm8"
        mem_oprs = f"xmm;xmm;{mem_w};imm8" if L == 0 else f"ymm;ymm;{mem_w};imm8"
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F3A", opcode, pp, L, W, "required", "reg", "1:imm8",
            name, reg_oprs, 6, c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0xC2, imm=0), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F3A", opcode, pp, L, W, "required", "mem", "1:imm8",
            name, mem_oprs, 10, with_disp32(c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0x05, imm=0)), sdm))
    return rows


def gen_nds_scalar_imm_family(name: str, opcode: int, pp: str, mem: str,
                              base_isa: str = "AVX", W: int = 0,
                              sdm: str = "SDM 2B") -> list[list[str]]:
    """NDS scalar imm8 family for 0F3A (e.g. VROUNDSS/SD)."""
    rows = []
    vvvv_src = 1
    L = 0
    rows.append(make_row(
        base_isa, "both", "0F3A", opcode, pp, L, W, "required", "reg", "1:imm8",
        name, "xmm;xmm;xmm;imm8", 6, c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0xC2, imm=0), sdm))
    rows.append(make_row(
        base_isa, "both", "0F3A", opcode, pp, L, W, "required", "mem", "1:imm8",
        name, f"xmm;xmm;{mem};imm8", 10, with_disp32(c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0x05, imm=0)), sdm))
    return rows


def gen_no_nds_imm_family(name: str, opcode: int, pp: str,
                          op_l0: tuple[str, str, str],
                          op_l1: tuple[str, str, str] | None = None,
                          base_isa: str = "AVX", W: int = 0,
                          sdm: str = "SDM 2B") -> list[list[str]]:
    """Non-NDS 2-operand imm8 family with custom per-L operand widths."""
    rows = []
    vvvv_src = 0
    configs = [(0, op_l0)]
    if op_l1 is not None:
        configs.append((1, op_l1))
    for L, (dst, src, mem) in configs:
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F3A", opcode, pp, L, W, "reserved", "reg", "1:imm8",
            name, f"{dst};{src};imm8", 6, c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0xC2, imm=0), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F3A", opcode, pp, L, W, "reserved", "mem", "1:imm8",
            name, f"{dst};{mem};imm8", 10, with_disp32(c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0x05, imm=0)), sdm))
    return rows


def gen_nds_is4_family(name: str, opcode: int, pp: str, mem_l0: str,
                       mem_l1: str | None = None, base_isa: str = "AVX",
                       W: int = 0, sdm: str = "SDM 2B") -> list[list[str]]:
    """NDS /is4 4-operand family for 0F3A."""
    rows = []
    vvvv_src = 1
    packed = mem_l1 is not None
    widths = [(0, mem_l0)]
    if packed:
        widths.append((1, mem_l1))
    for L, mem_w in widths:
        reg_oprs = "xmm;xmm;xmm;xmm" if L == 0 else "ymm;ymm;ymm;ymm"
        mem_oprs = f"xmm;xmm;{mem_w};xmm" if L == 0 else f"ymm;ymm;{mem_w};ymm"
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F3A", opcode, pp, L, W, "required", "reg", "1:is4",
            name, reg_oprs, 6, c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0xC2, is4=0x20), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", "0F3A", opcode, pp, L, W, "required", "mem", "1:is4",
            name, mem_oprs, 10, with_disp32(c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0x05, is4=0x20)), sdm))
    return rows


def gen_l1_nds_imm(name: str, opcode: int, pp: str, mem: str,
                   src: str = "ymm",
                   base_isa: str = "AVX2", W: int = 0,
                   sdm: str = "SDM 2B") -> list[list[str]]:
    """L=1 only NDS imm8 form for 0F3A."""
    rows = []
    vvvv_src = 1
    L = 1
    rows.append(make_row(
        base_isa, "both", "0F3A", opcode, pp, L, W, "required", "reg", "1:imm8",
        name, f"ymm;ymm;{src};imm8", 6, c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0xC2, imm=0), sdm))
    rows.append(make_row(
        base_isa, "both", "0F3A", opcode, pp, L, W, "required", "mem", "1:imm8",
        name, f"ymm;ymm;{mem};imm8", 10, with_disp32(c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0x05, imm=0)), sdm))
    return rows


def gen_l1_no_nds_imm(name: str, opcode: int, pp: str,
                      reg_oprs: str, mem_oprs: str,
                      base_isa: str = "AVX2", W: int = 0,
                      sdm: str = "SDM 2B") -> list[list[str]]:
    """L=1 only non-NDS imm8 form for 0F3A with explicit operand strings."""
    rows = []
    vvvv_src = 0
    L = 1
    rows.append(make_row(
        base_isa, "both", "0F3A", opcode, pp, L, W, "reserved", "reg", "1:imm8",
        name, reg_oprs, 6, c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0xC2, imm=0), sdm))
    rows.append(make_row(
        base_isa, "both", "0F3A", opcode, pp, L, W, "reserved", "mem", "1:imm8",
        name, mem_oprs, 10, with_disp32(c4_bytes(opcode, 3, pp, L, W, vvvv_src, 0x05, imm=0)), sdm))
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

    # VPERM2F128: L=1 only, NDS imm8.
    specs += gen_l1_nds_imm("VPERM2F128", 0x06, "66", "m256")

    # VROUNDPS/PD (non-NDS packed imm8, pp=66).
    specs += gen_no_nds_imm_family("VROUNDPS", 0x08, "66",
                                   ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_no_nds_imm_family("VROUNDPD", 0x09, "66",
                                   ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))

    # VROUNDSS/SD (NDS scalar imm8, pp=66).
    specs += gen_nds_scalar_imm_family("VROUNDSS", 0x0A, "66", "m32")
    specs += gen_nds_scalar_imm_family("VROUNDSD", 0x0B, "66", "m64")

    # VBLENDPS/PD (NDS packed imm8, pp=66).
    specs += gen_nds_imm_family("VBLENDPS", 0x0C, "66", "m128", "m256")
    specs += gen_nds_imm_family("VBLENDPD", 0x0D, "66", "m128", "m256")

    # VPBLENDW (NDS packed imm8, pp=66).
    specs += gen_nds_imm_family("VPBLENDW", 0x0E, "66", "m128", "m256")

    # VPALIGNR (NDS packed imm8, pp=66).
    specs += gen_nds_imm_family("VPALIGNR", 0x0F, "66", "m128", "m256")

    # VEXTRACTF128: L=1 only, non-NDS imm8 (store form).
    specs += gen_l1_no_nds_imm("VEXTRACTF128", 0x19, "66", "xmm;ymm;imm8", "m128;ymm;imm8")

    # VINSERTF128: L=1 only, NDS imm8.
    specs += gen_l1_nds_imm("VINSERTF128", 0x18, "66", "m128", src="xmm")

    # VDPPS (NDS packed imm8, pp=66).
    specs += gen_nds_imm_family("VDPPS", 0x40, "66", "m128", "m256")

    # VDPPD (NDS packed imm8, pp=66, L=0 only).
    specs += gen_nds_imm_family("VDPPD", 0x41, "66", "m128", None)

    # VMPSADBW (NDS packed imm8, pp=66).
    specs += gen_nds_imm_family("VMPSADBW", 0x42, "66", "m128", "m256")

    # /is4 blend forms (pp=66).
    specs += gen_nds_is4_family("VBLENDVPS", 0x4A, "66", "m128", "m256")
    specs += gen_nds_is4_family("VBLENDVPD", 0x4B, "66", "m128", "m256")
    specs += gen_nds_is4_family("VPBLENDVB", 0x4C, "66", "m128", "m256")

    # VPERMQ / VPERMPD immediate (AVX2, L=1 only, W=1).
    specs += gen_l1_no_nds_imm("VPERMQ", 0x00, "66", "ymm;ymm;imm8", "ymm;m256;imm8", W=1)
    specs += gen_l1_no_nds_imm("VPERMPD", 0x01, "66", "ymm;ymm;imm8", "ymm;m256;imm8", W=1)

    # Filter duplicates.
    new_rows = []
    for row in specs:
        key = "|".join(row[i] for i in KEY_INDICES)
        if key not in existing_keys:
            new_rows.append(row)

    if not new_rows:
        print("No new A2b rows to add.")
        return 0

    with CSV_PATH.open(encoding="utf-8", newline="") as f:
        content = f.read()
    if not content.endswith("\n"):
        content += "\n"
    lines = [",".join(f'"{c}"' if "," in c else c for c in row) for row in new_rows]
    with CSV_PATH.open("a", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Added {len(new_rows)} new A2b rows to {CSV_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

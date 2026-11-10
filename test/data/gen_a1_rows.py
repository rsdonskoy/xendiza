#!/usr/bin/env python3
"""Generate CSV rows for implemented A1 0F-map VEX forms and merge into the inventory."""

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = ROOT / "test" / "data" / "vex_avx_inventory.csv"

PP_BITS = {"none": 0, "66": 1, "F3": 2, "F2": 3}
DISP32 = "00 00 00 00"


def c5_second(vvvv_src: int, L: int, pp: int) -> int:
    """C5 second byte: inverted R=1, inverted vvvv, L, pp."""
    vvvv_raw = (~vvvv_src) & 0x0F
    return 0x80 | (vvvv_raw << 3) | (L << 2) | pp


def encode_bytes(opcode: int, pp: str, L: int, vvvv_src: int,
                 modrm: int, imm: int = None) -> str:
    """Encode a C5-prefixed VEX instruction with the given fields."""
    prefix = [0xC5, c5_second(vvvv_src, L, PP_BITS[pp])]
    body = prefix + [opcode, modrm]
    if imm is not None:
        body.append(imm & 0xFF)
    return " ".join(f"{b:02X}" for b in body)


def with_disp32(bytes_str: str) -> str:
    return f"{bytes_str} {DISP32}"


def make_row(isa: str, modes: str, opcode: int, pp: str, L: int, W: int,
             vvvv: str, modrm_kind: str, trailing: str, mnemonic: str,
             operands: str, length: int, bytes_str: str, sdm: str) -> list[str]:
    return [
        isa, modes, "0F", f"{opcode:02X}", pp, str(L), str(W), vvvv,
        "any", "any", "any", "none", modrm_kind, trailing,
        mnemonic, operands, str(length), bytes_str,
        "supported", "OK", sdm,
    ]


def isa_for(L: int, base_isa: str | tuple[str, str] | list[str]) -> str:
    """Return the ISA for a given L bit.

    `base_isa` is either a single ISA used for both L values, or a
    two-element sequence ``(L0_isa, L1_isa)`` for families whose 256-bit
    form belongs to a different ISA (e.g. integer SIMD).
    """
    if isinstance(base_isa, str):
        return base_isa
    return base_isa[L]


def gen_nds_family(name: str, opcode: int, pp: str, mem_l0: str,
                   mem_l1: str | None = None, is_scalar: bool = False,
                   base_isa: str | tuple[str, str] | list[str] = "AVX",
                   sdm: str = "SDM 2B") -> list[list[str]]:
    """NDS 3-operand packed or scalar family (VADDPS, VADDSS, VPADDB, ...)."""
    rows = []
    vvvv_src = 1  # canonical NDS source = xmm1
    packed = mem_l1 is not None
    widths = [(0, mem_l0)]
    if packed:
        widths.append((1, mem_l1))
    for L, mem_w in widths:
        if is_scalar:
            reg_oprs = "xmm;xmm;xmm"
            mem_oprs = f"xmm;xmm;{mem_w}"
        else:
            reg_oprs = "xmm;xmm;xmm" if L == 0 else "ymm;ymm;ymm"
            mem_oprs = (f"xmm;xmm;{mem_w}" if L == 0 else f"ymm;ymm;{mem_w}")
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "required", "reg", "0:none",
            name, reg_oprs, 4, encode_bytes(opcode, pp, L, vvvv_src, 0xC2), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "required", "mem", "0:none",
            name, mem_oprs, 8, with_disp32(encode_bytes(opcode, pp, L, vvvv_src, 0x05)), sdm))
    return rows


def gen_nds_imm_family(name: str, opcode: int, pp: str, mem_l0: str,
                       mem_l1: str | None = None, is_scalar: bool = False,
                       imm: int = 0x01,
                       base_isa: str | tuple[str, str] | list[str] = "AVX",
                       sdm: str = "SDM 2B") -> list[list[str]]:
    """NDS 3-operand + imm8 family (VCMPPS, VSHUFPS, ...)."""
    rows = []
    vvvv_src = 1
    packed = mem_l1 is not None
    widths = [(0, mem_l0)]
    if packed:
        widths.append((1, mem_l1))
    for L, mem_w in widths:
        if is_scalar:
            reg_oprs = "xmm;xmm;xmm;imm8"
            mem_oprs = f"xmm;xmm;{mem_w};imm8"
        else:
            reg_oprs = "xmm;xmm;xmm;imm8" if L == 0 else "ymm;ymm;ymm;imm8"
            mem_oprs = (f"xmm;xmm;{mem_w};imm8" if L == 0 else f"ymm;ymm;{mem_w};imm8")
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "required", "reg", "1:imm8",
            name, reg_oprs, 5, encode_bytes(opcode, pp, L, vvvv_src, 0xC2, imm), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "required", "mem", "1:imm8",
            name, mem_oprs, 9, with_disp32(encode_bytes(opcode, pp, L, vvvv_src, 0x05, imm)), sdm))
    return rows


def gen_move_family(name: str, opcode: int, pp: str, is_load: bool,
                    mem_l0: str, mem_l1: str | None = None,
                    base_isa: str | tuple[str, str] | list[str] = "AVX",
                    sdm: str = "SDM 2B") -> list[list[str]]:
    """Non-NDS packed move load/store family (VMOVUPS, VMOVAPS, ...)."""
    rows = []
    vvvv_src = 0
    packed = mem_l1 is not None
    widths = [(0, mem_l0)]
    if packed:
        widths.append((1, mem_l1))
    for L, mem_w in widths:
        dst = "xmm" if L == 0 else "ymm"
        src = "xmm" if L == 0 else "ymm"
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "reserved", "reg", "0:none",
            name, f"{dst};{src}", 4, encode_bytes(opcode, pp, L, vvvv_src, 0xC2), sdm))
        if is_load:
            mem_oprs = f"{dst};{mem_w}"
        else:
            mem_oprs = f"{mem_w};{src}"
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "reserved", "mem", "0:none",
            name, mem_oprs, 8, with_disp32(encode_bytes(opcode, pp, L, vvvv_src, 0x05)), sdm))
    return rows




def gen_scalar_move_load_family(name: str, opcode: int, pp: str, mem_op: str,
                                base_isa: str = "AVX",
                                sdm: str = "SDM 2B") -> list[list[str]]:
    """Scalar move load family (VMOVSS, VMOVSD): register merge is NDS 3-op."""
    rows = []
    # Register merge form: dest = xmm0, src1 (mask/merge) = vvvv, src2 = xmm2.
    rows.append(make_row(
        base_isa, "both", opcode, pp, 0, 0, "required", "reg", "0:none",
        name, "xmm;xmm;xmm", 4, encode_bytes(opcode, pp, 0, 1, 0xC2), sdm))
    # Memory load form is non-NDS.
    rows.append(make_row(
        base_isa, "both", opcode, pp, 0, 0, "reserved", "mem", "0:none",
        name, f"xmm;{mem_op}", 8, with_disp32(encode_bytes(opcode, pp, 0, 0, 0x05)), sdm))
    return rows


def gen_scalar_move_store_family(name: str, opcode: int, pp: str, mem_op: str,
                                 base_isa: str = "AVX",
                                 sdm: str = "SDM 2B") -> list[list[str]]:
    """Scalar move store family (VMOVSS, VMOVSD): memory-only, non-NDS."""
    rows = []
    rows.append(make_row(
        base_isa, "both", opcode, pp, 0, 0, "reserved", "mem", "0:none",
        name, f"{mem_op};xmm", 8, with_disp32(encode_bytes(opcode, pp, 0, 0, 0x05)), sdm))
    return rows


def gen_two_op_family(name: str, opcode: int, pp: str,
                      op_l0: tuple[str, str, str],
                      op_l1: tuple[str, str, str] | None = None,
                      base_isa: str | tuple[str, str] | list[str] = "AVX",
                      sdm: str = "SDM 2B") -> list[list[str]]:
    """Non-NDS 2-operand family with custom per-L operand widths."""
    rows = []
    vvvv_src = 0
    configs = [(0, op_l0)]
    if op_l1 is not None:
        configs.append((1, op_l1))
    for L, (dst, src, mem) in configs:
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "reserved", "reg", "0:none",
            name, f"{dst};{src}", 4, encode_bytes(opcode, pp, L, vvvv_src, 0xC2), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "reserved", "mem", "0:none",
            name, f"{dst};{mem}", 8, with_disp32(encode_bytes(opcode, pp, L, vvvv_src, 0x05)), sdm))
    return rows


def gen_imm_non_nds_family(name: str, opcode: int, pp: str, mem_l0: str,
                           mem_l1: str | None = None, imm: int = 0x1B,
                           base_isa: str | tuple[str, str] | list[str] = "AVX",
                           sdm: str = "SDM 2B") -> list[list[str]]:
    """Non-NDS 2-operand + imm8 family (VPSHUFD, VPSHUFHW, VPSHUFLW)."""
    rows = []
    vvvv_src = 0
    packed = mem_l1 is not None
    widths = [(0, mem_l0)]
    if packed:
        widths.append((1, mem_l1))
    for L, mem_w in widths:
        dst = "xmm" if L == 0 else "ymm"
        src = "xmm" if L == 0 else "ymm"
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "reserved", "reg", "1:imm8",
            name, f"{dst};{src};imm8", 5, encode_bytes(opcode, pp, L, vvvv_src, 0xC2, imm), sdm))
        rows.append(make_row(
            isa_for(L, base_isa), "both", opcode, pp, L, 0, "reserved", "mem", "1:imm8",
            name, f"{dst};{mem_w};imm8", 9, with_disp32(encode_bytes(opcode, pp, L, vvvv_src, 0x05, imm)), sdm))
    return rows


def gen_reg_only_family(name: str, opcode: int, pp: str, dst: str, src: str,
                        base_isa: str = "AVX", sdm: str = "SDM 2B") -> list[list[str]]:
    """Register-only non-NDS 2-operand family (VMOVMSKPS, VPMOVMSKB)."""
    rows = []
    vvvv_src = 0
    rows.append(make_row(
        base_isa, "both", opcode, pp, 0, 0, "reserved", "reg", "0:none",
        name, f"{dst};{src}", 4, encode_bytes(opcode, pp, 0, vvvv_src, 0xC2), sdm))
    return rows


def gen_scalar_compare_family(name: str, opcode: int, pp: str, mem_op: str,
                              base_isa: str = "AVX", sdm: str = "SDM 2B") -> list[list[str]]:
    """Scalar compare family (VUCOMISS, VUCOMISD, VCOMISS, VCOMISD)."""
    rows = []
    vvvv_src = 0
    rows.append(make_row(
        base_isa, "both", opcode, pp, 0, 0, "reserved", "reg", "0:none",
        name, "xmm;xmm", 4, encode_bytes(opcode, pp, 0, vvvv_src, 0xC2), sdm))
    rows.append(make_row(
        base_isa, "both", opcode, pp, 0, 0, "reserved", "mem", "0:none",
        name, f"xmm;{mem_op}", 8, with_disp32(encode_bytes(opcode, pp, 0, vvvv_src, 0x05)), sdm))
    return rows


def gen_vmovd(sdm: str = "SDM 2B") -> list[list[str]]:
    """VMOVD load (0F 6E) and store (0F 7E) forms."""
    rows = []
    vvvv_src = 0
    pp = "66"
    base_isa = "AVX"
    # load: xmm, r32/m32
    rows.append(make_row(
        base_isa, "both", 0x6E, pp, 0, 0, "reserved", "reg", "0:none",
        "VMOVD", "xmm;r32", 4, encode_bytes(0x6E, pp, 0, vvvv_src, 0xC2), sdm))
    rows.append(make_row(
        base_isa, "both", 0x6E, pp, 0, 0, "reserved", "mem", "0:none",
        "VMOVD", "xmm;m32", 8, with_disp32(encode_bytes(0x6E, pp, 0, vvvv_src, 0x05)), sdm))
    # store: r32/m32, xmm
    rows.append(make_row(
        base_isa, "both", 0x7E, pp, 0, 0, "reserved", "reg", "0:none",
        "VMOVD", "r32;xmm", 4, encode_bytes(0x7E, pp, 0, vvvv_src, 0xC2), sdm))
    rows.append(make_row(
        base_isa, "both", 0x7E, pp, 0, 0, "reserved", "mem", "0:none",
        "VMOVD", "m32;xmm", 8, with_disp32(encode_bytes(0x7E, pp, 0, vvvv_src, 0x05)), sdm))
    return rows


def main() -> int:
    if not CSV_PATH.exists():
        print(f"ERROR: {CSV_PATH} not found", file=sys.stderr)
        return 1

    # Read existing rows to avoid duplicates (keyed by the columns used by check_inventory.py).
    # CSV column order: isa=0 modes=1 map=2 opcode=3 pp=4 L=5 W=6 vvvv=7 ...
    # modrm=12 trailing=13 mnemonic=14 operands=15 bytes=17
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

    # Packed move load/store families.
    for opcode, name, pp in [(0x10, "VMOVUPS", "none"),
                             (0x10, "VMOVUPD", "66"),
                             (0x28, "VMOVAPS", "none"),
                             (0x28, "VMOVAPD", "66")]:
        specs += gen_move_family(name, opcode, pp, True, "m128", "m256")
    for opcode, name, pp in [(0x11, "VMOVUPS", "none"),
                             (0x11, "VMOVUPD", "66"),
                             (0x29, "VMOVAPS", "none"),
                             (0x29, "VMOVAPD", "66")]:
        specs += gen_move_family(name, opcode, pp, False, "m128", "m256")

    # Non-temporal packed stores (memory-only, non-NDS).
    for opcode, name, pp in [(0x2B, "VMOVNTPS", "none"),
                             (0x2B, "VMOVNTPD", "66")]:
        for L, mem_w, vec_w in [(0, "m128", "xmm"), (1, "m256", "ymm")]:
            specs.append(make_row(
                "AVX", "both", opcode, pp, L, 0, "reserved", "mem", "0:none",
                name, f"{mem_w};{vec_w}", 8,
                with_disp32(encode_bytes(opcode, pp, L, 0, 0x05)), "SDM 2B"))

    # Scalar moves: load vs store have different operand forms.
    specs += gen_scalar_move_load_family("VMOVSS", 0x10, "F3", "m32")
    specs += gen_scalar_move_store_family("VMOVSS", 0x11, "F3", "m32")
    specs += gen_scalar_move_load_family("VMOVSD", 0x10, "F2", "m64")
    specs += gen_scalar_move_store_family("VMOVSD", 0x11, "F2", "m64")

    # Scalar compares.
    specs += gen_scalar_compare_family("VUCOMISS", 0x2E, "none", "m32")
    specs += gen_scalar_compare_family("VUCOMISD", 0x2E, "66", "m64")
    specs += gen_scalar_compare_family("VCOMISS", 0x2F, "none", "m32")
    specs += gen_scalar_compare_family("VCOMISD", 0x2F, "66", "m64")

    # VMOVMSKPS/PD.
    specs += gen_reg_only_family("VMOVMSKPS", 0x50, "none", "r32", "xmm")
    specs += gen_reg_only_family("VMOVMSKPD", 0x50, "66", "r32", "xmm")

    # Packed arithmetic families.
    arith = {
        0x58: ("VADDPS", "VADDPD", "VADDSS", "VADDSD"),
        0x59: ("VMULPS", "VMULPD", "VMULSS", "VMULSD"),
        0x5C: ("VSUBPS", "VSUBPD", "VSUBSS", "VSUBSD"),
        0x5D: ("VMINPS", "VMINPD", "VMINSS", "VMINSD"),
        0x5E: ("VDIVPS", "VDIVPD", "VDIVSS", "VDIVSD"),
        0x5F: ("VMAXPS", "VMAXPD", "VMAXSS", "VMAXSD"),
    }
    for opcode, (ps, pd, ss, sd) in arith.items():
        specs += gen_nds_family(ps, opcode, "none", "m128", "m256")
        specs += gen_nds_family(pd, opcode, "66", "m128", "m256")
        specs += gen_nds_family(ss, opcode, "F3", "m32", is_scalar=True)
        specs += gen_nds_family(sd, opcode, "F2", "m64", is_scalar=True)

    # Logical packed.
    for opcode, ps, pd in [(0x54, "VANDPS", "VANDPD"),
                           (0x55, "VANDNPS", "VANDNPD"),
                           (0x56, "VORPS", "VORPD"),
                           (0x57, "VXORPS", "VXORPD")]:
        specs += gen_nds_family(ps, opcode, "none", "m128", "m256")
        specs += gen_nds_family(pd, opcode, "66", "m128", "m256")

    # Square root: packed is 2-operand non-NDS, scalar is NDS.
    specs += gen_two_op_family("VSQRTPS", 0x51, "none",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_two_op_family("VSQRTPD", 0x51, "66",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_nds_family("VSQRTSS", 0x51, "F3", "m32", is_scalar=True)
    specs += gen_nds_family("VSQRTSD", 0x51, "F2", "m64", is_scalar=True)

    # Reciprocal/RSQRT: packed is 2-operand non-NDS, scalar is NDS.
    specs += gen_two_op_family("VRSQRTPS", 0x52, "none",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_nds_family("VRSQRTSS", 0x52, "F3", "m32", is_scalar=True)
    specs += gen_two_op_family("VRCPPS", 0x53, "none",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_nds_family("VRCPSS", 0x53, "F3", "m32", is_scalar=True)

    # Conversions.
    specs += gen_two_op_family("VCVTPS2PD", 0x5A, "none",
                               ("xmm", "xmm", "m64"), ("ymm", "xmm", "m128"))
    specs += gen_two_op_family("VCVTPD2PS", 0x5A, "66",
                               ("xmm", "xmm", "m128"), ("xmm", "ymm", "m256"))
    specs += gen_nds_family("VCVTSS2SD", 0x5A, "F3", "m32", is_scalar=True)
    specs += gen_nds_family("VCVTSD2SS", 0x5A, "F2", "m64", is_scalar=True)
    specs += gen_two_op_family("VCVTDQ2PS", 0x5B, "none",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_two_op_family("VCVTPS2DQ", 0x5B, "66",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))
    specs += gen_two_op_family("VCVTTPS2DQ", 0x5B, "F3",
                               ("xmm", "xmm", "m128"), ("ymm", "ymm", "m256"))

    # Unpack.
    for opcode, ps, pd in [(0x14, "VUNPCKLPS", "VUNPCKLPD"),
                           (0x15, "VUNPCKHPS", "VUNPCKHPD")]:
        specs += gen_nds_family(ps, opcode, "none", "m128", "m256")
        specs += gen_nds_family(pd, opcode, "66", "m128", "m256")

    # HADD/HSUB: PS forms use F2, PD forms use 66.
    for opcode, ps, pd in [(0x7C, "VHADDPS", "VHADDPD"),
                           (0x7D, "VHSUBPS", "VHSUBPD")]:
        specs += gen_nds_family(ps, opcode, "F2", "m128", "m256")
        specs += gen_nds_family(pd, opcode, "66", "m128", "m256")

    # Compare and shuffle with imm8.
    specs += gen_nds_imm_family("VCMPPS", 0xC2, "none", "m128", "m256", imm=0x01)
    specs += gen_nds_imm_family("VCMPPD", 0xC2, "66", "m128", "m256", imm=0x01)
    specs += gen_nds_imm_family("VCMPSS", 0xC2, "F3", "m32", is_scalar=True, imm=0x01)
    specs += gen_nds_imm_family("VCMPSD", 0xC2, "F2", "m64", is_scalar=True, imm=0x01)
    specs += gen_nds_imm_family("VSHUFPS", 0xC6, "none", "m128", "m256", imm=0x03)
    specs += gen_nds_imm_family("VSHUFPD", 0xC6, "66", "m128", "m256", imm=0x03)

    # 128-bit integer SIMD (pp=66), L=1 is AVX2.
    int_simd_isa = ("AVX", "AVX2")
    for opcode, name in [(0xFC, "VPADDB"), (0xFD, "VPADDW"),
                         (0xFE, "VPADDD"), (0xD4, "VPADDQ"),
                         (0xE8, "VPSUBB"), (0xE9, "VPSUBW"),
                         (0xFA, "VPSUBD"), (0xFB, "VPSUBQ"),
                         (0xDB, "VPAND"),  (0xDF, "VPANDN"),
                         (0xEB, "VPOR"),   (0xEF, "VPXOR"),
                         (0x74, "VPCMPEQB"), (0x75, "VPCMPEQW"), (0x76, "VPCMPEQD"),
                         (0x64, "VPCMPGTB"), (0x65, "VPCMPGTW"), (0x66, "VPCMPGTD"),
                         (0xD5, "VPMULLW"),  (0xE5, "VPMULHW"),
                         (0xE4, "VPMULHUW"), (0xF4, "VPMULUDQ"),
                         (0x60, "VPUNPCKLBW"), (0x61, "VPUNPCKLWD"),
                         (0x62, "VPUNPCKLDQ"), (0x6C, "VPUNPCKLQDQ"),
                         (0x68, "VPUNPCKHBW"), (0x69, "VPUNPCKHWD"),
                         (0x6A, "VPUNPCKHDQ"), (0x6D, "VPUNPCKHQDQ")]:
        specs += gen_nds_family(name, opcode, "66", "m128", "m256",
                                base_isa=int_simd_isa)

    # VPMOVMSKB.
    specs += gen_reg_only_family("VPMOVMSKB", 0xD7, "66", "r32", "xmm")

    # VPSHUFD/PSHUFHW/PSHUFLW.
    specs += gen_imm_non_nds_family("VPSHUFD",  0x70, "66", "m128", "m256",
                                    imm=0x1B, base_isa=int_simd_isa)
    specs += gen_imm_non_nds_family("VPSHUFHW", 0x70, "F3", "m128", "m256",
                                    imm=0x1B, base_isa=int_simd_isa)
    specs += gen_imm_non_nds_family("VPSHUFLW", 0x70, "F2", "m128", "m256",
                                    imm=0x1B, base_isa=int_simd_isa)

    # VMOVD load/store.
    specs += gen_vmovd()

    # Filter out rows already present in the inventory.
    new_rows = []
    for row in specs:
        key = "|".join(row[i] for i in KEY_INDICES)
        if key not in existing_keys:
            new_rows.append(row)

    if not new_rows:
        print("No new A1 rows to add.")
        return 0

    with CSV_PATH.open(encoding="utf-8", newline="") as f:
        content = f.read()
    # Ensure the file ends with a newline before appending.
    if not content.endswith("\n"):
        content += "\n"
    lines = [",".join(f'"{c}"' if "," in c else c for c in row) for row in new_rows]
    with CSV_PATH.open("a", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Added {len(new_rows)} new A1 rows to {CSV_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

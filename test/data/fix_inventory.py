#!/usr/bin/env python3
"""Batch-correct test/data/vex_avx_inventory.csv for reviewer findings."""

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CSV_PATH = ROOT / "test" / "data" / "vex_avx_inventory.csv"

# AVX2-only mnemonics (everything else with L=1 is plain AVX).
AVX2_ONLY = {
    "VPADDB", "VPADDD", "VPADDQ", "VPADDW",
    "VPABSB", "VPABSD", "VPABSW",
    "VPAND", "VPANDN",
    "VPCMPEQB", "VPCMPEQD", "VPCMPEQQ", "VPCMPEQW",
    "VPCMPGTB", "VPCMPGTD", "VPCMPGTQ", "VPCMPGTW",
    "VPMOVMSKB",
    "VPMULHUW", "VPMULHW", "VPMULLD", "VPMULLW", "VPMULUDQ",
    "VPOR",
    "VPSHUFB", "VPSHUFD", "VPSHUFHW", "VPSHUFLW",
    "VPSLLD", "VPSLLDQ", "VPSLLQ", "VPSLLW",
    "VPSRAD", "VPSRAW", "VPSRLD", "VPSRLDQ", "VPSRLQ", "VPSRLW",
    "VPSUBB", "VPSUBD", "VPSUBQ", "VPSUBW",
    "VPUNPCKHBW", "VPUNPCKHDQ", "VPUNPCKHQDQ", "VPUNPCKHWD",
    "VPUNPCKLBW", "VPUNPCKLDQ", "VPUNPCKLQDQ", "VPUNPCKLWD",
    "VPXOR",
    "VPHADDD", "VPHADDSW", "VPHADDW", "VPHMINPOSUW",
    "VPHSUBD", "VPHSUBSW", "VPHSUBW",
    "VPMADDUBSW",
    "VPMAXSB", "VPMAXSD", "VPMAXUB", "VPMAXUD",
    "VPMINSB", "VPMINSD", "VPMINUB", "VPMINUD",
    "VPMOVSXBD", "VPMOVSXBQ", "VPMOVSXBW",
    "VPMOVSXDQ", "VPMOVSXWD", "VPMOVSXWQ",
    "VPMOVZXBD", "VPMOVZXBQ", "VPMOVZXBW",
    "VPMOVZXDQ", "VPMOVZXWD", "VPMOVZXWQ",
    "VPMULHRSW",
    "VPSIGNB", "VPSIGND", "VPSIGNW",
    "VPBLENDVB", "VPBLENDW",
    "VPBROADCASTB", "VPBROADCASTD", "VPBROADCASTQ",
    "VPBROADCASTSD", "VPBROADCASTSS", "VPBROADCASTW",
    "VBROADCASTI128",
    "VPERM2F128", "VPERMD", "VPERMPS", "VPERMQ", "VPERMPD",
    "VEXTRACTF128", "VINSERTF128",
    "VPSLLVD", "VPSLLVQ", "VPSRAVD", "VPSRAVQ", "VPSRLVD", "VPSRLVQ",
    "VPGATHERDD", "VPGATHERDQ", "VPGATHERQD", "VPGATHERQQ",
    "VGATHERDPS", "VGATHERDPD", "VGATHERQPS", "VGATHERQPD",
    "VPMASKMOVD", "VPMASKMOVQ",
}


def make_key(row):
    return (row["map"], row["opcode"], row["pp"], row["L"], row["W"], row["bytes"])


def fix_isa(row):
    """Most 256-bit FP/AVX forms are AVX, not AVX2."""
    if row["L"] == "1" and row["mnemonic"] not in AVX2_ONLY:
        row["isa"] = "AVX"


def fix_vmovss_sd(row, rows_by_key):
    """Scalar register merge form is NDS 3-op; store has no register form."""
    if row["mnemonic"] in ("VMOVSS", "VMOVSD") and row["modrm"] == "reg":
        if row["opcode"] == "10":  # load / merge
            row["vvvv"] = "required"
            row["operands"] = "xmm;xmm;xmm"
            # Update the VEX.vvvv byte to encode a non-reserved register (ymm1).
            # C5 FA -> C5 F2 for VMOVSS (pp=F3); C5 FB -> C5 F3 for VMOVSD (pp=F2).
            if row["mnemonic"] == "VMOVSS":
                row["bytes"] = "C5 F2 10 C2"
            else:
                row["bytes"] = "C5 F3 10 C2"
        else:  # opcode 11 store: register form is architecturally invalid
            row["class"] = "invalid"
            row["error"] = "UNDEFINED_INSTRUCTION"
            row["length"] = ""
            row["operands"] = ""


def fix_variable_shifts(row):
    """Correct W=0 rows that were mislabeled and leave room for W=1 rows."""
    if row["map"] != "0F38" or row["pp"] != "66" or row["opcode"] not in ("45", "46", "47"):
        return
    if row["W"] == "0":
        if row["opcode"] == "46":
            row["mnemonic"] = "VPSRAVD"


def fix_vpermq_pd(row):
    if row["mnemonic"] in ("VPERMQ", "VPERMPD") and row["modrm"] == "reg":
        row["operands"] = "ymm;ymm;imm8"


def fix_gather(row):
    """Set architectural order (dest, VSIB memory, mask) and mixed-width forms."""
    if row["mnemonic"] not in (
        "VPGATHERDD", "VPGATHERDQ", "VPGATHERQD", "VPGATHERQQ",
        "VGATHERDPS", "VGATHERDPD", "VGATHERQPS", "VGATHERQPD",
    ):
        return

    wide = row["L"] == "1"
    q_index = row["mnemonic"] in ("VPGATHERDQ", "VPGATHERQQ", "VGATHERDPD", "VGATHERQPD")
    qd_or_qps = row["mnemonic"] in ("VPGATHERQD", "VGATHERQPS")

    vsib = "m64_vsib" if q_index else "m32_vsib"
    if qd_or_qps:
        # 256-bit index but data element is 64/32-bit -> XMM dest/mask.
        dest_mask = "xmm"
    else:
        dest_mask = "ymm" if wide else "xmm"

    row["operands"] = f"{dest_mask};{vsib};{dest_mask}"


def remove_bad_vpsrlvq_rows(row):
    """Drop rows that claim W=0 opcodes are the Q forms."""
    if row["map"] == "0F38" and row["pp"] == "66" and row["opcode"] in ("45", "46", "47"):
        if row["mnemonic"].endswith("Q") and row["W"] == "0":
            return True
    return False


def remove_bad_vpmaskmov_rows(row):
    """0x8E is now the store encoding; remove stale load rows."""
    return row["map"] == "0F38" and row["opcode"] == "8E"


def remove_bad_w1_shift_rows(row):
    """Remove malformed W=1 variable-shift rows from earlier script versions."""
    if row["map"] != "0F38" or row["pp"] != "66" or row["W"] != "1":
        return False
    if row["opcode"] not in ("45", "46", "47"):
        return False
    # VPSRAVQ is not an AVX2 instruction; remove any W=1 rows for opcode 0x46.
    if row["opcode"] == "46":
        return True
    return "Fmm" in row["bytes"] or row["operands"].startswith("71;") or row["operands"].startswith("75;")


def remove_pclmulqdq(row):
    return row["mnemonic"] == "VPCLMULQDQ"


def build_vpsravd_rows():
    """Return W=0 VPSRAVD rows (0x46, AVX2-only, no Q form)."""
    rows = []
    for L, vreg, mreg, vlen_byte in [("0", "xmm", "m128", "71"), ("1", "ymm", "m256", "75")]:
        rows.append({
            "isa": "AVX2", "modes": "both", "map": "0F38", "opcode": "46", "pp": "66",
            "L": L, "W": "0", "vvvv": "required", "ext_r": "any", "ext_x": "any",
            "ext_b": "any", "prefixes": "none", "modrm": "reg", "trailing": "0:none",
            "mnemonic": "VPSRAVD", "operands": f"{vreg};{vreg};{vreg}", "length": "5",
            "bytes": f"C4 E2 {vlen_byte} 46 C2", "class": "supported", "error": "OK",
            "sdm": "SDM 2B",
        })
        rows.append({
            "isa": "AVX2", "modes": "both", "map": "0F38", "opcode": "46", "pp": "66",
            "L": L, "W": "0", "vvvv": "required", "ext_r": "any", "ext_x": "any",
            "ext_b": "any", "prefixes": "none", "modrm": "mem", "trailing": "0:none",
            "mnemonic": "VPSRAVD", "operands": f"{vreg};{vreg};{mreg}", "length": "9",
            "bytes": f"C4 E2 {vlen_byte} 46 05 00 00 00 00", "class": "supported",
            "error": "OK", "sdm": "SDM 2B",
        })
    return rows


def build_w1_variable_shift_rows():
    """Return new W=1 rows for 0x45/0x46/0x47 variable shifts."""
    specs = [
        ("45", "VPSRLVQ"),
        # VPSRAVQ is not AVX2; only VPSRLVQ and VPSLLVQ have Q forms.
        ("47", "VPSLLVQ"),
    ]
    new_rows = []
    for opcode, mnemonic in specs:
        for L, vreg, mreg, vlen_byte in [("0", "xmm", "m128", "71"), ("1", "ymm", "m256", "75")]:
            # reg form: C4 E2 <vvvv_byte> <opcode> C2
            new_rows.append({
                "isa": "AVX2",
                "modes": "both",
                "map": "0F38",
                "opcode": opcode,
                "pp": "66",
                "L": L,
                "W": "1",
                "vvvv": "required",
                "ext_r": "any",
                "ext_x": "any",
                "ext_b": "any",
                "prefixes": "none",
                "modrm": "reg",
                "trailing": "0:none",
                "mnemonic": mnemonic,
                "operands": f"{vreg};{vreg};{vreg}",
                "length": "5",
                "bytes": f"C4 E2 F{vlen_byte[1:]} {opcode} C2",
                "class": "supported",
                "error": "OK",
                "sdm": "SDM 2B",
            })
            # mem form: C4 E2 <vvvv_byte> <opcode> 05 00 00 00 00
            new_rows.append({
                "isa": "AVX2",
                "modes": "both",
                "map": "0F38",
                "opcode": opcode,
                "pp": "66",
                "L": L,
                "W": "1",
                "vvvv": "required",
                "ext_r": "any",
                "ext_x": "any",
                "ext_b": "any",
                "prefixes": "none",
                "modrm": "mem",
                "trailing": "0:none",
                "mnemonic": mnemonic,
                "operands": f"{vreg};{vreg};{mreg}",
                "length": "9",
                "bytes": f"C4 E2 F{vlen_byte[1:]} {opcode} 05 00 00 00 00",
                "class": "supported",
                "error": "OK",
                "sdm": "SDM 2B",
            })
    return new_rows


def build_vmovnt_rows():
    """Return VMOVNTPS/VMOVNTPD store rows (2-byte and 3-byte VEX)."""
    rows = []
    configs = [
        ("none", "VMOVNTPS", "F8", "78", "m128", "xmm", "0"),
        ("none", "VMOVNTPS", "FC", "7C", "m256", "ymm", "1"),
        ("66", "VMOVNTPD", "F9", "79", "m128", "xmm", "0"),
        ("66", "VMOVNTPD", "FD", "7D", "m256", "ymm", "1"),
    ]
    for pp, mnemonic, two_byte_v, three_byte_v, mreg, vreg, L in configs:
        rows.append({
            "isa": "AVX",
            "modes": "both",
            "map": "0F",
            "opcode": "2B",
            "pp": pp,
            "L": L,
            "W": "0",
            "vvvv": "reserved",
            "ext_r": "any",
            "ext_x": "any",
            "ext_b": "any",
            "prefixes": "none",
            "modrm": "mem",
            "trailing": "0:none",
            "mnemonic": mnemonic,
            "operands": f"{mreg};{vreg}",
            "length": "8",
            "bytes": f"C5 {two_byte_v} 2B 05 00 00 00 00",
            "class": "supported",
            "error": "OK",
            "sdm": "SDM 2B",
        })
        rows.append({
            "isa": "AVX",
            "modes": "both",
            "map": "0F",
            "opcode": "2B",
            "pp": pp,
            "L": L,
            "W": "0",
            "vvvv": "reserved",
            "ext_r": "any",
            "ext_x": "any",
            "ext_b": "any",
            "prefixes": "none",
            "modrm": "mem",
            "trailing": "0:none",
            "mnemonic": mnemonic,
            "operands": f"{mreg};{vreg}",
            "length": "9",
            "bytes": f"C4 E1 {three_byte_v} 2B 05 00 00 00 00",
            "class": "supported",
            "error": "OK",
            "sdm": "SDM 2B",
        })
    return rows


def build_vpmaskmov_load_rows():
    """Return VPMASKMOVQ load (0x8C W=1) rows that were missing."""
    rows = []
    for W, mnemonic, vvvv_bytes in [("0", "VPMASKMOVD", {"0": "71", "1": "75"}),
                                     ("1", "VPMASKMOVQ", {"0": "F1", "1": "F5"})]:
        for L, mreg, vreg in [("0", "m128", "xmm"), ("1", "m256", "ymm")]:
            rows.append({
                "isa": "AVX2",
                "modes": "both",
                "map": "0F38",
                "opcode": "8C",
                "pp": "66",
                "L": L,
                "W": W,
                "vvvv": "required",
                "ext_r": "any",
                "ext_x": "any",
                "ext_b": "any",
                "prefixes": "none",
                "modrm": "mem",
                "trailing": "0:none",
                "mnemonic": mnemonic,
                "operands": f"{vreg};{vreg};{mreg}",
                "length": "9",
                "bytes": f"C4 E2 {vvvv_bytes[L]} 8C 05 00 00 00 00",
                "class": "supported",
                "error": "OK",
                "sdm": "SDM 2B",
            })
    return rows


def build_vpmaskmov_store_rows():
    """Return VPMASKMOVD/Q store (0x8E) rows."""
    rows = []
    for W, mnemonic, vvvv_bytes in [("0", "VPMASKMOVD", {"0": "71", "1": "75"}),
                                     ("1", "VPMASKMOVQ", {"0": "F1", "1": "F5"})]:
        for L, mreg, vreg in [("0", "m128", "xmm"), ("1", "m256", "ymm")]:
            rows.append({
                "isa": "AVX2",
                "modes": "both",
                "map": "0F38",
                "opcode": "8E",
                "pp": "66",
                "L": L,
                "W": W,
                "vvvv": "required",
                "ext_r": "any",
                "ext_x": "any",
                "ext_b": "any",
                "prefixes": "none",
                "modrm": "mem",
                "trailing": "0:none",
                "mnemonic": mnemonic,
                "operands": f"{mreg};{vreg};{vreg}",
                "length": "9",
                "bytes": f"C4 E2 {vvvv_bytes[L]} 8E 05 00 00 00 00",
                "class": "supported",
                "error": "OK",
                "sdm": "SDM 2B",
            })
    return rows


def main():
    with CSV_PATH.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    # Apply per-row fixes and drop obsolete rows.
    kept = []
    seen = set()
    for row in rows:
        if remove_pclmulqdq(row):
            continue
        if remove_bad_vpsrlvq_rows(row):
            continue
        if remove_bad_vpmaskmov_rows(row):
            continue
        if remove_bad_w1_shift_rows(row):
            continue
        fix_isa(row)
        fix_vmovss_sd(row, None)
        fix_variable_shifts(row)
        fix_vpermq_pd(row)
        fix_gather(row)
        key = make_key(row)
        if key in seen:
            continue
        seen.add(key)
        kept.append(row)

    # Append missing rows (skip duplicates).
    for new_row in (
        build_vmovnt_rows()
        + build_vpmaskmov_load_rows()
        + build_vpmaskmov_store_rows()
        + build_vpsravd_rows()
        + build_w1_variable_shift_rows()
    ):
        key = make_key(new_row)
        if key in seen:
            continue
        seen.add(key)
        kept.append(new_row)

    with CSV_PATH.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(kept)

    print(f"Wrote {len(kept)} rows to {CSV_PATH}")


if __name__ == "__main__":
    main()

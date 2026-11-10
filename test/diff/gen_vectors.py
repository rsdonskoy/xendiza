#!/usr/bin/env python3
"""Convert Zydis / Capstone test cases into xendiza differential test vectors.

Stream-based: each vector is a byte stream plus the expected instruction
sequence. The harness decodes sequentially (like a real linear-disassembly
consumer); `size` expectations are only checked when the source provides them.

Output: out/streams.jsonl
  {src, id, mode, bytes, insns: [{mnemonic, ops ([..]|null), size (int|null)}]}
And out/streams.tsv for the harness:
  mode TAB hex TAB srcid TAB count
"""
import glob
import json
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # repo root (test/diff/ -> test/ -> root)
OUT = os.path.join(HERE, "out")
TP = os.path.join(ROOT, "third_party")

# ---------------------------------------------------------------------------
# Mnemonic mapping: capstone/zydis lowercase spellings -> xendiza OpcodeId names
# ---------------------------------------------------------------------------
JCC = ["jo", "jno", "jb", "jae", "jz", "jnz", "jbe", "ja", "js", "jns", "jp",
       "jnp", "jl", "jge", "jle", "jg"]
JCC_ALIAS = {
    "jnae": "jb", "jc": "jb", "jnb": "jae", "jnc": "jae", "je": "jz",
    "jne": "jnz", "jna": "jbe", "jnbe": "ja", "jpe": "jp", "jpo": "jnp",
    "jnge": "jl", "jnl": "jge", "jng": "jle", "jnle": "jg",
}
CCMAP = {
    "o": ("CMOVO", "SETO", "JO"), "no": ("CMOVNO", "SETNO", "JNO"),
    "b": ("CMOVB", "SETB", "JB"), "ae": ("CMOVAE", "SETAE", "JAE"),
    "z": ("CMOVZ", "SETZ", "JZ"), "nz": ("CMOVNZ", "SETNZ", "JNZ"),
    "be": ("CMOVBE", "SETBE", "JBE"), "a": ("CMOVA", "SETA", "JA"),
    "s": ("CMOVS", "SETS", "JS"), "ns": ("CMOVNS", "SETNS", "JNS"),
    "p": ("CMOVP", "SETP", "JP"), "np": ("CMOVNP", "SETNP", "JNP"),
    "l": ("CMOVL", "SETL", "JL"), "ge": ("CMOVGE", "SETGE", "JGE"),
    "le": ("CMOVLE", "SETLE", "JLE"), "g": ("CMOVG", "SETG", "JG"),
}
MNEMONIC_MAP = {
    "movabs": "MOV", "mov": "MOV",
    "movq": "MOV",  # ATT name for plain 64-bit MOV (xendiza: MOV + r64/rm64)
    "ret": "RET", "retq": "RET", "retl": "RET", "retw": "RET",
    "lret": "RETF", "retf": "RETF", "lretq": "RETF", "retfq": "RETF", "lretl": "RETF",
    "jmp": "JMP", "call": "CALL", "callq": "CALL",
    "nop": "NOP", "nopw": "NOP", "nopl": "NOP", "pause": "PAUSE",
    "leave": "LEAVE", "leaveq": "LEAVE",
    "cltq": "CDQE", "cqto": "CQO", "cltd": "CDQ", "cwtd": "CWD", "cbw": "CBW",
    "cbtw": "CBW", "cwtl": "CWDE",
    "clc": "CLC", "stc": "STC", "cli": "CLI", "sti": "STI", "cld": "CLD",
    "std": "STD", "cmc": "CMC", "hlt": "HLT",
    "sahf": "SAHF", "lahf": "LAHF", "xlat": "XLAT", "xlatb": "XLATB",
    "int3": "INT3", "int": "INT", "into": "INTO",
    "iret": "IRET", "iretd": "IRETD", "iretq": "IRETQ", "iretw": "IRET",
    "in": "IN", "out": "OUT", "ins": "INS", "outs": "OUTS",
    "movsb": "MOVS", "movsw": "MOVS", "movsl": "MOVS", "movsq": "MOVS",
    "cmpsb": "CMPS", "cmpsw": "CMPS", "cmpsl": "CMPS", "cmpsq": "CMPS",
    "stosb": "STOS", "stosw": "STOS", "stosl": "STOS", "stosq": "STOS",
    "lodsb": "LODS", "lodsw": "LODS", "lodsl": "LODS", "lodsq": "LODS",
    "scasb": "SCAS", "scasw": "SCAS", "scasl": "SCAS", "scasq": "SCAS",
    "insb": "INS", "insw": "INS", "insl": "INS",
    "outsb": "OUTS", "outsw": "OUTS", "outsl": "OUTS",
    "wait": "FWAIT", "fwait": "FWAIT",
    "jrcxz": "JRCXZ", "jecxz": "JRCXZ", "jcxz": "JRCXZ",
    "loop": "LOOP", "loope": "LOOPE", "loopne": "LOOPNE", "loopnz": "LOOPNE",
    "popaw": "POPA", "popal": "POPAD", "pushaw": "PUSHA", "pushal": "PUSHAD",
    "pushfq": "PUSHFQ", "popfq": "POPFQ", "pushf": "PUSHF", "popf": "POPF",
    "pushfd": "PUSHFD", "popfd": "POPFD",
    "sysenter": "SYSENTER", "sysexit": "SYSEXIT", "syscall": "SYSCALL",
    "sysret": "SYSRET",
    "rdtsc": "RDTSC", "rdtscp": "RDTSCP", "cpuid": "CPUID",
    "rdmsr": "RDMSR", "wrmsr": "WRMSR", "rdpmc": "RDPMC",
    "ud2": "UD", "xgetbv": "XGETBV", "xsetbv": "XSETBV",
    "monitor": "MONITOR", "mwait": "MWAIT", "swapgs": "SWAPGS",
    "invd": "INVD", "invlpg": "INVLPG", "wbinvd": "WBINVD",
    "enter": "ENTER", "arpl": "ARPL", "xadd": "XADD",
    "fnstsw": "FNSTSW", "fnstcw": "FNSTCW", "fldcw": "FLDCW",
    "fstcw": "FSTCW", "fstsw": "FSTSW",
    "emms": "EMMS",
    "movsx": "MOVSX", "movsxd": "MOVSXD", "movzx": "MOVZX",
    "fldl2t": "FLDL2T", "fldl2e": "FLDL2E", "fldlg2": "FLDLG2",
    "fldln2": "FLDLN2", "fldpi": "FLDPI", "fldz": "FLDZ", "fld1": "FLD1",
    # SSE forms that appear in capstone/zydis x86 test data
    "movups": "MOVUPS", "movaps": "MOVAPS", "movupd": "MOVUPD",
    "movapd": "MOVAPD", "movss": "MOVSS", "movsd": "MOVSD",
    "movd": "MOVD", "movdqa": "MOVDQA", "movdqu": "MOVDQU",
    "movntps": "MOVNTPS", "movntpd": "MOVNTPD", "movnti": "MOVNTI",
    "movmskps": "MOVMSKPS", "movmskpd": "MOVMSKPD",
    "movddup": "MOVDDUP", "movshdup": "MOVSHDUP", "movsldup": "MOVSLDUP",
    "movlhps": "MOVLHPS", "movhlps": "MOVHLPS",
    "movlps": "MOVLPS", "movhps": "MOVHPS", "movlpd": "MOVLPD", "movhpd": "MOVHPD",
    "addps": "ADDPS", "addpd": "ADDPD", "addss": "ADDSS", "addsd": "ADDSD",
    "subps": "SUBPS", "subpd": "SUBPD", "subss": "SUBSS", "subsd": "SUBSD",
    "mulps": "MULPS", "mulpd": "MULPD", "mulss": "MULSS", "mulsd": "MULSD",
    "divps": "DIVPS", "divpd": "DIVPD", "divss": "DIVSS", "divsd": "DIVSD",
    "andps": "ANDPS", "andpd": "ANDPD", "orps": "ORPS", "orpd": "ORPD",
    "xorps": "XORPS", "xorpd": "XORPD", "andnps": "ANDNPS", "andnpd": "ANDNPD",
    "ucomiss": "UCOMISS", "ucomisd": "UCOMISD", "comiss": "COMISS",
    "comisd": "COMISD", "sqrtps": "SQRTPS", "sqrtpd": "SQRTPD",
    "maxps": "MAXPS", "maxpd": "MAXPD", "maxss": "MAXSS", "maxsd": "MAXSD",
    "minps": "MINPS", "minpd": "MINPD", "minss": "MINSS", "minsd": "MINSD",
    "punpcklbw": "PUNPCKLBW", "punpcklwd": "PUNPCKLWD",
    "punpckldq": "PUNPCKLDQ", "punpcklqdq": "PUNPCKLQDQ",
    "punpckhbw": "PUNPCKHBW", "punpckhwd": "PUNPCKHWD",
    "punpckhdq": "PUNPCKHDQ", "punpckhqdq": "PUNPCKHQDQ",
    "pshufd": "PSHUFD", "pshufhw": "PSHUFHW", "pshuflw": "PSHUFLW",
    "shufps": "SHUFPS", "shufpd": "SHUFPD",
    "crc32": "CRC32", "popcnt": "POPCNT", "lzcnt": "LZCNT",
    "psllw": "PSLLW", "pslld": "PSLLD", "psllq": "PSLLQ",
    "psrlw": "PSRLW", "psrld": "PSRLD", "psrlq": "PSRLQ",
    "psraw": "PSRAW", "psrad": "PSRAD",
    "pcmpeqb": "PCMPEQB", "pcmpeqd": "PCMPEQD", "pcmpgtd": "PCMPGTD",
    "pxor": "PXOR", "por": "POR", "pand": "PAND", "pandn": "PANDN",
    "packsswb": "PACKSSWB", "packssdw": "PACKSSDW", "packuswb": "PACKUSWB",
    "prefetchnta": "PREFETCHNTA", "prefetcht0": "PREFETCHT0",
    "prefetcht1": "PREFETCHT1", "prefetcht2": "PREFETCHT2",
    "clflush": "CLFLUSH", "lfence": "LFENCE", "mfence": "MFENCE",
    "sfence": "SFENCE", "stmxcsr": "STMXCSR", "ldmxcsr": "LDMXCSR",
    "fxsave": "FXSAVE", "fxrstor": "FXRSTOR",
    "rdrand": "RDRAND", "rdseed": "RDSEED", "rdpid": "RDPID",
    "cmpxchg8b": "CMPXCHG8B", "cmpxchg16b": "CMPXCHG16B",
    "rsm": "RSM",
}

XENDIZA_NAMES = set("""
AAA AAD AAM AAS ADC ADD ADDPD ADDPS ADDSD ADDSS AND ANDPD ANDPS ARPL BSF BSR
BSWAP BT BTC BTR BTS CALL CBW CDQ CDQE CLC CLD CLDEMOTE CLFLUSH CLI CLTS CMC
CMOVO CMOVNO CMOVB CMOVAE CMOVZ CMOVNZ CMOVBE CMOVA CMOVS CMOVNS CMOVP CMOVNP
CMOVL CMOVGE CMOVLE CMOVG CMP CMPS CMPSB CMPSW CMPSD CMPSQ CMPXCHG CMPXCHG8B
CMPXCHG16B COMISD COMISS CPUID CQO CWD CWDE DAA DAS DEC DIV EMMS ENTER HLT
IDIV IMUL IN INC INT INT1 INT3 INTO INVD INVLPG IRET IRETD IRETQ JMP JRCXZ
LAHF LAR LDS LEA LEAVE LES LFENCE LFS LGDT LGS LIDT LLDT LMSW LODSB LODSW
LODSD LODSQ LOOP LOOPE LOOPNE LSL LSS LTR MFENCE MONITOR MOV MOVAPS MOVUPS
MOVAPD MOVUPD MOVD MOVQ MOVSB MOVSW MOVSD MOVSQ MOVS MOVSX MOVSXD MOVZX MUL
MWAIT NEG NOP NOT OR ORPD ORPS OUT OUTS PAUSE POP POPA POPAD POPF POPFD POPFQ
PREFETCHNTA PREFETCHT0 PREFETCHT1 PREFETCHT2 PUSH PUSHA PUSHAD PUSHF PUSHFD
PUSHFQ RCL RCR RDMSR RDPID RDPKRU RDPMC RDRAND RDSEED RDTSC RDTSCP RET RETF
ROL ROR RSM SAHF SAL SAR SBB SCAS SCASB SCASW SCASD SCASQ SERIALIZE SETO SETNO
SETB SETAE SETZ SETNZ SETBE SETA SETS SETNS SETP SETNP SETL SETGE SETLE SETG
SFENCE SGDT SHLD SHRD SIDT SLDT SMSW STAC STC STD STI STMXCSR STOS STOSB
STOSW STOSD STOSQ STR SUB SUBPD SUBPS SUBSD SUBSS SWAPGS SYSCALL SYSENTER
SYSEXIT SYSRET TEST UCOMISD UCOMISS UD XADD XCHG XGETBV XLAT XLATB XOR XORPD
XORPS XSAVE XSAVEC XSAVEOPT XSAVES XRSTOR XRSTORS XSETBV XTEST
FWAIT F2XM1 FABS FADD FADDP FBLD FBSTP FCHS FCLEX FCOM FCOMP FCOMPP FCOS
FDECSTP FDIV FDIVP FDIVR FDIVRP FFREE FIADD FICOM FICOMP FIDIV FIDIVR FILD
FIMUL FINCSTP FINIT FIST FISTP FISUB FISUBR FLD FLD1 FLDCW FLDENV FLDL2E
FLDL2T FLDLG2 FLDLN2 FLDPI FLDZ FMUL FMULP FNCLEX FNINIT FNOP FNSAVE FNSTCW
FNSTENV FNSTSW FPATAN FPREM FPREM1 FPTAN FRNDINT FRSTOR FSAVE FSCALE FSIN
FSINCOS FSQRT FST FSTCW FSTENV FSTP FSTSW FSUB FSUBP FSUBR FSUBRP FTST FUCOM
FUCOMP FUCOMPP FXAM FXCH FXRSTOR FXSAVE FXTRACT FYL2X FYL2XP1
PUNPCKLBW PUNPCKLWD PUNPCKLDQ PUNPCKLQDQ PUNPCKHBW PUNPCKHWD PUNPCKHDQ
PUNPCKHQDQ PSHUFD PSHUFHW PSHUFLW SHUFPS SHUFPD PSHUFW
PADDB PADDW PADDD PADDQ PADDSB PADDSW PADDUSB PADDUSW PSUBB PSUBW PSUBD PSUBQ
PSUBSB PSUBSW PSUBUSB PSUBUSW PMULLW PMULHW PMULHUW PMADDWD PMULUDQ PAVGB
PAVGW PMAXUB PMAXSB PMINUB PMINSB PMAXSW PMINSW PMAXSD PMINSD PSADBW
MASKMOVDQU MASKMOVQ MOVNTDQ MOVDQ2Q MOVQ2DQ
PABSB PABSW PABSD PABSQ PALIGNR PHADDW PHADDD PHADDSW PHSUBW PHSUBD PHSUBSW
PMADDUBSW PHMINPOSUW PMAXSB PMAXSD PMAXSW PMAXUB PMAXUD PMAXUW PMINSB PMINSD
PMINSW PMINUB PMINUD PMINUW PMOVMSKB PMOVSX PMOVZX PMULDQ PMULLD PSIGNB PSIGNW
PSIGND PSHUFB PSLLDQ PSRLDQ PCMPEQQ PCMPGTB PCMPGTQ PTEST
ADDPD ADDPS ADDSD ADDSS ADDSUBPD ADDSUBPS DPPD DPPS EXTRACTPS INSERTPS HADDPD
HADDPS HSUBPD HSUBPS MPSADBW PBLENDVB PBLENDW PCLMULQDQ PCMPESTRI PCMPESTRM
PCMPISTRI PCMPISTRM ROUNDPD ROUNDPS ROUNDSD ROUNDSS
LDDQU MOVDDUP MOVSHDUP MOVSLDUP
CRC32 MOVBE POPCNT
BLENDVPS BLENDVPD PEXTRB PEXTRW PEXTRD PEXTRQ PINSRB PINSRD PINSRQ
AESIMC AESENC AESENCLAST AESDEC AESDECLAST AESKEYGENASSIST
""".split())

def map_mnemonic(m):
    m = m.lower()
    if m in MNEMONIC_MAP:
        return MNEMONIC_MAP[m]
    if m in JCC or m in JCC_ALIAS or (m.startswith("j") and m not in ("jmp",)):
        cond = JCC_ALIAS.get(m, m)[1:]
        return CCMAP[cond][2] if cond in CCMAP else "Jcc"
    if m.startswith("set"):
        cond = m[3:]
        cond = JCC_ALIAS.get("j" + cond, "j" + cond)[1:]
        return CCMAP[cond][1] if cond in CCMAP else None
    if m.startswith("cmov"):
        cond = m[4:]
        cond = JCC_ALIAS.get("j" + cond, "j" + cond)[1:]
        return CCMAP[cond][0] if cond in CCMAP else None
    for suf in ("q", "l", "w", "b", "t", "s"):
        if m.endswith(suf) and len(m) > len(suf) and m[: -len(suf)].upper() in XENDIZA_NAMES:
            return m[: -len(suf)].upper()
    if m.upper() in XENDIZA_NAMES:
        return m.upper()
    return None

# ---------------------------------------------------------------------------
# Operand mapping
# ---------------------------------------------------------------------------
GPR_SIZE = {1: "r8", 2: "r16", 4: "r32", 8: "r64"}

def cs_operand(op):
    t = op.get("type")
    size = op.get("size", 0)
    if t == "X86_OP_REG":
        reg = str(op.get("reg", "")).lower()
        if reg.startswith("xmm"):
            return "xmm"
        if reg.startswith(("mm", "k", "cr", "dr", "tr")) or reg in ("eip", "rip"):
            return None
        if reg.startswith("st"):
            return "st0" if reg in ("st(0)", "st0") else "sti"
        if reg in ("es", "cs", "ss", "ds", "fs", "gs"):
            return "sreg"
        return GPR_SIZE.get(size)
    if t == "X86_OP_MEM":
        return {1: "m8", 2: "m16", 4: "m32", 6: "m16_32", 8: "m64",
                16: "m128", 10: "m80"}.get(size)
    if t == "X86_OP_IMM":
        return {1: "imm8", 2: "imm16", 4: "imm32", 8: "imm64"}.get(size)
    return None

def zydis_operand(otype, osize):
    # ZydisInfo reports SIZE in bits; xendiza classes are byte-sized.
    if otype == "REGISTER":
        return GPR_SIZE.get(osize // 8)
    if otype == "MEMORY":
        if osize == 80:
            return "m80fp"
        return {1: "m8", 2: "m16", 4: "m32", 6: "m16_32", 8: "m64",
                16: "m128"}.get(osize // 8)
    if otype == "IMMEDIATE":
        return {1: "imm8", 2: "imm16", 4: "imm32", 8: "imm64"}.get(osize // 8)
    if otype == "RELATIVE":
        return {8: "rel8", 16: "rel16", 32: "rel32", 64: "rel32"}.get(osize)
    if otype == "POINTER":
        return "ptr16_32" if osize and osize > 32 else "ptr16_16"
    return None

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)

PREFIX_TOKENS = ("repz", "repnz", "rep", "repe", "repne", "lock", "bnd",
                 "notrack", "xacquire", "xrelease")

def asm_mnemonic(asm):
    toks = asm.replace(",", " ").split()
    while toks and toks[0].lower() in PREFIX_TOKENS:
        toks.pop(0)
    return map_mnemonic(toks[0].lower()) if toks else None

def parse_capstone_yaml(path, srcname, streams):
    """All capstone YAMLs share the test_cases schema; build stream vectors."""
    data = load_yaml(path)
    for ci, case in enumerate(data.get("test_cases", []) or []):
        inp = case.get("input", {})
        opts = inp.get("options", []) or []
        mode = 64 if "CS_MODE_64" in opts else 32 if "CS_MODE_32" in opts else 16
        raw = inp.get("bytes", [])
        insns = (case.get("expected", {}) or {}).get("insns", []) or []
        if mode == 16 or not raw or not insns:
            continue
        exp = []
        usable = True
        for ins in insns:
            asm = ins.get("asm_text", "")
            if not asm:
                usable = False
                break
            ops = None
            det = (ins.get("details", {}) or {}).get("x86", {}) or {}
            cops = det.get("operands")
            if cops:
                mapped = [cs_operand(o) for o in cops]
                # capstone's operand array follows the print syntax:
                # AT&T (source-first) vs Intel (dest-first).
                if "CS_OPT_SYNTAX_ATT" in opts:
                    mapped.reverse()
                ops = mapped if None not in mapped else None
            exp.append({"mnemonic": asm_mnemonic(asm), "ops": ops,
                        "size": ins.get("size")})
        if usable:
            streams.append({"src": srcname, "id": f"{os.path.basename(path)}#{ci}",
                            "mode": mode, "bytes": bytes(raw).hex(), "insns": exp})

ZYDIS_BASIC_RE = re.compile(r"^== \[    BASIC \]", re.M)
MN_RE = re.compile(r"MNEMONIC:\s+(\S+)")
LEN_RE = re.compile(r"LENGTH:\s+(\d+)")
OPROW_RE = re.compile(
    r"^\s*\d+\s+(REGISTER|MEMORY|IMMEDIATE|POINTER|RELATIVE)\s+"
    r"(\w+)\s+\w+\s+\S+\s+(\d+)", re.M)

def parse_zydis(streams):
    for inf in sorted(glob.glob(os.path.join(TP, "zydis", "default_*.in"))):
        outf = inf[:-3] + ".out"
        if not os.path.exists(outf):
            continue
        args = open(inf).read().strip()
        parts = args.split()
        mode, hexs = None, ""
        for p in parts:
            if p.startswith("-"):
                mode = {"-64": 64, "-32": 32, "-16": 16}.get(p)
            else:
                hexs = p
        if mode is None or not hexs:
            continue
        text = open(outf, encoding="utf-8", errors="replace").read()
        exp = []
        for blk in ZYDIS_BASIC_RE.split(text):
            mm = MN_RE.search(blk)
            ml = LEN_RE.search(blk)
            if not mm or not ml:
                continue
            ops, bad = [], False
            for m in OPROW_RE.finditer(blk):
                if m.group(2) != "EXPLICIT":
                    continue
                o = zydis_operand(m.group(1), int(m.group(3)))
                if o is None:
                    bad = True
                    break
                ops.append(o)
            name = map_mnemonic(mm.group(1))
            if name is None:
                continue
            exp.append({"mnemonic": name, "ops": None if bad else ops,
                        "size": int(ml.group(1))})
        if exp:
            streams.append({"src": "zydis", "id": os.path.basename(inf)[:-3],
                            "mode": mode, "bytes": hexs, "insns": exp})

def main():
    streams = []
    files = [os.path.join(TP, "capstone", "x86.yaml")] + \
        sorted(glob.glob(os.path.join(TP, "capstone", "*.yaml")))
    seen = set()
    for f in files:
        if f in seen or os.path.basename(f) == "x86_jcc_mode.yaml" and False:
            continue
        seen.add(f)
        before = len(streams)
        parse_capstone_yaml(f, "capstone", streams)
        print(f"{os.path.basename(f)}: +{len(streams) - before}", file=sys.stderr)
    before = len(streams)
    parse_zydis(streams)
    print(f"zydis: +{len(streams) - before}", file=sys.stderr)

    with open(os.path.join(OUT, "streams.jsonl"), "w") as f:
        for s in streams:
            f.write(json.dumps(s) + "\n")
    with open(os.path.join(OUT, "streams.tsv"), "w") as f:
        for s in streams:
            f.write(f"{s['mode']}\t{s['bytes']}\t{s['src']}:{s['id']}\t{len(s['insns'])}\n")
    n_insns = sum(len(s["insns"]) for s in streams)
    print(f"streams: {len(streams)}, expected instructions: {n_insns}",
          file=sys.stderr)

if __name__ == "__main__":
    main()

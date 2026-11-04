# Differential test vectors from Zydis and Capstone

This directory converts test data from the [Zydis](https://github.com/zyantific/zydis)
and [Capstone](https://github.com/capstone-engine/capstone) projects into
differential vectors for xendiza, and runs a comparison against the decoder.

## Why external vectors

The hand-written GoogleTest suites assert xendiza against itself. These vectors
assert it against two independent, widely validated decoders:

- **Capstone** test data (`tests/details/x86.yaml`, `tests/MC/X86/*.s.yaml`,
  `tests/issues/x86-*.yaml`) is ported from LLVM MC tests — independent ground
  truth with structured operand details (type/size/prefix/modrm) in
  `details/x86.yaml`, plus mnemonic/length expectations elsewhere.
- **Zydis** regression cases (`tests/cases/default_*.in/.out`) carry full
  ZydisInfo dumps (mnemonic, length, explicit operand types+sizes). They are
  fuzzer-derived crash regressions, so they are great edge-case byte streams;
  expectations are Zydis-generated (useful for differential agreement, less so
  as independent truth).

## Layout

- `gen_vectors.py` — parses `third_party/` YAML / ZydisInfo dumps into
  `out/streams.jsonl` (byte stream + expected instruction sequence).
- `harness.cpp` — decodes each stream linearly with xendiza and prints
  per-instruction results. Uses a minimal `gsl/span` shim
  (`gsl/span`) instead of Microsoft.GSL.
- `build.bat` — compiles the harness with MSVC (no CMake/GTest/GSL needed);
  binaries and objects go to `out/`.
- `compare.py` — runs the harness, normalizes representation differences
  (AT&T vs Intel operand order, sign-extended immediates, segment composites,
  string-op no-operand policy), and reports match/mismatch statistics plus
  `out/report.json`.

All generated artifacts live in `out/` (gitignored).

## Usage

Run from the repo root:

```bash
python test/diff/gen_vectors.py     # rebuild out/streams.jsonl from third_party/
cmd //c test/diff/build.bat         # build out/harness.exe (MSVC dev environment)
python test/diff/compare.py         # run and report
```

## Current results (2026-11-04, post add-sse1-sse2-support)

- 425 streams / 773 expected instructions from 13 files.
- Agreement: **90.7%** of comparable instructions (baseline before the SSE
  change: 89.9%); Zydis vectors 53/56. Delta drivers: the legacy SSE1/SSE2
  scope gaps closed (`MOVSD F2 0F 10`, `MOVQ 66 0F D6`, `PMOVMSKB`, packed
  block rows), plus harness mnemonic-name completion.
- Remaining deltas classify into:
  - **By design** (unit-tested in `test/`): legacy-invalid opcodes in 32-bit
    mode (POP/PUSH segreg, PUSHA/POPA, INTO), MOV CR/DR memory forms,
    strict duplicate/mandatory-prefix rejection (capstone's
    `x86-mandatory-prefixes.yaml` expects last-prefix-wins for `66`+`F2`/`F3`
    mixes; xendiza returns undefined-instruction), MMX strict rejection
    (packed-integer opcodes without the mandatory `66h` and MMX-operand
    variants such as `F2/F3 0F D6` and REX+MMX `0F 6E/7E` decode
    `UNDEFINED_INSTRUCTION`), F2-prefixed `0F BC/BD` decoded as BSF/BSR
    (Intel ignores `F2` there; capstone expects `LZCNT`/`TZCNT` — xendiza
    follows the SDM), capstone aliasing `66 0F D6` to `MOV` (xendiza reports
    the SDM mnemonic `MOVQ`), string instructions without explicit operands,
    and 64-bit near branches keeping `rel32` under the `0x66` prefix (Intel
    ignores the prefix there; see below).
  - **Scope gaps**: three-byte opcodes `0F 38`/`0F 3A` (`CRC32`,
    `PHADDSW`, SSSE3/SSE4.x), reserved-NOP forms `0F 19-1B/1D` (capstone
    reports `NOP`), VEX/EVEX (zydis EVEX fuzzer case), and the capstone
    `48 A1` stream quirk (expects `imm64` operand naming for `moffs64`).
    AVX files are excluded entirely.
  - **Known upstream divergence**: capstone's `x86_jcc_mode.yaml` "DEFAULT"
    64-bit vectors expect `0x66`-prefixed Jcc to decode as `rel16`
    (AMD-style). xendiza follows the Intel SDM / Zydis default, where the
    `0x66` prefix is ignored on near branches in 64-bit mode (`rel32`,
    length includes the prefix byte). Zydis calls the capstone behavior
    `ZYDIS_DECODER_MODE_AMD_BRANCHES` and does not enable it by default.

## Resolved in fix-operand16-branches-and-aam-aad

The two former "suspected real issues" are fixed and covered by GoogleTest
cases:

1. ~~`66`-prefixed near branches in 64-bit decode as `rel32`~~ — analysis
   showed this is correct Intel behavior (prefix ignored in 64-bit mode);
   the actual defect was the `eAX, imm32` family (`05/0D/…/3D`, `A9`) and
   `PUSH imm32` (`68`) ignoring `0x66` in the 64-bit path. They now decode
   as `ax, imm16` / `imm16` with the shortened length.
2. `AAM`/`AAD` (`D4`/`D5`) now decode in 32-bit mode as `AAM`/`AAD ax,
   imm8` (length 2, truncated buffer → `INSUFFICIENT_BUFFER`) and remain
   `UNDEFINED_INSTRUCTION` in 64-bit mode.

## License note

`third_party/zydis/*` is MIT (see `third_party/zydis/LICENSE`).
`third_party/capstone/*` is BSD-3-Clause; the MC-derived files trace to LLVM
test data (see `third_party/capstone/LICENSE_LLVM.TXT`). Both are compatible
with xendiza's Apache-2.0; keep the license files alongside any data you keep.

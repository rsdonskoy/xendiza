# Xendiza

[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=c%2B%2B&logoColor=white)](#)
[![Build: CMake](https://img.shields.io/badge/Build-CMake-064F8C?logo=cmake&logoColor=white)](#build)
[![Tests: GoogleTest](https://img.shields.io/badge/Tests-GoogleTest-25A162)](#test-status)
[![Targets: x86/x64](https://img.shields.io/badge/Targets-IA--32%20%7C%20x86--64-6f42c1)](#scope-and-limits)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Fast IA-32 and x86-64 disassembler focused on code analysis workloads.

License: Apache License 2.0. See `LICENSE` for details.

## Goals

- High throughput for linear decode workloads.
- Simple API for C++ and C callers.
- Deterministic decode behavior with strong test coverage.
- Dual-mode: both 32-bit (IA-32) and 64-bit (x86-64) decode paths.
- Complete Intel AVX/AVX2 VEX decoding through shared, table-driven descriptors.

## Current Public API

### C++

```cpp
#include <xendiza/xendiza.hpp>

// 64-bit mode
std::array<uint8_t, 2> code{0x90, 0x90};
auto di64 = xendiza::Disasm<64>(gsl::span<const uint8_t>(code));

// 32-bit mode
auto di32 = xendiza::Disasm<32>(gsl::span<const uint8_t>(code));
```

Supported overloads:

- `DecodedInstruction xendiza::Disasm<64>(gsl::span<const uint8_t>)`
- `DecodedInstruction xendiza::Disasm<64>(gsl::span<const std::byte>)`
- `DecodedInstruction xendiza::Disasm<32>(gsl::span<const uint8_t>)`
- `DecodedInstruction xendiza::Disasm<32>(gsl::span<const std::byte>)`

### C ABI

```c
#include <xendiza/xendiza_c.h>

uint8_t code[] = { 0x90, 0x90 };
xendiza_decoded_instruction_t out = xendiza_disasm64(code, sizeof(code));
```

## Core Files

- `include/xendiza/xendiza.hpp` - Public C++ entry points (both 32-bit and 64-bit template specializations).
- `include/xendiza/xendiza_c.h` - Public C ABI declarations.
- `include/xendiza/xendiza_x64.hpp` - x64 decode traits/tables.
- `include/xendiza/xendiza_x86.hpp` - x86-32 decode traits/prefix structures.
- `include/xendiza/detail/xendiza_common.hpp` - Shared decode tables and core structures (internal).
- `include/xendiza/detail/instruction.hpp` - Operand definitions, including AVX/AVX2 abstract vector and VSIB forms (internal).
- `include/xendiza/detail/opcode_id.hpp` - Opcode identifiers (internal).
- `include/xendiza/detail/vex.hpp` - VEX prefix metadata and descriptor tables (internal).
- `include/xendiza/detail/vex_decode.hpp` - Shared VEX decode engine (internal).
- `src/xendiza.cpp` - C ABI implementation.
- `src/xendiza_x64.cpp` - x64 decode implementation.
- `src/xendiza_x86.cpp` - x86-32 decode implementation.
- `src/vex.cpp` - VEX prefix parsing and recognition.
- `src/vex_decode.cpp` - Shared VEX/AVX/AVX2 decode engine.

## Build

### Baseline (library + tests + example)

```bash
cmake -S . -B build -DCMAKE_PREFIX_PATH="<YOUR_CMAKE_PREFIX_PATH>"
cmake --build build
```

### Run tests

```bash
./build/xendiza_tests.exe
```

## Test Status

Current suites:

- `DisasmTest` — x64 basic 1-byte instructions
- `OpcodeExtTest` — x64 opcode extension groups
- `PublicApiTest` — public C++/C API surface
- `TwoByteOpcodeTest` — x64 `0x0F` two-byte subset
- `NoOperandTest` — no-operand instruction semantics
- `StackOperandTest` — stack-operand forms of ModR/M extension groups (x64 path)
- `X64PrefixTest` — x64 prefix handling (REX, 66h/67h, multibyte NOP length corner cases)
- `X87OpcodeTest` — x87 D8–DF core family (x64 path)
- `X86BasicTest` — x86-32 basic 1-byte instructions via `Disasm<32>`
- `X86TwoByteOpcodeTest` — x86-32 `0x0F` two-byte subset via `Disasm<32>`
- `X86x87Test` — x87 D8–DF core family via `Disasm<32>`
- `X86OpcodeExtTest` — x86-32 opcode extension groups
- `X86PrefixTest` — legacy prefix combinations and 15-byte length limits (x86-32)
- `X86OperandSizeTest` — 66h operand-size toggles (x86-32)
- `X86AddrSizeTest` — 67h address-size overrides (x86-32)
- `X86SegOverrideTest` — segment-override composite operands (x86-32)
- `X86AamAadTest` — AAM/AAD immediate forms (x86-32)
- `X86IncDecTest` — opcode-embedded INC/DEC (`0x40–0x4F`) as r32/r16 (x86-32)
- `X86JccTest` — short/near Jcc forms (x86-32)
- `X86NoOperandTest` — no-operand instruction semantics (x86-32)
- `X86InvalidTest` — undefined/invalid instruction rejection (x86-32)
- `SystemOpcodeTest` — system/privileged instruction decode paths (0F 00/01/18/1C/1E/20–23/C7)
- `VexA0Test` — VEX prefix recognition, permitted/forbidden prefixes, address-size selection, and 32-bit C4/C5 ambiguity
- `VexA1Test` — AVX/AVX2 `0F` map forms (NDS, L/W/vvvv, load/store, immediate, group sub-tables)
- `VexA2aTest` — AVX/AVX2 `0F 38` map forms
- `VexA2bTest` — AVX/AVX2 `0F 3A` map forms, including `/is4` fourth-vector operands
- `VexA3Test` — AVX2 VSIB/gather forms and architectural register-overlap legality
- `AbiBaselineTest` — C/C++ ABI and numeric compatibility baseline for pre-existing identifiers
- `VexForms` — dual-mode regressions for VEX encoding subforms, immediate-shift groups, lane forms, string comparisons, mask moves, and scalar moves

Latest full Release run: **910 tests from 35 test suites passed**. For a new run, use `ctest --output-on-failure` in your build directory.

## Benchmark

- Legacy benchmark source: `bench/bench_disasm.cpp`
- AVX/AVX2 benchmark source: `bench/bench_avx.cpp`

### Build legacy benchmark (xendiza only)

```bash
cmake -S . -B build -DCMAKE_PREFIX_PATH="<YOUR_CMAKE_PREFIX_PATH>"
cmake --build build --target xendiza_bench
./build/xendiza_bench.exe --mb 8 --iters 30
```

### Build legacy benchmark with Capstone + Zydis

```bash
cmake -S . -B build \
  -DXENDIZA_BENCH_WITH_CAPSTONE=ON \
  -DXENDIZA_BENCH_WITH_ZYDIS=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-vcpkg-rel --config Release --target xendiza_bench
```

Capstone note:

- Install with x86 backend enabled: `vcpkg install capstone[x86]:x64-windows --recurse`

### AVX/AVX2 dedicated benchmark

```bash
cmake -S . -B build -DXENDIZA_BENCH_WITH_ZYDIS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --target xendiza_bench_avx
./build/xendiza_bench_avx.exe --isa avx  --mode 64 --iters 10
./build/xendiza_bench_avx.exe --isa avx2 --mode 64 --iters 10
```

See `bench/README.md` for full AVX/AVX2 results, corpus construction, and interpretation.

### Latest legacy comparative result

Workload: `--mb 8 --iters 30` (Release)

| Decoder | Throughput | Decode Rate |
|--------|------------|-------------|
| xendiza | 73.71 MiB/s | 26.42 Minsn/s |
| zydis | 50.98 MiB/s | 18.27 Minsn/s |
| capstone | 12.92 MiB/s | 4.63 Minsn/s |

All decoders completed with `decoded=86009850`, `errors=0` on this corpus.

## Scope and Limits

### Shared (both 32-bit and 64-bit paths)

- Primarily optimized for one-byte opcode map and common extension groups used in fast analysis paths.
- **VEX/AVX/AVX2**: complete table-driven decode of Intel AVX and AVX2 instructions in the `0F`, `0F 38`, and `0F 3A` maps. C4/C5 VEX prefixes are recognized after permitted leading prefixes (`67` address-size override and segment overrides). LOCK, `66`, `F2`, `F3`, and x64 REX prefixes before VEX are rejected as `UNDEFINED_INSTRUCTION`. In 32-bit mode, `C4/C5` with `mod!=11` in the second byte fall back to the legacy path.
- Prefix-aware decode includes practical support for `REX.W` (x64 only) and `0x66` operand-size behavior across implemented paths. `0x66` shrinks the accumulator-immediate family (`05/0D/…/3D`, `A9`), `PUSH imm32` (`68`), and 32-bit near branches to their 16-bit forms; in 64-bit mode it is architecturally ignored on near branches (`E8`/`E9`/`0F 80–8F` keep `rel32`).
- Global operand contract: decoding output stops at the operand-form layer for all implemented instruction families.
- Operands are reported as abstract classes/types (for example: `r8/r16/r32/r64`, `m8/m16/m32/m64/m128/m256`, `xmm`, `ymm`, `m32_vsib`/`m64_vsib`, `imm*`, `rel*`, and x87 forms such as `st0`/`sti`, `m32fp/m64fp/m80fp`) rather than concrete register-index or effective-address expansion.
- Segment-prefixed memory operands are represented as composite operands (for example: `fs_m64`, `gs_m32`, `ds_moffs32`). The segment override is fused into the memory operand name rather than emitted as a standalone operand.
  - In x86-64 mode, only `fs` and `gs` segment overrides produce composite memory operands.
  - In x86-32 mode, all six segment overrides (`es`/`cs`/`ss`/`ds`/`fs`/`gs`) produce composite memory operands.
  - Non-memory segment-register instructions (for example `PUSH FS`, `POP GS`, `MOV Sreg, r/m16`) remain unchanged.
- Concrete register identity and index expansion are out of current scope (including opcode-embedded register ids, `REX.B/R/X` extended-register ids, VEX `R/X/B` extended vector-register ids, x87 `ST(i)` concrete index expansion, and VSIB concrete index registers).

### Independent ISA extensions (not covered)

AVX/AVX2 coverage is defined by the concrete VEX encodings in `test/data/vex_avx_inventory.csv`. The following independent ISA extensions are intentionally outside this boundary and their absence is not treated as a coverage gap: AVX-512 (EVEX), XOP, FMA3, F16C, BMI/BMI2, AES, PCLMULQDQ, and other non-VEX/non-AVX2 extensions.

### x86-64 (64-bit path) specific

- A focused `0x0F` two-byte subset is implemented: `Jcc rel32`, `CMOVcc`, `IMUL r,r/m`, `BSF`, `BSR`, `MOVZX`/`MOVSX` (`0F B6/B7/BE/BF`), `CMPXCHG` (`0F B0/B1`), `XADD` (`0F C0/C1`), `BT/BTS/BTR/BTC` (`0F A3/AB/B3/BB`), `BT/BTS/BTR/BTC` immediate group (`0F BA /4-/7`, `imm8`), `SETcc` (`0F 90-9F`), `BSWAP` (`0F C8-CF`), multibyte `NOP` (`0F 1F /0`), `SHLD`/`SHRD` (`0F A4/A5/AC/AD`), plus P2.4 SIMD forms: `MOVUPS` (`0F 10/11`), `MOVAPS` (`0F 28/29`), `UCOMISS/COMISS` (`0F 2E/2F`), `66`-prefixed `UCOMISD/COMISD`, and arithmetic families `0F 58/59/5C/5E` with prefix remap to `PS/PD/SS/SD`.
- **VEX/AVX/AVX2**: complete `0F`, `0F 38`, and `0F 3A` map coverage with C4/C5 prefix recognition, NDS (non-destructive source) operands, L=0/1 vector-width selection, W/vvvv policies, immediate and `/is4` trailing bytes, and AVX2 VSIB/gather forms. Gather destination/mask/vector-index register overlap is enforced internally and returns `UNDEFINED_INSTRUCTION` when any two coincide.
- System/privileged decode: Group 6 (`0F 00`: `SLDT`/`STR`/`LLDT`/`LTR`/`VERR`/`VERW`), Group 7 (`0F 01`: `SGDT`/`SIDT`/`LGDT`/`LIDT`/`SMSW`/`LMSW`/`INVLPG` plus register forms `SWAPGS`/`RDTSCP`/`MONITOR`/`MWAIT`/`CLAC`/`STAC`/`XGETBV`/`XSETBV`/`XTEST`/`RDPKRU`/`WRPKRU`/`SERIALIZE`), Group 16 (`0F 18`: `PREFETCHNTA/T0/T1/T2`), `CLDEMOTE` (`0F 1C`), `ENDBR64`/`ENDBR32` (`F3 0F 1E FA/FB`), `MOV` to/from control and debug registers (`0F 20-23`), Group 9 (`0F C7`: `CMPXCHG8B`, `CMPXCHG16B`, `RDRAND`, `RDSEED`, `XRSTORS`/`XSAVEC`/`XSAVES`, `RDPID`), and `0F AE` (`FXSAVE`/`FXRSTOR`/`LDMXCSR`/`STMXCSR`/`LFENCE`/`MFENCE`/`SFENCE`/`CLFLUSH`).
- x87 core one-byte family (`D8`-`DF`) is implemented with abstract operand forms, including stack forms (`st0`/`sti`), floating memory forms (`m32fp`/`m64fp`/`m80fp`), environment/control forms (`FLDENV`/`FNSTENV`/`FSAVE`/`FRSTOR`), BCD forms (`FBLD`/`FBSTP`), and strict `FWAIT` vs `FN*` distinction.

### x86-32 (32-bit path) specific

- Same 1-byte opcode map coverage as the x64 path, adapted for 32-bit default operand sizes (no `REX` prefix, `0x66` toggles 32↔16 instead of 64↔16).
- Segment override prefix parsing (`CS`/`SS`/`DS`/`ES`/`FS`/`GS`) with composite memory operand reporting (for example `ds_moffs32`, `fs_m32`).
- Opcode-embedded `INC`/`DEC` (`0x40–0x4F`) decoded as `INC`/`DEC` `r32`/`r16` (rather than REX prefix bytes).
- `0x0F` two-byte subset mirrors the x64 coverage for the `MOVZX`/`MOVSX`, bit-test, `SETcc`, `BSWAP`, `SHLD`/`SHRD`, SIMD, and `0F AE` fence/flush families; integer width is 32-bit by default.
- **VEX/AVX/AVX2**: same `0F`/`0F 38`/`0F 3A` map coverage as x64, with 32-bit-mode restrictions applied. `C4/C5` with second-byte `mod!=11` retain their legacy decode rather than being consumed as VEX; `C4 00`/`C5 00` preserve their pre-change legacy results.
- Group 6 (`0F 00`), Group 7 (`0F 01`), Group 16 (`0F 18`), `PREFETCH` (`0F 18`), `0F BA` bit ops, `MOVNTI` (`0F C3`), and Group 9 (`0F C7`) are implemented for x86-32 (no `CMPXCHG16B`; GPR size is `r32` instead of `r64`).
- `F3`-prefixed register forms of `0F AE` (`RDFSBASE`/`RDGSBASE`/`WRFSBASE`/`WRGSBASE`) are x64-only and return `UNDEFINED_INSTRUCTION` in x86-32 mode.

## Authorship

- **Basic x64 instructions** — implemented by the project author (human).
- **Remaining instruction families** (extended two-byte opcodes, x87, system/privileged, x86-32 path, SIMD subsets, AVX/AVX2 VEX decoding, etc.) — implemented with AI assistance.

## References

- Intel 64 and IA-32 Architectures Software Developer Manuals
- x86 opcode references (for verification)

---

Last Updated: 2026-11

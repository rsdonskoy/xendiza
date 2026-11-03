# xendiza Test Suite

This directory contains comprehensive unit tests for the xendiza x86/x86-64 disassembler library. Tests are organized into x64-only suites (using `X64Traits::Disasm` directly) and x86-32 suites (using the public `xendiza::Disasm<32>` entry point).

## Test Organization

### `test_basic_instructions.cpp`
Tests for fundamental 1-byte opcode instructions (without opcode extensions).

**Coverage:**
- **Arithmetic/Logic Operations**: ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
  - All ModR/M addressing modes: mod=00 (indirect), mod=01 (indirect+disp8), mod=10 (indirect+disp32), mod=11 (register)
  - With and without SIB (Scale-Index-Base) bytes
  - Immediate operand variants (imm8, imm32)
  
- **Data Movement**: MOV (all variants), XCHG, PUSH/POP
  - Memory to register, register to memory, register to register
  - Direct memory offsets (moffs)
  
- **Control Flow**: 
  - Conditional jumps (Jcc: JO, JNO, JB, JAE, JE, JNE, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG)
  - CALL, RET, RETF
  - LOOP, LOOPE, LOOPNE, JRCXZ
  
- **String Operations**: MOVSB, MOVSD, CMPSB, CMPSD, STOSB, STOSD, LODSB, LODSD, SCASB, SCASD

- **I/O Operations**: IN, OUT (with immediate and DX port)

- **System & Flags**: INT, HLT, CLC, STC, CLI, STI, CLD, STD

- **Miscellaneous**: NOP, TEST, XLAT, ENTER, LEAVE

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_opcode_extensions.cpp`
Tests for instructions that use opcode extensions via the ModR/M.reg field, including prefix handling.

**Coverage:**

#### 1. **Prefix Handling** (REX.W, 0x66)
- REX.W prefix (0x48): Forces 64-bit operands
- 0x66 prefix: Forces 16-bit operands
- Verifies 8-bit operations are unaffected by prefixes

#### 2. **Group 1: Arithmetic/Logic with Immediate** (0x80-0x83)
- **Opcodes**: 0x80 (r/m8, imm8), 0x81 (r/m32, imm32), 0x83 (r/m32, imm8)
- **Instructions**: ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
- **Prefix variants**: Default (32-bit), REX.W (64-bit), 0x66 (16-bit)

#### 3. **Group 2: Shift/Rotate with Immediate** (0xC0-0xC1)
- **Instructions**: ROL, ROR, RCL, RCR, SHL, SHR, SAL, SAR
- **Forms**: r/m with imm8
- **Prefix variants**: 8-bit, 32-bit, 64-bit, 16-bit

#### 4. **Group 3: Shift/Rotate by 1 or CL** (0xD0-0xD3)
- **Instructions**: ROL, ROR, RCL, RCR, SHL, SHR, SAL, SAR
- **Forms**: 
  - 0xD0/0xD1: shift by 1
  - 0xD2/0xD3: shift by CL register
- **Prefix variants**: All operand sizes

#### 5. **Group 4: MOV Immediate** (0xC6-0xC7)
- **Instructions**: MOV r/m, immediate
- **Prefix handling**: Adjusts immediate size (32→16 bits with 0x66)

#### 6. **Group 5: Unary Operations** (0xF6-0xF7)
- **Instructions**: TEST, NOT, NEG, MUL, IMUL, DIV, IDIV
- **Prefix variants**: 8-bit, 16-bit, 32-bit, 64-bit

#### 7. **Group 6: INC/DEC/CALL/JMP/PUSH** (0xFE-0xFF)
- **Instructions**: INC, DEC, CALL, JMP, PUSH
- **Prefix variants**: All operand sizes

#### 8. **Special: IMUL Three-Operand Form** (0x69-0x6B)
- **Forms**:
  - 0x69: IMUL r, r/m, imm32
  - 0x6B: IMUL r, r/m, imm8
- **Prefix variants**: 16-bit, 32-bit, 64-bit

#### 9. **Edge Cases**
- 8-bit operations unaffected by REX.W or 0x66
- Memory operands with prefixes
- SIB byte with prefixes
- Immediate size adjustments

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_public_api.cpp`
Tests the public API surface exposed from `xendiza.hpp` and the C ABI shim in `xendiza_c.h`.

**Coverage:**
- `xendiza::Disasm<64>(gsl::span<uint8_t>)`
- `xendiza::Disasm<64>(gsl::span<std::byte>)`
- C ABI parity via `xendiza_disasm64(const uint8_t*, size_t)`

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_2byte_opcodes.cpp`
Tests the implemented `0x0F` two-byte opcode subset.

**Coverage:**
- `Jcc rel32`, `CMOVcc`, `IMUL r,r/m`, `BSF`, `BSR`
- `MOVZX`/`MOVSX` (`0F B6/B7/BE/BF`)
- `CMPXCHG` (`0F B0/B1`), `XADD` (`0F C0/C1`)
- `BT/BTS/BTR/BTC` (`0F A3/AB/B3/BB`)
- `BT/BTS/BTR/BTC` immediate group (`0F BA /4-/7`, `imm8`)
- `SETcc` (`0F 90-9F`)
- `BSWAP` (`0F C8-CF`)
- Multibyte `NOP` (`0F 1F /0`)
- Direct system/control opcodes (`0F 05/06/07/08/09/0B/31/A0/A1/A2/A8/A9`, `0F AE` fences/flush)
- `SHLD`/`SHRD` (`0F A4/A5/AC/AD`) with `imm8` and `CL` forms
- Prefix/length behavior (`REX.W`, `0x66` where applicable), plus error paths

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_no_operands.cpp`
Dedicated tests for instructions with no explicit operands.

**Coverage:**
- 1-byte no-operand instructions such as `NOP`, `RET`, `HLT`, `CLC/STC`, `CLI/STI`, `CLD/STD`, `PUSHFQ/POPFQ`, `CDQ`
- 2-byte no-operand instruction check (`RDTSC`)
- Verifies `operand_count == 0` for these forms

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_x87_opcodes.cpp`
Tests the implemented x87 core one-byte opcode family (`D8`-`DF`) with abstract operand forms.

**Coverage:**
- Memory and register-stack forms across the x87 decode path (`st0`/`sti`, `m32fp`/`m64fp`/`m80fp`)
- Environment/control instructions (`FLDENV`, `FNSTENV`, `FSAVE`, `FRSTOR`)
- BCD forms (`FBLD`, `FBSTP`)
- Distinction checks between `FWAIT` (`0x9B`) and `FN*` forms
- Reserved/invalid encodings and insufficient-buffer behavior

Test count evolves with coverage expansion; use `ctest -N` in your build directory for the current number.

---

### `test_x86_basic.cpp`
32-bit (`xendiza::Disasm<32>`) smoke tests for the 1-byte map: NOP, a few `ADD`/`MOV` ModR/M forms, the `0x66` operand-size override, the `0x64` (FS) segment override on `MOV moffs32`, the 32-bit-only single-byte `INC`/`DEC` short forms (0x40-0x4F), and the empty-buffer error path.

---

### `test_x86_2byte_opcodes.cpp`
32-bit tests for the `0F` two-byte map, mirroring the x64 2-byte suite but asserting 32-bit-only semantics (no REX.W, no CMPXCHG16B, `BSWAP` always `r32`, `0F D6` invalid, etc.). Covers MOVZX/MOVSX, SETcc, multibyte NOP, SHLD/SHRD, Group 6/7/15/16, MOV creg, CMPXCHG8B/RDRAND, `0F BA`, MOVNTI, the minimal SSE/PS family, and the composite segment-prefix + memory forms.

---

### `test_x86_opcode_extensions.cpp`
32-bit tests for the 1-byte opcode-extension groups dispatched via `case 0xEE` (Groups 1-6: `0x80/81/82/83`, `0xC0/C1`, `0xD0-D3`, `0xC6/C7`, `0xF6/F7`, `0xFE/FF`), plus `0x8F` POP and the `0x69/0x6B` IMUL three-operand forms.

**Coverage:**
- Each group: `mod=11` register form + `mod=00` memory form, plus `0x66` shrink (r32→r16, imm32→imm16; 8-bit forms unaffected by `0x66`)
- `0x82` always-UNDEFINED error path
- Invalid reg-field sub-instructions (e.g. `0xFE /2`, `0xFF /3,/5,/7`, `0x8F /1-/7`, `0xC6/C7 /1-/7`)
- SIB base=5 disp32 length correction (`case 0xEE` +4 path)
- Segment-prefix composite memory operands (`cs_m8`, `fs_m32`) combined with extension groups
- `0xFF /2,/4,/6` register form (`r32`) and memory form (`m32`, downgraded from the shared `m64`)

---

### `test_x86_x87_opcodes.cpp`
32-bit tests for the x87 core one-byte family (`D8`-`DF`) dispatched via `case 0x87`, mirroring the x64 x87 suite via the public `Disasm<32>` API.

**Coverage:**
- Memory forms across D8-DF (`m32fp`/`m64fp`/`m80fp`/`m16`/`m32`/`m64`/`m`)
- Register-stack forms (`st0`,`sti`) including operand-order reversal for DC vs D8
- Fixed-ModR/M specials (`FNOP`, `FCHS`, `FLD1`, `FSQRT`, `FNCLEX`, `FNINIT`, `FCOMPP`, `FUCOMPP`, `FNSTSW ax`, …)
- `FWAIT` (`0x9B`) standalone
- Reserved/invalid encodings → `UNDEFINED_INSTRUCTION`
- SIB base=5 disp32 length correction for x87 memory forms, including the truncated-buffer `INSUFFICIENT_BUFFER` path

---

### `test_x86_prefixes.cpp`
32-bit tests for `ProcessPrefix`, the no-operand single-byte instructions (`case 0x01` direct dispatch), and the 32-bit-only `INC`/`DEC` short forms.

**Coverage:**
- **0x40-0x4F = INC/DEC r32** (the single biggest 32-vs-64 divergence; in x64 these are REX prefixes). All 16 forms + `0x66` shrink to `r16`.
- PUSH/POP r32 (`0x50-0x5F`), normalized from `r64`
- No-operand instructions: `NOP`, `RET`, `CLC/STC/CLI/STI/CLD/STD/CMC/HLT`, `CWDE/CDQ`, `PUSHFQ/POPFQ`, `SAHF/LAHF`, `XLAT`, `INT3`, `IRETD` (32-bit form), `LEAVE`, `RETF`
- Legacy opcodes the shared table marks invalid in 32-bit mode (asserting current behavior): `PUSHA/POPA`, `PUSH/POP ES`, `PUSH CS`, BCD-adjusts (`DAA/DAS/AAA/AAS`), `CALL far`, `JMP far`, `INTO`, `LES/LDS` (decode as length-1 INVALID). Note: `AAM`/`AAD` (`0xD4`/`0xD5`) used to fall in this set unintentionally; they are architecturally valid in 32-bit mode and are now decoded (see below).
- Duplicate-prefix detection → `UNDEFINED_INSTRUCTION`: duplicate `LOCK`, `REP/REPNE`, `0x66`, `0x67`
- Valid prefix combinations; segment prefixes are last-wins (no dedup)
- **Segment-override composite memory operands across all 6 segments (ES/CS/SS/DS/FS/GS) × multiple widths** (`es_m8` … `gs_m64`), plus `moffs` composite forms (`fs_moffs32`, `gs_moffs8`, `cs_moffs32`), and the non-composited fall-through for `m32fp`/`m`/`m128`
- `0x67` address-size override: `moffs32 → moffs16` (length = prefix + 3)
- `0x66` operand-size override on `moffs` MOV and `PUSH imm32`
- `0x66` on near branches (`E8`, `0F 84`) and the accumulator-immediate family (`05`): `rel16` / `ax, imm16` with shortened length (32-bit mode honors the prefix)
- `AAM`/`AAD` (`0xD4`/`0xD5`): 32-bit decodes `ax, imm8` length 2, truncated buffer → `INSUFFICIENT_BUFFER`; 64-bit stays `UNDEFINED_INSTRUCTION`
- All 16 `Jcc rel8` short forms

---

## Fixed Decoder Bugs

The 32-bit test suite surfaced the following decoder inconsistencies in `xendiza_x86.cpp`. All three have been fixed; the tests now assert the correct behavior and guard against regression:

1. **`FF /2`,`/4`,`/6` and `8F /0` memory forms emitted `m64` instead of `m32`.** The shared helpers rewrite these to the long-mode-default `m64`. `NormalizeOperandSize32` downgrades the register form (`r64→r32`) but intentionally leaves fixed-width `m64` operands (e.g. `CMPXCHG8B`, `FILD`) alone, so the fix rewrites `m64→m32` in the `0xEE` handler scoped to opcodes `0xFF`/`0x8F`. (Tests: `Grp6_0xFF_CALL/PUSH_mem_form_m32`, `POP_0x8F_slash0_mem_form_m32`.)
2. **`case 0xEE` (extension groups with immediates) did not verify the trailing immediate bytes were within the buffer** before returning success. Both `DecodeModrmWithImmediate` and the `0xEE` handler now validate the full encoding length against `buffer.size()` and return `INSUFFICIENT_BUFFER` for a truncated immediate. (Test: `BufferTooShort_missing_imm`.)
3. **`case 0x87` (x87) did not verify the `disp32` for SIB base=5 was within the buffer** before returning success. The handler now checks the full length (including the mandatory disp32) before reporting success. (Test: `BufferTooShort_SIB_disp32`.)

Differential testing against capstone/zydis vectors (`test/diff/`) surfaced two more, fixed in `fix-operand16-branches-and-aam-aad`:

4. **The 64-bit fixed-length dispatch cases ignored the `0x66` operand-size override.** The one-byte (`case 0x01–0x05`, `case 0x09`) and two-byte (`case 0x01–0x09`) fixed-length returns in `xendiza_x64.cpp` now route through `ApplyPrefixSizes`, so `05/0D/…/3D`, `A9`, and `68` decode as `ax, imm16` / `imm16` with the shortened length under `0x66`. Note the initially-suspected "near branches ignore `0x66` in 64-bit" turned out to be correct Intel behavior — the prefix is architecturally ignored on `E8`/`E9`/`0F 80–8F` in 64-bit mode (Zydis default; capstone's `x86_jcc_mode.yaml` "DEFAULT" 64-bit vectors encode the AMD-style `rel16` behavior, which xendiza deliberately does not follow). (Tests: `ADD_0x05_with_66h_shrinks_to_imm16`, `TEST_0xA9_with_66h_shrinks_to_imm16`, `PUSH_0x68_with_66h_shrinks_to_imm16`, `CALL_0xE8_with_66h_stays_rel32_in_x64`, `JZ_0F84_with_66h_stays_rel32_in_x64`; 32-bit side: `CALL_0xE8_with_66h_rel16`, `JZ_0F84_with_66h_rel16`, `ADD_0x05_with_66h_imm16`.)
5. **`AAM`/`AAD` (`0xD4`/`0xD5`) were rejected in 32-bit mode**, swept into the shared table's INVALID entries that only apply to 64-bit. The 32-bit table now patches them to `AAM`/`AAD ax, imm8` (length 2) with a truncated-buffer check (`INSUFFICIENT_BUFFER`); the shared table stays invalid so 64-bit keeps returning `UNDEFINED_INSTRUCTION`. (Tests: `X86AamAadTest.*`.)

---

## Test Statistics

- Current totals and pass/fail status are build-dependent snapshots; run `ctest --output-on-failure` for the latest result.
- Core coverage focus remains: 1-byte map + selected `0x0F` subset + P2 minimal SIMD path.
- Prefix combinations covered include default/no-prefix, `REX.W`, `REX.B`, and `0x66` (where applicable).
- ModR/M addressing modes are exercised across `00`, `01`, `10`, `11` in relevant suites.

---

## Performance Regression Guard

`test/test_perf_regression.cpp` adds two ctest-registered throughput guards
for the 64-bit decode hot path (`xendiza::Disasm<64>`): an absolute floor
(`ThroughputGuard`) and a machine-independent ratio against a naive reference
decoder (`RelativeThroughputGuard`).

### What it measures

The guard uses the same deterministic synthetic corpus as `bench/bench_disasm.cpp`:
the 79-byte legacy-opcode seed tile (ModR/M, SIB, immediates, and prefixes) tiled
until it is at least 1 MiB long. The measurement loop is identical to the bench:
linear `Disasm<64>` sweep, advancing by `di.length`, with 1 warmup iteration
followed by 5 timed iterations. The best MiB/s across the 5 timed iterations is
taken as the result, because environmental noise only ever slows a run.

Before the throughput assertion, the test asserts two correctness constants:

- `decoded` = 358,398 instructions per iteration
- `checksum` = 1,619,428 (sum of `di.length + di.instrId.operand_count` per instruction)

These prevent a "faster but wrong" optimization from passing the gate and stop
the compiler from eliding the decode loop.

### Throughput floor

The default floor is **35 MiB/s**, roughly 57% of the 61.41 MiB/s Release
baseline recorded in `bench/README.md` for the synthetic seed (8 MiB, 40
iterations). The margin is intentionally loose to avoid flaky failures on noisy
dev machines or CI runners while still catching order-of-magnitude regressions
(allocation in the hot path, an extra prefix pass, a rescan per instruction, etc.).

On the baseline-class machine the guard actually measures ~65–68 MiB/s in
Release, so the floor keeps ~2x headroom.

### Relative guard (machine-independent)

`RelativeThroughputGuard` removes the machine dependence entirely. It sweeps the
same corpus with a deliberately naive reference decoder (prefix walk + plain
switch + sequential ModR/M sizing, covering exactly the seed's opcode subset)
and asserts that xendiza's best-of-5 throughput stays above a fixed fraction of
the naive decoder's best-of-5 throughput, measured in the same run. Since both
decoders slow down together on a slower machine, their **ratio** is a stable,
machine-independent signal — the baseline calibrates itself on whatever machine
runs it.

On the baseline-class machine the measured ratio is ~0.085 (xendiza ~65 MiB/s
vs naive ~770 MiB/s); the default floor **0.05** leaves ~40% headroom for
cross-machine ratio drift and catches regressions of roughly 2x or worse,
complementing the absolute floor. Before the ratio assertion, the test asserts
the naive decoder lands on exactly the same instruction boundaries (same
decoded count, full byte coverage), so the comparison is always like-for-like.

Note for future ISA coverage: the naive reference only knows the opcode subset
in `kSeed`. When adding new instruction families (SSE `0F` map, AVX2/VEX, …),
extend `NaiveDecodeLength` alongside the library and the seed corpus, then
re-derive the constants from a Release run.

### Environment override

Set `XENDIZA_PERF_MIN_MIBS` to override the default MiB/s floor, and
`XENDIZA_PERF_MIN_RATIO` to override the default xendiza/naive ratio floor,
each with a positive double:

```bash
# Relax the gates for a slow CI runner
XENDIZA_PERF_MIN_MIBS=10 ctest -R PerfRegression

# Tighten them for a local Release gate
XENDIZA_PERF_MIN_MIBS=50 XENDIZA_PERF_MIN_RATIO=0.07 ctest -R PerfRegression
```

Invalid or non-positive values fall back to the defaults.

### Debug builds

Both test bodies begin with `#ifndef NDEBUG → GTEST_SKIP()`. Debug timings are
not comparable to the Release baseline, so the guards do not run in Debug
builds.

### Re-calibration

If the Release baseline changes significantly:

1. Build Release and run `xendiza_bench --mb 8 --iters 40`.
2. Set the floor to ~50–60% of the reported xendiza MiB/s.
3. Update `kDefaultMinMiBPerSec` in `test/test_perf_regression.cpp` and this
   section, then re-run `ctest -R PerfRegression` to confirm it still passes
   comfortably.

The relative guard's ratio floor only needs re-calibration when the corpus or
`NaiveDecodeLength` changes: read the measured ratio from a failing run (set
`XENDIZA_PERF_MIN_RATIO` above the real value and the failure message prints
it), then set `kDefaultMinRatio` to ~50–60% of it.

---

## Operand Contract (Current Scope)

- Tests follow the same global operand contract as `README.md`: decode assertions stop at the operand-form layer for all implemented instruction families.
- Tests assert abstract operand classes (`r*`/`m*`) instead of concrete register numbers.
- `REX.W` and `0x66` are validated for width/length effects.
- `REX.B/R/X` presence must not change assertions into concrete extended-register identities.

---

## Running Tests

### Run all tests:
```bash
ctest --output-on-failure
```

### Run specific test suite:
```bash
ctest -R "DisasmTest"        # Basic instructions
ctest -R "OpcodeExtTest"     # Opcode extensions
ctest -R "PublicApiTest"     # Public C++/C API tests
ctest -R "TwoByteOpcodeTest" # 0x0F two-byte subset
ctest -R "NoOperandTest"     # No-operand instruction semantics
ctest -R "X87OpcodeTest"     # x87 D8-DF core matrix
ctest -R "X86OpcodeExtTest"  # 32-bit 1-byte opcode-extension groups
ctest -R "X86x87Test"        # 32-bit x87 D8-DF
ctest -R "X86IncDecTest|X86NoOperandTest|X86InvalidTest|X86PrefixTest|X86SegOverrideTest|X86AddrSizeTest|X86OperandSizeTest|X86JccTest"  # 32-bit prefixes/no-operand/INC-DEC
ctest -R "PerfRegression"    # Throughput regression guard (Release only)
```

### Run with verbose output:
```bash
ctest --verbose
```

### Run tests in parallel:
```bash
ctest -j8
```

---

## Test Naming Convention

### Basic Instructions (`DisasmTest`)
Format: `{MNEMONIC}_{OPCODE}_{VARIANT}`

Examples:
- `ADD_0x00_modrm_00_000` - ADD with mod=00, r/m=000
- `PUSH_all_regs` - PUSH for all register encodings
- `Jcc_all_conditions` - All conditional jumps

### Opcode Extensions (`OpcodeExtTest`)
Format: `{MNEMONIC}_{OPCODE}_{PREFIX}_{OPERANDS}`

Examples:
- `ADD_0x81_REX_W_r64_imm32` - ADD with REX.W prefix
- `ROL_0xC1_Prefix66_r16_imm8` - ROL with 0x66 prefix
- `ADD_0x80_r8_imm8_with_REXW_no_effect` - Edge case test

---

## Helper Macros

```cpp
#define MKINSTR(opc, opr) \
    mkinst(static_cast<uint32_t>(detail::OpcodeId::opc), \
           static_cast<uint32_t>(detail::OperandType::opr))
```

Creates an instruction identifier from opcode and operand type for testing.

---

## Coverage Analysis

### Implemented & Tested
- ✅ All basic arithmetic/logic operations (x64) + 1-byte opcode-extension Groups 1-6 in 32-bit mode (`test_x86_opcode_extensions.cpp`)
- ✅ All MOV variants (x64)
- ✅ Stack operations (PUSH/POP) (x64), plus 32-bit `PUSH/POP r32` normalization
- ✅ Conditional jumps (Jcc) (x64), plus 32-bit `Jcc rel8` all-conditions loop
- ✅ String operations (x64)
- ✅ I/O instructions (x64)
- ✅ All opcode extensions (Groups 1-6) (x64)
- ✅ IMUL three-operand forms (x64), plus 32-bit `0x69/0x6B`
- ✅ System/flag instructions (x64), plus 32-bit no-operand flag instructions
- ✅ No-operand instruction semantics (`operand_count == 0`) (x64 + 32-bit)
- ✅ REX.W and 0x66 prefix handling (x64), plus `0x66` shrink in 32-bit
- ✅ 0x0F two-byte subset (x64), plus the 32-bit `0F`-subset mirror (`test_x86_2byte_opcodes.cpp`)
- ✅ P2.4 minimal SIMD path (x64 + 32-bit)
- ✅ x87 core D8-DF path with abstract operand forms (x64 + 32-bit)
- ✅ **32-bit-only `INC`/`DEC` short forms (0x40-0x4F)** — the key 32-vs-64 divergence
- ✅ **Address size prefix (0x67)** — 32-bit `moffs32→moffs16`
- ✅ **Segment override prefixes (ES/CS/SS/DS/FS/GS) × all widths**, including composite memory operands (`fs_m32`, `gs_moffs8`, …) and the non-composited fall-through for `m32fp`/`m`/`m128`
- ✅ **LOCK prefix** presence/length (32-bit) and duplicate-prefix detection (`LOCK`/`REP`/`66`/`67`)
- ✅ Legacy invalid-in-32-bit opcodes (`PUSHA`, `CALL/JMP far`, `LES/LDS`, BCD-adjusts) asserted at current behavior

### Not Yet Tested
- ❌ Remaining 2-byte opcodes (0x0F prefix) beyond the current subset
- ❌ Broader x87 coverage beyond the current D8-DF core matrix
- ❌ Broader SSE/AVX and VEX/EVEX instruction families beyond the P2.4 minimal SIMD subset
- ❌ REX.R and REX.X combinations (x64)

---

## Future Enhancements

1. **Expand 2-byte opcode tests** (0x0F prefix)
   - Additional integer instructions beyond current subset
   - Incremental SSE/SSE2 coverage beyond current minimal SIMD set

2. **Add REX prefix combination tests** (x64)
   - Additional REX.R and REX.X variations
   - Concrete register extensions (`R8-R15`) are currently out of scope

3. **Expand benchmark corpus coverage**

---

## Benchmarking

The repo includes a benchmark executable at `bench/bench_disasm.cpp`.

### Build benchmark (xendiza only)
```bash
cmake -S . -B build
cmake --build build --target xendiza_bench
```

### Build benchmark with Zydis + Capstone (vcpkg)
```bash
cmake -S . -B build-vcpkg-rel \
  -DCMAKE_TOOLCHAIN_FILE=C:/devdrv/scoop/apps/vcpkg/current/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows \
  -DXENDIZA_BENCH_WITH_CAPSTONE=ON \
  -DXENDIZA_BENCH_WITH_ZYDIS=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-vcpkg-rel --config Release --target xendiza_bench
```

### Run benchmark
```bash
./build-vcpkg-rel/Release/xendiza_bench.exe --mb 8 --iters 30
```

### Latest reference result (`--mb 8 --iters 30`, Release)

| Decoder | Throughput | Decode Rate |
|--------|------------|-------------|
| xendiza | 73.71 MiB/s | 26.42 Minsn/s |
| zydis | 50.98 MiB/s | 18.27 Minsn/s |
| capstone | 12.92 MiB/s | 4.63 Minsn/s |

All three decoders completed with `decoded=86009850`, `errors=0` on this corpus.

Notes:
- Capstone must be installed with x86 support (`capstone[x86]`) for x64 decoding.
- Benchmark numbers are machine- and compiler-dependent; compare with identical build type and workload.

---

## Contributing

When adding new tests:
1. Follow the existing naming conventions
2. Group related tests together with clear section comments
3. Test all ModR/M modes where applicable
4. Include prefix variants (REX.W, 0x66) for sized operations
5. Add edge cases and boundary conditions
6. Update this README with new coverage

---

## Build Requirements

- **C++ Standard**: C++20
- **Build System**: CMake 3.20+
- **Test Framework**: Google Test (GTest)
- **Compiler**: MSVC 14.44+ / GCC 10+ / Clang 12+

---

Last Updated: 2026-05

# xendiza Benchmark

Measures x86-64 linear-decode throughput of xendiza against Zydis on both a
synthetic seed and real system-DLL `.text` sections.

## Build

xendiza and the reference decoder must share the same C runtime. Build Zydis
with MSVC + `/MD` (dynamic CRT) first, then point xendiza at it:

```sh
# 1. Build & install Zydis (MSVC, /MD runtime) into C:/devdrv/usr
#    (run from a "x64 Native Tools Command Prompt for VS 2022")
cd C:\devdrv\src\zydis
cmake -B build_msvc -G Ninja -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_INSTALL_PREFIX=C:/devdrv/usr ^
      -DZYDIS_BUILD_EXAMPLES=OFF -DZYDIS_BUILD_TOOLS=OFF -DZYAN_DEV_MODE=ON ^
      -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL
cmake --build build_msvc --target install

# 2. Build xendiza bench with Zydis enabled (same MSVC/Ninja toolchain)
cd C:\devdrv\src\xendiza
cmake -B build_ninja -G Ninja -DCMAKE_BUILD_TYPE=Release ^
      -DXENDIZA_BENCH_WITH_ZYDIS=ON ^
      -DCMAKE_PREFIX_PATH=C:/devdrv/usr
cmake --build build_ninja --target xendiza_bench
```

> **Note on the VS generator:** the Visual Studio generator mixes the Debug and
> Release CRT references in a way that causes a `STATUS_STACK_BUFFER_OVERRUN`
> crash at startup when statically linking Zydis. Use the **Ninja** generator
> (shown above) for the benchmark. This is a toolchain-linking quirk, not a
> xendiza or Zydis bug.
>
> **Note on Zydis warning flags:** Zydis' installed CMake target exports
> `/WX /W4` as `INTERFACE_COMPILE_OPTIONS`. `CMakeLists.txt` strips these from
> the imported `Zydis::Zydis` target so the benchmark builds under xendiza's
> own (non-fatal) warning policy. If you upgrade Zydis and the export changes,
> the strip logic in `CMakeLists.txt` may need adjustment.
>
> **Capstone:** the comparison is omitted by default. Enabling
> `-DXENDIZA_BENCH_WITH_CAPSTONE=ON` requires an MSVC-built `capstone.lib`;
> the prebuilt `libcapstone.a` in this environment is GCC-built and will not
> link under MSVC.

## Usage

```sh
# Synthetic seed (79-byte legacy-opcode tile, backward-compatible default)
./xendiza_bench.exe [--mb N] [--iters N]

# A single raw-bytes file (e.g. your own .text dump)
./xendiza_bench.exe --file path/to/code.bin [--iters N]

# One or more bundled fixtures
./xendiza_bench.exe --fixture ntdll [--fixture kernelbase] [--iters N]

# SIMD-heavy OpenSSL .text slice
./xendiza_bench.exe --fixture openssl-simd --iters 30
```

Corpus source priority: `--file` > `--fixture` (concatenated) > synthetic seed.

## Fixtures

The bundled fixtures include Windows system DLL `.text` sections and a
SIMD-heavy OpenSSL `.text` slice. See [the fixture documentation](fixtures/README.md)
for instruction counts, provenance, hashes, and extraction instructions.

The bundled fixtures contain a realistic mix of legacy, SSE, and AVX
instructions. The results below are from the implementation that includes the
shared SSE tables and complete AVX/AVX2 VEX decoding. The OpenSSL slice also
contains independent extensions outside the current boundary (including BMI,
SHA, EVEX, and XOP bytes), so its linear-sweep error count includes both those
coverage gaps and follow-on byte-resynchronization effects.

## Results

Single run, MSVC 19.44 / Visual Studio 17 2022 / Release, 30 iterations,
Windows 11 10.0.26200.

### Synthetic seed (79-byte tile, 8 MiB) — *regression baseline*

| Decoder | Throughput | Decode rate | decoded | errors |
|---|---:|---:|---:|---:|
| xendiza | 57.67 MiB/s | 20.67 Minsn/s | 86,009,850 | 0 |
| zydis    | 36.94 MiB/s | 13.24 Minsn/s | 86,009,850 | 0 |

The seed only contains 1-byte legacy opcodes xendiza fully covers, so both
decoders decode the same instructions with zero errors. xendiza is **~1.56×**
faster here, but this number is optimistic (tiled seed = perfect branch
prediction, L1-resident working set, no resync).

### Real `.text` fixtures

| Fixture | Bytes | Decoder | Throughput | Minsn/s | decoded | errors | err % |
|---|---:|---|---:|---:|---:|---:|---:|
| ntdll | 1,482,752 | xendiza | 42.72 MiB/s | 12.60 | 12,517,860 |   4,920 | 0.039% |
|       |           | zydis    | 30.22 MiB/s |  8.92 | 12,512,940 |     780 | 0.006% |
| kernelbase | 1,724,416 | xendiza | 47.76 MiB/s | 13.97 | 14,433,720 |   5,430 | 0.038% |
|            |           | zydis    | 34.36 MiB/s | 10.05 | 14,433,720 |   5,130 | 0.036% |
| kernel32 | 544,768 | xendiza | 42.15 MiB/s | 13.41 | 4,960,620 |     240 | 0.005% |
|          |         | zydis    | 31.38 MiB/s |  9.99 | 4,960,620 |     180 | 0.004% |
| openssl-simd | 131,074 | xendiza | 44.55 MiB/s | 12.50 | 1,052,190 | 148,950 | 14.157% |
|              |         | zydis    | 35.23 MiB/s |  8.90 |   946,920 |     150 | 0.016% |

### System-DLL fixtures combined (3,751,936 bytes / 3.58 MiB)

| Decoder | Throughput | Minsn/s | decoded | errors | err % |
|---|---:|---:|---:|---:|---:|
| xendiza | 46.69 MiB/s | 13.88 | 31,912,200 | 10,560 | 0.033% |
| zydis    | 33.10 MiB/s |  9.84 | 31,907,280 |  6,060 | 0.019% |

### All fixtures combined (3,883,010 bytes / 3.70 MiB)

| Decoder | Throughput | Minsn/s | decoded | errors | err % |
|---|---:|---:|---:|---:|---:|
| xendiza | 46.76 MiB/s | 13.88 | 32,964,390 | 159,510 | 0.484% |
| zydis    | 32.75 MiB/s |  9.69 | 32,854,200 |   6,210 | 0.019% |

### Interpretation

On the three system-DLL corpora, xendiza's error count dropped from the
pre-SSE/AVX recorded total of 279,600 to **10,560** (a 96.2% reduction), and
its error rate fell from 0.87% to **0.033%**. Its decoded count is within
0.02% of Zydis, so instruction-boundary recovery on ordinary system code is now
close even though the two decoders still make different strict-legality choices
on a small number of byte patterns.

The combined system-DLL throughput ratio is ~**1.41×** (46.69 vs 33.10 MiB/s).
The absolute xendiza throughput is lower than the historical fixture run because
it now performs full SSE/AVX/AVX2 decoding instead of quickly rejecting those
encodings and byte-resynchronizing; the comparative ratio remains essentially
unchanged.

OpenSSL is deliberately retained as a stress case. Its high error count is not
a measure of missing SSE/AVX support: representative failures include BMI
instructions such as `RORX`/`ANDN`, SHA-extension rows, EVEX, and XOP bytes,
none of which are inside the documented AVX/AVX2 boundary. Because linear sweep
resynchronizes one byte after an unsupported instruction, one real gap can also
produce many downstream false errors; Zydis additionally accepts some encodings
with non-reserved VEX fields that the Intel SDM makes architecturally invalid.

## AVX/AVX2 dedicated benchmark

`xendiza_bench_avx` measures VEX/AVX/AVX2 decode throughput on deterministic,
ISA-specific corpora built from `test/data/vex_avx_inventory.csv`. It requires
Zydis (`-DXENDIZA_BENCH_WITH_ZYDIS=ON`).

### Build

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release ^
      -DXENDIZA_BENCH_WITH_ZYDIS=ON ^
      -DCMAKE_PREFIX_PATH=C:/devdrv/usr
cmake --build build --target xendiza_bench_avx
```

The corpora are generated automatically as a build dependency. For these results,
`bench/corpus_avx.bin` is 8,387,113 bytes and `bench/corpus_avx2.bin` is
8,387,734 bytes.

### Usage

```sh
./xendiza_bench_avx.exe --isa avx  --mode 64 --inner-iters 10 --samples 10
./xendiza_bench_avx.exe --isa avx2 --mode 64 --inner-iters 10 --samples 10
./xendiza_bench_avx.exe --isa avx  --mode 32 --inner-iters 10 --samples 10
./xendiza_bench_avx.exe --isa avx2 --mode 32 --inner-iters 10 --samples 10
```

A correctness gate runs before timing: both decoders must produce identical
instruction boundaries and zero errors on the whole corpus. The gate reports the
first mismatch and aborts if anything differs.

### Measurement modes

Each run reports four rows:

- `xendiza-length`: consumes only `length`, preserving the historical timing
  metric and the Zydis comparison.
- `xendiza-full`: consumes `length`, opcode, operand count and all four
  operands, preventing LTO from discarding semantic decode work as unused.
  Its checksum intentionally differs from the length-only checksum.
- `empty-floor`: replays the per-instruction length stream collected by the
  correctness gate, retaining the outer loop, dependent offset update, error
  branch and length checksum without doing any decoding. Its length-stream
  load is part of the measurement; this is a floor, not a target throughput.
- `zydis-length`: the existing Zydis boundary/length comparison.

### LTO A/B measurement

Use separate build directories with otherwise identical configuration:

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release ^
      -DXENDIZA_BENCH_WITH_ZYDIS=ON -DXENDIZA_ENABLE_LTO=OFF ^
      -DCMAKE_PREFIX_PATH=C:/devdrv/usr
cmake -B build_lto -G Ninja -DCMAKE_BUILD_TYPE=Release ^
      -DXENDIZA_BENCH_WITH_ZYDIS=ON -DXENDIZA_ENABLE_LTO=ON ^
      -DCMAKE_PREFIX_PATH=C:/devdrv/usr
cmake --build build --target xendiza_bench_avx
cmake --build build_lto --target xendiza_bench_avx
```

`XENDIZA_ENABLE_LTO` enables interprocedural optimization before any project
target is created, so both the static library and benchmark consumer use
compatible IPO/LTO settings. The benchmark header prints `lto=on` or
`lto=off`. Compare both length-only and full-metadata rows with identical
benchmark arguments; the LTO delta also includes constant propagation, dead
code elimination and code-layout effects, not just call overhead.

### Results

Direct VEX dispatch (this branch): unprefixed x64 `C4/C5` input no longer
runs the general prefix-recognition scan or the noinline slow-path call; the
shared VEX decoder still makes every form/legality/sizing decision. Toolchain:
MSVC 19.44 / Visual Studio 17 2022 / Release, inner-iters=10, samples=10
(best-of-10), warmup=1, Windows 11 10.0.26200, Zydis 4.1.1#1 (vcpkg).
"Before" is the pre-dispatch state of this branch, including the dual-metric
benchmark and LTO controls, measured with identical benchmark arguments.

64-bit mode, non-LTO (`build`, `-DXENDIZA_ENABLE_LTO=OFF`):

| ISA | Metric | Before | After |
|---|---|---:|---:|
| AVX  | xendiza-length | 122.03 MiB/s | 156.68 MiB/s |
| AVX  | xendiza-full   | 106.60 MiB/s | 130.55 MiB/s |
| AVX2 | xendiza-length | 133.93 MiB/s | 167.25 MiB/s |
| AVX2 | xendiza-full   | 116.05 MiB/s | 138.94 MiB/s |

64-bit mode, LTO (`build_lto`, `-DXENDIZA_ENABLE_LTO=ON`):

| ISA | Metric | Before | After |
|---|---|---:|---:|
| AVX  | xendiza-length | 139.51 MiB/s | 175.60 MiB/s |
| AVX  | xendiza-full   | 117.02 MiB/s | 142.02 MiB/s |
| AVX2 | xendiza-length | 152.46 MiB/s | 185.71 MiB/s |
| AVX2 | xendiza-full   | 128.13 MiB/s | 151.45 MiB/s |

Every row kept identical decoded counts, zero errors, and identical checksums
before and after (AVX: decoded=12,963,510, length checksum=83,871,130; AVX2:
decoded=11,895,700, length checksum=83,877,340; full-metadata checksums
unchanged as well). Empty-floor rows stay at ~10 GB/s in all runs; the floor
measures only loop/offset overhead and is not a target.

32-bit mode is an unchanged-path control: 129-143 MiB/s non-LTO and
151-170 MiB/s LTO before and after (within run-to-run noise).

#### Real `.text` fixture outcome (non-LTO, `--iters 30`)

| Corpus | xendiza throughput | decoded | errors | checksum |
|---|---:|---:|---:|---:|
| system DLLs, before | 48.10 MiB/s | 31,912,200 | 10,560 | 157,920,180 |
| system DLLs, after    | 49.50 MiB/s | 31,912,200 | 10,560 | 157,920,180 |
| openssl-simd, before | 44.43 MiB/s | 1,052,190 | 148,950 | 5,777,040 |
| openssl-simd, after    | 46.74 MiB/s | 1,052,190 | 148,950 | 5,777,040 |

Decoded counts, error counts, and checksums are byte-identical before and
after; no real-corpus regression was observed. The real corpora contain mostly
non-VEX code, so the gain (+3-5%) is smaller than the tiled AVX/AVX2 synthetic
rate (+20-28%); the synthetic rate must not be read as a general speedup.

### Interpretation

These numbers are **not** directly comparable to the legacy benchmark above:
`xendiza_bench_avx` exercises only VEX-encoded AVX/AVX2 instructions and compares
xendiza's lightweight opcode/operand-class decode against Zydis' fuller semantic
decode. On this workload xendiza is currently about **2.7-3.1×** faster
(length-only metric, both LTO settings), while the
checksum parity confirms both decoders agree on every instruction boundary in the
corpus. This benchmark is intended as a regression guard and optimization target.


## Re-running / updating results

Numbers are machine- and patch-level-specific. To regenerate:

```sh
# Regenerate fixtures (reflects your machine's DLL versions)
python bench/fixtures/extract_text.py

# Re-run (adjust --iters for stability)
./xendiza_bench.exe --fixture ntdll --fixture kernelbase --fixture kernel32 --iters 30

# AVX/AVX2 benchmark
./xendiza_bench_avx.exe --isa avx2 --mode 64 --inner-iters 30 --samples 10
```

Update the tables above with the new numbers and the fixture SHA256s in
`bench/fixtures/README.md`.

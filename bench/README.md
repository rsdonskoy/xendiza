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
instructions. The historical system-DLL results below were recorded before the
current AVX/AVX2 implementation and include coverage-related resynchronization
errors from that revision; they are not fresh measurements of current AVX/AVX2
support. The OpenSSL fixture remains useful for measuring a mixed workload of
supported decoding and resynchronization on SIMD-heavy code.

## Results

Single run, MSVC 19.44 / Ninja / Release, 30 iterations, Windows 11 10.0.26200.

### Synthetic seed (79-byte tile, 8 MiB) — *regression baseline*

| Decoder | Throughput | Decode rate | decoded | errors |
|---|---:|---:|---:|---:|
| xendiza | 61.41 MiB/s | 22.01 Minsn/s | 86,009,850 | 0 |
| zydis    | 38.11 MiB/s | 13.66 Minsn/s | 86,009,850 | 0 |

The seed only contains 1-byte legacy opcodes xendiza fully covers, so both
decoders decode the same instructions with zero errors. xendiza is **~1.61×**
faster here, but this number is optimistic (tiled seed = perfect branch
prediction, L1-resident working set, no resync).

### Real `.text` fixtures

| Fixture | Bytes | Decoder | Throughput | Minsn/s | decoded | errors | err % |
|---|---:|---|---:|---:|---:|---:|---:|
| ntdll | 1,482,752 | xendiza | 55.75 MiB/s | 16.51 | 12,560,190 | 120,570 | 0.95% |
|       |           | zydis    | 38.08 MiB/s | 11.23 | 12,512,940 |     780 | 0.006% |
| kernelbase | 1,724,416 | xendiza | 59.85 MiB/s | 17.59 | 14,499,690 | 122,820 | 0.84% |
|            |           | zydis    | 41.19 MiB/s | 12.05 | 14,433,690 |   4,980 | 0.034% |
| kernel32 | 544,768 | xendiza | 56.85 MiB/s | 18.15 | 4,976,040 | 36,240 | 0.72% |
|          |         | zydis    | 36.57 MiB/s | 11.64 | 4,960,620 |    180 | 0.004% |

### All fixtures combined (3,751,936 bytes / 3.58 MiB)

| Decoder | Throughput | Minsn/s | decoded | errors | err % |
|---|---:|---:|---:|---:|---:|
| xendiza | 57.17 MiB/s | 17.06 | 32,035,920 | 279,600 | 0.87% |
| zydis    | 39.84 MiB/s | 11.84 | 31,907,250 |   5,910 | 0.019% |

### Historical interpretation

In that revision's **real system-DLL `.text`** run, xendiza was **~1.43×** faster
than Zydis (57.17 vs 39.84 MiB/s combined), down from ~1.61× on the synthetic
seed. The advantage shrank because:

1. **Resync cost** — ~0.87% of xendiza's decode attempts hit unsupported
   opcodes (AVX/SSE/3-byte-escapes) and fell through to the `++off` byte-resync
   slow path. Zydis had a 45× lower error rate (0.019%).
2. **Decode-count parity** — despite the resync overhead, xendiza decoded
   32.04M vs Zydis's 31.91M instructions (0.4% more, from resync occasionally
   splitting one long instruction into two short false-positive decodes).
3. **No cache/branch-prediction cheating** — the working set (3.6 MiB) exceeded
   L1 and the instruction mix was diverse, so this reflected real-world linear
   sweep cost.

These observations describe the historical revision, including its then-incomplete
AVX/SSE coverage; they do not quantify resync or decode accuracy for the current
implementation.

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

### Results

Four independent runs, MSVC 19.44 / Ninja / Release, inner-iters=10, samples=10,
Windows 11 10.0.26200, Zydis 4.1.1#1 (vcpkg).

| ISA | Mode | Decoder | Throughput | Minsn/s | decoded | errors | checksum |
|---|---:|---|---:|---:|---:|---:|---:|
| AVX | 32 | xendiza | 134.32 MiB/s | 21.77 | 12,963,510 | 0 | 83,871,130 |
| AVX | 32 | zydis    |  62.07 MiB/s | 10.06 | 12,963,510 | 0 | 83,871,130 |
| AVX | 64 | xendiza | 123.92 MiB/s | 20.08 | 12,963,510 | 0 | 83,871,130 |
| AVX | 64 | zydis    |  59.98 MiB/s |  9.72 | 12,963,510 | 0 | 83,871,130 |
| AVX2 | 32 | xendiza | 146.38 MiB/s | 21.77 | 11,895,700 | 0 | 83,877,340 |
| AVX2 | 32 | zydis    |  66.76 MiB/s |  9.93 | 11,895,700 | 0 | 83,877,340 |
| AVX2 | 64 | xendiza | 135.53 MiB/s | 20.15 | 11,895,700 | 0 | 83,877,340 |
| AVX2 | 64 | zydis    |  64.37 MiB/s |  9.57 | 11,895,700 | 0 | 83,877,340 |

xendiza/Zydis throughput ratio: 2.066-2.193 on this pure AVX/AVX2 decode workload.

### Interpretation

These numbers are **not** directly comparable to the legacy benchmark above:
`xendiza_bench_avx` exercises only VEX-encoded AVX/AVX2 instructions and compares
xendiza's lightweight opcode/operand-class decode against Zydis' fuller semantic
decode. On this workload xendiza is currently about **2×** faster, while the
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

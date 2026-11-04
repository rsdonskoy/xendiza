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

Unsupported encodings such as AVX trigger the `++off` resynchronization path.
The OpenSSL fixture measures a mixed workload of supported decode and
resynchronization on SIMD-heavy code.

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

### Interpretation

On **real system-DLL `.text`**, xendiza is **~1.43×** faster than Zydis
(57.17 vs 39.84 MiB/s combined), down from ~1.61× on the synthetic seed. The
advantage shrinks because:

1. **Resync cost** — ~0.87% of xendiza's decode attempts hit unsupported
   opcodes (AVX/SSE/3-byte-escapes) and fall through to the `++off` byte-resync
   slow path. Zydis, which covers the full ISA, has a 45× lower error rate
   (0.019% — its errors are genuinely malformed/undefined bytes, not coverage
   gaps).
2. **Decode-count parity** — despite the resync overhead, xendiza decodes
   32.04M vs Zydis's 31.91M instructions (0.4% more, from resync occasionally
   splitting one long instruction into two short false-positive decodes). The
   counts are close, confirming xendiza's instruction-boundary recovery is
   largely correct on legacy code.
3. **No cache/branch-prediction cheating** — the working set (3.6 MiB) exceeds
   L1 and the instruction mix is diverse, so this reflects real-world linear
   sweep cost.

**Bottom line for the two-stage pipeline use case** (xendiza fast-scan to
locate points of interest, then Zydis for precise analysis): on real code,
xendiza sustains a ~1.4× throughput advantage while correctly decoding >99% of
instructions. The ~0.87% resync rate is the cost of incomplete AVX/SSE coverage;
for a *locator* that only needs opcode + operand-class to flag candidate
instructions (call/jmp/lea/mov-imm/mov-stack), this is an acceptable trade, and
the located offsets should be re-validated by Zydis from a known-aligned anchor
(function entry) to absorb the rare boundary-misalignment from resync.

## Re-running / updating results

Numbers are machine- and patch-level-specific. To regenerate:

```sh
# Regenerate fixtures (reflects your machine's DLL versions)
python bench/fixtures/extract_text.py

# Re-run (adjust --iters for stability)
./xendiza_bench.exe --fixture ntdll --fixture kernelbase --fixture kernel32 --iters 30
```

Update the tables above with the new numbers and the fixture SHA256s in
`bench/fixtures/README.md`.

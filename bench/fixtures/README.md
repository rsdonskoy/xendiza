# Benchmark Fixtures

Raw x86-64 code from PE `.text` sections. The Windows system DLLs provide
general-purpose workloads. The OpenSSL fixture provides a SIMD-heavy workload.

## Files

| fixture | source | `.text` bytes | `.text` RVA | source SHA256 | fixture SHA256 |
|---|---|---:|---:|---|---|
| `ntdll.text.bin` | `C:\Windows\System32\ntdll.dll` | 1,482,752 | `0x1000` | `b8f3a6aa...0087` | `aa28e5a5...9f3d` |
| `kernelbase.text.bin` | `C:\Windows\System32\kernelbase.dll` | 1,724,416 | `0x1000` | `8e8499fc...c07c` | `05b4a1ab...014a` |
| `kernel32.text.bin` | `C:\Windows\System32\kernel32.dll` | 544,768 | `0x1000` | `26410f49...c341` | `17943503...6031` |

**Windows DLL total: 3,751,936 bytes (~3.58 MiB).**

## OpenSSL SIMD fixture

`openssl-simd.text.bin` contains 131,074 bytes from the x86-64 MSYS2
`libopenssl` package version `3.6.4-1` (`usr/bin/msys-crypto-3.dll`).
It is the contiguous `.text` slice `[0x260000, 0x280002)` at RVA `0x261000`.
The slice was selected for its SIMD density, with endpoints aligned to
instruction boundaries in the reference linear decode.

| Capstone 5.0.5 instruction groups | Count | Share of decoded instructions |
|---|---:|---:|
| All decoded instructions | 31,564 | 100% |
| SSE family (including SSSE3) | 5,596 | 17.7% |
| AVX or AVX2 | 7,951 | 25.2% |
| AVX2 (included above) | 3,357 | 10.6% |

The linear decode skipped 5 bytes. Source DLL SHA256 is
`318a5ff40425f08f2b740649f9afe40b28af270c70a2253df924aaee49bc2548`.
Fixture SHA256 is
`579bfb582c76f03ed5a50b99337fbb0a79bd46fe601f68c774504712b866d671`.

The fixture contains code from the OpenSSL Project under Apache-2.0.
See the [OpenSSL 3.6.4 source](https://github.com/openssl/openssl/tree/openssl-3.6.4),
the [OpenSSL license](https://openssl-library.org/source/license/index.html),
and the [MSYS2 package](https://packages.msys2.org/packages/libopenssl).

To reproduce it, verify the input DLL hash and run the following from
`bench/fixtures` with the path to that DLL.

```sh
python -c "from pathlib import Path; from extract_text import read_pe_text_section; import sys; text, _, _ = read_pe_text_section(Path(sys.argv[1])); Path('openssl-simd.text.bin').write_bytes(text[0x260000:0x280002])" path/to/msys-crypto-3.dll
```

## Provenance

- **Extracted:** 2026-08-03
- **OS:** Windows-11-10.0.26200-SP0
- **Method:** `python bench/fixtures/extract_text.py` (zero-dependency minimal
  PE parser; DOS header → `e_lfanew` → PE signature → COFF header → optional
  header → section table → `.text` entry → raw bytes)
- **Full source SHA256** (not abbreviated) is reproducible by re-running the
  script; the table above shows the first/last 4 bytes for readability.

## Re-extracting

The fixtures are machine-specific (they reflect the exact patch level of the
source DLLs). To regenerate on your machine:

```sh
# Default: extracts ntdll, kernelbase, kernel32 from %SystemRoot%\System32
python bench/fixtures/extract_text.py

# Custom DLLs or paths
python bench/fixtures/extract_text.py C:\Windows\System32\ntdll.dll

# Override output directory / Windows root
python bench/fixtures/extract_text.py --outdir bench/fixtures --sysroot C:\Windows
```

The script overwrites existing `.text.bin` files in place and prints the
updated provenance table to stdout. After re-extraction, update the SHA256
values in this file (`python bench/fixtures/extract_text.py` prints them).

## Why these fixtures (not a synthetic seed)

The previous benchmark tiled a 79-byte hardcoded seed (only 1-byte legacy
opcodes that xendiza fully covers) to 8 MiB. This inflated xendiza's measured
advantage in three ways:

1. **Coverage bias** — the seed contained zero SSE/AVX/3-byte-escape bytes, so
   xendiza never hit its `UNIMPLEMENTED`/`UNDEFINED` slow path.
2. **Branch-prediction cheating** — a tiled 79-byte seed makes the `switch`
   dispatch in `Disasm` trivially predictable (~100% hit rate).
3. **Cache cheating** — the working set stays inside L1.

The fixtures include supported legacy and SSE encodings alongside unsupported
encodings such as AVX. On unsupported input, xendiza increments `errors` and
tries again one byte later. The throughput therefore includes resynchronization,
and the error count measures failed decode attempts.

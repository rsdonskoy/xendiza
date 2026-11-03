// test_perf_regression.cpp
// Performance regression guard for the x86-64 decode hot path.

#include <gtest/gtest.h>

#include <xendiza/xendiza.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <vector>

namespace {

// 79-byte legacy-opcode tile copied from bench/bench_disasm.cpp.
// The tile mixes ModR/M, SIB, immediates, and prefixes so the sweep exercises
// the main decode path without requiring AVX/SSE coverage.
//
// IMPORTANT: the original bench literal only lists 77 explicit bytes; the
// std::array<79> zero-fills the last two bytes. Those zeros decode as an
// additional `add m8, r8` (0x00 0x00), so the actual tile yields 27
// instructions, not 26. If kSeed ever changes, kExpectedDecoded and
// kExpectedChecksum below must be re-derived from a real Release run.
static constexpr std::array<uint8_t, 79> kSeed = {
    0x00, 0xC3,                   // add r8, r8
    0x00, 0x00,                   // add m8, r8
    0x01, 0xC8,                   // add r32, r32
    0x03, 0xC3,                   // add r32, r32
    0x04, 0x7F,                   // add al, imm8
    0x05, 0x01, 0x00, 0x00, 0x00, // add eax, imm32
    0x08, 0xC3,                   // or r8, r8
    0x20, 0xC3,                   // and r8, r8
    0x28, 0xC3,                   // sub r8, r8
    0x30, 0xC0,                   // xor r8, r8
    0x38, 0xC3,                   // cmp r8, r8
    0x48, 0x81, 0xC0, 0x01, 0x00, 0x00, 0x00, // rex.w add r64, imm32
    0x66, 0x83, 0xC0, 0x01,       // 66 add r16, imm8
    0x6A, 0x01,                   // push imm8
    0x70, 0x02,                   // jo rel8
    0x84, 0xC3,                   // test r8, r8
    0x89, 0xC3,                   // mov r32, r32
    0x8D, 0x40, 0x04,             // lea r32, [rax+disp8]
    0x90,                         // nop
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, imm32
    0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
    0xC3,                         // ret
    0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32
    0xE9, 0x00, 0x00, 0x00, 0x00, // jmp rel32
    0xEB, 0x00,                   // jmp rel8
    0xF4,                         // hlt
    0x00, 0x00                    // implicit zero-fill decodes as add m8, r8
};

// Representative 0F two-byte and x87 sequences, added so the guards also
// cover the two-byte escape dispatch (Decode2ByteOpcode) and the x87
// descriptor path — not just the 1-byte legacy map. Every sequence here is
// drawn from opcodes covered by test/test_2byte_opcodes.cpp and
// test/test_x86_x87_opcodes.cpp (and their 32-bit twins), so the sweep stays
// on the zero-error decode path. Test-only: the bench keeps the legacy tile.
//
// When adding ISA families (more SSE forms, AVX2/VEX, ...), extend this tile
// AND NaiveDecodeLength's opcode subset in the same change, then re-derive
// the constants below from a Release run. The initializer must list exactly
// 68 bytes: std::array zero-fill would silently append decodable bytes — the
// same trap as the original bench kSeed (see the note above).
static constexpr std::array<uint8_t, 68> kSeedExt = {
    // 0F two-byte map
    0x0F, 0x05,                         // syscall
    0x0F, 0x31,                         // rdtsc
    0x0F, 0xA2,                         // cpuid
    0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, // jz rel32
    0x0F, 0x90, 0x00,                   // seto m8      ([rax])
    0x0F, 0x95, 0xC0,                   // setnz r8
    0x0F, 0xB6, 0xC3,                   // movzx r32, r8
    0x0F, 0xB6, 0x00,                   // movzx r32, m8 ([rax])
    0x0F, 0xAF, 0xC3,                   // imul r32, r32
    0x0F, 0xBA, 0xE0, 0x04,             // bt r32, imm8
    0x0F, 0xC8,                         // bswap eax
    0x0F, 0x1F, 0x00,                   // nop m        ([rax])
    0x0F, 0x58, 0xC3,                   // addps xmm, xmm
    0x0F, 0x58, 0x00,                   // addps xmm, m  ([rax])
    0x66, 0x0F, 0x58, 0x00,             // addpd xmm, m  ([rax])
    0xF3, 0x0F, 0x58, 0x00,             // addss xmm, m  ([rax])
    // x87 D8-DF
    0xD8, 0x00,                         // fadd m32fp   ([rax])
    0xD8, 0xC1,                         // fadd st0, st1
    0xD9, 0x00,                         // fld  m32fp   ([rax])
    0xD9, 0xC1,                         // fld  st1
    0xD9, 0xD0,                         // fnop
    0xD9, 0xE0,                         // fchs
    0xDB, 0x28,                         // fld  m80fp   ([rax])
    0xDD, 0x30,                         // fsave m      ([rax])
    0xDF, 0xE0,                         // fnstsw ax
};

// Tile the legacy seed + extension until the corpus is at least `min_bytes`
// long. One pattern period is kSeed.size() + kSeedExt.size() bytes, so the
// sweep stays periodically aligned.
auto BuildCorpus(const size_t min_bytes) -> std::vector<uint8_t>
{
    std::vector<uint8_t> corpus;
    corpus.reserve(min_bytes);
    while (corpus.size() < min_bytes) {
        corpus.insert(corpus.end(), kSeed.begin(), kSeed.end());
        corpus.insert(corpus.end(), kSeedExt.begin(), kSeedExt.end());
    }
    return corpus;
}

// Known constants for the corpus (legacy 79-byte tile + 68-byte 0F/x87
// extension, pattern period 147 bytes) tiled until >= 1 MiB (corpus size =
// 1,048,698 bytes), derived from an actual Release run of this suite. They pin
// the correctness of the decode loops so a throughput gate cannot be passed by
// wrong results or by the compiler eliding the work. If kSeed or kSeedExt
// changes, re-derive them from a Release run.
constexpr uint64_t kExpectedDecoded = 370968;
constexpr uint64_t kExpectedChecksum = 1569480;

// Returns the best MiB/s across the timed iterations, and fills `decoded` and
// `checksum` with the values observed during the run.
auto MeasureThroughput(const std::vector<uint8_t>& corpus, uint32_t warmup_iters, uint32_t timed_iters,
                       uint64_t& decoded, uint64_t& checksum) -> double
{
    decoded = 0;
    checksum = 0;

    auto run_once = [&]() -> double {
        uint64_t local_decoded = 0;
        uint64_t local_checksum = 0;

        const auto t0 = std::chrono::steady_clock::now();
        size_t off = 0;
        while (off < corpus.size()) {
            auto span = gsl::span<const uint8_t>(corpus.data() + off, corpus.size() - off);
            const auto di = xendiza::Disasm<64>(span);
            if (di.length >= 0xE0 || di.length == 0) {
                ++off;
                continue;
            }
            ++local_decoded;
            local_checksum += di.length;
            local_checksum += static_cast<uint64_t>(di.instrId.operand_count);
            off += di.length;
        }
        const auto t1 = std::chrono::steady_clock::now();

        decoded = local_decoded;
        checksum = local_checksum;

        const double seconds = std::chrono::duration<double>(t1 - t0).count();
        const double mib = static_cast<double>(corpus.size()) / (1024.0 * 1024.0);
        return (seconds > 0.0) ? (mib / seconds) : 0.0;
    };

    for (uint32_t i = 0; i < warmup_iters; ++i) {
        run_once();
    }

    double best_mibs = 0.0;
    for (uint32_t i = 0; i < timed_iters; ++i) {
        best_mibs = std::max(best_mibs, run_once());
    }
    return best_mibs;
}

// Deliberately naive reference decoder covering exactly the opcode subset that
// appears in kSeed: a prefix walk + a plain switch + sequential ModR/M sizing.
// No decode tables, no operand metadata. Its cost scales with the machine just
// like the library's, so the xendiza/naive throughput ratio is
// machine-independent — this is the self-calibrating baseline for the relative
// guard: a library regression shows up as a ratio drop on any machine,
// regardless of that machine's absolute speed.
//
// Returns the instruction length (prefix bytes included), or 0xE0 (mirroring
// the library's error encoding) for opcodes outside the seed subset or
// truncated input.
auto NaiveDecodeLength(const gsl::span<const uint8_t> code) -> unsigned
{
    size_t i = 0;
    bool rex_w = false;
    bool op66 = false;
    while (i < code.size() &&
           (code[i] == 0x48 || code[i] == 0x66 || code[i] == 0xF2 || code[i] == 0xF3)) {
        rex_w = rex_w || code[i] == 0x48;
        op66 = op66 || code[i] == 0x66;
        ++i;
    }
    if (i >= code.size()) {
        return 0xE0;
    }

    uint8_t op = code[i];
    ++i;

    bool has_modrm = false;
    unsigned imm = 0;

    if (op == 0x0F) {
        // Two-byte escape. Only the subset present in kSeedExt is sized; any
        // other second opcode is reported as undefined, mirroring the
        // library sweep's resync on uncovered opcodes.
        if (i >= code.size()) {
            return 0xE0;
        }
        const uint8_t op2 = code[i];
        ++i;
        switch (op2) {
        case 0x05: case 0x31: case 0xA2: // syscall, rdtsc, cpuid
            break;
        case 0x84:                       // Jcc rel32 (0F 80-8F)
            imm = 4;
            break;
        case 0x90: case 0x91: case 0x92: case 0x93: // SETcc r/m8
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F:
        case 0x1F:                       // multi-byte NOP r/m
        case 0x2E: case 0x2F:            // ucomiss/ucomisd
        case 0x58: case 0x5C:            // addps/addpd, subps/subpd
        case 0xAF:                       // imul r, r/m
        case 0xB6: case 0xB7:            // movzx
        case 0xBE: case 0xBF:            // movsx
        case 0xA3: case 0xAB: case 0xB3: case 0xBB: // BT/BTS/BTR/BTC
            has_modrm = true;
            break;
        case 0xBA:                       // group 8: r/m, imm8
            imm = 1;
            has_modrm = true;
            break;
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: // bswap r32
        case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            break;
        default:
            return 0xE0;
        }
    } else if (op >= 0xD8 && op <= 0xDF) {
        // x87: every form in D8-DF takes a ModR/M (register or memory).
        has_modrm = true;
    } else {
        switch (op) {
    case 0x00: case 0x01: case 0x03: case 0x08:
    case 0x20: case 0x28: case 0x30: case 0x38:
    case 0x84: case 0x89: case 0x8D:
        has_modrm = true;
        break;
    case 0x04: case 0x6A: case 0x70: case 0xEB:
        imm = 1;
        break;
    case 0x05:
        imm = (op66 && !rex_w) ? 2 : 4;
        break;
    case 0x81:
        imm = (op66 && !rex_w) ? 2 : 4;
        has_modrm = true;
        break;
    case 0x83:
        imm = 1;
        has_modrm = true;
        break;
    case 0xB8:
        imm = rex_w ? 8 : 4;
        break;
    case 0xE8: case 0xE9:
        imm = 4;
        break;
    case 0x90: case 0xC3: case 0xF4:
        break;
    default:
        return 0xE0;
    }
    }

    unsigned len = i; // prefix bytes + opcode byte
    if (has_modrm) {
        if (i >= code.size()) {
            return 0xE0;
        }
        const uint8_t modrm = code[i];
        ++len;
        const unsigned mod = modrm >> 6;
        const unsigned rm = modrm & 7;
        if (mod != 3) {
            if (rm == 4) { // SIB byte follows
                if (i + 1 >= code.size()) {
                    return 0xE0;
                }
                const uint8_t sib = code[i + 1];
                ++len;
                if (mod == 0 && (sib & 7) == 5) {
                    len += 4; // SIB base=disp32
                }
            } else if (mod == 0 && rm == 5) {
                len += 4; // RIP-relative disp32
            }
            if (mod == 1) {
                len += 1; // disp8
            } else if (mod == 2) {
                len += 4; // disp32
            }
        }
    }
    return len + imm;
}

// Same best-of-N protocol as MeasureThroughput, but sweeping with the naive
// reference decoder. Only decoded count and covered bytes are accumulated (the
// naive decoder produces no operand metadata); the loop cannot be elided
// because each returned length drives the sweep offset.
auto MeasureReferenceThroughput(const std::vector<uint8_t>& corpus, uint32_t warmup_iters,
                                uint32_t timed_iters, uint64_t& decoded, uint64_t& covered) -> double
{
    decoded = 0;
    covered = 0;

    auto run_once = [&]() -> double {
        uint64_t local_decoded = 0;
        uint64_t local_covered = 0;

        const auto t0 = std::chrono::steady_clock::now();
        size_t off = 0;
        while (off < corpus.size()) {
            auto span = gsl::span<const uint8_t>(corpus.data() + off, corpus.size() - off);
            const unsigned len = NaiveDecodeLength(span);
            if (len >= 0xE0 || len == 0) {
                ++off; // resync, mirrors the library sweep
                continue;
            }
            ++local_decoded;
            local_covered += len;
            off += len;
        }
        const auto t1 = std::chrono::steady_clock::now();

        decoded = local_decoded;
        covered = local_covered;

        const double seconds = std::chrono::duration<double>(t1 - t0).count();
        const double mib = static_cast<double>(corpus.size()) / (1024.0 * 1024.0);
        return (seconds > 0.0) ? (mib / seconds) : 0.0;
    };

    for (uint32_t i = 0; i < warmup_iters; ++i) {
        run_once();
    }

    double best_mibs = 0.0;
    for (uint32_t i = 0; i < timed_iters; ++i) {
        best_mibs = std::max(best_mibs, run_once());
    }
    return best_mibs;
}

// Default floor for the absolute throughput guard. The corpus now mixes the
// legacy tile with 0F/x87 sequences; on the baseline-class machine the guard
// measures ~61–67 MiB/s in Release, so 35 MiB/s keeps ~2x headroom while
// catching order-of-magnitude regressions. (The 61.41 MiB/s figure in
// bench/README.md describes the legacy-only 8 MiB bench corpus.)
// To re-calibrate: build Release, run this guard with XENDIZA_PERF_MIN_MIBS
// set above the measured value to read the actual MiB/s from the failure
// message, then set the floor to ~50–60% of it.
static constexpr double kDefaultMinMiBPerSec = 35.0;

// Returns a positive double from the environment variable `name`, or
// `fallback` when the variable is unset, empty, non-numeric, non-positive,
// or out of range.
auto GetEnvPositiveDouble(const char* name, const double fallback) -> double
{
    const char* env = std::getenv(name);
    if (env != nullptr && env[0] != '\0') {
        char* end = nullptr;
        const double value = std::strtod(env, &end);
        if (end != env && value > 0.0 && value < std::numeric_limits<double>::max()) {
            return value;
        }
    }
    return fallback;
}

} // namespace

TEST(PerfRegression, ThroughputGuard)
{
#ifndef NDEBUG
    GTEST_SKIP() << "Performance regression guard is skipped in Debug builds";
#endif

    // 1 MiB tiled corpus: a smaller, L2-resident variant of the bench
    // synthetic workload (bench default is 8 MiB x 40 iterations).
    const auto corpus = BuildCorpus(1024 * 1024);

    constexpr uint32_t kWarmupIters = 1;
    constexpr uint32_t kTimedIters = 5;

    uint64_t decoded = 0;
    uint64_t checksum = 0;
    const double best_mibs = MeasureThroughput(corpus, kWarmupIters, kTimedIters, decoded, checksum);

    EXPECT_EQ(decoded, kExpectedDecoded)
        << "Decoded-instruction count changed; the perf measurement may be invalid";
    EXPECT_EQ(checksum, kExpectedChecksum)
        << "Decode checksum changed; lengths or operand counts may be wrong";

    const double min_mibs = GetEnvPositiveDouble("XENDIZA_PERF_MIN_MIBS", kDefaultMinMiBPerSec);
    EXPECT_GE(best_mibs, min_mibs)
        << "Throughput " << best_mibs << " MiB/s is below the floor " << min_mibs << " MiB/s";
}

// Default floor for the xendiza/naive throughput ratio (see
// RelativeThroughputGuard). The ratio is machine-independent (both decoders
// are measured in the same run), so no per-machine re-calibration is needed.
// Calibrated from an actual Release run on the baseline-class machine:
// measured ratio ~0.11 (xendiza ~62–67 MiB/s vs naive ~610 MiB/s on the
// extended corpus); the floor at 0.055 leaves ~50% headroom for cross-machine
// ratio drift while catching ~2x regressions. Override with
// XENDIZA_PERF_MIN_RATIO.
static constexpr double kDefaultMinRatio = 0.055;

TEST(PerfRegression, RelativeThroughputGuard)
{
#ifndef NDEBUG
    GTEST_SKIP() << "Performance regression guard is skipped in Debug builds";
#endif

    const auto corpus = BuildCorpus(1024 * 1024);

    constexpr uint32_t kWarmupIters = 1;
    constexpr uint32_t kTimedIters = 5;

    uint64_t decoded = 0;
    uint64_t checksum = 0;
    const double xendiza_mibs = MeasureThroughput(corpus, kWarmupIters, kTimedIters, decoded, checksum);

    EXPECT_EQ(decoded, kExpectedDecoded)
        << "Decoded-instruction count changed; the perf measurement may be invalid";
    EXPECT_EQ(checksum, kExpectedChecksum)
        << "Decode checksum changed; lengths or operand counts may be wrong";

    uint64_t ref_decoded = 0;
    uint64_t ref_covered = 0;
    const double ref_mibs = MeasureReferenceThroughput(corpus, kWarmupIters, kTimedIters,
                                                       ref_decoded, ref_covered);

    // The naive baseline must land on exactly the same instruction boundaries
    // with zero resync; otherwise the ratio is comparing different work.
    EXPECT_EQ(ref_decoded, kExpectedDecoded)
        << "Naive reference decoded a different instruction count; the ratio is meaningless";
    EXPECT_EQ(ref_covered, static_cast<uint64_t>(corpus.size()))
        << "Naive reference did not cover the corpus exactly; the ratio is meaningless";

    const double ratio = (ref_mibs > 0.0) ? xendiza_mibs / ref_mibs : 0.0;
    const double min_ratio = GetEnvPositiveDouble("XENDIZA_PERF_MIN_RATIO", kDefaultMinRatio);
    EXPECT_GE(ratio, min_ratio)
        << "xendiza/naive ratio " << ratio << " (xendiza " << xendiza_mibs
        << " MiB/s, naive " << ref_mibs << " MiB/s) is below the floor " << min_ratio;
}


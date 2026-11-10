// test_perf_avx_a0.cpp
// A0 AVX milestone performance guard.
//
// Uses a small, deterministic VEX-only tile (VZEROUPPER, VZEROALL, VMOVUPS
// memory load) tiled to ~1 MiB.  The tile is independent from the legacy seed
// used by test_perf_regression.cpp: kSeed, kSeedExt and their constants are
// intentionally left untouched.  A deliberately naive VEX length reference is
// measured alongside the library so the ratio guard is self-calibrating across
// machines.

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

// 14-byte VEX tile exercised by A0:
//   C5 F8 77          VZEROUPPER
//   C5 FC 77          VZEROALL
//   C5 F8 10 05 ...   VMOVUPS xmm,m128 (disp32 / RIP-relative in 64-bit)
static constexpr std::array<uint8_t, 14> kAvxA0Tile = {
    0xC5, 0xF8, 0x77,
    0xC5, 0xFC, 0x77,
    0xC5, 0xF8, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00,
};

// Tile the A0 VEX tile until the corpus is close to 1 MiB.  The copy count is
// chosen so the corpus is an exact multiple of the tile period, which keeps the
// sweep on instruction boundaries with zero resync.
auto BuildAvxA0Corpus() -> std::vector<uint8_t>
{
    constexpr size_t kTargetBytes = 1024 * 1024;
    constexpr size_t kCopies = kTargetBytes / kAvxA0Tile.size();
    std::vector<uint8_t> corpus;
    corpus.reserve(kCopies * kAvxA0Tile.size());
    for (size_t i = 0; i < kCopies; ++i) {
        corpus.insert(corpus.end(), kAvxA0Tile.begin(), kAvxA0Tile.end());
    }
    return corpus;
}

// Known constants for the A0 VEX corpus, derived from an actual Release run.
// They pin the correctness of the decode loop so a throughput gate cannot be
// passed by wrong results.
constexpr uint64_t kExpectedDecoded = 224694;
constexpr uint64_t kExpectedChecksum = 1198368;

// Returns the best MiB/s across the timed iterations, and fills `decoded` and
// `checksum` with the values observed during the run.
auto MeasureAvxThroughput(const std::vector<uint8_t>& corpus, uint32_t warmup_iters,
                          uint32_t timed_iters, uint64_t& decoded, uint64_t& checksum) -> double
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

// Naive VEX length reference covering exactly the opcode subset in kAvxA0Tile.
// It parses the permitted legacy-prefix chain (67h and segment overrides), the
// C4/C5 VEX prefix, the opcode, and a simple ModR/M memory sizing for the
// VMOVUPS form.  Anything outside the tile returns 0xE0, mirroring the library
// sweep's resync behaviour.
auto NaiveVexDecodeLength(const gsl::span<const uint8_t> code) -> unsigned
{
    size_t i = 0;
    while (i < code.size()) {
        const uint8_t b = code[i];
        if (b == 0x67 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            ++i;
            continue;
        }
        break;
    }
    if (i >= code.size()) {
        return 0xE0;
    }

    uint8_t vex_len = 0;
    if (code[i] == 0xC5) {
        vex_len = 2;
    } else if (code[i] == 0xC4) {
        vex_len = 3;
    } else {
        return 0xE0;
    }
    if (i + vex_len >= code.size()) {
        return 0xE0;
    }
    const size_t opcode_pos = i + vex_len;
    const uint8_t op = code[opcode_pos];

    size_t len = opcode_pos + 1;
    if (op == 0x77) {
        // VZEROUPPER / VZEROALL: no ModR/M.
        return static_cast<unsigned>(len);
    }
    if (op == 0x10) {
        // VMOVUPS xmm,m128 (memory form only in this tile).
        if (opcode_pos + 1 >= code.size()) {
            return 0xE0;
        }
        const uint8_t modrm = code[opcode_pos + 1];
        const unsigned mod = modrm >> 6;
        if (mod == 3) {
            return 0xE0; // register form is not in the tile
        }
        len += 1; // ModR/M byte
        const unsigned rm = modrm & 7;
        if (rm == 4) {
            // SIB byte follows.
            if (opcode_pos + 2 >= code.size()) {
                return 0xE0;
            }
            const uint8_t sib = code[opcode_pos + 2];
            len += 1;
            if (mod == 0 && (sib & 7) == 5) {
                len += 4; // disp32 with no base
            }
        } else if (mod == 0 && rm == 5) {
            len += 4; // disp32 / RIP-relative
        }
        if (mod == 1) {
            len += 1; // disp8
        } else if (mod == 2) {
            len += 4; // disp32
        }
        return static_cast<unsigned>(len);
    }
    return 0xE0;
}

// Same best-of-N protocol as MeasureAvxThroughput, sweeping with the naive VEX
// reference decoder.  Only decoded count and covered bytes are accumulated.
auto MeasureAvxReferenceThroughput(const std::vector<uint8_t>& corpus, uint32_t warmup_iters,
                                   uint32_t timed_iters, uint64_t& decoded,
                                   uint64_t& covered) -> double
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
            const unsigned len = NaiveVexDecodeLength(span);
            if (len >= 0xE0 || len == 0) {
                ++off;
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

TEST(PerfAvxA0, ThroughputGuard)
{
#ifndef NDEBUG
    GTEST_SKIP() << "A0 AVX milestone guard is skipped in Debug builds";
#endif

    const auto corpus = BuildAvxA0Corpus();

    constexpr uint32_t kWarmupIters = 1;
    constexpr uint32_t kTimedIters = 5;

    uint64_t decoded = 0;
    uint64_t checksum = 0;
    const double best_mibs = MeasureAvxThroughput(corpus, kWarmupIters, kTimedIters, decoded, checksum);

    EXPECT_EQ(decoded, kExpectedDecoded)
        << "Decoded-instruction count changed; the A0 AVX measurement may be invalid";
    EXPECT_EQ(checksum, kExpectedChecksum)
        << "Decode checksum changed; A0 AVX lengths or operand counts may be wrong";

    // Calibrated from an actual Release run on the baseline-class machine:
    // measured ~120 MiB/s; the floor at 60 MiB/s leaves ~2x headroom.
    // Override with XENDIZA_AVX_A0_MIN_MIBS to read the measured value.
    static constexpr double kDefaultMinMiBPerSec = 60.0;
    const double min_mibs = GetEnvPositiveDouble("XENDIZA_AVX_A0_MIN_MIBS", kDefaultMinMiBPerSec);
    EXPECT_GE(best_mibs, min_mibs)
        << "Throughput " << best_mibs << " MiB/s is below the floor " << min_mibs << " MiB/s";
}

TEST(PerfAvxA0, RelativeThroughputGuard)
{
#ifndef NDEBUG
    GTEST_SKIP() << "A0 AVX milestone guard is skipped in Debug builds";
#endif

    const auto corpus = BuildAvxA0Corpus();

    constexpr uint32_t kWarmupIters = 1;
    constexpr uint32_t kTimedIters = 5;

    uint64_t decoded = 0;
    uint64_t checksum = 0;
    const double xendiza_mibs = MeasureAvxThroughput(corpus, kWarmupIters, kTimedIters, decoded, checksum);

    EXPECT_EQ(decoded, kExpectedDecoded)
        << "Decoded-instruction count changed; the A0 AVX measurement may be invalid";
    EXPECT_EQ(checksum, kExpectedChecksum)
        << "Decode checksum changed; A0 AVX lengths or operand counts may be wrong";

    uint64_t ref_decoded = 0;
    uint64_t ref_covered = 0;
    const double ref_mibs = MeasureAvxReferenceThroughput(corpus, kWarmupIters, kTimedIters,
                                                          ref_decoded, ref_covered);

    EXPECT_EQ(ref_decoded, kExpectedDecoded)
        << "Naive VEX reference decoded a different instruction count; the ratio is meaningless";
    EXPECT_EQ(ref_covered, static_cast<uint64_t>(corpus.size()))
        << "Naive VEX reference did not cover the corpus exactly; the ratio is meaningless";

    const double ratio = (ref_mibs > 0.0) ? xendiza_mibs / ref_mibs : 0.0;

    // Calibrated from an actual Release run on the baseline-class machine:
    // measured ratio ~0.074; the floor at 0.04 leaves ~50% headroom.
    // Override with XENDIZA_AVX_A0_MIN_RATIO.
    static constexpr double kDefaultMinRatio = 0.04;
    const double min_ratio = GetEnvPositiveDouble("XENDIZA_AVX_A0_MIN_RATIO", kDefaultMinRatio);
    EXPECT_GE(ratio, min_ratio)
        << "xendiza/naive ratio " << ratio << " (xendiza " << xendiza_mibs
        << " MiB/s, naive " << ref_mibs << " MiB/s) is below the floor " << min_ratio;
}

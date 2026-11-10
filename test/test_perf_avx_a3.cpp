// test_perf_avx_a3.cpp
// A3 VSIB/gather milestone performance guard.
//
// Extends the A2b VEX tile with a representative AVX2 gather form
// (VPGATHERDD xmm, m32_vsib, xmm) so the A3 guard exercises the new
// VSIB parsing and register-overlap paths.

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

// 66-byte VEX tile exercised by A3 (extends A2b):
//   C5 F8 77                VZEROUPPER
//   C5 FC 77                VZEROALL
//   C5 F8 10 05 ...         VMOVUPS xmm,m128 (disp32)
//   C5 F0 58 C2             VADDPS xmm,xmm,xmm
//   C5 F0 58 05 ...         VADDPS xmm,xmm,m128 (disp32)
//   C4 E2 71 00 C2          VPSHUFB xmm,xmm,xmm
//   C4 E2 71 00 05 ...      VPSHUFB xmm,xmm,m128 (disp32)
//   C4 E3 71 0C C2 00       VBLENDPS xmm,xmm,xmm,imm8
//   C4 E3 71 0C 05 ... 00   VBLENDPS xmm,xmm,m128,imm8 (disp32)
//   C4 E2 71 90 04 15 ...   VPGATHERDD xmm,m32_vsib,xmm (disp32)
static constexpr std::array<uint8_t, 66> kAvxA3Tile = {
    0xC5, 0xF8, 0x77,
    0xC5, 0xFC, 0x77,
    0xC5, 0xF8, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00,
    0xC5, 0xF0, 0x58, 0xC2,
    0xC5, 0xF0, 0x58, 0x05, 0x00, 0x00, 0x00, 0x00,
    0xC4, 0xE2, 0x71, 0x00, 0xC2,
    0xC4, 0xE2, 0x71, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
    0xC4, 0xE3, 0x71, 0x0C, 0xC2, 0x00,
    0xC4, 0xE3, 0x71, 0x0C, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC4, 0xE2, 0x71, 0x90, 0x04, 0x15, 0x00, 0x00, 0x00, 0x00,
};

auto BuildAvxA3Corpus() -> std::vector<uint8_t>
{
    constexpr size_t kTargetBytes = 1024 * 1024;
    constexpr size_t kCopies = kTargetBytes / kAvxA3Tile.size();
    std::vector<uint8_t> corpus;
    corpus.reserve(kCopies * kAvxA3Tile.size());
    for (size_t i = 0; i < kCopies; ++i) {
        corpus.insert(corpus.end(), kAvxA3Tile.begin(), kAvxA3Tile.end());
    }
    return corpus;
}

// Known constants for the A3 VEX corpus, derived from an actual Release run.
constexpr uint64_t kExpectedDecoded = 158870;
constexpr uint64_t kExpectedChecksum = 1445717;

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

// Naive VEX length reference covering exactly the opcode subset in kAvxA3Tile.
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
        return static_cast<unsigned>(len);
    }

    bool has_modrm = false;
    uint8_t trailing = 0;
    if (op == 0x10 || op == 0x58 || op == 0x00 || op == 0x90) {
        has_modrm = true;
    } else if (op == 0x0C) {
        has_modrm = true;
        trailing = 1;
    } else {
        return 0xE0;
    }

    if (opcode_pos + 1 >= code.size()) {
        return 0xE0;
    }
    const uint8_t modrm = code[opcode_pos + 1];
    const unsigned mod = modrm >> 6;
    if (mod == 3) {
        return static_cast<unsigned>(len + 1 + trailing);
    }
    len += 1; // ModR/M byte
    const unsigned rm = modrm & 7;
    if (rm == 4) {
        if (opcode_pos + 2 >= code.size()) {
            return 0xE0;
        }
        const uint8_t sib = code[opcode_pos + 2];
        len += 1;
        if (mod == 0 && (sib & 7) == 5) {
            len += 4;
        }
    } else if (mod == 0 && rm == 5) {
        len += 4;
    }
    if (mod == 1) {
        len += 1;
    } else if (mod == 2) {
        len += 4;
    }
    return static_cast<unsigned>(len + trailing);
}

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

TEST(PerfAvxA3, ThroughputGuard)
{
#ifndef NDEBUG
    GTEST_SKIP() << "A3 AVX milestone guard is skipped in Debug builds";
#endif

    const auto corpus = BuildAvxA3Corpus();

    constexpr uint32_t kWarmupIters = 1;
    constexpr uint32_t kTimedIters = 5;

    uint64_t decoded = 0;
    uint64_t checksum = 0;
    const double best_mibs = MeasureAvxThroughput(corpus, kWarmupIters, kTimedIters, decoded, checksum);

    EXPECT_EQ(decoded, kExpectedDecoded)
        << "Decoded-instruction count changed; the A3 AVX measurement may be invalid";
    EXPECT_EQ(checksum, kExpectedChecksum)
        << "Decode checksum changed; A3 AVX lengths or operand counts may be wrong";

    static constexpr double kDefaultMinMiBPerSec = 30.0;
    const double min_mibs = GetEnvPositiveDouble("XENDIZA_AVX_A3_MIN_MIBS", kDefaultMinMiBPerSec);
    EXPECT_GE(best_mibs, min_mibs)
        << "Throughput " << best_mibs << " MiB/s is below the floor " << min_mibs << " MiB/s";
}

TEST(PerfAvxA3, RelativeThroughputGuard)
{
#ifndef NDEBUG
    GTEST_SKIP() << "A3 AVX milestone guard is skipped in Debug builds";
#endif

    const auto corpus = BuildAvxA3Corpus();

    constexpr uint32_t kWarmupIters = 1;
    constexpr uint32_t kTimedIters = 5;

    uint64_t decoded = 0;
    uint64_t checksum = 0;
    const double xendiza_mibs = MeasureAvxThroughput(corpus, kWarmupIters, kTimedIters, decoded, checksum);

    EXPECT_EQ(decoded, kExpectedDecoded)
        << "Decoded-instruction count changed; the A3 AVX measurement may be invalid";
    EXPECT_EQ(checksum, kExpectedChecksum)
        << "Decode checksum changed; A3 AVX lengths or operand counts may be wrong";

    uint64_t ref_decoded = 0;
    uint64_t ref_covered = 0;
    const double ref_mibs = MeasureAvxReferenceThroughput(corpus, kWarmupIters, kTimedIters,
                                                          ref_decoded, ref_covered);

    EXPECT_EQ(ref_decoded, kExpectedDecoded)
        << "Naive VEX reference decoded a different instruction count; the ratio is meaningless";
    EXPECT_EQ(ref_covered, static_cast<uint64_t>(corpus.size()))
        << "Naive VEX reference did not cover the corpus exactly; the ratio is meaningless";

    const double ratio = (ref_mibs > 0.0) ? xendiza_mibs / ref_mibs : 0.0;

    static constexpr double kDefaultMinRatio = 0.02;
    const double min_ratio = GetEnvPositiveDouble("XENDIZA_AVX_A3_MIN_RATIO", kDefaultMinRatio);
    EXPECT_GE(ratio, min_ratio)
        << "xendiza/naive ratio " << ratio << " (xendiza " << xendiza_mibs
        << " MiB/s, naive " << ref_mibs << " MiB/s) is below the floor " << min_ratio;
}

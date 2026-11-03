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

// Tile the seed until the corpus is at least `min_bytes` long, matching the
// BuildCorpus() logic in bench/bench_disasm.cpp exactly.
auto BuildCorpus(const size_t min_bytes) -> std::vector<uint8_t>
{
    std::vector<uint8_t> corpus;
    corpus.reserve(min_bytes);
    while (corpus.size() < min_bytes) {
        corpus.insert(corpus.end(), kSeed.begin(), kSeed.end());
    }
    return corpus;
}

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

// Default floor is ~40% of the 61.41 MiB/s Release baseline recorded in
// bench/README.md for the synthetic seed (8 MiB, 40 iterations).
// To re-calibrate: build Release, run `xendiza_bench --mb 8 --iters 40`,
// multiply the reported xendiza MiB/s by a safety factor (e.g. 0.4), and update
// this constant. Override at runtime with XENDIZA_PERF_MIN_MIBS.
static constexpr double kDefaultMinMiBPerSec = 25.0;

auto GetMinMiBPerSec() -> double
{
    const char* env = std::getenv("XENDIZA_PERF_MIN_MIBS");
    if (env != nullptr && env[0] != '\0') {
        char* end = nullptr;
        const double value = std::strtod(env, &end);
        if (end != env && value > 0.0 && value < std::numeric_limits<double>::max()) {
            return value;
        }
    }
    return kDefaultMinMiBPerSec;
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

    // Known constants for the 79-byte seed tiled until >= 1 MiB
    // (corpus size = 1,048,646 bytes). These were derived from an actual
    // Release run of this test and pin the correctness of the decode loop so
    // the throughput gate cannot be passed by wrong results or by the compiler
    // eliding the work. If kSeed changes, re-derive them from a Release run.
    constexpr uint64_t kExpectedDecoded = 358398;
    constexpr uint64_t kExpectedChecksum = 1619428;

    EXPECT_EQ(decoded, kExpectedDecoded)
        << "Decoded-instruction count changed; the perf measurement may be invalid";
    EXPECT_EQ(checksum, kExpectedChecksum)
        << "Decode checksum changed; lengths or operand counts may be wrong";

    const double min_mibs = GetMinMiBPerSec();
    EXPECT_GE(best_mibs, min_mibs)
        << "Throughput " << best_mibs << " MiB/s is below the floor " << min_mibs << " MiB/s";
}

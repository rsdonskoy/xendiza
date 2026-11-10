// bench_avx.cpp
// AVX/AVX2 decode-throughput benchmark comparing xendiza and Zydis.
//
// Uses deterministic ISA-specific corpora generated from the VEX inventory.
// A correctness gate runs before timing: both decoders must decode the corpus
// with identical instruction boundaries and lengths and zero errors.

#include <xendiza/xendiza.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#ifdef XENDIZA_BENCH_WITH_ZYDIS
#include <Zydis/Zydis.h>
#endif

namespace {

struct Options {
    std::string isa = "avx2";   // "avx" or "avx2"
    std::string mode = "64";    // "32" or "64"
    uint32_t inner_iters = 10;  // iterations inside one timed sample
    uint32_t samples = 10;      // best-of-N samples
    uint32_t warmup = 1;
    std::string corpus_path;
};

struct Result {
    std::string name;
    double best_seconds = 0.0;
    uint64_t bytes_processed = 0;
    uint64_t decoded = 0;
    uint64_t errors = 0;
    uint64_t checksum = 0;
};

auto ParseOptions(const int argc, char** argv) -> Options
{
    Options opt;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--isa") == 0 && i + 1 < argc) {
            opt.isa = argv[++i];
        } else if (std::strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            opt.mode = argv[++i];
        } else if (std::strcmp(argv[i], "--inner-iters") == 0 && i + 1 < argc) {
            const auto n = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
            if (n > 0) opt.inner_iters = n;
        } else if (std::strcmp(argv[i], "--samples") == 0 && i + 1 < argc) {
            const auto n = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
            if (n > 0) opt.samples = n;
        } else if (std::strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
            const auto n = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
            opt.warmup = n;
        } else if (std::strcmp(argv[i], "--corpus") == 0 && i + 1 < argc) {
            opt.corpus_path = argv[++i];
        }
    }
    return opt;
}

auto LoadFileBytes(const std::string& path) -> std::vector<uint8_t>
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return {};
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                std::istreambuf_iterator<char>());
}

auto DefaultCorpusPath(const std::string& isa) -> std::string
{
    namespace fs = std::filesystem;
    const fs::path here = fs::path(__FILE__).parent_path();
    return (here / ("corpus_" + isa + ".bin")).string();
}

auto DecodeXendiza(const std::vector<uint8_t>& corpus, bool is_64bit,
                   std::vector<uint8_t>& lengths, uint64_t& checksum) -> uint64_t
{
    lengths.clear();
    checksum = 0;
    uint64_t decoded = 0;
    size_t off = 0;
    while (off < corpus.size()) {
        auto span = gsl::span<const uint8_t>(corpus.data() + off, corpus.size() - off);
        const auto di = is_64bit ? xendiza::Disasm<64>(span) : xendiza::Disasm<32>(span);
        if (di.length >= 0xE0 || di.length == 0) {
            lengths.push_back(0);
            ++off;
        } else {
            lengths.push_back(static_cast<uint8_t>(di.length));
            checksum += di.length;
            off += di.length;
            ++decoded;
        }
    }
    return decoded;
}

#ifdef XENDIZA_BENCH_WITH_ZYDIS
auto InitZydis(bool is_64bit, ZydisDecoder& decoder) -> bool
{
    const auto machine_mode = is_64bit
        ? ZYDIS_MACHINE_MODE_LONG_64
        : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
    const auto stack_width = is_64bit
        ? ZYDIS_STACK_WIDTH_64
        : ZYDIS_STACK_WIDTH_32;
    return ZYAN_SUCCESS(ZydisDecoderInit(&decoder, machine_mode, stack_width));
}

auto DecodeZydis(const std::vector<uint8_t>& corpus, bool is_64bit,
                 std::vector<uint8_t>& lengths, uint64_t& checksum) -> uint64_t
{
    lengths.clear();
    checksum = 0;
    uint64_t decoded = 0;

    ZydisDecoder decoder;
    if (!InitZydis(is_64bit, decoder)) {
        return 0;
    }

    size_t off = 0;
    while (off < corpus.size()) {
        ZydisDecodedInstruction instr;
        const auto status = ZydisDecoderDecodeInstruction(
            &decoder, nullptr, corpus.data() + off, corpus.size() - off, &instr);
        if (ZYAN_SUCCESS(status) && instr.length > 0) {
            lengths.push_back(static_cast<uint8_t>(instr.length));
            checksum += instr.length;
            off += instr.length;
            ++decoded;
        } else {
            lengths.push_back(0);
            ++off;
        }
    }
    return decoded;
}

auto TimeZydis(const std::vector<uint8_t>& corpus, bool is_64bit,
               uint32_t warmup, uint32_t inner_iters, uint32_t samples,
               uint64_t& decoded, uint64_t& checksum) -> double
{
    decoded = 0;
    checksum = 0;

    ZydisDecoder decoder;
    if (!InitZydis(is_64bit, decoder)) {
        return 0.0;
    }

    auto run_once = [&]() -> double {
        uint64_t local_decoded = 0;
        uint64_t local_checksum = 0;
        const auto t0 = std::chrono::steady_clock::now();
        for (uint32_t it = 0; it < inner_iters; ++it) {
            size_t off = 0;
            while (off < corpus.size()) {
                ZydisDecodedInstruction instr;
                const auto status = ZydisDecoderDecodeInstruction(
                    &decoder, nullptr, corpus.data() + off, corpus.size() - off, &instr);
                if (ZYAN_SUCCESS(status) && instr.length > 0) {
                    ++local_decoded;
                    local_checksum += instr.length;
                    off += instr.length;
                } else {
                    ++off;
                }
            }
        }
        const auto t1 = std::chrono::steady_clock::now();
        decoded = local_decoded;
        checksum = local_checksum;
        return std::chrono::duration<double>(t1 - t0).count();
    };

    for (uint32_t i = 0; i < warmup; ++i) {
        run_once();
    }

    double best = 0.0;
    for (uint32_t i = 0; i < samples; ++i) {
        const double seconds = run_once();
        if (best == 0.0 || seconds < best) {
            best = seconds;
        }
    }
    return best;
}
#endif

auto TimeXendiza(const std::vector<uint8_t>& corpus, bool is_64bit,
                 uint32_t warmup, uint32_t inner_iters, uint32_t samples,
                 uint64_t& decoded, uint64_t& checksum) -> double
{
    decoded = 0;
    checksum = 0;

    auto run_once = [&]() -> double {
        uint64_t local_decoded = 0;
        uint64_t local_checksum = 0;
        const auto t0 = std::chrono::steady_clock::now();
        for (uint32_t it = 0; it < inner_iters; ++it) {
            size_t off = 0;
            while (off < corpus.size()) {
                auto span = gsl::span<const uint8_t>(corpus.data() + off, corpus.size() - off);
                const auto di = is_64bit ? xendiza::Disasm<64>(span) : xendiza::Disasm<32>(span);
                if (di.length >= 0xE0 || di.length == 0) {
                    ++off;
                } else {
                    ++local_decoded;
                    local_checksum += di.length;
                    off += di.length;
                }
            }
        }
        const auto t1 = std::chrono::steady_clock::now();
        decoded = local_decoded;
        checksum = local_checksum;
        return std::chrono::duration<double>(t1 - t0).count();
    };

    for (uint32_t i = 0; i < warmup; ++i) {
        run_once();
    }

    double best = 0.0;
    for (uint32_t i = 0; i < samples; ++i) {
        const double seconds = run_once();
        if (best == 0.0 || seconds < best) {
            best = seconds;
        }
    }
    return best;
}

void PrintResult(const Result& r)
{
    const auto mib = static_cast<double>(r.bytes_processed) / (1024.0 * 1024.0);
    const auto mib_per_s = (r.best_seconds > 0.0) ? (mib / r.best_seconds) : 0.0;
    const auto minsn_per_s = (r.best_seconds > 0.0)
        ? (static_cast<double>(r.decoded) / r.best_seconds / 1'000'000.0)
        : 0.0;

    std::cout << std::left << std::setw(14) << r.name
              << " | " << std::right << std::setw(9) << std::fixed << std::setprecision(2) << mib_per_s << " MiB/s"
              << " | " << std::setw(8) << std::fixed << std::setprecision(2) << minsn_per_s << " Minsn/s"
              << " | decoded=" << r.decoded
              << " errors=" << r.errors
              << " checksum=" << r.checksum
              << "\n";
}

} // namespace

int main(int argc, char** argv)
{
    const auto opt = ParseOptions(argc, argv);

    if (opt.isa != "avx" && opt.isa != "avx2") {
        std::cerr << "error: --isa must be 'avx' or 'avx2'\n";
        return 1;
    }
    if (opt.mode != "32" && opt.mode != "64") {
        std::cerr << "error: --mode must be '32' or '64'\n";
        return 1;
    }
    const bool is_64bit = opt.mode == "64";

    const std::string corpus_path = opt.corpus_path.empty()
        ? DefaultCorpusPath(opt.isa)
        : opt.corpus_path;
    const auto corpus = LoadFileBytes(corpus_path);
    if (corpus.empty()) {
        std::cerr << "error: could not read corpus '" << corpus_path << "'\n";
        return 1;
    }

    std::cout << "AVX benchmark | ISA=" << opt.isa
              << " mode=" << opt.mode
              << " corpus=" << corpus.size() << " bytes"
              << " inner_iters=" << opt.inner_iters
              << " samples=" << opt.samples
              << " warmup=" << opt.warmup << "\n";

#ifndef XENDIZA_BENCH_WITH_ZYDIS
    std::cout << "Zydis comparison unavailable (build with -DXENDIZA_BENCH_WITH_ZYDIS=ON)\n";
    return 0;
#endif

#ifdef XENDIZA_BENCH_WITH_ZYDIS
    // Correctness gate: collect per-instruction lengths and checksums once.
    std::vector<uint8_t> x_lengths;
    uint64_t x_checksum = 0;
    const uint64_t x_decoded = DecodeXendiza(corpus, is_64bit, x_lengths, x_checksum);
    const uint64_t x_errors = static_cast<uint64_t>(
        std::count(x_lengths.begin(), x_lengths.end(), uint8_t{0}));

    std::vector<uint8_t> z_lengths;
    uint64_t z_checksum = 0;
    const uint64_t z_decoded = DecodeZydis(corpus, is_64bit, z_lengths, z_checksum);
    const uint64_t z_errors = static_cast<uint64_t>(
        std::count(z_lengths.begin(), z_lengths.end(), uint8_t{0}));

    bool gate_ok = true;
    if (x_errors != 0 || z_errors != 0) {
        std::cerr << "correctness gate failed: errors xendiza=" << x_errors
                  << " zydis=" << z_errors << "\n";
        gate_ok = false;
    }
    if (x_decoded != z_decoded) {
        std::cerr << "correctness gate failed: decoded count differs xendiza="
                  << x_decoded << " zydis=" << z_decoded << "\n";
        gate_ok = false;
    }
    if (x_lengths != z_lengths) {
        std::cerr << "correctness gate failed: instruction boundaries differ\n";
        size_t offset = 0;
        int shown = 0;
        for (size_t i = 0; i < x_lengths.size() && i < z_lengths.size() && shown < 10; ++i) {
            if (x_lengths[i] != z_lengths[i]) {
                std::cerr << "  first diff at tile offset " << offset
                          << " xendiza_len=" << int(x_lengths[i])
                          << " zydis_len=" << int(z_lengths[i])
                          << " bytes=";
                for (size_t k = offset; k < offset + 16 && k < corpus.size(); ++k) {
                    std::cerr << std::hex << std::setw(2) << std::setfill('0')
                              << int(corpus[k]) << " ";
                }
                std::cerr << std::dec << "\n";
                ++shown;
            }
            offset += (x_lengths[i] == 0) ? 1 : x_lengths[i];
        }
        gate_ok = false;
    }
    if (x_checksum != z_checksum) {
        std::cerr << "correctness gate failed: checksum differs xendiza="
                  << x_checksum << " zydis=" << z_checksum << "\n";
        gate_ok = false;
    }
    if (!gate_ok) {
        return 1;
    }

    std::cout << "Decoder        | Throughput |    Decode | Stats\n";
    std::cout << "---------------------------------------------------------------\n";

    Result x_result;
    x_result.name = "xendiza";
    x_result.best_seconds = TimeXendiza(corpus, is_64bit, opt.warmup, opt.inner_iters, opt.samples,
                                        x_result.decoded, x_result.checksum);
    x_result.bytes_processed = static_cast<uint64_t>(corpus.size()) * opt.inner_iters;
    x_result.errors = 0;
    PrintResult(x_result);

    Result z_result;
    z_result.name = "zydis";
    z_result.best_seconds = TimeZydis(corpus, is_64bit, opt.warmup, opt.inner_iters, opt.samples,
                                      z_result.decoded, z_result.checksum);
    z_result.bytes_processed = static_cast<uint64_t>(corpus.size()) * opt.inner_iters;
    z_result.errors = 0;
    PrintResult(z_result);

    // Throughput ratio = (bytes/x_seconds) / (bytes/z_seconds) = z_seconds / x_seconds.
    const double ratio = (x_result.best_seconds > 0.0)
        ? (z_result.best_seconds / x_result.best_seconds)
        : 0.0;
    std::cout << "xendiza/Zydis throughput ratio: "
              << std::fixed << std::setprecision(3) << ratio << "\n";
    std::cout << "(xendiza returns abstract opcode/operand classes; Zydis performs fuller semantic decoding)\n";

    return 0;
#endif
}

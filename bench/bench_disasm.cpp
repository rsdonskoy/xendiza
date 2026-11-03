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
#include <string_view>
#include <vector>

#ifdef XENDIZA_BENCH_WITH_CAPSTONE
#include <capstone/capstone.h>
#endif

#ifdef XENDIZA_BENCH_WITH_ZYDIS
#include <Zydis/Zydis.h>
#endif

namespace {

struct Options {
    size_t corpus_bytes = 8 * 1024 * 1024;
    uint32_t iters = 40;
    std::string file_path;                 // --file <path>: load a single raw-bytes file
    std::vector<std::string> fixtures;     // --fixture <name>: load bench/fixtures/<name>.text.bin (repeatable)
};

struct Result {
    std::string name;
    double seconds = 0.0;
    uint64_t bytes_processed = 0;
    uint64_t decoded = 0;
    uint64_t errors = 0;
    uint64_t checksum = 0;
};

// Read an entire file as raw bytes. Mirrors example/example.cpp LoadFileBytes.
auto LoadFileBytes(const std::string& path) -> std::vector<uint8_t>
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return {};
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                std::istreambuf_iterator<char>());
}

// Resolve a fixture name (e.g. "ntdll") to bench/fixtures/ntdll.text.bin,
// relative to this source file's location so it works from any CWD.
auto FixturePath(const std::string& name) -> std::string
{
    // __FILE__ is bench/bench_disasm.cpp; fixtures live in bench/fixtures/.
    namespace fs = std::filesystem;
    const fs::path here = fs::path(__FILE__).parent_path();
    return (here / "fixtures" / (name + ".text.bin")).string();
}

auto ParseOptions(const int argc, char** argv) -> Options
{
    Options opt;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--mb") == 0 && i + 1 < argc) {
            const auto mb = static_cast<size_t>(std::strtoull(argv[++i], nullptr, 10));
            if (mb > 0) {
                opt.corpus_bytes = mb * 1024 * 1024;
            }
        } else if (std::strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
            const auto iters = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
            if (iters > 0) {
                opt.iters = iters;
            }
        } else if (std::strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            opt.file_path = argv[++i];
        } else if (std::strcmp(argv[i], "--fixture") == 0 && i + 1 < argc) {
            opt.fixtures.emplace_back(argv[++i]);
        }
    }
    return opt;
}

auto BuildCorpus(const size_t min_bytes) -> std::vector<uint8_t>
{
    // Supported 1-byte opcodes with mixed ModRM, immediates, prefixes.
    // NOTE: only 77 bytes are listed explicitly; the std::array<79>
    // zero-fills the final two, which decode as one extra `add m8, r8`
    // (0x00 0x00) — the effective tile is 27 instructions, not 26. Keep this
    // literal byte-identical with kSeed in test/test_perf_regression.cpp.
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
        0xF4                          // hlt
    };

    std::vector<uint8_t> corpus;
    corpus.reserve(min_bytes);
    while (corpus.size() < min_bytes) {
        corpus.insert(corpus.end(), kSeed.begin(), kSeed.end());
    }
    return corpus;
}

auto RunXendiza(const std::vector<uint8_t>& corpus, const uint32_t iters) -> Result
{
    Result r;
    r.name = "xendiza";

    const auto t0 = std::chrono::steady_clock::now();
    for (uint32_t it = 0; it < iters; ++it) {
        size_t off = 0;
        while (off < corpus.size()) {
            auto span = gsl::span<const uint8_t>(corpus.data() + off, corpus.size() - off);
            const auto di = xendiza::Disasm<64>(span);
            if (di.length >= 0xE0 || di.length == 0) {
                ++r.errors;
                ++off;
                continue;
            }
            ++r.decoded;
            r.checksum += di.length;
            r.checksum += static_cast<uint64_t>(di.instrId.operand_count);
            off += di.length;
        }
    }
    const auto t1 = std::chrono::steady_clock::now();

    r.seconds = std::chrono::duration<double>(t1 - t0).count();
    r.bytes_processed = static_cast<uint64_t>(corpus.size()) * iters;
    return r;
}

#ifdef XENDIZA_BENCH_WITH_CAPSTONE
auto RunCapstone(const std::vector<uint8_t>& corpus, const uint32_t iters) -> Result
{
    Result r;
    r.name = "capstone";

    csh handle = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        r.name += "(init-failed)";
        return r;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_insn* insn = cs_malloc(handle);
    if (insn == nullptr) {
        cs_close(&handle);
        r.name += "(alloc-failed)";
        return r;
    }

    const auto t0 = std::chrono::steady_clock::now();
    for (uint32_t it = 0; it < iters; ++it) {
        size_t off = 0;
        while (off < corpus.size()) {
            const uint8_t* code = corpus.data() + off;
            size_t code_size = corpus.size() - off;
            uint64_t addr = static_cast<uint64_t>(off);
            if (cs_disasm_iter(handle, &code, &code_size, &addr, insn)) {
                ++r.decoded;
                r.checksum += insn->size;
                off = static_cast<size_t>(code - corpus.data());
            } else {
                ++r.errors;
                ++off;
            }
        }
    }
    const auto t1 = std::chrono::steady_clock::now();

    cs_free(insn, 1);
    cs_close(&handle);

    r.seconds = std::chrono::duration<double>(t1 - t0).count();
    r.bytes_processed = static_cast<uint64_t>(corpus.size()) * iters;
    return r;
}
#endif

#ifdef XENDIZA_BENCH_WITH_ZYDIS
auto RunZydis(const std::vector<uint8_t>& corpus, const uint32_t iters) -> Result
{
    Result r;
    r.name = "zydis";

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        r.name += "(init-failed)";
        return r;
    }

    const auto t0 = std::chrono::steady_clock::now();
    for (uint32_t it = 0; it < iters; ++it) {
        size_t off = 0;
        while (off < corpus.size()) {
            ZydisDecodedInstruction instr;
            const auto status = ZydisDecoderDecodeInstruction(
                &decoder, nullptr, corpus.data() + off, corpus.size() - off, &instr);
            if (ZYAN_SUCCESS(status) && instr.length > 0) {
                ++r.decoded;
                r.checksum += instr.length;
                off += instr.length;
            } else {
                ++r.errors;
                ++off;
            }
        }
    }
    const auto t1 = std::chrono::steady_clock::now();

    r.seconds = std::chrono::duration<double>(t1 - t0).count();
    r.bytes_processed = static_cast<uint64_t>(corpus.size()) * iters;
    return r;
}
#endif

void PrintResult(const Result& r)
{
    const auto mib = static_cast<double>(r.bytes_processed) / (1024.0 * 1024.0);
    const auto mib_per_s = (r.seconds > 0.0) ? (mib / r.seconds) : 0.0;
    const auto minsn_per_s = (r.seconds > 0.0) ? (static_cast<double>(r.decoded) / r.seconds / 1'000'000.0) : 0.0;

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

    // Corpus source priority: --file > --fixture (concatenated) > synthetic seed.
    std::vector<uint8_t> corpus;
    std::string corpus_desc;
    if (!opt.file_path.empty()) {
        corpus = LoadFileBytes(opt.file_path);
        corpus_desc = "file:" + opt.file_path;
        if (corpus.empty()) {
            std::cerr << "error: could not read --file '" << opt.file_path << "'\n";
            return 1;
        }
    } else if (!opt.fixtures.empty()) {
        for (const auto& name : opt.fixtures) {
            const auto path = FixturePath(name);
            auto bytes = LoadFileBytes(path);
            if (bytes.empty()) {
                std::cerr << "error: could not read fixture '" << name
                          << "' (" << path << ")\n";
                return 1;
            }
            corpus.insert(corpus.end(), bytes.begin(), bytes.end());
        }
        corpus_desc = "fixtures:" ;
        for (size_t i = 0; i < opt.fixtures.size(); ++i) {
            corpus_desc += (i ? "+" : "") + opt.fixtures[i];
        }
    } else {
        corpus = BuildCorpus(opt.corpus_bytes);
        corpus_desc = "seed(tiled to " + std::to_string(opt.corpus_bytes) + " bytes)";
    }

    std::cout << "Benchmark corpus: " << corpus.size() << " bytes (" << corpus_desc
              << "), iterations: " << opt.iters << "\n";
    std::cout << "Decoder        | Throughput |    Decode | Stats\n";
    std::cout << "---------------------------------------------------------------\n";

    const auto xr = RunXendiza(corpus, opt.iters);
    PrintResult(xr);

#ifdef XENDIZA_BENCH_WITH_CAPSTONE
    PrintResult(RunCapstone(corpus, opt.iters));
#else
    std::cout << "capstone       | not built (set -DXENDIZA_BENCH_WITH_CAPSTONE=ON)\n";
#endif

#ifdef XENDIZA_BENCH_WITH_ZYDIS
    PrintResult(RunZydis(corpus, opt.iters));
#else
    std::cout << "zydis          | not built (set -DXENDIZA_BENCH_WITH_ZYDIS=ON)\n";
#endif

    return 0;
}

// Differential oracle for the unprefixed x64 VEX fast path.
//
// The oracle replays the pre-optimization sequence explicitly: general x64
// VEX recognition (VexRecognizer::Recognize), status-to-error mapping, then
// the shared VexDecoder::Decode. For buffers beginning with C4/C5 it must
// produce a complete DecodedInstruction identical to the public xendiza::Disasm<64>
// entry, which now dispatches directly to the fast path. Covering every C5
// second byte and every C4 second/third-byte pair, at full and every truncated
// length, catches field-mapping, legality, and truncation-order drift between
// direct recognition and the general prefix-aware recognizer.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <gsl/span>

#include <xendiza/detail/instruction.hpp>
#include <xendiza/detail/vex.hpp>
#include <xendiza/detail/vex_decode.hpp>
#include <xendiza/xendiza.hpp>

namespace xendiza {
namespace {

using detail::ERR_INSUFFICIENT_BUFFER;
using detail::ERR_UNDEFINED_INSTRUCTION;
using detail::VexDecoder;
using detail::VexRecognizer;
using detail::VexStatus;

constexpr size_t kVectorLength = 15;

// Fixed trailing bytes after the VEX prefix: one opcode, a ModR/M with SIB
// (mod=10, rm=100), the SIB byte, then ample displacement/immediate bytes so
// any legal form can reach its full length.
constexpr std::array<uint8_t, kVectorLength - 1> kTrailing = {
    0x59, 0xA4, 0x24, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB
};

// Replays the old general-recognition + shared-decode sequence for a buffer
// that begins with C4/C5. Never returns NotVex for this input class.
auto OracleDecode64(const gsl::span<const uint8_t> buffer) -> DecodedInstruction
{
    const auto [status, info] = VexRecognizer::Recognize(buffer, true, 64);
    switch (status) {
    case VexStatus::Valid:
        return VexDecoder::Decode(buffer, info);
    case VexStatus::NeedMore:
        return ERR_INSUFFICIENT_BUFFER;
    case VexStatus::Invalid:
        return ERR_UNDEFINED_INSTRUCTION;
    case VexStatus::NotVex:
        break;
    }
    ADD_FAILURE() << "oracle: NotVex for C4/C5-first buffer";
    return ERR_UNDEFINED_INSTRUCTION;
}

auto HexBytes(const gsl::span<const uint8_t> buffer) -> std::string
{
    std::ostringstream os;
    for (const auto b : buffer) {
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << ' ';
    }
    return os.str();
}

void ExpectCompleteResultMatch(const std::array<uint8_t, kVectorLength>& full,
                               const size_t size)
{
    const gsl::span<const uint8_t> input(full.data(), size);

    const auto oracle = OracleDecode64(input);
    const auto direct = Disasm<64>(input);

    const bool match = direct.length == oracle.length
        && direct.instrId.opcode == oracle.instrId.opcode
        && direct.instrId.operand_count == oracle.instrId.operand_count
        && direct.instrId.operands.operand == oracle.instrId.operands.operand;
    if (match) {
        return;
    }

    // Failure path only: dump the input and both complete results.
    ADD_FAILURE() << "mismatch for input=" << HexBytes(input)
        << " oracle={length=" << static_cast<int>(oracle.length)
        << " opcode=" << static_cast<int>(oracle.instrId.opcode)
        << " operands=" << static_cast<int>(oracle.instrId.operand_count) << "}"
        << " direct={length=" << static_cast<int>(direct.length)
        << " opcode=" << static_cast<int>(direct.instrId.opcode)
        << " operands=" << static_cast<int>(direct.instrId.operand_count) << "}";
}

// Every truncated length must match too: recognition-order differences
// (e.g. INSUFFICIENT_BUFFER vs a later decode error) show up exactly here.
void ExpectAllTruncations(const std::array<uint8_t, kVectorLength>& full)
{
    for (size_t size = 1; size <= kVectorLength; ++size) {
        ExpectCompleteResultMatch(full, size);
    }
}

TEST(VexDirectDispatch, C5SecondByteExhaustive)
{
    for (unsigned second = 0; second < 256; ++second) {
        std::array<uint8_t, kVectorLength> full{};
        full[0] = 0xC5;
        full[1] = static_cast<uint8_t>(second);
        for (size_t i = 0; i < kTrailing.size(); ++i) {
            full[2 + i] = kTrailing[i];
        }
        ExpectAllTruncations(full);
    }
}

TEST(VexDirectDispatch, C4SecondThirdBytesExhaustive)
{
    for (unsigned second = 0; second < 256; ++second) {
        for (unsigned third = 0; third < 256; ++third) {
            std::array<uint8_t, kVectorLength> full{};
            full[0] = 0xC4;
            full[1] = static_cast<uint8_t>(second);
            full[2] = static_cast<uint8_t>(third);
            for (size_t i = 0; i < kTrailing.size(); ++i) {
                full[3 + i] = kTrailing[i];
            }
            ExpectAllTruncations(full);
        }
    }
}

} // namespace
} // namespace xendiza

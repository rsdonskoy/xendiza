#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/detail/instruction.hpp>
#include <xendiza/detail/opcode_id.hpp>
#include <xendiza/xendiza_c.h>
#include <xendiza/xendiza.hpp>

namespace xendiza {

namespace {

auto Disasm64(const std::array<uint8_t, 16>& code, size_t n) noexcept -> DecodedInstruction
{
    return Disasm<64>(gsl::span<const uint8_t>(code.data(), n));
}

auto Disasm32(const std::array<uint8_t, 16>& code, size_t n) noexcept -> DecodedInstruction
{
    return Disasm<32>(gsl::span<const uint8_t>(code.data(), n));
}

} // namespace

TEST(VexA0, VzeroUpper64)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF8, 0x77 };
    auto r = Disasm64(code, 3);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VZEROUPPER);
    EXPECT_EQ(r.instrId.operand_count, 0);
    EXPECT_EQ(r.length, 3);
}

TEST(VexA0, VzeroUpper64_ThreeByte)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE1, 0x78, 0x77 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VZEROUPPER);
    EXPECT_EQ(r.length, 4);
}

TEST(VexA0, VzeroAll64)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xFC, 0x77 };
    auto r = Disasm64(code, 3);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VZEROALL);
    EXPECT_EQ(r.length, 3);
}

TEST(VexA0, VzeroUpperWithAddressSize64)
{
    std::array<uint8_t, 16> code{ 0x67, 0xC5, 0xF8, 0x77 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VZEROUPPER);
    EXPECT_EQ(r.length, 4);
}

TEST(VexA0, VzeroUpper32)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF8, 0x77 };
    auto r = Disasm32(code, 3);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VZEROUPPER);
    EXPECT_EQ(r.length, 3);
}

TEST(VexA0, VmovupsLoad32)
{
    // mod=00 rm=101 -> [disp32].
    std::array<uint8_t, 16> code{ 0xC5, 0xF8, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm32(code, 8);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VMOVUPS);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(r.length, 8);
}

TEST(VexA0, VmovupsLoad32_16BitAddressing)
{
    // 67 C5 F8 10 06 34 12 -> 16-bit addressing with disp16.
    std::array<uint8_t, 16> code{ 0x67, 0xC5, 0xF8, 0x10, 0x06, 0x34, 0x12 };
    auto r = Disasm32(code, 7);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VMOVUPS);
    EXPECT_EQ(r.length, 7);
}

TEST(VexA0, VmovupsLoad64_67)
{
    // In x64, 67 selects 32-bit addressing; mod=00 rm=101 -> disp32.
    std::array<uint8_t, 16> code{ 0x67, 0xC5, 0xF8, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 9);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VMOVUPS);
    EXPECT_EQ(r.length, 9);
}

TEST(VexA0, VmovupsTruncated)
{
    // mod=00 rm=101 requires a disp32 that is missing.
    std::array<uint8_t, 16> code{ 0xC5, 0xF8, 0x10, 0x05 };
    auto r32 = Disasm32(code, 4);
    auto r64 = Disasm64(code, 4);
    EXPECT_EQ(r32.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
    EXPECT_EQ(r64.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(VexA0, DisallowedPrefixes)
{
    std::array<uint8_t, 16> code{ 0x66, 0xC5, 0xF8, 0x77 };
    auto r32 = Disasm32(code, 4);
    auto r64 = Disasm64(code, 4);
    EXPECT_EQ(r32.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
    EXPECT_EQ(r64.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(VexA0, LockPrefixRejected)
{
    std::array<uint8_t, 16> code{ 0xF0, 0xC5, 0xF8, 0x77 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(VexA0, RexBeforeVexUndefined64)
{
    // 40 C5 F8 77 in x64: REX immediately before VEX is undefined.
    std::array<uint8_t, 16> code{ 0x40, 0xC5, 0xF8, 0x77 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(VexA0, RexBeforeVexIsInc32)
{
    // 40 C5 F8 77 in x86: 40 is INC EAX, C5 F8 77 is VZEROUPPER.
    std::array<uint8_t, 16> code{ 0x40, 0xC5, 0xF8, 0x77 };
    auto r = Disasm32(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INC);
    EXPECT_EQ(r.length, 1);
}

TEST(VexA0, C5NotVexWhenModNot11In32)
{
    // C5 00 in 32-bit: second byte mod=00 -> legacy path (LES/LDS invalid short).
    std::array<uint8_t, 16> code{ 0xC5, 0x00 };
    auto r = Disasm32(code, 2);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(r.length, 1);
}

TEST(VexA0, C4C5LoneInsufficientBuffer32)
{
    std::array<uint8_t, 16> code{ 0xC4 };
    auto r = Disasm32(code, 1);
    EXPECT_EQ(r.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(VexA0, CApiParity)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF8, 0x77 };
    auto cpp = Disasm<64>(gsl::span<const uint8_t>(code.data(), 3));
    auto c = xendiza_disasm64(code.data(), 3);
    EXPECT_EQ(c.length, cpp.length);
    EXPECT_EQ(c.opcode, static_cast<uint16_t>(cpp.instrId.opcode));
    EXPECT_EQ(c.operand_count, cpp.instrId.operand_count);
}

TEST(VexA0, NoModrmRejectsNonReservedVvvv)
{
    constexpr std::array<uint8_t, 16> upper{ 0xC5, 0xF0, 0x77 };
    constexpr std::array<uint8_t, 16> all{ 0xC5, 0xF4, 0x77 };
    for (const auto& code : { upper, all }) {
        const auto r32 = Disasm32(code, 3);
        const auto r64 = Disasm64(code, 3);
        const auto c32 = xendiza_disasm32(code.data(), 3);
        const auto c64 = xendiza_disasm64(code.data(), 3);
        EXPECT_EQ(r32.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
        EXPECT_EQ(r64.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
        EXPECT_EQ(c32.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
        EXPECT_EQ(c64.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
    }
}

} // namespace xendiza

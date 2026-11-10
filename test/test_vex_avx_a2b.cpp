#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/detail/instruction.hpp>
#include <xendiza/detail/opcode_id.hpp>
#include <xendiza/xendiza.hpp>

namespace xendiza {

namespace {

auto Disasm64(const std::array<uint8_t, 16>& code, size_t n) noexcept -> DecodedInstruction
{
    return Disasm<64>(gsl::span<const uint8_t>(code.data(), n));
}

} // namespace

TEST(VexA2b, Vroundps128)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x79, 0x08, 0xC2, 0x00 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VROUNDPS);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
}

TEST(VexA2b, Vroundps256)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x7D, 0x08, 0xC2, 0x00 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VROUNDPS);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
}

TEST(VexA2b, Vroundss)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x71, 0x0A, 0xC2, 0x00 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VROUNDSS);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 4);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[3], Operand::imm8);
}

TEST(VexA2b, VdppsMem)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x71, 0x40, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VDPPS);
    EXPECT_EQ(r.length, 10);
    EXPECT_EQ(r.instrId.operand_count, 4);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::m128);
    EXPECT_EQ(r.instrId.operands.operand[3], Operand::imm8);
}

TEST(VexA2b, Vblendps)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x71, 0x0C, 0xC2, 0x00 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VBLENDPS);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 4);
}

TEST(VexA2b, VblendvpsReg)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x71, 0x4A, 0xC2, 0x20 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VBLENDVPS);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 4);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[3], Operand::xmm);
}

TEST(VexA2b, VblendvpsMem)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x71, 0x4A, 0x05, 0x00, 0x00, 0x00, 0x00, 0x20 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VBLENDVPS);
    EXPECT_EQ(r.length, 10);
    EXPECT_EQ(r.instrId.operand_count, 4);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::m128);
    EXPECT_EQ(r.instrId.operands.operand[3], Operand::xmm);
}

TEST(VexA2b, Vblendvpd256)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x75, 0x4B, 0xC2, 0x20 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VBLENDVPD);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 4);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[3], Operand::ymm);
}

TEST(VexA2b, Vpblendvb)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x71, 0x4C, 0xC2, 0x20 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPBLENDVB);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 4);
}

TEST(VexA2b, Vperm2f128)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x75, 0x06, 0xC2, 0x00 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPERM2F128);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 4);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[3], Operand::imm8);
}

TEST(VexA2b, Vextractf128)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x7D, 0x19, 0xC2, 0x00 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VEXTRACTF128);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::ymm);
}

TEST(VexA2b, Vinsertf128Mem)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0x75, 0x18, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VINSERTF128);
    EXPECT_EQ(r.length, 10);
    EXPECT_EQ(r.instrId.operand_count, 4);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::m128);
}

TEST(VexA2b, VpermqImm)
{
    // VPERMQ is non-NDS; VEX.vvvv must be 1111 (byte3 = FD).
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0xFD, 0x00, 0xC2, 0x00 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPERMQ);
    EXPECT_EQ(r.length, 6);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
}

TEST(VexA2b, VpermpdImmMem)
{
    // VPERMPD is non-NDS; VEX.vvvv must be 1111 (byte3 = FD).
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0xFD, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPERMPD);
    EXPECT_EQ(r.length, 10);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
}

TEST(VexA2b, VpermqW0Rejected)
{
    // VPERMQ requires W=1; W=0 is undefined.
    std::array<uint8_t, 16> code{ 0xC4, 0xE3, 0xED, 0x00, 0xC2, 0x00 };
    auto r = Disasm64(code, 6);
    EXPECT_EQ(r.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

} // namespace xendiza

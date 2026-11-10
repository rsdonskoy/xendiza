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

TEST(VexA2a, Vpshufb128)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x71, 0x00, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPSHUFB);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
}

TEST(VexA2a, Vpermilps256)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x75, 0x0C, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPERMILPS);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::ymm);
}

TEST(VexA2a, VtestpsMem128)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x79, 0x0E, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 9);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VTESTPS);
    EXPECT_EQ(r.length, 9);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
}

TEST(VexA2a, Vpmovsxbw256)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x7D, 0x20, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPMOVSXBW);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
}

TEST(VexA2a, Vpbroadcastd256)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x7D, 0x58, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPBROADCASTD);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
}

TEST(VexA2a, VpermpsW0)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x75, 0x16, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPERMPS);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
}

TEST(VexA2a, VpermdW0)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x75, 0x36, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPERMD);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
}

TEST(VexA2a, VpmaskmovdMem)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x71, 0x8C, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 9);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPMASKMOVD);
    EXPECT_EQ(r.length, 9);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::m128);
}

TEST(VexA2a, Vphminposuw)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x79, 0x41, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPHMINPOSUW);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 2);
}

TEST(VexA2a, Vbroadcasti128)
{
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x7D, 0x5A, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 9);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VBROADCASTI128);
    EXPECT_EQ(r.length, 9);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
}

TEST(VexA2a, VpsrlvqW1)
{
    // VPSRLVQ: W=1 selects the Q form.
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0xF5, 0x45, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPSRLVQ);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 3);
}

TEST(VexA2a, VpsllvqW1)
{
    // VPSLLVQ: W=1 selects the Q form.
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0xF5, 0x47, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPSLLVQ);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 3);
}

TEST(VexA2a, VpsravqW1Invalid)
{
    // VPSRAVQ is not an AVX2 instruction (introduced in AVX-512); W=1 on
    // opcode 0x46 is undefined.
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0xF5, 0x46, 0xC2 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.length, 0xE2); // ERR_UNDEFINED_INSTRUCTION
}

} // namespace xendiza

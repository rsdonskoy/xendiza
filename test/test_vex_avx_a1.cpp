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

auto Disasm32(const std::array<uint8_t, 16>& code, size_t n) noexcept -> DecodedInstruction
{
    return Disasm<32>(gsl::span<const uint8_t>(code.data(), n));
}

} // namespace

TEST(VexA1, VaddpsReg128)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF0, 0x58, 0xC2 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VADDPS);
    EXPECT_EQ(r.length, 4);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
}

TEST(VexA1, VaddpsMem128)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF0, 0x58, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 8);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VADDPS);
    EXPECT_EQ(r.length, 8);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::m128);
}

TEST(VexA1, VaddpsReg256)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF4, 0x58, 0xC2 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VADDPS);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::ymm);
}

TEST(VexA1, VaddssScalar)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF2, 0x58, 0xC2 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VADDSS);
    EXPECT_EQ(r.length, 4);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
}

TEST(VexA1, VmovupsStore128)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF8, 0x11, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 8);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VMOVUPS);
    EXPECT_EQ(r.length, 8);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::m128);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
}

TEST(VexA1, VmovapsLoad256)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xFC, 0x28, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 8);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VMOVAPS);
    EXPECT_EQ(r.length, 8);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m256);
}

TEST(VexA1, VcmppsImm)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF0, 0xC2, 0xC2, 0x01 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VCMPPS);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 4);
    EXPECT_EQ(r.instrId.operands.operand[3], Operand::imm8);
}

TEST(VexA1, Vshufpd256)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xED, 0xC6, 0xC2, 0x03 };
    auto r = Disasm64(code, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VSHUFPD);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.operand_count, 4);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[3], Operand::imm8);
}

TEST(VexA1, Vpaddb128)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF1, 0xFC, 0xC2 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPADDB);
    EXPECT_EQ(r.length, 4);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
}

TEST(VexA1, Vpaddb256)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF5, 0xFC, 0xC2 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPADDB);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::ymm);
}

TEST(VexA1, VpshufdMem)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF9, 0x70, 0x05, 0x00, 0x00, 0x00, 0x00, 0x1B };
    auto r = Disasm64(code, 9);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPSHUFD);
    EXPECT_EQ(r.length, 9);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
}

TEST(VexA1, Vpmovmskb)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF9, 0xD7, 0xC2 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPMOVMSKB);
    EXPECT_EQ(r.length, 4);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
}

TEST(VexA1, Vucomiss)
{
    std::array<uint8_t, 16> code{ 0xC5, 0xF8, 0x2E, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 8);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VUCOMISS);
    EXPECT_EQ(r.length, 8);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32);
}

TEST(VexA1, ScalarLigAcceptsL1)
{
    // VADDSS is LIG: L=1 is accepted and retains scalar XMM operands.
    std::array<uint8_t, 16> code{ 0xC5, 0xF6, 0x58, 0xC2 };
    for (auto r : { Disasm32(code, 4), Disasm64(code, 4) }) {
        EXPECT_EQ(r.instrId.opcode, OpcodeId::VADDSS);
        EXPECT_EQ(r.length, 4);
        ASSERT_EQ(r.instrId.operand_count, 3);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
    }
}

TEST(VexA1, VmovssRegMerge)
{
    // VMOVSS xmm0, xmm1, xmm2 (register NDS merge form).  pp=F3, vvvv=~1=0xE.
    std::array<uint8_t, 16> code{ 0xC5, 0xF2, 0x10, 0xC2 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VMOVSS);
    EXPECT_EQ(r.length, 4);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
}

TEST(VexA1, VmovssMemLoad)
{
    // VMOVSS xmm0, m32 (vvvv must be reserved).
    std::array<uint8_t, 16> code{ 0xC5, 0xFA, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 8);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VMOVSS);
    EXPECT_EQ(r.length, 8);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32);
}

TEST(VexA1, VmovssMemStore)
{
    // VMOVSS m32, xmm0.
    std::array<uint8_t, 16> code{ 0xC5, 0xFA, 0x11, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 8);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VMOVSS);
    EXPECT_EQ(r.length, 8);
    EXPECT_EQ(r.instrId.operand_count, 2);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
}

TEST(VexA1, VmovssMemFormWithNonReservedVvvv)
{
    // VMOVSS m32, xmm0 with vvvv != 1111 is undefined.
    std::array<uint8_t, 16> code{ 0xC5, 0xF2, 0x11, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 8);
    EXPECT_EQ(r.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(VexA1, VmovsdRegMerge)
{
    // VMOVSD xmm0, xmm1, xmm2.
    std::array<uint8_t, 16> code{ 0xC5, 0xF3, 0x10, 0xC2 };
    auto r = Disasm64(code, 4);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VMOVSD);
    EXPECT_EQ(r.length, 4);
    EXPECT_EQ(r.instrId.operand_count, 3);
}

TEST(VexA1, ScalarMoveOpcode11RegMerge)
{
    constexpr std::array<uint8_t, 16> movss{ 0xC5, 0xCA, 0x11, 0xC1 };
    constexpr std::array<uint8_t, 16> movsd{ 0xC5, 0xCB, 0x11, 0xC1 };
    for (const auto& code : { movss, movsd }) {
        for (const auto& r : { Disasm32(code, 4), Disasm64(code, 4) }) {
            EXPECT_EQ(r.instrId.opcode, code[1] == 0xCA ? OpcodeId::VMOVSS : OpcodeId::VMOVSD);
            EXPECT_EQ(r.length, 4);
            ASSERT_EQ(r.instrId.operand_count, 3);
            EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
            EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
            EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
        }
    }
}

} // namespace xendiza

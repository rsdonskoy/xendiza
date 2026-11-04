// test_2byte_opcodes.cpp
// Tests for 0x0F two-byte opcode decode paths.

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/xendiza_x64.hpp>

using namespace xendiza;
using namespace xendiza::detail;

template <size_t N>
static DecodedInstruction Disasm(const std::array<uint8_t, N>& buf)
{
    return X64Traits::Disasm(gsl::span<const uint8_t>(buf.data(), N));
}

TEST(TwoByteOpcodeTest, JZ_0F84_rel32)
{
    auto result = Disasm(std::array<uint8_t, 6>{0x0F, 0x84, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JZ);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel32);
    EXPECT_EQ(result.length, 6);
}

TEST(TwoByteOpcodeTest, Jcc_0F80_0F8F_all_conditions)
{
    const std::array<OpcodeId, 16> expected = {
        OpcodeId::JO,  OpcodeId::JNO, OpcodeId::JB,  OpcodeId::JAE,
        OpcodeId::JZ,  OpcodeId::JNZ, OpcodeId::JBE, OpcodeId::JA,
        OpcodeId::JS,  OpcodeId::JNS, OpcodeId::JP,  OpcodeId::JNP,
        OpcodeId::JL,  OpcodeId::JGE, OpcodeId::JLE, OpcodeId::JG,
    };

    for (uint8_t i = 0; i < expected.size(); ++i) {
        const auto opcode = static_cast<uint8_t>(0x80 + i);
        auto result = Disasm(std::array<uint8_t, 6>{0x0F, opcode, 0x00, 0x00, 0x00, 0x00});
        EXPECT_EQ(result.instrId.opcode, expected[i]) << "0F " << std::hex << static_cast<int>(opcode);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel32);
        EXPECT_EQ(result.length, 6);
    }
}

TEST(TwoByteOpcodeTest, CMOVcc_0F40_0F4F_all_conditions_modrm_reg)
{
    const std::array<OpcodeId, 16> expected = {
        OpcodeId::CMOVO,  OpcodeId::CMOVNO, OpcodeId::CMOVB,  OpcodeId::CMOVAE,
        OpcodeId::CMOVZ,  OpcodeId::CMOVNZ, OpcodeId::CMOVBE, OpcodeId::CMOVA,
        OpcodeId::CMOVS,  OpcodeId::CMOVNS, OpcodeId::CMOVP,  OpcodeId::CMOVNP,
        OpcodeId::CMOVL,  OpcodeId::CMOVGE, OpcodeId::CMOVLE, OpcodeId::CMOVG,
    };

    for (uint8_t i = 0; i < expected.size(); ++i) {
        const auto opcode = static_cast<uint8_t>(0x40 + i);
        auto result = Disasm(std::array<uint8_t, 3>{0x0F, opcode, 0xC1});
        EXPECT_EQ(result.instrId.opcode, expected[i]) << "0F " << std::hex << static_cast<int>(opcode);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
        EXPECT_EQ(result.length, 3);
    }
}

TEST(TwoByteOpcodeTest, SETcc_0F90_0F9F_all_conditions_modrm_reg)
{
    const std::array<OpcodeId, 16> expected = {
        OpcodeId::SETO,  OpcodeId::SETNO, OpcodeId::SETB,  OpcodeId::SETAE,
        OpcodeId::SETZ,  OpcodeId::SETNZ, OpcodeId::SETBE, OpcodeId::SETA,
        OpcodeId::SETS,  OpcodeId::SETNS, OpcodeId::SETP,  OpcodeId::SETNP,
        OpcodeId::SETL,  OpcodeId::SETGE, OpcodeId::SETLE, OpcodeId::SETG,
    };

    for (uint8_t i = 0; i < expected.size(); ++i) {
        const auto opcode = static_cast<uint8_t>(0x90 + i);
        auto result = Disasm(std::array<uint8_t, 3>{0x0F, opcode, 0xC0});
        EXPECT_EQ(result.instrId.opcode, expected[i]) << "0F " << std::hex << static_cast<int>(opcode);
        EXPECT_EQ(result.instrId.operand_count, 1);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
        EXPECT_EQ(result.length, 3);
    }
}

TEST(TwoByteOpcodeTest, IMUL_0FAF_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAF, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, IMUL_0FAF_REXW_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xAF, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, CMOVZ_0F44_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x44, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMOVZ);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, CMOVZ_0F44_Prefix66_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x44, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMOVZ);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, BSF_0FBC_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xBC, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BSF);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, TZCNT_F30FBC_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xBC, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::TZCNT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, BSR_0FBD_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xBD, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BSR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, LZCNT_F30FBD_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xBD, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LZCNT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, POPCNT_F30FB8_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xB8, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POPCNT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, POPCNT_F3_REXW_0FB8_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 5>{0xF3, 0x48, 0x0F, 0xB8, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POPCNT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 5);
}

TEST(TwoByteOpcodeTest, POPCNT_F3_66_0FB8_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 5>{0xF3, 0x66, 0x0F, 0xB8, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POPCNT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 5);
}

TEST(TwoByteOpcodeTest, POPCNT_0FB8_without_F3_invalid)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB8, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, BufferTooShort_AfterEscape)
{
    auto result = Disasm(std::array<uint8_t, 1>{0x0F});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(TwoByteOpcodeTest, MOVUPS_0F10_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x10, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVUPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVUPS_0F10_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x10, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVUPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVUPS_0F11_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x11, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVUPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m128);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, UCOMISS_0F2E_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x2E, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::UCOMISS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, COMISS_0F2F_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x2F, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::COMISS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, SIMD_0F10_66_prefix_MOVUPD)
{
    // Full SSE1/SSE2 scope: 66 0F 10 is MOVUPD (no longer the P2.4 rejection).
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x10, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVUPD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SIMD_0F2E_F3_prefix_is_invalid)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0x2E, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, MOVUPS_0F10_SIB_base5_disp32_length)
{
    auto result = Disasm(std::array<uint8_t, 8>{0x0F, 0x10, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVUPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 8);
}

TEST(TwoByteOpcodeTest, MOVAPS_0F28_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x28, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVAPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVAPS_0F28_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x28, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVAPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVAPS_0F29_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x29, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVAPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m128);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, UCOMISD_660F2E_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x2E, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::UCOMISD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, COMISD_660F2F_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x2F, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::COMISD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SIMD_0F11_66_prefix_MOVUPD_store)
{
    // Full SSE1/SSE2 scope: 66 0F 11 is the MOVUPD store (P2.4 rejected it).
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x11, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVUPD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SIMD_0F10_11_scalar_and_packed_variants)
{
    // F2 0F 10 /r -> MOVSD xmm, m64 (the largest single diff-harness gap).
    {
        auto result = Disasm(std::array<uint8_t, 9>{0xF2, 0x0F, 0x10, 0x2C, 0x25, 0xF8, 0xFF, 0xFF, 0xFF});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVSD);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::m64);
        EXPECT_EQ(result.length, 9);
    }
    // F3 0F 10 /r -> MOVSS xmm, m32.
    {
        auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0x10, 0x01});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVSS);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
        EXPECT_EQ(result.length, 4);
    }
    // F2 0F 11 /r (mem) -> MOVSD m64, xmm (store direction).
    {
        auto result = Disasm(std::array<uint8_t, 4>{0xF2, 0x0F, 0x11, 0x01});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVSD);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
        EXPECT_EQ(result.length, 4);
    }
    // 66 0F 29 (mem) -> MOVAPD m128, xmm; 66 0F 28 -> MOVAPD xmm, m128.
    {
        auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x28, 0x01});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVAPD);
        EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    }
    {
        auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x29, 0x01});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVAPD);
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::m128);
    }
    // F2/F3 on 0F 28 are absent variants (aligned moves have no scalar form).
    {
        auto result = Disasm(std::array<uint8_t, 4>{0xF2, 0x0F, 0x28, 0xC1});
        EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
    }
}

TEST(TwoByteOpcodeTest, ADDPS_0F58_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x58, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADDPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, ADDPD_660F58_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x58, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADDPD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, ADDSS_F30F58_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0x58, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADDSS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, ADDSD_F20F58_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF2, 0x0F, 0x58, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADDSD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, ADDPS_0F58_SIB_base5_disp32_length)
{
    auto result = Disasm(std::array<uint8_t, 8>{0x0F, 0x58, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADDPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 8);
}

TEST(TwoByteOpcodeTest, ADD_0F58_mixed_prefix_66_and_F3_invalid)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x66, 0xF3, 0x0F, 0x58, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, MULPS_0F59_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x59, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MULPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MULPD_660F59_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x59, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MULPD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MULSS_F30F59_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0x59, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MULSS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MULSD_F20F59_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF2, 0x0F, 0x59, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MULSD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SUBPS_0F5C_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x5C, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SUBPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, SUBPD_660F5C_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x5C, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SUBPD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SUBSS_F30F5C_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0x5C, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SUBSS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SUBSD_F20F5C_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF2, 0x0F, 0x5C, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SUBSD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, DIVPS_0F5E_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x5E, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DIVPS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::xmm);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, DIVPD_660F5E_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x5E, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DIVPD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m128);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, DIVSS_F30F5E_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0x5E, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DIVSS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, DIVSD_F20F5E_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF2, 0x0F, 0x5E, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::DIVSD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, ReservedOrIllegalOpcode_0FFF)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xFF, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// ---------------------------------------------------------------------------
// MOVZX  0F B6  Gv, Eb  (zero-extend byte → 16/32/64)
// ---------------------------------------------------------------------------

TEST(TwoByteOpcodeTest, MOVZX_0FB6_modrm_mem)
{
    // 0F B6 01  ->  movzx eax, byte ptr [rcx]  (mod=00, rm=001)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB6, 0x01});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::m8);
    EXPECT_EQ(result.instrId.operand_count,        2);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVZX_0FB6_modrm_reg)
{
    // 0F B6 C1  ->  movzx eax, cl  (mod=11, reg=000, rm=001)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB6, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r8);
    EXPECT_EQ(result.instrId.operand_count,        2);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVZX_0FB6_REXW_modrm_reg)
{
    // 48 0F B6 C1  ->  movzx rax, cl
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xB6, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MOVZX_0FB6_Prefix66_modrm_reg)
{
    // 66 0F B6 C1  ->  movzx ax, cl
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xB6, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MOVZX_0FB6_REXB_stays_abstract)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x41, 0x0F, 0xB6, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r8);
    EXPECT_EQ(result.length, 4);
}

// ---------------------------------------------------------------------------
// MOVZX  0F B7  Gv, Ew  (zero-extend word → 32/64)
// ---------------------------------------------------------------------------

TEST(TwoByteOpcodeTest, MOVZX_0FB7_modrm_mem)
{
    // 0F B7 01  ->  movzx eax, word ptr [rcx]
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB7, 0x01});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::m16);
    EXPECT_EQ(result.instrId.operand_count,        2);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVZX_0FB7_modrm_reg)
{
    // 0F B7 C1  ->  movzx eax, cx
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB7, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r16);
    EXPECT_EQ(result.instrId.operand_count,        2);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVZX_0FB7_REXW_modrm_reg)
{
    // 48 0F B7 C1  ->  movzx rax, cx
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xB7, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MOVZX_0FB7_REXWB_stays_abstract)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x49, 0x0F, 0xB7, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVZX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r16);
    EXPECT_EQ(result.length, 4);
}

// ---------------------------------------------------------------------------
// MOVSX  0F BE  Gv, Eb  (sign-extend byte → 16/32/64)
// ---------------------------------------------------------------------------

TEST(TwoByteOpcodeTest, MOVSX_0FBE_modrm_mem)
{
    // 0F BE 01  ->  movsx eax, byte ptr [rcx]
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xBE, 0x01});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::m8);
    EXPECT_EQ(result.instrId.operand_count,        2);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVSX_0FBE_modrm_reg)
{
    // 0F BE C1  ->  movsx eax, cl
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xBE, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r8);
    EXPECT_EQ(result.instrId.operand_count,        2);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVSX_0FBE_REXW_modrm_reg)
{
    // 48 0F BE C1  ->  movsx rax, cl
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xBE, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MOVSX_0FBE_Prefix66_modrm_reg)
{
    // 66 0F BE C1  ->  movsx ax, cl
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xBE, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MOVSX_0FBE_REXB_stays_abstract)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x41, 0x0F, 0xBE, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r8);
    EXPECT_EQ(result.length, 4);
}

// ---------------------------------------------------------------------------
// MOVSX  0F BF  Gv, Ew  (sign-extend word → 32/64)
// ---------------------------------------------------------------------------

TEST(TwoByteOpcodeTest, MOVSX_0FBF_modrm_mem)
{
    // 0F BF 01  ->  movsx eax, word ptr [rcx]
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xBF, 0x01});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::m16);
    EXPECT_EQ(result.instrId.operand_count,        2);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVSX_0FBF_modrm_reg)
{
    // 0F BF C1  ->  movsx eax, cx
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xBF, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r16);
    EXPECT_EQ(result.instrId.operand_count,        2);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVSX_0FBF_REXW_modrm_reg)
{
    // 48 0F BF C1  ->  movsx rax, cx
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xBF, 0xC1});
    EXPECT_EQ(result.instrId.opcode,               OpcodeId::MOVSX);
    EXPECT_EQ(result.instrId.operands.operand[0],  Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1],  Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, CMPXCHG_0FB0_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB0, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMPXCHG);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, CMPXCHG_0FB0_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMPXCHG);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, CMPXCHG_0FB1_REXW_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xB1, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMPXCHG);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, CMPXCHG_0FB1_Prefix66_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xB1, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMPXCHG);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, XADD_0FC0_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC0, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, XADD_0FC0_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC0, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, XADD_0FC1_REXW_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xC1, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, XADD_0FC1_Prefix66_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xC1, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MOVNTI_0FC3_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC3, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVNTI);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MOVNTI_0FC3_REXW_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xC3, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVNTI);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MOVNTI_660FC3_no_operand_size_change)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xC3, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVNTI);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, MOVNTI_0FC3_modrm_reg_invalid)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xC3, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, MOVNTI_0FC3_SIB_base5_disp32_length)
{
    auto result = Disasm(std::array<uint8_t, 8>{0x0F, 0xC3, 0x04, 0x85, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVNTI);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 8);
}

TEST(TwoByteOpcodeTest, BT_0FA3_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xA3, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BT_0FA3_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xA3, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BT_0FA3_REXW_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xA3, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, BTS_0FAB_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAB, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BTS_0FAB_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAB, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BTS_0FAB_Prefix66_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xAB, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, BTR_0FB3_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB3, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BTR_0FB3_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB3, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BTR_0FB3_REXW_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xB3, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, BTC_0FBB_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xBB, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BTC_0FBB_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xBB, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BTC_0FBB_Prefix66_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xBB, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SETO_0F90_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x90, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SETO);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, SETO_0F90_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x90, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SETO);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, SETNZ_0F95_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x95, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SETNZ);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, SETNZ_0F95_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x95, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SETNZ);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, SETNZ_0F95_Prefix66_no_operand_size_effect)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0x95, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SETNZ);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SETNZ_0F95_REXW_no_operand_size_effect)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0x95, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SETNZ);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SETNZ_0F95_REXB_stays_abstract)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x41, 0x0F, 0x95, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SETNZ);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, BT_0FBA_slash4_imm8_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xBA, 0xE0, 0x7F});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, BT_0FBA_slash4_imm8_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xBA, 0x21, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, BTS_0FBA_slash5_imm8_REXW_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x48, 0x0F, 0xBA, 0xE9, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 5);
}

TEST(TwoByteOpcodeTest, BTR_0FBA_slash6_imm8_Prefix66_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x66, 0x0F, 0xBA, 0xF1, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 5);
}

TEST(TwoByteOpcodeTest, BTC_0FBA_slash7_imm8_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xBA, 0x39, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BTC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, OpcodeExt_0FBA_invalid_slash0)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xBA, 0xC1, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, BSWAP_0FC8_default)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BSWAP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, BSWAP_0FC9_default)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0xC9});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BSWAP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, BSWAP_0FC8_REXW)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x48, 0x0F, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BSWAP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BSWAP_0FC8_Prefix66_no_operand_size_effect)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x66, 0x0F, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::BSWAP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, BSWAP_0FC8_0FCF_all_opcodes)
{
    for (uint8_t i = 0; i < 8; ++i) {
        const auto opcode = static_cast<uint8_t>(0xC8 + i);

        auto no_prefix = Disasm(std::array<uint8_t, 2>{0x0F, opcode});
        EXPECT_EQ(no_prefix.instrId.opcode, OpcodeId::BSWAP) << "0F " << std::hex << static_cast<int>(opcode);
        EXPECT_EQ(no_prefix.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(no_prefix.length, 2);

        auto rex_w = Disasm(std::array<uint8_t, 3>{0x48, 0x0F, opcode});
        EXPECT_EQ(rex_w.instrId.opcode, OpcodeId::BSWAP) << "48 0F " << std::hex << static_cast<int>(opcode);
        EXPECT_EQ(rex_w.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(rex_w.length, 3);
    }
}

TEST(TwoByteOpcodeTest, NOP_0F1F_slash0_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x1F, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, NOP_0F1F_slash0_modrm_with_disp8)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0x1F, 0x40, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, NOP_0F1F_slash0_REXW)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0x1F, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, NOP_0F1F_invalid_slash1)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x1F, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, SYSCALL_0F05)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x05});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SYSCALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, CLTS_0F06)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x06});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLTS);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, SYSRET_0F07)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x07});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SYSRET);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, INVD_0F08)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVD);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, WBINVD_0F09)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x09});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::WBINVD);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, WBNOINVD_F30F09)
{
    auto result = Disasm(std::array<uint8_t, 3>{0xF3, 0x0F, 0x09});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::WBNOINVD);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, WBINVD_660F09_still_wbinvd)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x66, 0x0F, 0x09});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::WBINVD);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, EMMS_0F77)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x77});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::EMMS);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, UD_0F0B)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x0B});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::UD);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, RDTSC_0F31)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x31});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RDTSC);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, PUSH_FS_0FA0)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0xA0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::fs);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, POP_FS_0FA1)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0xA1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::fs);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, CPUID_0FA2)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0xA2});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CPUID);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, PREFETCHW_0F0D_slash1_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x0D, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PREFETCHW);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, PREFETCHW_0F0D_slash1_mem_disp8)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0x0D, 0x48, 0x10});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PREFETCHW);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, OpcodeExt_0F0D_invalid_slash0)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x0D, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, OpcodeExt_0F0D_register_form_invalid)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x0D, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, PUSH_GS_0FA8)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0xA8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::gs);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, POP_GS_0FA9)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0xA9});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::POP);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::gs);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, RSM_0FAA)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0xAA});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RSM);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, CPUID_0FA2_REXW_length_only)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x48, 0x0F, 0xA2});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CPUID);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::noopr);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, SHLD_0FA4_imm8_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xA4, 0xC1, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SHLD_0FA4_imm8_REXW_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 5>{0x48, 0x0F, 0xA4, 0x01, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm8);
    EXPECT_EQ(result.length, 5);
}

TEST(TwoByteOpcodeTest, SHLD_0FA5_cl_Prefix66_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xA5, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::cl);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SHRD_0FAC_imm8_modrm_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xAC, 0x01, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHRD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SHRD_0FAD_cl_REXW_modrm_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0x48, 0x0F, 0xAD, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SHRD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r64);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::cl);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, SHLD_0FA4_imm8_insufficient_buffer)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xA4, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

// Tests for newly added instructions

TEST(TwoByteOpcodeTest, LAR_0F02_Gv_Ew_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x02, 0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LAR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, LAR_0F02_Gv_Ew_memory)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x02, 0x03});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LAR);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m16);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, LSL_0F03_Gv_Ew_reg)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0x03, 0xC1});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LSL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, WRMSR_0F30_no_operands)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x30});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::WRMSR);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, RDMSR_0F32_no_operands)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x32});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RDMSR);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, RDPMC_0F33_no_operands)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x33});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RDPMC);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, SYSENTER_0F34_no_operands)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x34});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SYSENTER);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, SYSEXIT_0F35_no_operands)
{
    auto result = Disasm(std::array<uint8_t, 2>{0x0F, 0x35});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SYSEXIT);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 2);
}

TEST(TwoByteOpcodeTest, LSS_0FB2_Gv_M_memory)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB2, 0x03});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LSS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, LFS_0FB4_Gv_M_memory)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB4, 0x03});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LFS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, LGS_0FB5_Gv_M_memory)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xB5, 0x03});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LGS);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, LFENCE_0FAE_reg_fence)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0xE8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LFENCE);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, MFENCE_0FAE_reg_fence)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0xF0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MFENCE);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, SFENCE_0FAE_reg_fence)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0xF8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::SFENCE);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, RDFSBASE_F30FAE_slash0_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xAE, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RDFSBASE);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, RDGSBASE_F3_REXW_0FAE_slash1_reg)
{
    auto result = Disasm(std::array<uint8_t, 5>{0xF3, 0x48, 0x0F, 0xAE, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RDGSBASE);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r64);
    EXPECT_EQ(result.length, 5);
}

TEST(TwoByteOpcodeTest, WRFSBASE_F30FAE_slash2_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xAE, 0xD0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::WRFSBASE);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, WRGSBASE_F30FAE_slash3_reg)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xAE, 0xD8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::WRGSBASE);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, OpcodeExt_0FAE_slash0_reg_without_F3_invalid)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0xC0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, OpcodeExt_F30FAE_slash0_memory_invalid)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xAE, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, CLRSSBSY_F30FAE_slash6_mem)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xAE, 0x30});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLRSSBSY);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, CLRSSBSY_F30FAE_slash6_mem_disp8)
{
    auto result = Disasm(std::array<uint8_t, 5>{0xF3, 0x0F, 0xAE, 0x70, 0x10});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLRSSBSY);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m64);
    EXPECT_EQ(result.length, 5);
}

TEST(TwoByteOpcodeTest, OpcodeExt_F30FAE_slash6_reg_invalid)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xAE, 0xF0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, OpcodeExt_F30FAE_slash7_memory_invalid)
{
    auto result = Disasm(std::array<uint8_t, 4>{0xF3, 0x0F, 0xAE, 0x38});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, CLFLUSH_0FAE_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0x39});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLFLUSH);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, FXSAVE_0FAE_slash0_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FXSAVE);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, FXRSTOR_0FAE_slash1_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FXRSTOR);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, LDMXCSR_0FAE_slash2_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0x10});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LDMXCSR);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, STMXCSR_0FAE_slash3_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0x18});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::STMXCSR);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, XSAVE_0FAE_slash4_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0x20});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XSAVE);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, XRSTOR_0FAE_slash5_mem)
{
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0x28});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XRSTOR);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, CLFLUSHOPT_660FAE_slash7_mem)
{
    // 66 0F AE 39  ->  CLFLUSHOPT [rcx] (/7 memory form with 66h)
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xAE, 0x39});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLFLUSHOPT);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, CLFLUSHOPT_660FAE_slash7_mem_disp8)
{
    // 66 0F AE 79 10  ->  CLFLUSHOPT [rcx+0x10] (/7 memory form with disp8)
    auto result = Disasm(std::array<uint8_t, 5>{0x66, 0x0F, 0xAE, 0x79, 0x10});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLFLUSHOPT);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 5);
}

TEST(TwoByteOpcodeTest, CLWB_660FAE_slash6_mem)
{
    // 66 0F AE 31  ->  CLWB [rcx] (/6 memory form with 66h)
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xAE, 0x31});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLWB);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, XSAVEOPT_0FAE_slash6_mem)
{
    // 0F AE 30  ->  XSAVEOPT [rax] (/6 memory form without 66h)
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0x30});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XSAVEOPT);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, XSAVEOPT_0FAE_slash6_mem_disp8)
{
    // 0F AE 70 7F  ->  XSAVEOPT [rax+0x7F] (/6 with disp8)
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xAE, 0x70, 0x7F});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XSAVEOPT);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 4);
}

TEST(TwoByteOpcodeTest, XSAVEOPT_0FAE_slash6_mem_disp32)
{
    // 0F AE B0 78 56 34 12  ->  XSAVEOPT [rax+0x12345678] (/6 with disp32)
    auto result = Disasm(std::array<uint8_t, 7>{0x0F, 0xAE, 0xB0, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XSAVEOPT);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 7);
}

TEST(TwoByteOpcodeTest, CLWB_660FAE_slash6_mem_disp8)
{
    // 66 0F AE 71 10  ->  CLWB [rcx+0x10] (/6 memory form with disp8)
    auto result = Disasm(std::array<uint8_t, 5>{0x66, 0x0F, 0xAE, 0x71, 0x10});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLWB);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 5);
}

TEST(TwoByteOpcodeTest, OpcodeExt_0FAE_invalid_register_form_reg0)
{
    // 0F AE E0  ->  /0 register form (mod=11, reg=0) - invalid
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0xE0});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, OpcodeExt_0FAE_invalid_register_form_reg4)
{
    // 0F AE E4  ->  /4 register form (mod=11, reg=4) - invalid
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0xE4});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, OpcodeExt_0FAE_invalid_memory_form_slash5)
{
    // 66 0F AE 29  ->  /5 memory form is currently invalid with 66h prefix
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xAE, 0x29});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, OpcodeExt_660FAE_invalid_memory_form_slash5)
{
    // 66 0F AE 29  ->  /5 memory form stays invalid even with 66h prefix
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xAE, 0x29});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, OpcodeExt_0FAE_slash6_mem_is_xsaveopt)
{
    // 0F AE 31  ->  /6 memory form (mod=00, reg=6) - XSAVEOPT without 66h
    auto result = Disasm(std::array<uint8_t, 3>{0x0F, 0xAE, 0x31});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XSAVEOPT);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m);
    EXPECT_EQ(result.length, 3);
}

TEST(TwoByteOpcodeTest, OpcodeExt_0FAE_invalid_memory_form_slash0)
{
    // 66 0F AE 01  ->  /0 memory form is currently invalid with 66h prefix
    auto result = Disasm(std::array<uint8_t, 4>{0x66, 0x0F, 0xAE, 0x01});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(TwoByteOpcodeTest, OpcodeExt_0FAE_valid_CLFLUSH_with_disp8)
{
    // 0F AE 7F 10  ->  CLFLUSH [rdi+0x10] (/7 with disp8, mod=01)
    auto result = Disasm(std::array<uint8_t, 4>{0x0F, 0xAE, 0x7F, 0x10});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CLFLUSH);
    EXPECT_EQ(result.instrId.operand_count, 1);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m8);
    EXPECT_EQ(result.length, 4);
}


TEST(TwoByteOpcodeTest, JZ_0F84_with_66h_stays_rel32_in_x64)
{
    // 64-bit mode ignores 0x66 on near branches (Intel SDM / Zydis default):
    // rel32 stays rel32, length = prefix + opcode + 4.
    auto result = Disasm(std::array<uint8_t, 7>{0x66, 0x0F, 0x84, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JZ);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel32);
    EXPECT_EQ(result.length, 7);
}

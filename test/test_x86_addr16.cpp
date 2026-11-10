// test_x86_addr16.cpp
// 32-bit-mode decode behavior under the 67h address-size prefix: 16-bit
// addressing ModR/M length rules (disp16 at mod=00/rm=110 and mod=10, disp8
// at mod=01, no SIB byte), plain-memory resolution of rm=100, truncation
// reporting, and the x64 counterpart where 67h keeps the 32-bit layout.
// All lengths are total byte counts including the prefix byte itself.

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/xendiza.hpp>

using namespace xendiza;

template <size_t N>
static DecodedInstruction Disasm32(const std::array<uint8_t, N>& buf)
{
    return xendiza::Disasm<32>(gsl::span<const uint8_t>(buf.data(), N));
}

template <size_t N>
static DecodedInstruction Disasm64(const std::array<uint8_t, N>& buf)
{
    return xendiza::Disasm<64>(gsl::span<const uint8_t>(buf.data(), N));
}

static constexpr uint8_t INSUFFICIENT =
    static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER);

// ---------------------------------------------------------------------------
// Requirement: 67h selects 16-bit-addressing ModR/M lengths in 32-bit mode
// ---------------------------------------------------------------------------

TEST(X86Addr16Test, Disp16AtMod00Rm110_Length5)
{
    // 67 8B 06 34 12 → MOV eax, dword ptr [disp16]; true length 5 (was 3).
    // 8B is MOV Gv,Ev: dest = register (class r32), src = memory m32.
    auto result = Disasm32(std::array<uint8_t, 5>{0x67, 0x8B, 0x06, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 5);
}

TEST(X86Addr16Test, Mod10Disp16ReplacesDisp32_Length5)
{
    // 67 8B 86 34 12 78 56 → MOV with disp16; the same ModR/M without 67h
    // encodes disp32 (length 6). Under 67h: 1 + table[0x86]=4 → 5.
    auto result = Disasm32(std::array<uint8_t, 7>{0x67, 0x8B, 0x86, 0x34, 0x12, 0x78, 0x56});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.length, 5);
}

TEST(X86Addr16Test, Mod01Disp8_Length4)
{
    // 67 03 40 08 → ADD eax, dword ptr [bx+di+8]; disp8 form unchanged in size.
    auto result = Disasm32(std::array<uint8_t, 4>{0x67, 0x03, 0x40, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.length, 4);
}

TEST(X86Addr16Test, Rm100IsPlainMemory_NoSibConsumed)
{
    // 67 8B 04 → MOV eax, dword ptr [si]; rm=100 is NOT a SIB escape under
    // 16-bit addressing — length 3, no byte consumed as SIB, plain m32 class
    // (Sib_Mv marker resolved synthetically to the non-stack memory form).
    auto result = Disasm32(std::array<uint8_t, 3>{0x67, 0x8B, 0x04});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32);
    EXPECT_EQ(result.length, 3);
}

TEST(X86Addr16Test, Mod11RegisterForm_Length3)
{
    // 67 03 C1 → ADD r32, r32 (mod=11); register forms are unaffected by 67h.
    // Form tables encode register classes (r32), not specific registers.
    auto result = Disasm32(std::array<uint8_t, 3>{0x67, 0x03, 0xC1});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 3);
}

TEST(X86Addr16Test, TwoByteFamily_Length6)
{
    // 67 0F 10 06 34 12 → MOVUPS xmm0, xmmword ptr [disp16]; length 6.
    auto result = Disasm32(std::array<uint8_t, 6>{0x67, 0x0F, 0x10, 0x06, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOVUPS);
    EXPECT_EQ(result.length, 6);
}

// ---------------------------------------------------------------------------
// Requirement: 67h memory forms report truncation
// ---------------------------------------------------------------------------

TEST(X86Addr16Test, TruncatedDisp16_InsufficientBuffer)
{
    // 67 8B 06 34 → disp16 incomplete → insufficient-buffer (was: success, 3).
    auto result = Disasm32(std::array<uint8_t, 4>{0x67, 0x8B, 0x06, 0x34});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, INSUFFICIENT);
}

TEST(X86Addr16Test, DisplacementCompleteButImmediateMissing_InsufficientBuffer)
{
    // 67 C7 06 34 12 78 56 → disp16 complete, but C7 /0 needs imm32 and only
    // two immediate bytes are present → insufficient-buffer.
    auto result = Disasm32(std::array<uint8_t, 7>{0x67, 0xC7, 0x06, 0x34, 0x12, 0x78, 0x56});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, INSUFFICIENT);
}

// ---------------------------------------------------------------------------
// Requirement: group helpers honor the 16-bit length
// ---------------------------------------------------------------------------

TEST(X86Addr16Test, X87MemoryForm_Length5)
{
    // 67 D8 06 34 12 → FADD st0, dword ptr [disp16]; length 5.
    auto result = Disasm32(std::array<uint8_t, 5>{0x67, 0xD8, 0x06, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FADD);
    EXPECT_EQ(result.length, 5);
}

TEST(X86Addr16Test, TrailingImm32GroupWithDisp16_Length9)
{
    // 67 C7 06 34 12 78 56 00 00 → C7 /0 MOV m32, imm32 with disp16 + imm32;
    // 1 + (4 modrm+disp16) + 4 imm32 = 9.
    auto result = Disasm32(std::array<uint8_t, 9>{
        0x67, 0xC7, 0x06, 0x34, 0x12, 0x78, 0x56, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.length, 9);
}

TEST(X86Addr16Test, SixtySixShrinksImmediateButNotAddressing_Length8)
{
    // 66 67 C7 06 34 12 78 56 → 66h shrinks imm32 to imm16 (8 - 2 = 8 total:
    // 2 prefix bytes + opcode + modrm + disp16 + imm16); disp16 unchanged.
    auto result = Disasm32(std::array<uint8_t, 8>{
        0x66, 0x67, 0xC7, 0x06, 0x34, 0x12, 0x78, 0x56});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.length, 8);
}

TEST(X86Addr16Test, ImulImm16_Rm100PlainMemory_Length6)
{
    const auto result = Disasm32(std::array<uint8_t, 6>{0x66, 0x67, 0x69, 0x04, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IMUL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m16);
    EXPECT_EQ(result.instrId.operands.operand[2], Operand::imm16);
    EXPECT_EQ(result.length, 6);
}

TEST(X86Addr16Test, ImulImm16_Truncated_InsufficientBuffer)
{
    const auto result = Disasm32(std::array<uint8_t, 5>{0x66, 0x67, 0x69, 0x04, 0x34});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, INSUFFICIENT);
}

TEST(X86Addr16Test, ZeroFBA_PostCorrection_WithImm8_Length7)
{
    // 67 0F BA 26 34 12 01 → BT dword ptr [disp16], imm8; 1 + 4 + 2 = 7.
    auto result = Disasm32(std::array<uint8_t, 7>{
        0x67, 0x0F, 0xBA, 0x26, 0x34, 0x12, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::BT);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 7);
}

TEST(X86Addr16Test, ZeroFBA_MissingImm8_InsufficientBuffer)
{
    // The same BT encoding without the imm8 byte → insufficient-buffer.
    auto result = Disasm32(std::array<uint8_t, 6>{
        0x67, 0x0F, 0xBA, 0x26, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, INSUFFICIENT);
}

TEST(X86Addr16Test, CallerLengthGroup_0F01_LGDT_Length6)
{
    // 67 0F 01 16 34 12 → LGDT m16&64 [disp16]; 1 + 4 + 1 = 6.
    auto result = Disasm32(std::array<uint8_t, 6>{0x67, 0x0F, 0x01, 0x16, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LGDT);
    EXPECT_EQ(result.length, 6);
}

TEST(X86Addr16Test, CallerLengthGroup_0FAE_LDMXCSR_Length6)
{
    // 67 0F AE 16 34 12 → LDMXCSR dword ptr [disp16]; 1 + 4 + 1 = 6.
    auto result = Disasm32(std::array<uint8_t, 6>{0x67, 0x0F, 0xAE, 0x16, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LDMXCSR);
    EXPECT_EQ(result.length, 6);
}

// ---------------------------------------------------------------------------
// Requirement: moffs forms keep their existing 67h behavior
// ---------------------------------------------------------------------------

TEST(X86Addr16Test, MoffsRegressionPin_Length4_Moffs16)
{
    // 67 A1 34 12 → MOV eax, moffs16; length 4 (prefix + opcode + moffs16).
    auto result = Disasm32(std::array<uint8_t, 4>{0x67, 0xA1, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::moffs16);
    EXPECT_EQ(result.length, 4);
}

// ---------------------------------------------------------------------------
// Requirement: 64-bit mode keeps the 32-bit layout under 67h
// ---------------------------------------------------------------------------

TEST(X86Addr16Test, X64LayoutUnchanged_Length7)
{
    // 67 8B 86 34 12 78 56 in 64-bit mode = unprefixed 6-byte disp32 form
    // plus the prefix byte; no byte consumed as a 16-bit displacement.
    auto result = Disasm64(std::array<uint8_t, 7>{0x67, 0x8B, 0x86, 0x34, 0x12, 0x78, 0x56});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.length, 7);
}

// ---------------------------------------------------------------------------
// Requirement: No-67h decode is byte-identical
// ---------------------------------------------------------------------------

TEST(X86Addr16Test, No67Pin_Disp32Unchanged_Length6)
{
    // 8B 86 34 12 78 56 (no 67h) → disp32; length 6, unchanged.
    auto result = Disasm32(std::array<uint8_t, 6>{0x8B, 0x86, 0x34, 0x12, 0x78, 0x56});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.length, 6);
}

// ---------------------------------------------------------------------------
// MOV Sreg (dispatch 0xAC: 8C/8E)
// ---------------------------------------------------------------------------

TEST(X86Addr16Test, MovSregToMemory_8C_Length5)
{
    // 67 8C 06 34 12 → MOV word ptr [disp16], sreg; length 5.
    auto result = Disasm32(std::array<uint8_t, 5>{0x67, 0x8C, 0x06, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.length, 5);
}

TEST(X86Addr16Test, MovSregFromMemory_8E_Length5)
{
    // 67 8E 1E 34 12 → MOV sreg, word ptr [disp16]; length 5.
    auto result = Disasm32(std::array<uint8_t, 5>{0x67, 0x8E, 0x1E, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.length, 5);
}

// ---------------------------------------------------------------------------
// SHLD/SHRD (dispatch 0x5B imm8 / 0x5C CL)
// ---------------------------------------------------------------------------

TEST(X86Addr16Test, ShldImm8_Rm100PlainM32_Length5)
{
    // 67 0F A4 04 01 → SHLD dword ptr [si], eax, imm8 (modrm 0x04 = rm=100,
    // plain [SI] under 16-bit addressing); 1 + 3 + 1 = 5.
    auto result = Disasm32(std::array<uint8_t, 5>{0x67, 0x0F, 0xA4, 0x04, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 5);
}

TEST(X86Addr16Test, ShrdImm8_Rm100PlainM32_Length5)
{
    // 67 0F AC 04 01 → SHRD dword ptr [si], eax, imm8; length 5.
    auto result = Disasm32(std::array<uint8_t, 5>{0x67, 0x0F, 0xAC, 0x04, 0x01});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHRD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 5);
}

TEST(X86Addr16Test, ShldImm8_Truncated_InsufficientBuffer)
{
    // SHLD imm8 without the trailing imm8 byte → insufficient-buffer.
    auto result = Disasm32(std::array<uint8_t, 4>{0x67, 0x0F, 0xA4, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, INSUFFICIENT);
}

TEST(X86Addr16Test, ShrdImm8_Truncated_InsufficientBuffer)
{
    // SHRD imm8 without the trailing imm8 byte → insufficient-buffer.
    auto result = Disasm32(std::array<uint8_t, 4>{0x67, 0x0F, 0xAC, 0x04});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, INSUFFICIENT);
}

TEST(X86Addr16Test, ShldCl_Rm100PlainM32_Length4)
{
    // 67 0F A5 04 → SHLD dword ptr [si], eax, CL; length 4.
    auto result = Disasm32(std::array<uint8_t, 4>{0x67, 0x0F, 0xA5, 0x04});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHLD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 4);
}

TEST(X86Addr16Test, ShrdCl_Rm100PlainM32_Length4)
{
    // 67 0F AD 04 → SHRD dword ptr [si], eax, CL; length 4.
    auto result = Disasm32(std::array<uint8_t, 4>{0x67, 0x0F, 0xAD, 0x04});
    EXPECT_EQ(result.instrId.opcode,              OpcodeId::SHRD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 4);
}

// ---------------------------------------------------------------------------
// Linear sweep alignment: the reported length advances exactly onto the
// next instruction boundary (a following 90h NOP).
// ---------------------------------------------------------------------------

TEST(X86Addr16Test, SweepAlignment_Disp16_LandsOnNop)
{
    // 67 8B 06 34 12 (len 5) followed by 90 (NOP): the decode must advance
    // exactly onto the NOP byte.
    const std::array<uint8_t, 6> stream{0x67, 0x8B, 0x06, 0x34, 0x12, 0x90};
    auto result = xendiza::Disasm<32>(gsl::span<const uint8_t>(stream.data(), stream.size()));
    ASSERT_EQ(result.length, 5u);
    EXPECT_EQ(stream[static_cast<size_t>(result.length)], 0x90);
}

TEST(X86Addr16Test, SweepAlignment_X87_LandsOnNop)
{
    // 67 D8 06 34 12 (len 5) followed by 90 (NOP).
    const std::array<uint8_t, 6> stream{0x67, 0xD8, 0x06, 0x34, 0x12, 0x90};
    auto result = xendiza::Disasm<32>(gsl::span<const uint8_t>(stream.data(), stream.size()));
    ASSERT_EQ(result.length, 5u);
    EXPECT_EQ(stream[static_cast<size_t>(result.length)], 0x90);
}

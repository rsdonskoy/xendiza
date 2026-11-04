// test_sse_m4.cpp
// M4 SSE suite: the SSE2 packed-integer block as an explicit per-row
// enumeration (design.md Decision 11).
//
// SDM-derived expectations, independent of the production table:
// representative uniform xmm, xmm/m128 rows per sub-range, the 66/F3 0F 7F
// store-direction counterparts, block exceptions (66 0F E7 MOVNTDQ
// memory-destination-only, F2 0F F0 LDDQU, 66 0F FF UD0), MMX strict
// rejection (no-66 forms, MMX-operand D6 variants), and 32-bit parity.

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/xendiza_x64.hpp>
#include <xendiza/xendiza_x86.hpp>

using namespace xendiza;
using namespace xendiza::detail;

namespace {

constexpr uint8_t kUndefined = static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION);

template <typename TraitsT, size_t N>
auto DisasmOffset(const std::array<uint8_t, N>& buf, const size_t offset, const size_t len)
    -> DecodedInstruction
{
    return TraitsT::Disasm(gsl::span<const uint8_t>(buf.data() + offset, len));
}

auto D64(const std::initializer_list<uint8_t> bytes, const size_t len) -> DecodedInstruction
{
    std::array<uint8_t, 12> buf{};
    size_t n = 0;
    for (const auto b : bytes) {
        buf[n++] = b;
    }
    return X64Traits::Disasm(gsl::span<const uint8_t>(buf.data(), len));
}

// One uniform packed-integer row: 66 0F op /r decodes {xmm, xmm} (reg) and
// {xmm, m128} (mem), with SIB length accounting on the memory form.
void ExpectUniformRow(const uint8_t opcode2, const OpcodeId mnemonic)
{
    {
        const auto r = D64({ 0x66, 0x0F, opcode2, 0xC1 }, 4);
        EXPECT_EQ(r.length, 4) << int(opcode2);
        EXPECT_EQ(r.instrId.opcode, mnemonic) << int(opcode2);
        EXPECT_EQ(r.instrId.operand_count, 2);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0x66, 0x0F, opcode2, 0x00 }, 4); // [rax]
        EXPECT_EQ(r.length, 4) << int(opcode2);
        EXPECT_EQ(r.instrId.opcode, mnemonic) << int(opcode2);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    {
        // SIB + disp8: the operand stays the abstract m128 class (the SIMD
        // path has no stack-marker resolution); the case pins SIB length
        // accounting (prefix + op2 + modrm + sib + disp8 = 6).
        const auto r = D64({ 0x66, 0x0F, opcode2, 0x44, 0x24, 0x08 }, 6); // [rsp+8] SIB
        EXPECT_EQ(r.length, 6) << int(opcode2);
        EXPECT_EQ(r.instrId.opcode, mnemonic) << int(opcode2);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128) << int(opcode2);
    }
    // The no-66 MMX form is strictly rejected.
    const auto mmx = D64({ 0x0F, opcode2, 0xC1 }, 3);
    EXPECT_EQ(mmx.length, kUndefined) << "MMX form of " << int(opcode2);
}

void ExpectUndefined(const DecodedInstruction& r)
{
    EXPECT_EQ(r.length, kUndefined);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

} // namespace

// Representative uniform rows per numeric sub-range (SDM-derived enumeration).
TEST(SimdM4Test, UniformRows_RepresentativePerSubRange)
{
    ExpectUniformRow(0x60, OpcodeId::PUNPCKLBW);
    ExpectUniformRow(0x63, OpcodeId::PACKSSWB);
    ExpectUniformRow(0x66, OpcodeId::PCMPGTD);
    ExpectUniformRow(0x6D, OpcodeId::PUNPCKHQDQ);
    ExpectUniformRow(0x74, OpcodeId::PCMPEQB);
    ExpectUniformRow(0xD4, OpcodeId::PADDQ);
    ExpectUniformRow(0xDB, OpcodeId::PAND);
    ExpectUniformRow(0xE0, OpcodeId::PAVGB);
    ExpectUniformRow(0xE4, OpcodeId::PMULHUW);
    ExpectUniformRow(0xEA, OpcodeId::PMINSW);
    ExpectUniformRow(0xEF, OpcodeId::PXOR);
    ExpectUniformRow(0xF4, OpcodeId::PMULUDQ);
    ExpectUniformRow(0xF6, OpcodeId::PSADBW);
    ExpectUniformRow(0xFB, OpcodeId::PSUBQ);
    ExpectUniformRow(0xFE, OpcodeId::PADDD);
    // Spec scenarios: 66 0F 6F MOVDQA, 66 0F FE PADDD.
    ExpectUniformRow(0x6F, OpcodeId::MOVDQA);
}

// Variable-shift rows share the uniform shape (PSRLW/PSRLD/PSRLQ, PSLLW/D/Q).
TEST(SimdM4Test, VariableShiftRows_UniformShape)
{
    ExpectUniformRow(0xD1, OpcodeId::PSRLW);
    ExpectUniformRow(0xD2, OpcodeId::PSRLD);
    ExpectUniformRow(0xD3, OpcodeId::PSRLQ);
    ExpectUniformRow(0xF1, OpcodeId::PSLLW);
    ExpectUniformRow(0xF2, OpcodeId::PSLLD);
    ExpectUniformRow(0xF3, OpcodeId::PSLLQ);
}

// Store-direction counterparts: 66 0F 7F (MOVDQA) and F3 0F 7F (MOVDQU)
// report {xmm, xmm} (reg) and {m128, xmm} (mem); spec scenario for the mem form.
TEST(SimdM4Test, StoreDirection_0F7F)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0x7F, 0xC1 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVDQA);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0x7F, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVDQA);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m128);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0xF3, 0x0F, 0x6F, 0x00 }, 4); // spec: MOVDQU load
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVDQU);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    {
        const auto r = D64({ 0xF3, 0x0F, 0x7F, 0x00 }, 4); // MOVDQU store
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVDQU);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m128);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    // MMX forms of the block moves are rejected.
    ExpectUndefined(D64({ 0x0F, 0x6F, 0xC1 }, 3));
    ExpectUndefined(D64({ 0x0F, 0x7F, 0xC1 }, 3));
    ExpectUndefined(D64({ 0xF2, 0x0F, 0x6F, 0xC1 }, 4)); // F2 absent on 6F
}

// Block exception: 66 0F E7 MOVNTDQ is memory-destination-only (spec scenarios).
TEST(SimdM4Test, BlockException_E7_MemoryDestinationOnly)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0xE7, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVNTDQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m128);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    ExpectUndefined(D64({ 0x66, 0x0F, 0xE7, 0xC1 }, 4)); // reg form rejected
}

// Block exception: F2 0F F0 LDDQU is memory-source-only; the register form
// and all other prefixes are undefined (spec scenario).
TEST(SimdM4Test, BlockException_F0_Lddqu)
{
    {
        const auto r = D64({ 0xF2, 0x0F, 0xF0, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::LDDQU);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    ExpectUndefined(D64({ 0xF2, 0x0F, 0xF0, 0xC1 }, 4)); // register form (#UD)
    ExpectUndefined(D64({ 0x66, 0x0F, 0xF0, 0xC1 }, 4));
    ExpectUndefined(D64({ 0xF3, 0x0F, 0xF0, 0xC1 }, 4));
    ExpectUndefined(D64({ 0x0F, 0xF0, 0xC1 }, 3));
}

// Block exception: 66 0F FF (UD0) is undefined in every prefix combination.
TEST(SimdM4Test, BlockException_FF_Undefined)
{
    ExpectUndefined(D64({ 0x66, 0x0F, 0xFF, 0xC1 }, 4));
    ExpectUndefined(D64({ 0x0F, 0xFF, 0xC1 }, 3));
    ExpectUndefined(D64({ 0xF3, 0x0F, 0xFF, 0xC1 }, 4));
}

// MMX-operand D6 variants (MOVQ2DQ/MOVDQ2Q) stay rejected; 66 D6 store decodes.
TEST(SimdM4Test, MmxOperandD6Variants_Rejected)
{
    ExpectUndefined(D64({ 0xF2, 0x0F, 0xD6, 0xC1 }, 4));
    ExpectUndefined(D64({ 0xF3, 0x0F, 0xD6, 0xC1 }, 4));
    {
        const auto r = D64({ 0x66, 0x0F, 0xD6, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVQ);
    }
}

// 32-bit parity: same uniform rows through the 32-bit decoder.
TEST(SimdM4Test, Mode32Parity)
{
    {
        const std::array<uint8_t, 8> buf = { 0x66, 0x66, 0x0F, 0x6F, 0x00, 0x90, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVDQA);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    {
        const std::array<uint8_t, 8> buf = { 0x0F, 0x6F, 0xC1, 0x90, 0x90, 0x90, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 0, 3);
        EXPECT_EQ(r.length, kUndefined); // MMX rejected in both modes
    }
    {
        const std::array<uint8_t, 8> buf = { 0x66, 0x66, 0x0F, 0x7F, 0x00, 0x90, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVDQA);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m128);
    }
}

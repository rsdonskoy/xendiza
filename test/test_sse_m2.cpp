// test_sse_m2.cpp
// M2 SSE suite: irregular MOV/CVT/GPR rows (0F 12/13/16/17, 2A/2C/2D, 50,
// 66 0F 6E/7E, 66 0F D6/D7/E7/F7, F3 0F 12/16 riders).
//
// SDM-derived expectations, independent of the production table: dual-name
// rows, store-only / reg-only / memory-destination-only forms, MMX-slot
// rejection, REX.W upgrades on marked rows and REX.W ignoring on unmarked
// rows (design.md Decision 12), and 32-bit parity.

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

// One 64-bit decode: prefixes are given explicitly, buffer tail zero-filled.
auto D64(const std::initializer_list<uint8_t> bytes, const size_t len) -> DecodedInstruction
{
    std::array<uint8_t, 12> buf{};
    size_t n = 0;
    for (const auto b : bytes) {
        buf[n++] = b;
    }
    return X64Traits::Disasm(gsl::span<const uint8_t>(buf.data(), len));
}

auto D32(const std::initializer_list<uint8_t> bytes, const size_t len) -> DecodedInstruction
{
    std::array<uint8_t, 12> buf{};
    size_t n = 0;
    for (const auto b : bytes) {
        buf[n++] = b;
    }
    return X86Traits::Disasm(gsl::span<const uint8_t>(buf.data(), len));
}

void ExpectUndefined(const DecodedInstruction& r)
{
    EXPECT_EQ(r.length, kUndefined);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

} // namespace

// Dual-name rows: 0F 12 reports MOVHLPS (reg) vs MOVLPS (mem); spec scenarios.
TEST(SimdM2Test, DualNameRow_0F12)
{
    {
        const auto r = D64({ 0x0F, 0x12, 0xC1 }, 3); // mod=11
        EXPECT_EQ(r.length, 3);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVHLPS);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0x0F, 0x12, 0x00 }, 3); // mem [rax]
        EXPECT_EQ(r.length, 3);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVLPS);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
    // 66 0F 12 MOVLPD is memory-source-only: the register form is reserved.
    ExpectUndefined(D64({ 0x66, 0x0F, 0x12, 0xC1 }, 4));
    {
        const auto r = D64({ 0x66, 0x0F, 0x12, 0x00 }, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVLPD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
        EXPECT_EQ(r.length, 4);
    }
}

// 0F 16 dual names and the spec MOVHPD scenario.
TEST(SimdM2Test, DualNameRow_0F16_Movhpd)
{
    {
        const auto r = D64({ 0x0F, 0x16, 0xC1 }, 3);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVLHPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    // 66 0F 16 MOVHPD is memory-source-only; the register form is reserved.
    ExpectUndefined(D64({ 0x66, 0x0F, 0x16, 0xC1 }, 4));
    {
        const auto r = D64({ 0x66, 0x0F, 0x16, 0x00 }, 4); // mod!=11
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVHPD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
}

// Store-only rows reject register forms; memory store decodes (spec scenarios).
TEST(SimdM2Test, StoreOnlyRows_0F13_0F17)
{
    ExpectUndefined(D64({ 0x0F, 0x13, 0xC1 }, 3)); // mod=11 rejected
    {
        const auto r = D64({ 0x66, 0x0F, 0x13, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVLPD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    ExpectUndefined(D64({ 0x0F, 0x17, 0xC1 }, 3));
    {
        const auto r = D64({ 0x66, 0x0F, 0x17, 0x00 }, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVHPD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
}

// MOVMSKPS/PD: register-form only (spec: memory form undefined); REX.W ignored
// (design.md Decision 12).
TEST(SimdM2Test, Movmsk_RegOnly_RexWIgnored)
{
    {
        const auto r = D64({ 0x0F, 0x50, 0xC1 }, 3);
        EXPECT_EQ(r.length, 3);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVMSKPS);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    ExpectUndefined(D64({ 0x0F, 0x50, 0x00 }, 3)); // memory form rejected
    {
        const auto r = D64({ 0x66, 0x0F, 0x50, 0xC1 }, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVMSKPD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
    }
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0x50, 0xC1 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVMSKPD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32); // REX.W ignored
    }
}

// CVTSI2SS: REX.W upgrades the GPR source in register AND memory forms (spec).
TEST(SimdM2Test, Cvtsi2ss_RexWUpgrade_RegAndMem)
{
    {
        const auto r = D64({ 0xF3, 0x0F, 0x2A, 0xC8 }, 4); // mod=11, rm=eax
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CVTSI2SS);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r32);
    }
    {
        const auto r = D64({ 0xF3, 0x48, 0x0F, 0x2A, 0xC8 }, 5); // REX.W reg
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CVTSI2SS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r64);
    }
    {
        const auto r = D64({ 0xF3, 0x48, 0x0F, 0x2A, 0x00 }, 5); // REX.W mem
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CVTSI2SS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
    {
        const auto r = D64({ 0xF2, 0x0F, 0x2A, 0x00 }, 4); // CVTSI2SD mem m32
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CVTSI2SD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32);
    }
    // none/66 slots are the MMX forms (rejected).
    ExpectUndefined(D64({ 0x0F, 0x2A, 0xC8 }, 3));
    ExpectUndefined(D64({ 0x66, 0x0F, 0x2A, 0xC8 }, 4));
}

// F2/F3 0F 2C/2D scalar CVT to GPR: r32 default, r64 under REX.W; MMX slots
// rejected. Spec scenario: F2 48 0F 2C 00 -> CVTTSD2SI r64, m64, length 5.
TEST(SimdM2Test, CvtToGpr_2C_2D)
{
    {
        const auto r = D64({ 0xF2, 0x48, 0x0F, 0x2C, 0x00 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CVTTSD2SI);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
    {
        const auto r = D64({ 0xF3, 0x0F, 0x2C, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CVTTSS2SI);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32); // stays m32 under no REX
    }
    {
        const auto r = D64({ 0xF3, 0x48, 0x0F, 0x2C, 0x00 }, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CVTTSS2SI);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32); // source NOT widened
    }
    {
        const auto r = D64({ 0xF2, 0x48, 0x0F, 0x2D, 0xC0 }, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CVTSD2SI);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0xF3, 0x0F, 0x2D, 0xC0 }, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CVTSS2SI);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
    }
    // none/66 slots are the MMX CVTTPS2PI/CVTPD2PI forms (rejected).
    ExpectUndefined(D64({ 0x0F, 0x2C, 0x00 }, 3));
    ExpectUndefined(D64({ 0x66, 0x0F, 0x2D, 0x00 }, 4));
}

// 66 0F D6 MOVQ xmm2/m64, xmm1: both forms legal — the register form
// (MOVQ xmm, xmm) is the canonical reg-reg copy; the memory form stores.
TEST(SimdM2Test, Movq66D6_BothForms)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0xD6, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0xD6, 0xC1 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    // F2/F3 0F D6 are the MMX MOVQ2DQ/DQ2Q variants (rejected).
    ExpectUndefined(D64({ 0xF2, 0x0F, 0xD6, 0xC1 }, 4));
    ExpectUndefined(D64({ 0xF3, 0x0F, 0xD6, 0xC1 }, 4));
}

// MOVD/MOVQ: REX.W upgrades both directions and both forms (spec scenarios).
TEST(SimdM2Test, MovqF37E_LoadBothFormsInBothModes)
{
    for (const auto decode : { D32, D64 }) {
        const auto reg = decode({ 0xF3, 0x0F, 0x7E, 0xC1 }, 4);
        EXPECT_EQ(reg.length, 4);
        EXPECT_EQ(reg.instrId.opcode, OpcodeId::MOVQ);
        EXPECT_EQ(reg.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(reg.instrId.operands.operand[1], Operand::xmm);

        const auto mem = decode({ 0xF3, 0x0F, 0x7E, 0x00 }, 4);
        EXPECT_EQ(mem.length, 4);
        EXPECT_EQ(mem.instrId.opcode, OpcodeId::MOVQ);
        EXPECT_EQ(mem.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(mem.instrId.operands.operand[1], Operand::m64);
    }
}

TEST(SimdM2Test, MovdMovq_RexWBothDirections)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0x6E, 0xC8 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r32);
    }
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0x6E, 0x00 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0x7E, 0x00 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0x7E, 0xC8 }, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    // no-66 forms are the MMX moves (rejected).
    ExpectUndefined(D64({ 0x0F, 0x6E, 0xC8 }, 3));
    ExpectUndefined(D64({ 0x0F, 0x7E, 0xC8 }, 3));
}

// 66 0F D7 PMOVMSKB: register-form only, REX.W ignored (Decision 12 pin).
TEST(SimdM2Test, Pmovmskb_RegOnly_RexWIgnored)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0xD7, 0xC8 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PMOVMSKB);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0xD7, 0xC8 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PMOVMSKB);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32); // REX.W ignored
    }
    ExpectUndefined(D64({ 0x66, 0x0F, 0xD7, 0x00 }, 4)); // memory form rejected
    ExpectUndefined(D64({ 0x0F, 0xD7, 0xC8 }, 3));       // no-66 MMX form
}

// 66 0F E7 MOVNTDQ: memory destination only. 66 0F F7 MASKMOVDQU: register only.
TEST(SimdM2Test, Movntdq_Maskmovdqu_FormRestrictions)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0xE7, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVNTDQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m128);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    ExpectUndefined(D64({ 0x66, 0x0F, 0xE7, 0xC1 }, 4)); // reg form rejected
    {
        const auto r = D64({ 0x66, 0x0F, 0xF7, 0xC1 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MASKMOVDQU);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    ExpectUndefined(D64({ 0x66, 0x0F, 0xF7, 0x00 }, 4)); // memory form rejected
    ExpectUndefined(D64({ 0x0F, 0xF7, 0xC1 }, 3));       // no-66 MMX form
}

// F3 0F 12/16 SSE3 riders: MOVSLDUP/MOVSHDUP xmm, xmm/m128.
TEST(SimdM2Test, SldupShdup_F3Riders)
{
    {
        const auto r = D64({ 0xF3, 0x0F, 0x12, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVSLDUP);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    {
        const auto r = D64({ 0xF3, 0x0F, 0x16, 0xC1 }, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVSHDUP);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    // F2 0F 12/16 (MOVDDUP) is outside this change's rider list.
    ExpectUndefined(D64({ 0xF2, 0x0F, 0x12, 0xC1 }, 4));
    ExpectUndefined(D64({ 0xF2, 0x0F, 0x16, 0xC1 }, 4));
}

// REX.W is ignored on unmarked packed rows (no mnemonic change, no widening).
TEST(SimdM2Test, RexWIgnored_UnmarkedRows)
{
    {
        const auto r = D64({ 0x48, 0x0F, 0x12, 0x00 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVLPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64); // not widened
    }
    {
        const auto r = D64({ 0x48, 0x66, 0x0F, 0xD6, 0x00 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m64);
    }
}

// Non-immediate memory forms must not report success while the mandatory
// displacement is still missing (byte-by-byte truncation contract).
TEST(SimdM2Test, MemoryFormTruncation_InsufficientBuffer)
{
    constexpr uint8_t kInsufficient = static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER);
    // 0F 10 05 (mod=00 rm=101): needs disp32; 3..6 bytes truncated, 7 complete.
    EXPECT_EQ(D64({ 0x0F, 0x10, 0x05 }, 3).length, kInsufficient);
    EXPECT_EQ(D64({ 0x0F, 0x10, 0x05, 0x78 }, 4).length, kInsufficient);
    EXPECT_EQ(D64({ 0x0F, 0x10, 0x05, 0x78, 0x56 }, 5).length, kInsufficient);
    EXPECT_EQ(D64({ 0x0F, 0x10, 0x05, 0x78, 0x56, 0x34 }, 6).length, kInsufficient);
    {
        const auto r = D64({ 0x0F, 0x10, 0x05, 0x78, 0x56, 0x34, 0x12 }, 7);
        EXPECT_EQ(r.length, 7);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVUPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    // 66 0F 6F 05 (MOVDQA): same disp32 requirement.
    EXPECT_EQ(D64({ 0x66, 0x0F, 0x6F, 0x05 }, 4).length, kInsufficient);
    {
        const auto r = D64({ 0x66, 0x0F, 0x6F, 0x05, 0x78, 0x56, 0x34, 0x12 }, 8);
        EXPECT_EQ(r.length, 8);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVDQA);
    }
    // disp8 form: 0F 12 41 ([ecx+disp8]) missing the disp8 byte.
    EXPECT_EQ(D64({ 0x0F, 0x12, 0x41 }, 3).length, kInsufficient);
    {
        const auto r = D64({ 0x0F, 0x12, 0x41, 0x08 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVLPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
}

// 67h in 32-bit mode selects 16-bit addressing: mod=00/rm=110 carries disp16
// (not [esi]), rm=100 is [SI] (not a SIB escape), mod=10 carries disp16.
TEST(SimdM2Test, Mode32Addr16_16BitAddressing)
{
    constexpr uint8_t kInsufficient = static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER);
    // 67 0F 10 06 34 12 -> MOVUPS xmm, [disp16], length 6.
    {
        const auto r = D32({ 0x67, 0x0F, 0x10, 0x06, 0x34, 0x12 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVUPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    // Truncated disp16 -> insufficient buffer.
    EXPECT_EQ(D32({ 0x67, 0x0F, 0x10, 0x06, 0x34 }, 5).length, kInsufficient);
    // 67 0F 10 00 -> [bx+si], length 4 (no disp).
    EXPECT_EQ(D32({ 0x67, 0x0F, 0x10, 0x00 }, 4).length, 4);
    // rm=100 is [si] in 16-bit addressing, not a SIB escape.
    {
        const auto r = D32({ 0x67, 0x0F, 0x10, 0x04 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVUPS);
    }
    // mod=01: disp8 -> length 5; mod=10: disp16 -> length 6.
    EXPECT_EQ(D32({ 0x67, 0x0F, 0x10, 0x40, 0x08 }, 5).length, 5);
    EXPECT_EQ(D32({ 0x67, 0x0F, 0x10, 0x80, 0x34, 0x12 }, 6).length, 6);
    // Without 67h, mod=00 rm=110 is [esi] (length 3) and rm=101 is disp32 (7).
    EXPECT_EQ(D32({ 0x0F, 0x10, 0x06 }, 3).length, 3);
    EXPECT_EQ(D32({ 0x0F, 0x10, 0x05, 0x78, 0x56, 0x34, 0x12 }, 7).length, 7);
}

// 32-bit parity through the 32-bit decoder.
TEST(SimdM2Test, Mode32Parity)
{
    {
        const auto r = D32({ 0x66, 0x0F, 0x6E, 0xC8 }, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r32);
    }
    {
        const auto r = D32({ 0x0F, 0x2C, 0x00 }, 3);
        EXPECT_EQ(r.length, kUndefined); // MMX slot rejected in both modes
    }
    {
        const auto r = D32({ 0x0F, 0x12, 0x00 }, 3);
        EXPECT_EQ(r.length, 3);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVLPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
}

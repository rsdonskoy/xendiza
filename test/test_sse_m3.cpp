// test_sse_m3.cpp
// M3 SSE suite: trailing-immediate rows (0F C2 compare, C6 shuffle, 70 packed
// shuffle, 66 C4/C5 insert/extract, 66 71/72/73 shift groups).
//
// SDM-derived expectations, independent of the production table: immediate
// length accounting, reg-field sub-mnemonic selection across every ModR/M.reg
// value, memory-form rejection for shift groups, the CMPSD/CMPSS prefix remap,
// PEXTRW REX.W-ignored form, byte-by-byte truncation (INSUFFICIENT_BUFFER
// before the encoding is complete), and sweep alignment on the next
// instruction.

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
constexpr uint8_t kInsufficient = static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER);

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

void ExpectUndefined(const DecodedInstruction& r)
{
    EXPECT_EQ(r.length, kUndefined);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

// The 66 71/72/73 sub-mnemonic layout: reg value -> expected opcode.
struct ShiftCase {
    uint8_t opcode2;    // 71/72/73
    uint8_t reg;        // ModR/M.reg field
    OpcodeId mnemonic;
};

} // namespace

// Shift groups: every reg value, including the empty (reserved) slots.
TEST(SimdM3Test, ShiftGroups_AllRegValues)
{
    const ShiftCase cases[] = {
        { 0x71, 2, OpcodeId::PSRLW }, { 0x71, 4, OpcodeId::PSRAW }, { 0x71, 6, OpcodeId::PSLLW },
        { 0x71, 0, OpcodeId::INVALID_OPCODE }, { 0x71, 1, OpcodeId::INVALID_OPCODE },
        { 0x71, 3, OpcodeId::INVALID_OPCODE }, { 0x71, 5, OpcodeId::INVALID_OPCODE },
        { 0x71, 7, OpcodeId::INVALID_OPCODE },
        { 0x72, 2, OpcodeId::PSRLD }, { 0x72, 4, OpcodeId::PSRAD }, { 0x72, 6, OpcodeId::PSLLD },
        { 0x72, 0, OpcodeId::INVALID_OPCODE }, { 0x72, 1, OpcodeId::INVALID_OPCODE },
        { 0x72, 3, OpcodeId::INVALID_OPCODE }, { 0x72, 5, OpcodeId::INVALID_OPCODE },
        { 0x72, 7, OpcodeId::INVALID_OPCODE },
        { 0x73, 2, OpcodeId::PSRLQ }, { 0x73, 3, OpcodeId::PSRLDQ },
        { 0x73, 6, OpcodeId::PSLLQ }, { 0x73, 7, OpcodeId::PSLLDQ },
        { 0x73, 0, OpcodeId::INVALID_OPCODE }, { 0x73, 1, OpcodeId::INVALID_OPCODE },
        { 0x73, 4, OpcodeId::INVALID_OPCODE }, { 0x73, 5, OpcodeId::INVALID_OPCODE },
    };
    for (const auto& c : cases) {
        const uint8_t modrm = static_cast<uint8_t>(0b11'000'000 | (c.reg << 3)); // rm = 0
        const auto r = D64({ 0x66, 0x0F, c.opcode2, modrm, 0x07 }, 5);
        if (c.mnemonic == OpcodeId::INVALID_OPCODE) {
            EXPECT_EQ(r.length, kUndefined) << "opcode2=" << int(c.opcode2) << " reg=" << int(c.reg);
            EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE)
                << "opcode2=" << int(c.opcode2) << " reg=" << int(c.reg);
        } else {
            EXPECT_EQ(r.length, 5) << "opcode2=" << int(c.opcode2) << " reg=" << int(c.reg);
            EXPECT_EQ(r.instrId.opcode, c.mnemonic) << "opcode2=" << int(c.opcode2) << " reg=" << int(c.reg);
            EXPECT_EQ(r.instrId.operand_count, 2);
            EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
            EXPECT_EQ(r.instrId.operands.operand[1], Operand::imm8);
        }
    }
    // Spec scenario: 66 0F 73 /7 imm8 -> PSLLDQ xmm, imm8.
    {
        const auto r = D64({ 0x66, 0x0F, 0x73, 0xF8, 0x07 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSLLDQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::imm8);
    }
}

// Shift groups: memory forms rejected; no-66 MMX forms rejected.
TEST(SimdM3Test, ShiftGroups_MemoryAndMmxRejected)
{
    for (const uint8_t op : { 0x71, 0x72, 0x73 }) {
        ExpectUndefined(D64({ 0x66, 0x0F, op, 0x00, 0x07 }, 5));     // [rax]
        ExpectUndefined(D64({ 0x66, 0x0F, op, 0x04, 0x00, 0x07 }, 6)); // SIB
        ExpectUndefined(D64({ 0x0F, op, 0xC0, 0x07 }, 4));           // MMX (no 66)
        ExpectUndefined(D64({ 0xF3, 0x0F, op, 0xC0, 0x07 }, 5));     // F3 absent
    }
}

// SIB + disp + imm8 byte streams (PSHUFD allows memory forms); the returned
// length lands on the next instruction in a linear sweep. Shift groups reject
// every memory form (covered above), so SIB-length accounting shows up here.
TEST(SimdM3Test, SibDispImm_StreamSweep)
{
    // 66 0F 70 54 11 22 0B -> PSHUFD xmm, [rax*2+0x11], imm8; 1+op2+modrm+sib+disp8+imm = 7.
    {
        const std::array<uint8_t, 8> buf = { 0x66, 0x0F, 0x70, 0x54, 0x11, 0x22, 0x0B, 0x90 };
        const auto r = DisasmOffset<X64Traits>(buf, 0, 8);
        EXPECT_EQ(r.length, 7);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSHUFD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
        // The returned length lands exactly on the next instruction (NOP).
        const auto next = DisasmOffset<X64Traits>(buf, r.length, 1);
        EXPECT_EQ(next.instrId.opcode, OpcodeId::NOP);
        EXPECT_EQ(next.length, 1);
    }
    // disp32 form: 66 0F 70 95 xx xx xx xx 0B -> modrm_len 6 -> total 9.
    {
        const std::array<uint8_t, 10> buf = { 0x66, 0x0F, 0x70, 0x95, 0x78, 0x56, 0x34, 0x12, 0x0B, 0x90 };
        const auto r = DisasmOffset<X64Traits>(buf, 0, 10);
        EXPECT_EQ(r.length, 9);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSHUFD);
        const auto next = DisasmOffset<X64Traits>(buf, r.length, 1);
        EXPECT_EQ(next.instrId.opcode, OpcodeId::NOP);
    }
}

// Byte-by-byte truncation of imm-bearing encodings -> INSUFFICIENT_BUFFER
// until the full encoding (including the immediate) is in-buffer.
TEST(SimdM3Test, Truncation_InsufficientBuffer)
{
    // PSHUFD needs the imm8: 66 0F 70 C0 (4 bytes) is truncated; 5 bytes decodes.
    EXPECT_EQ(D64({ 0x66, 0x0F, 0x70, 0xC0 }, 4).length, kInsufficient);
    {
        const auto r = D64({ 0x66, 0x0F, 0x70, 0xC0, 0x0B }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSHUFD);
    }
    // Shift with SIB: modrm present, SIB missing -> insufficient.
    EXPECT_EQ(D64({ 0x66, 0x0F, 0x71, 0x54 }, 4).length, kInsufficient);
    // Shift with SIB + disp8 present but imm missing: the memory form is
    // rejected before imm accounting, so this is undefined, not truncated.
    EXPECT_EQ(D64({ 0x66, 0x0F, 0x71, 0x54, 0x11, 0x22 }, 6).length, kUndefined);
    // Compare with imm: truncated then complete.
    EXPECT_EQ(D64({ 0x0F, 0xC2, 0xC1 }, 3).length, kInsufficient);
    EXPECT_EQ(D64({ 0x0F, 0xC2, 0xC1, 0x02 }, 4).length, 4);
    // PINSRW memory form without imm -> insufficient.
    EXPECT_EQ(D64({ 0x66, 0x0F, 0xC4, 0x00 }, 4).length, kInsufficient);
}

// Compare predicate: prefix remap (spec scenarios) and length accounting.
TEST(SimdM3Test, ComparePredicate_PrefixRemap)
{
    // F2 -> CMPSD xmm, m64, imm8; F3 -> CMPSS xmm, m32, imm8.
    {
        const auto r = D64({ 0xF2, 0x0F, 0xC2, 0x00, 0x02 }, 5);
        EXPECT_EQ(r.length, 5); // includes the immediate
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CMPSD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
        EXPECT_EQ(r.instrId.operand_count, 3);
    }
    {
        const auto r = D64({ 0xF3, 0x0F, 0xC2, 0x00, 0x02 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CMPSS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0xC2, 0xC1, 0x02 }, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CMPPD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0x0F, 0xC2, 0x00, 0x02 }, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CMPPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
        EXPECT_EQ(r.instrId.operand_count, 3);
    }
}

// Shuffles: 66 0F 70 PSHUFD (spec scenario), C6 SHUFPS/SHUFPD.
TEST(SimdM3Test, Shuffles)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0x70, 0x00, 0x0B }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSHUFD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    {
        const auto r = D64({ 0xF3, 0x0F, 0x70, 0xC1, 0x0B }, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSHUFHW);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0xF2, 0x0F, 0x70, 0xC1, 0x0B }, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSHUFLW);
    }
    ExpectUndefined(D64({ 0x0F, 0x70, 0xC1, 0x0B }, 4)); // no-66 MMX form
    {
        const auto r = D64({ 0x0F, 0xC6, 0xC1, 0x02 }, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::SHUFPS);
        EXPECT_EQ(r.instrId.operand_count, 3);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0xC6, 0xC1, 0x02 }, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::SHUFPD);
    }
    ExpectUndefined(D64({ 0xF3, 0x0F, 0xC6, 0xC1, 0x02 }, 5)); // F3 absent
}

// PINSRW/PEXTRW: imm8 accounting, mem classes, PEXTRW reg-only + REX.W ignored.
TEST(SimdM3Test, PinsrwPextrw)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0xC4, 0xC1, 0x0B }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PINSRW);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0xC4, 0x00, 0x0B }, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PINSRW);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m16);
    }
    ExpectUndefined(D64({ 0x0F, 0xC4, 0xC1, 0x0B }, 4)); // MMX form
    // PEXTRW register form; REX.W is ignored (spec scenario).
    {
        const auto r = D64({ 0x66, 0x0F, 0xC5, 0xC8, 0x0B }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PEXTRW);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0xC5, 0xC8, 0x0B }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PEXTRW);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32); // REX.W ignored
    }
    // PEXTRW memory form rejected (spec scenario).
    ExpectUndefined(D64({ 0x66, 0x0F, 0xC5, 0x00, 0x0B }, 5));
}

// 32-bit parity: representative M3 rows.
TEST(SimdM3Test, Mode32Parity)
{
    {
        const std::array<uint8_t, 8> buf = { 0x66, 0x66, 0x0F, 0x70, 0x00, 0x0B, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSHUFD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    {
        const std::array<uint8_t, 8> buf = { 0x0F, 0x71, 0xD0, 0x07, 0x90, 0x90, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 0, 4);
        EXPECT_EQ(r.length, kUndefined); // MMX shift form rejected in both modes
    }
    {
        const std::array<uint8_t, 8> buf = { 0x66, 0x66, 0x0F, 0x73, 0xF8, 0x07, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSLLDQ); // 73 /7
    }
}

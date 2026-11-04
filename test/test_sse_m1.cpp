// test_sse_m1.cpp
// M1 SSE suite: prefix-remap binary rows (0F 51/52/53/54-57/5A/5B/5D/5F,
// 66/F2/F3 0F E6, SSE3 riders 66|F2 0F D0, F2|66 0F 7C/7D).
//
// Encodings are derived from the Intel SDM opcode map independent of the
// production descriptor table: each row is checked across none/66/F2/F3,
// register and memory forms, absent-variant rejection, mixed mandatory
// prefixes, REX.W ignoring, and 32-bit parity on representative rows.

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

// One mandatory-prefix variant of a SIMD row: prefix byte, mnemonic, and the
// memory class the slot's memory form reads.
struct PrefixVariant {
    uint8_t prefix_byte; // 0 when the variant has no mandatory prefix
    uint8_t prefix_len;
    OpcodeId mnemonic;
    Operand mem_class;
};

// Asserts one variant's register form (mod=11) and memory forms: [rax]
// (mod=00), SIB [eax+eax] (mod=00, rm=100), and [rax+disp8] (mod=01).
void ExpectVariant64(const uint8_t opcode2, const PrefixVariant& v)
{
    // Buffers hold two leading prefix slots; the slice starts where the
    // actual prefixes end so no-prefix variants begin at the 0F escape.
    const size_t off = 2 - v.prefix_len;

    // Register form: [prefix] 0F op C1
    {
        const std::array<uint8_t, 8> buf = { v.prefix_byte, v.prefix_byte, 0x0F, opcode2, 0xC1 };
        const auto r = DisasmOffset<X64Traits>(buf, off, v.prefix_len + 3);
        EXPECT_EQ(r.length, v.prefix_len + 3) << "reg form";
        EXPECT_EQ(r.instrId.opcode, v.mnemonic) << "reg form";
        EXPECT_EQ(r.instrId.operand_count, 2) << "reg form";
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm) << "reg form";
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm) << "reg form";
    }
    // Memory [rax]: modrm 0x00 (mod=00, rm=000; rm=101 would be disp32).
    {
        const std::array<uint8_t, 8> buf = { v.prefix_byte, v.prefix_byte, 0x0F, opcode2, 0x00 };
        const auto r = DisasmOffset<X64Traits>(buf, off, v.prefix_len + 3);
        EXPECT_EQ(r.length, v.prefix_len + 3) << "mem [rax]";
        EXPECT_EQ(r.instrId.opcode, v.mnemonic) << "mem [rax]";
        EXPECT_EQ(r.instrId.operand_count, 2) << "mem [rax]";
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm) << "mem [rax]";
        EXPECT_EQ(r.instrId.operands.operand[1], v.mem_class) << "mem [rax]";
    }
    // Memory via SIB (mod=00, rm=100, base=000): modrm 0x04, sib 0x00.
    {
        const std::array<uint8_t, 8> buf = { v.prefix_byte, v.prefix_byte, 0x0F, opcode2, 0x04, 0x00 };
        const auto r = DisasmOffset<X64Traits>(buf, off, v.prefix_len + 4);
        EXPECT_EQ(r.length, v.prefix_len + 4) << "mem SIB";
        EXPECT_EQ(r.instrId.opcode, v.mnemonic) << "mem SIB";
        EXPECT_EQ(r.instrId.operands.operand[1], v.mem_class) << "mem SIB";
    }
    // Memory [rax+disp8]: modrm 0x40 (mod=01, rm=000) + disp8.
    {
        const std::array<uint8_t, 8> buf = { v.prefix_byte, v.prefix_byte, 0x0F, opcode2, 0x40, 0x11 };
        const auto r = DisasmOffset<X64Traits>(buf, off, v.prefix_len + 4);
        EXPECT_EQ(r.length, v.prefix_len + 4) << "mem disp8";
        EXPECT_EQ(r.instrId.opcode, v.mnemonic) << "mem disp8";
        EXPECT_EQ(r.instrId.operands.operand[1], v.mem_class) << "mem disp8";
    }
}

void ExpectUndefined64(const std::initializer_list<uint8_t> bytes)
{
    std::array<uint8_t, 8> buf{};
    size_t n = 0;
    for (const auto b : bytes) {
        buf[n++] = b;
    }
    const auto r = X64Traits::Disasm(gsl::span<const uint8_t>(buf.data(), n));
    EXPECT_EQ(r.length, kUndefined) << "expected undefined";
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE) << "expected undefined";
}

constexpr PrefixVariant None(const OpcodeId mn, const Operand mem = Operand::m128)
{
    return { 0x00, 0, mn, mem };
}

constexpr PrefixVariant P66(const OpcodeId mn, const Operand mem = Operand::m128)
{
    return { 0x66, 1, mn, mem };
}

constexpr PrefixVariant PF3(const OpcodeId mn, const Operand mem = Operand::m32)
{
    return { 0xF3, 1, mn, mem };
}

constexpr PrefixVariant PF2(const OpcodeId mn, const Operand mem = Operand::m64)
{
    return { 0xF2, 1, mn, mem };
}

} // namespace

// Full PS/PD/SS/SD families: all four prefix slots decode.
TEST(SimdM1Test, FullRemapFamilies_51_5D_5F)
{
    const struct {
        uint8_t opcode2;
        PrefixVariant none;
        PrefixVariant p66;
        PrefixVariant pf3;
        PrefixVariant pf2;
    } rows[] = {
        { 0x51, None(OpcodeId::SQRTPS), P66(OpcodeId::SQRTPD), PF3(OpcodeId::SQRTSS), PF2(OpcodeId::SQRTSD) },
        { 0x5D, None(OpcodeId::MINPS), P66(OpcodeId::MINPD), PF3(OpcodeId::MINSS), PF2(OpcodeId::MINSD) },
        { 0x5F, None(OpcodeId::MAXPS), P66(OpcodeId::MAXPD), PF3(OpcodeId::MAXSS), PF2(OpcodeId::MAXSD) },
    };
    for (const auto& row : rows) {
        ExpectVariant64(row.opcode2, row.none);
        ExpectVariant64(row.opcode2, row.p66);
        ExpectVariant64(row.opcode2, row.pf3);
        ExpectVariant64(row.opcode2, row.pf2);
    }
}

// PS/PD logical rows: none and 66h decode; F3/F2 are absent variants.
TEST(SimdM1Test, LogicalPsPdRows_54_57_F3F2Rejected)
{
    const struct {
        uint8_t opcode2;
        OpcodeId ps;
        OpcodeId pd;
    } rows[] = {
        { 0x54, OpcodeId::ANDPS, OpcodeId::ANDPD },
        { 0x55, OpcodeId::ANDNPS, OpcodeId::ANDNPD },
        { 0x56, OpcodeId::ORPS, OpcodeId::ORPD },
        { 0x57, OpcodeId::XORPS, OpcodeId::XORPD },
    };
    for (const auto& row : rows) {
        ExpectVariant64(row.opcode2, None(row.ps));
        ExpectVariant64(row.opcode2, P66(row.pd));
        ExpectUndefined64({ 0xF3, 0x0F, row.opcode2, 0xC1 });
        ExpectUndefined64({ 0xF2, 0x0F, row.opcode2, 0xC1 });
    }
}

// RCP/RSQRT rows: none = packed (m128), F3 = scalar RSQRTSS/RCPSS (m32);
// 66h and F2 are absent variants (spec scenarios: F2 0F 52, 66 0F 52).
// SDM byte mapping verified 2026-11-04: 0F 52 = rsqrt family, 0F 53 = rcp family.
TEST(SimdM1Test, RcpRsqrt_52_53_PrefixSlots)
{
    ExpectVariant64(0x52, None(OpcodeId::RSQRTPS));
    ExpectVariant64(0x53, None(OpcodeId::RCPPS));
    ExpectVariant64(0x52, PF3(OpcodeId::RSQRTSS, Operand::m32));
    ExpectVariant64(0x53, PF3(OpcodeId::RCPSS, Operand::m32));
    for (const uint8_t op : { 0x52, 0x53 }) {
        ExpectUndefined64({ 0x66, 0x0F, op, 0xC1 });
        ExpectUndefined64({ 0xF2, 0x0F, op, 0xC1 });
    }
}

// 0F 5A conversions: each slot carries its own source width.
// Spec: unprefixed 0F 5A with memory source -> CVTPS2PD xmm, m64.
TEST(SimdM1Test, Conversions_5A_PerSlotMemoryClass)
{
    ExpectVariant64(0x5A, None(OpcodeId::CVTPS2PD, Operand::m64));
    ExpectVariant64(0x5A, P66(OpcodeId::CVTPD2PS, Operand::m128));
    ExpectVariant64(0x5A, PF3(OpcodeId::CVTSS2SD, Operand::m32));
    ExpectVariant64(0x5A, PF2(OpcodeId::CVTSD2SS, Operand::m64));
}

// 0F 5B: none/66/F3 packed int<->ps; F2 absent.
TEST(SimdM1Test, Conversions_5B_F2Rejected)
{
    ExpectVariant64(0x5B, None(OpcodeId::CVTDQ2PS));
    ExpectVariant64(0x5B, P66(OpcodeId::CVTPS2DQ));
    ExpectVariant64(0x5B, PF3(OpcodeId::CVTTPS2DQ, Operand::m128));
    ExpectUndefined64({ 0xF2, 0x0F, 0x5B, 0xC1 });
}

// 66/F2/F3 0F E6: none absent; 66/F2 read m128, F3 reads m64.
TEST(SimdM1Test, Conversions_E6_NoNoneSlot)
{
    ExpectVariant64(0xE6, P66(OpcodeId::CVTPD2DQ));
    ExpectVariant64(0xE6, PF2(OpcodeId::CVTTPD2DQ, Operand::m128));
    ExpectVariant64(0xE6, PF3(OpcodeId::CVTDQ2PD, Operand::m64));
    ExpectUndefined64({ 0x0F, 0xE6, 0xC1 });
}

// SSE3 riders: 66/F2 0F D0 ADDSUB, 66/F2 0F 7C/7D HADD/HSUB; none/F3 absent.
TEST(SimdM1Test, Sse3Riders_D0_7C_7D)
{
    ExpectVariant64(0xD0, P66(OpcodeId::ADDSUBPD));
    ExpectVariant64(0xD0, PF2(OpcodeId::ADDSUBPS, Operand::m128));
    ExpectVariant64(0x7C, P66(OpcodeId::HADDPD));
    ExpectVariant64(0x7C, PF2(OpcodeId::HADDPS, Operand::m128));
    ExpectVariant64(0x7D, P66(OpcodeId::HSUBPD));
    ExpectVariant64(0x7D, PF2(OpcodeId::HSUBPS, Operand::m128));
    for (const uint8_t op : { 0xD0, 0x7C, 0x7D }) {
        ExpectUndefined64({ 0x0F, op, 0xC1 });
        ExpectUndefined64({ 0xF3, 0x0F, op, 0xC1 });
    }
}

// Mixed mandatory prefixes are ambiguous -> undefined (spec requirement).
TEST(SimdM1Test, MixedMandatoryPrefixes_Undefined)
{
    ExpectUndefined64({ 0x66, 0xF3, 0x0F, 0x58, 0xC1 });
    ExpectUndefined64({ 0x66, 0xF2, 0x0F, 0x58, 0xC1 });
    ExpectUndefined64({ 0xF3, 0x66, 0x0F, 0x51, 0xC1 });
    ExpectUndefined64({ 0x66, 0xF3, 0x0F, 0x54, 0xC1 });
}

// REX.W is ignored on unmarked M1 rows: no mnemonic change, no widening.
TEST(SimdM1Test, RexWIgnored_UnmarkedRows)
{
    {
        const std::array<uint8_t, 5> buf = { 0x48, 0x0F, 0x51, 0xC1, 0x00 };
        const auto r = DisasmOffset<X64Traits>(buf, 0, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::SQRTPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const std::array<uint8_t, 6> buf = { 0x48, 0x66, 0x0F, 0x54, 0x00, 0x00 };
        const auto r = DisasmOffset<X64Traits>(buf, 0, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::ANDPD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    // 66h never shrinks the packed operands either.
    {
        const std::array<uint8_t, 5> buf = { 0x66, 0x0F, 0x51, 0x00, 0x00 };
        const auto r = DisasmOffset<X64Traits>(buf, 0, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::SQRTPD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
}

// 32-bit parity: representative M1 rows through the 32-bit decoder.
TEST(SimdM1Test, Mode32Parity_RepresentativeRows)
{
    {
        const std::array<uint8_t, 8> buf = { 0x66, 0x66, 0x0F, 0x51, 0x00 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::SQRTPD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    {
        const std::array<uint8_t, 8> buf = { 0xF2, 0xF2, 0x0F, 0xD0, 0x00 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 4);
        EXPECT_EQ(r.length, 4);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::ADDSUBPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    {
        const std::array<uint8_t, 8> buf = { 0xF3, 0xF3, 0x0F, 0x52, 0xC1 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 4);
        EXPECT_EQ(r.length, 4); // F3 0F 52 is RSQRTSS (scalar, both modes)
        EXPECT_EQ(r.instrId.opcode, OpcodeId::RSQRTSS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const std::array<uint8_t, 8> buf = { 0xF2, 0xF2, 0x0F, 0x52, 0xC1 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 4);
        EXPECT_EQ(r.length, kUndefined); // F2 is absent on the rsqrt family
    }
}

// test_x86_x64_0f38_0f3a.cpp
// M5 suite: the three-byte opcode space (0F 38 / 0F 3A) as explicit
// SDM-derived enumerations (spec: three-byte-opcode-decode).
//
// This file holds the M5b (0F 38) tests: SSSE3/SSE4.1/SSE4.2/AES 66-mandatory
// rows with strict MMX/REP rejection, MOVNTDQA memory-source-only, the shared
// MOVBE/CRC32 rows (prefix slot + operand-size override policy, REX.W
// precedence), CRC32 r32 forms in both modes, truncation bounds, and 32-bit
// parity. The M5a (0F 3A) tests live further down in SimdM5aTest.

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
    std::array<uint8_t, 16> buf{};
    size_t n = 0;
    for (const auto b : bytes) {
        buf[n++] = b;
    }
    return X64Traits::Disasm(gsl::span<const uint8_t>(buf.data(), len));
}

template <size_t N>
auto D32(const std::array<uint8_t, N>& buf, const size_t len) -> DecodedInstruction
{
    return X86Traits::Disasm(gsl::span<const uint8_t>(buf.data(), len));
}

void ExpectUndefined(const DecodedInstruction& r)
{
    EXPECT_EQ(r.length, kUndefined);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

void ExpectInsufficient(const DecodedInstruction& r)
{
    EXPECT_EQ(r.length, kInsufficient);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

// One uniform 66-mandatory 0F 38 row: 66 0F 38 op /r decodes {xmm, xmm} (reg)
// and {xmm, m128} (mem); no-66 (MMX) and F3 forms are strictly rejected.
void ExpectPacked38Row(const uint8_t opcode3, const OpcodeId mnemonic)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0x38, opcode3, 0xC1 }, 5);
        EXPECT_EQ(r.length, 5) << int(opcode3);
        EXPECT_EQ(r.instrId.opcode, mnemonic) << int(opcode3);
        EXPECT_EQ(r.instrId.operand_count, 2);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0x38, opcode3, 0x00 }, 5); // [rax]
        EXPECT_EQ(r.length, 5) << int(opcode3);
        EXPECT_EQ(r.instrId.opcode, mnemonic) << int(opcode3);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    {
        // SIB + disp8 length accounting: prefix + 0F + 38 + op3 + modrm + sib
        // + disp8 = 7.
        const auto r = D64({ 0x66, 0x0F, 0x38, opcode3, 0x44, 0x24, 0x08 }, 7);
        EXPECT_EQ(r.length, 7) << int(opcode3);
        EXPECT_EQ(r.instrId.opcode, mnemonic) << int(opcode3);
    }
    ExpectUndefined(D64({ 0x0F, 0x38, opcode3, 0xC1 }, 4));      // MMX form
    ExpectUndefined(D64({ 0xF3, 0x0F, 0x38, opcode3, 0xC1 }, 5)); // F3 absent
    ExpectUndefined(D64({ 0xF2, 0x0F, 0x38, opcode3, 0xC1 }, 5)); // F2 absent
    ExpectUndefined(D64({ 0x66, 0xF2, 0x0F, 0x38, opcode3, 0xC1 }, 6)); // 66+REP
}

} // namespace

// ── SSSE3 packed-integer rows: 66 slot semantics ────────────────────────────
TEST(SimdM5bTest, Pshufb_SlotSemantics)
{
    // Spec: 66 0F 38 00 /r memory form in 32-bit mode → PSHUFB xmm, m128
    // (parity case lives in Mode32Parity below); register + memory in 64-bit.
    ExpectPacked38Row(0x00, OpcodeId::PSHUFB);
    // Spec scenarios: no-66 → undefined (MMX policy), F3 → undefined.
    ExpectUndefined(D64({ 0x0F, 0x38, 0x00, 0xC1 }, 4));
    ExpectUndefined(D64({ 0xF3, 0x0F, 0x38, 0x00, 0xC1 }, 5));
}

TEST(SimdM5bTest, Ssse3_PackedRows_Representative)
{
    ExpectPacked38Row(0x01, OpcodeId::PHADDW);
    ExpectPacked38Row(0x04, OpcodeId::PMADDUBSW);
    ExpectPacked38Row(0x07, OpcodeId::PHSUBSW);
    ExpectPacked38Row(0x08, OpcodeId::PSIGNB);
    ExpectPacked38Row(0x0B, OpcodeId::PMULHRSW);
    ExpectPacked38Row(0x1C, OpcodeId::PABSB);
    ExpectPacked38Row(0x1E, OpcodeId::PABSD);
}

// ── SSE4.1 implied-mask and uniform rows ────────────────────────────────────
TEST(SimdM5bTest, Sse41_UniformAndImpliedRows)
{
    // PBLENDVB/BLENDVPS/BLENDVPD: implied XMM0 mask is not reported — the
    // operand contract is the two explicit operands.
    ExpectPacked38Row(0x10, OpcodeId::PBLENDVB);
    ExpectPacked38Row(0x14, OpcodeId::BLENDVPS);
    ExpectPacked38Row(0x15, OpcodeId::BLENDVPD);
    ExpectPacked38Row(0x17, OpcodeId::PTEST);
    ExpectPacked38Row(0x29, OpcodeId::PCMPEQQ);
    ExpectPacked38Row(0x2B, OpcodeId::PACKUSDW);
    ExpectPacked38Row(0x40, OpcodeId::PMULLD);
    ExpectPacked38Row(0x41, OpcodeId::PHMINPOSUW);
}

// PMOVSX/PMOVZX rows report the SDM's per-row memory class (not uniform m128).
TEST(SimdM5bTest, Sse41_PmovsxPmovzx_MemoryClasses)
{
    struct Row { uint8_t op3; Operand mem; };
    constexpr Row rows[] = {
        { 0x20, Operand::m64 }, { 0x21, Operand::m32 }, { 0x22, Operand::m16 },
        { 0x23, Operand::m64 }, { 0x24, Operand::m32 }, { 0x25, Operand::m64 },
        { 0x30, Operand::m64 }, { 0x31, Operand::m32 }, { 0x32, Operand::m16 },
        { 0x33, Operand::m64 }, { 0x34, Operand::m32 }, { 0x35, Operand::m64 },
    };
    for (const auto [op3, mem] : rows) {
        const auto r = D64({ 0x66, 0x0F, 0x38, op3, 0x00 }, 5); // [rax]
        EXPECT_EQ(r.length, 5) << int(op3);
        EXPECT_EQ(r.instrId.operands.operand[1], mem) << int(op3);
        const auto reg = D64({ 0x66, 0x0F, 0x38, op3, 0xC1 }, 5);
        EXPECT_EQ(reg.length, 5) << int(op3);
        EXPECT_EQ(reg.instrId.operands.operand[1], Operand::xmm) << int(op3);
    }
}

// ── MOVNTDQA: memory-source-only ────────────────────────────────────────────
TEST(SimdM5bTest, Movntdqa_MemorySourceOnly)
{
    // Spec: memory form decodes; register form (mod=11) is undefined.
    {
        const auto r = D64({ 0x66, 0x0F, 0x38, 0x2A, 0x00 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVNTDQA);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    ExpectUndefined(D64({ 0x66, 0x0F, 0x38, 0x2A, 0xC1 }, 5)); // mod=11
    ExpectUndefined(D64({ 0x0F, 0x38, 0x2A, 0x00 }, 4));       // MMX form
}

// ── AES-NI rows: IMC + the four round instructions, reg + mem ───────────────
TEST(SimdM5bTest, Aes_Rows_RegAndMem)
{
    ExpectPacked38Row(0xDB, OpcodeId::AESIMC);
    ExpectPacked38Row(0xDC, OpcodeId::AESENC);
    ExpectPacked38Row(0xDD, OpcodeId::AESENCLAST);
    ExpectPacked38Row(0xDE, OpcodeId::AESDEC);
    ExpectPacked38Row(0xDF, OpcodeId::AESDECLAST);
}

// SSE4.2 PCMPGTQ decodes with the uniform packed shape (spec memory scenario).
TEST(SimdM5bTest, Pcmpgtq_UniformRow)
{
    ExpectPacked38Row(0x37, OpcodeId::PCMPGTQ);
}

// SSE4.1 PMULDQ (66 0F 38 28): uniform xmm, xmm/m128 row, register + memory
// forms in both modes.
TEST(SimdM5bTest, Pmuldq_RegAndMem)
{
    ExpectPacked38Row(0x28, OpcodeId::PMULDQ);
    // 32-bit mode register form.
    constexpr std::array<uint8_t, 8> buf = { 0x90, 0x66, 0x0F, 0x38, 0x28, 0xC1, 0x90, 0x90 };
    const auto r = DisasmOffset<X86Traits>(buf, 1, 5);
    EXPECT_EQ(r.length, 5);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::PMULDQ);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);

    constexpr std::array<uint8_t, 5> mem = { 0x66, 0x0F, 0x38, 0x28, 0x00 };
    const auto memory = D32(mem, mem.size());
    EXPECT_EQ(memory.length, mem.size());
    EXPECT_EQ(memory.instrId.opcode, OpcodeId::PMULDQ);
    EXPECT_EQ(memory.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(memory.instrId.operands.operand[1], Operand::m128);
}

// LOCK (F0h) is #UD on every 0F 38/0F 3A row (SDM exception tables). Pinned
// with memory forms so the ModR/M constraints cannot mask the rejection.
TEST(SimdM5bTest, LockPrefix_Rejected_AllRows)
{
    // LOCK + MOVBE load (memory form; decodes fine without the LOCK).
    ExpectUndefined(D64({ 0xF0, 0x0F, 0x38, 0xF0, 0x00 }, 5));
    // LOCK + CRC32 (memory form).
    ExpectUndefined(D64({ 0xF0, 0xF2, 0x0F, 0x38, 0xF0, 0x00 }, 6));
    // LOCK + a 66-mandatory packed row (PMULDQ, memory form).
    ExpectUndefined(D64({ 0xF0, 0x66, 0x0F, 0x38, 0x28, 0x00 }, 6));
    // LOCK + a 0F 3A imm8 row (PALIGNR, memory form).
    ExpectUndefined(D64({ 0xF0, 0x66, 0x0F, 0x3A, 0x0F, 0x00, 0x02 }, 7));
    // 32-bit parity (memory form).
    constexpr std::array<uint8_t, 8> buf = { 0xF0, 0x0F, 0x38, 0xF0, 0x00, 0x90, 0x90, 0x90 };
    const auto r = DisasmOffset<X86Traits>(buf, 0, 5);
    EXPECT_EQ(r.length, kUndefined);
}

// ADCX/ADOX (38 F6/F7) are excluded by the design: every prefix form is
// undefined-instruction.
TEST(SimdM5bTest, AdcxAdox_RowsExcluded)
{
    ExpectUndefined(D64({ 0x66, 0x0F, 0x38, 0xF6, 0xC1 }, 5));
    ExpectUndefined(D64({ 0xF2, 0x0F, 0x38, 0xF6, 0xC1 }, 5));
    ExpectUndefined(D64({ 0xF3, 0x0F, 0x38, 0xF6, 0xC1 }, 5));
    ExpectUndefined(D64({ 0x66, 0x0F, 0x38, 0xF7, 0xC1 }, 5));
    ExpectUndefined(D64({ 0xF3, 0x0F, 0x38, 0xF7, 0xC1 }, 5));
}

// Unenumerated third byte (spec scenario: 66 0F 38 FE).
TEST(SimdM5bTest, Unenumerated_Opcode3_Undefined)
{
    ExpectUndefined(D64({ 0x66, 0x0F, 0x38, 0xFE, 0xC1 }, 5));
    ExpectUndefined(D64({ 0x66, 0x0F, 0x38, 0xFE, 0x00 }, 5));
    ExpectUndefined(D64({ 0x66, 0x0F, 0x3A, 0xFE, 0xC1 }, 5));
    ExpectUndefined(D64({ 0xF2, 0x0F, 0x38, 0xF3, 0xC1 }, 5));
}

// ── MOVBE: memory-only, prefix-size policy ──────────────────────────────────
TEST(SimdM5bTest, Movbe_LoadStore_SizeForms)
{
    // Spec: 0F 38 F0 05 disp32 in 32-bit mode → MOVBE r32, m32, length 8.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x0F, 0x38, 0xF0, 0x05, 0x34, 0x12, 0x78, 0x56 };
        const auto r = D32(buf, 8);
        EXPECT_EQ(r.length, 8);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVBE);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32);
    }
    // Spec: 66 0F 38 F1 05 disp32 in 32-bit mode → MOVBE m16, r16, length 9.
    {
        constexpr std::array<uint8_t, 9> buf = { 0x66, 0x0F, 0x38, 0xF1, 0x05, 0x34, 0x12, 0x78, 0x56 };
        const auto r = D32(buf, 9);
        EXPECT_EQ(r.length, 9);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVBE);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m16);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r16);
    }
    // 64-bit unprefixed load/store: r32/m32 both directions.
    {
        const auto load = D64({ 0x0F, 0x38, 0xF0, 0x00 }, 4);
        EXPECT_EQ(load.length, 4);
        EXPECT_EQ(load.instrId.opcode, OpcodeId::MOVBE);
        EXPECT_EQ(load.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(load.instrId.operands.operand[1], Operand::m32);
        const auto store = D64({ 0x0F, 0x38, 0xF1, 0x00 }, 4);
        EXPECT_EQ(store.length, 4);
        EXPECT_EQ(store.instrId.opcode, OpcodeId::MOVBE);
        EXPECT_EQ(store.instrId.operands.operand[0], Operand::m32);
        EXPECT_EQ(store.instrId.operands.operand[1], Operand::r32);
    }
    // 66 without REX in 64-bit mode selects the 16-bit forms.
    {
        const auto load = D64({ 0x66, 0x0F, 0x38, 0xF0, 0x00 }, 5);
        EXPECT_EQ(load.length, 5);
        EXPECT_EQ(load.instrId.operands.operand[0], Operand::r16);
        EXPECT_EQ(load.instrId.operands.operand[1], Operand::m16);
    }
}

TEST(SimdM5bTest, Movbe_RegisterForm_Rejected)
{
    // Spec: 0F 38 F0 C1 (mod=11) in either mode → undefined.
    ExpectUndefined(D64({ 0x0F, 0x38, 0xF0, 0xC1 }, 4));
    ExpectUndefined(D64({ 0x66, 0x0F, 0x38, 0xF0, 0xC1 }, 5));
    ExpectUndefined(D64({ 0x48, 0x0F, 0x38, 0xF0, 0xC1 }, 5));
    ExpectUndefined(D64({ 0x0F, 0x38, 0xF1, 0xC1 }, 4));
    ExpectUndefined(D64({ 0x66, 0x0F, 0x38, 0xF1, 0xC1 }, 5));
}

TEST(SimdM5bTest, Movbe_RexW_Precedence)
{
    // Spec: 66 48 0F 38 F1 00 in 64-bit mode → MOVBE m64, r64, length 6
    // (REX.W takes precedence over 66h).
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0x38, 0xF1, 0x00 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::MOVBE);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r64);
    }
    {
        const auto r = D64({ 0x48, 0x0F, 0x38, 0xF0, 0x00 }, 5); // REX.W load
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
    // F3 on the MOVBE bytes is undefined.
    ExpectUndefined(D64({ 0xF3, 0x0F, 0x38, 0xF0, 0x00 }, 5));
    ExpectUndefined(D64({ 0xF3, 0x0F, 0x38, 0xF1, 0x00 }, 5));
}

// ── CRC32: prefix slots, both modes, REX.W forms ────────────────────────────
TEST(SimdM5bTest, Crc32_R32_Forms_BothModes)
{
    // 64-bit: F2 0F 38 F0 (r/m8) and F2 0F 38 F1 (r/m32), reg + mem forms.
    {
        const auto r = D64({ 0xF2, 0x0F, 0x38, 0xF0, 0xC3 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CRC32);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r8);
    }
    // Capstone cross-check vector: F2 0F 38 F0 43 04 → CRC32 r32, m8 (+disp8).
    {
        const auto r = D64({ 0xF2, 0x0F, 0x38, 0xF0, 0x43, 0x04 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CRC32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m8);
    }
    // Capstone cross-check vector: F2 0F 38 F1 C3 → CRC32 r32, r32.
    {
        const auto r = D64({ 0xF2, 0x0F, 0x38, 0xF1, 0xC3 }, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CRC32);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r32);
    }
    // 32-bit mode: F2 0F 38 F0 C1 → CRC32 r32, r8, length 5 (spec scenario).
    {
        constexpr std::array<uint8_t, 5> buf = { 0xF2, 0x0F, 0x38, 0xF0, 0xC1 };
        const auto r = D32(buf, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CRC32);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r8);
    }
    // 32-bit mode r/m32 form.
    {
        constexpr std::array<uint8_t, 5> buf = { 0xF2, 0x0F, 0x38, 0xF1, 0xC1 };
        const auto r = D32(buf, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CRC32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r32);
    }
}

TEST(SimdM5bTest, Crc32_Halfword_Via66AndF2_BothModes)
{
    // Spec: 66 F2 0F 38 F1 C1 → CRC32 r32, r16, length 6 (either mode).
    {
        const auto r = D64({ 0x66, 0xF2, 0x0F, 0x38, 0xF1, 0xC1 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CRC32);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r16);
    }
    {
        constexpr std::array<uint8_t, 6> buf = { 0x66, 0xF2, 0x0F, 0x38, 0xF1, 0xC1 };
        const auto r = D32(buf, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CRC32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r16);
    }
    // Memory halfword form.
    {
        const auto r = D64({ 0x66, 0xF2, 0x0F, 0x38, 0xF1, 0x43, 0x04 }, 7);
        EXPECT_EQ(r.length, 7);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m16);
    }
    // 66 on the F0 row does not shrink: CRC32 stays r32, r/m8.
    {
        const auto r = D64({ 0x66, 0xF2, 0x0F, 0x38, 0xF0, 0xC1 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r8);
    }
}

TEST(SimdM5bTest, Crc32_F3_Rejected)
{
    // Spec: F3 0F 38 F0 00 (memory operand) → undefined in either mode.
    ExpectUndefined(D64({ 0xF3, 0x0F, 0x38, 0xF0, 0x00 }, 5));
    ExpectUndefined(D64({ 0xF3, 0x0F, 0x38, 0xF1, 0x00 }, 5));
    constexpr std::array<uint8_t, 5> buf = { 0xF3, 0x0F, 0x38, 0xF0, 0x00 };
    ExpectUndefined(D32(buf, 5));
    // 66 + F3 mixed mandatory prefixes are rejected as well.
    ExpectUndefined(D64({ 0x66, 0xF3, 0x0F, 0x38, 0xF0, 0x00 }, 6));
}

TEST(SimdM5bTest, Crc32_RexW_Forms)
{
    // Spec: F2 48 0F 38 F0 C1 → CRC32 r64, r8, length 6 (source stays byte).
    {
        const auto r = D64({ 0xF2, 0x48, 0x0F, 0x38, 0xF0, 0xC1 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CRC32);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r8);
    }
    // Spec: 66 F2 48 0F 38 F1 C8 → CRC32 r64, r64, length 7 (REX.W wins).
    {
        const auto r = D64({ 0x66, 0xF2, 0x48, 0x0F, 0x38, 0xF1, 0xC8 }, 7);
        EXPECT_EQ(r.length, 7);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::CRC32);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r64);
    }
    // REX.W F1 memory form (crc32q cross-check family).
    {
        const auto r = D64({ 0xF2, 0x48, 0x0F, 0x38, 0xF1, 0x43, 0x04 }, 7);
        EXPECT_EQ(r.length, 7);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
}

// ── Bounds: truncation returns insufficient-buffer ──────────────────────────
TEST(SimdM5bTest, Truncation_InsufficientBuffer)
{
    ExpectInsufficient(D64({ 0x66, 0x0F, 0x38 }, 3));              // missing op3
    ExpectInsufficient(D64({ 0x66, 0x0F, 0x38, 0x00 }, 4));        // missing ModR/M
    ExpectInsufficient(D64({ 0x66, 0x0F, 0x38, 0x00, 0x44 }, 5));  // missing SIB
    ExpectInsufficient(D64({ 0x0F, 0x38, 0xF0, 0x05, 0x34 }, 5));  // truncated disp32
    ExpectInsufficient(D64({ 0xF2, 0x0F, 0x38, 0xF0 }, 4));        // missing ModR/M
}

// ── 32-bit parity pins ──────────────────────────────────────────────────────
TEST(SimdM5bTest, Mode32Parity)
{
    // Spec: 66 0F 38 04 /r (PMADDUBSW) via the 32-bit decoder.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x90, 0x66, 0x0F, 0x38, 0x04, 0xC1, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PMADDUBSW);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    // Spec: 66 0F 38 00 memory form through the 32-bit decoder.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x90, 0x66, 0x0F, 0x38, 0x00, 0x00, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 5);
        EXPECT_EQ(r.length, 5);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PSHUFB);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
    // MMX rejection parity.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x0F, 0x38, 0x00, 0xC1, 0x90, 0x90, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 0, 4);
        EXPECT_EQ(r.length, kUndefined);
    }
    // MOVBE register-form rejection parity.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x0F, 0x38, 0xF0, 0xC1, 0x90, 0x90, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 0, 4);
        EXPECT_EQ(r.length, kUndefined);
    }
}

// ── M5a: 0F 3A rows ─────────────────────────────────────────────────────────
//
// One uniform 66-mandatory 0F 3A imm8 row: 66 0F 3A op /r ib decodes {xmm,
// xmm, imm8} (reg) / {xmm, m128, imm8} (mem); no-66 (MMX) and F2/F3 forms are
// rejected.
void ExpectImm8Row3A(const uint8_t opcode3, const OpcodeId mnemonic)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, opcode3, 0xC1, 0x1B }, 6);
        EXPECT_EQ(r.length, 6) << int(opcode3);
        EXPECT_EQ(r.instrId.opcode, mnemonic) << int(opcode3);
        EXPECT_EQ(r.instrId.operand_count, 3);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, opcode3, 0x00, 0x1B }, 6); // [rax]
        EXPECT_EQ(r.length, 6) << int(opcode3);
        EXPECT_EQ(r.instrId.opcode, mnemonic) << int(opcode3);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    ExpectUndefined(D64({ 0x0F, 0x3A, opcode3, 0xC1, 0x1B }, 5));       // MMX form
    ExpectUndefined(D64({ 0xF3, 0x0F, 0x3A, opcode3, 0xC1, 0x1B }, 6)); // F3 absent
    ExpectUndefined(D64({ 0xF2, 0x0F, 0x3A, opcode3, 0xC1, 0x1B }, 6)); // F2 absent
    ExpectUndefined(D64({ 0x66, 0xF2, 0x0F, 0x3A, opcode3, 0xC1, 0x1B }, 7)); // 66+REP
}

// ROUND*/BLEND*/DPP* prefix-slot selection (spec scenarios; ROUNDSS/SD carry
// the SDM m32/m64 memory classes).
TEST(SimdM5aTest, RoundBlendDpp_PrefixSlots)
{
    ExpectImm8Row3A(0x08, OpcodeId::ROUNDPS);
    ExpectImm8Row3A(0x09, OpcodeId::ROUNDPD);
    ExpectImm8Row3A(0x0C, OpcodeId::BLENDPS);
    ExpectImm8Row3A(0x0D, OpcodeId::BLENDPD);
    ExpectImm8Row3A(0x0E, OpcodeId::PBLENDW);
    ExpectImm8Row3A(0x40, OpcodeId::DPPS);
    ExpectImm8Row3A(0x41, OpcodeId::DPPD);
    // Scalar round rows keep their narrowed memory classes.
    {
        const auto ss = D64({ 0x66, 0x0F, 0x3A, 0x0A, 0x00, 0x04 }, 6);
        EXPECT_EQ(ss.length, 6);
        EXPECT_EQ(ss.instrId.opcode, OpcodeId::ROUNDSS);
        EXPECT_EQ(ss.instrId.operands.operand[1], Operand::m32);
        const auto sd = D64({ 0x66, 0x0F, 0x3A, 0x0B, 0x00, 0x04 }, 6);
        EXPECT_EQ(sd.length, 6);
        EXPECT_EQ(sd.instrId.opcode, OpcodeId::ROUNDSD);
        EXPECT_EQ(sd.instrId.operands.operand[1], Operand::m64);
    }
}

// PALIGNR length accounting: register imm8 form, disp32 memory form, SIB.
TEST(SimdM5aTest, Palignr_LengthAccounting)
{
    // Spec: 66 0F 3A 0F C1 02 in 32-bit mode → length 6.
    {
        constexpr std::array<uint8_t, 6> buf = { 0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x02 };
        const auto r = D32(buf, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PALIGNR);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    // Spec: 66 0F 3A 0F 05 disp32 01 (mod=00/rm=101) in 32-bit mode → length 10.
    {
        constexpr std::array<uint8_t, 10> buf = { 0x66, 0x0F, 0x3A, 0x0F, 0x05, 0x34, 0x12, 0x78, 0x56, 0x01 };
        const auto r = D32(buf, 10);
        EXPECT_EQ(r.length, 10);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PALIGNR);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    // SIB + disp8 form: prefix + 3 opcode bytes + modrm + sib + disp8 + imm8.
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x0F, 0x44, 0x24, 0x08, 0x02 }, 8);
        EXPECT_EQ(r.length, 8);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PALIGNR);
    }
    ExpectImm8Row3A(0x0F, OpcodeId::PALIGNR);
}

// Bounds: every truncation shape on the imm8 rows returns insufficient-buffer
// (spec scenarios, PALIGNR examples).
TEST(SimdM5aTest, Truncation_InsufficientBuffer)
{
    ExpectInsufficient(D64({ 0x66, 0x0F, 0x3A }, 3));                 // missing op3
    ExpectInsufficient(D64({ 0x66, 0x0F, 0x3A, 0x0F }, 4));           // missing ModR/M
    ExpectInsufficient(D64({ 0x66, 0x0F, 0x3A, 0x0F, 0x04 }, 5));     // missing SIB
    ExpectInsufficient(D64({ 0x66, 0x0F, 0x3A, 0x0F, 0xC1 }, 5));     // missing imm8
    ExpectInsufficient(D64({ 0x66, 0x0F, 0x3A, 0x0F, 0x05, 0x34 }, 6)); // truncated disp32
    ExpectInsufficient(D64({ 0x66, 0x0F, 0x3A, 0x0F, 0x00 }, 5));     // missing imm8 (mem form)
}

// Extract family: destination selected by the ModR/M, REX.W switches the
// mnemonic (PEXTRQ) and widens the destination.
TEST(SimdM5aTest, Pextr_DestinationForms)
{
    // PEXTRB r32/m8, xmm, imm8.
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x14, 0xC1, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PEXTRB);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x14, 0x00, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PEXTRB);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m8);
    }
    // PEXTRW r32/m16 (SSE4.1 3A 15; the SSE2 0F C5 row keeps its two-byte decode).
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x15, 0x00, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PEXTRW);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m16);
    }
    // Spec: PEXTRD to register (mod=11) in 64-bit mode.
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x16, 0xC0, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PEXTRD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    // Spec: PEXTRQ under REX.W to memory.
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0x3A, 0x16, 0x00, 0x03 }, 7);
        EXPECT_EQ(r.length, 7);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PEXTRQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m64);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    // REX.W register form → PEXTRQ r64.
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0x3A, 0x16, 0xC0, 0x03 }, 7);
        EXPECT_EQ(r.length, 7);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PEXTRQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r64);
    }
    // REX.W without 66 on the extract rows: mixed mandatory prefix → undefined.
    ExpectUndefined(D64({ 0x48, 0x0F, 0x3A, 0x16, 0x00, 0x03 }, 6));
}

// EXTRACTPS forms: r32 (mod=11) and m32 destinations.
TEST(SimdM5aTest, Extractps_Forms)
{
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x17, 0xC1, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::EXTRACTPS);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x17, 0x00, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::EXTRACTPS);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::m32);
    }
}

// Insert family: SDM source classes; PINSRD/PINSRQ REX.W switch; PINSRB
// memory byte source (spec scenarios).
TEST(SimdM5aTest, Pinsr_SourceForms)
{
    // Spec: PINSRB memory byte source in 32-bit mode.
    {
        constexpr std::array<uint8_t, 6> buf = { 0x66, 0x0F, 0x3A, 0x20, 0x00, 0x03 };
        const auto r = D32(buf, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PINSRB);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m8);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    // PINSRB register source (r32 class).
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x20, 0xC1, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PINSRB);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r32);
    }
    // INSERTPS xmm, xmm/m32, imm8.
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x21, 0x00, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::INSERTPS);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32);
    }
    // Spec: PINSRD from memory (mod!=11) in 64-bit mode.
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x22, 0x00, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PINSRD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32);
    }
    // Spec: PINSRQ under REX.W from register (mod=11).
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0x3A, 0x22, 0xC0, 0x03 }, 7);
        EXPECT_EQ(r.length, 7);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PINSRQ);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::r64);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    // PINSRQ memory form under REX.W.
    {
        const auto r = D64({ 0x66, 0x48, 0x0F, 0x3A, 0x22, 0x00, 0x03 }, 7);
        EXPECT_EQ(r.length, 7);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PINSRQ);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64);
    }
    // PINSRW stays the SSE2 0F C4 encoding: 0F 3A has no PINSRW row.
    ExpectUndefined(D64({ 0x66, 0x0F, 0x3A, 0x71, 0xC1, 0x03 }, 6));
}

// SSE4.2 string rows: two explicit operands + imm8; implied XMM0/ECX are NOT
// in the operand contract (spec scenarios).
TEST(SimdM5aTest, Pcmpstr_Rows_TwoExplicitOperands)
{
    ExpectImm8Row3A(0x60, OpcodeId::PCMPESTRM);
    ExpectImm8Row3A(0x62, OpcodeId::PCMPISTRM);
    {
        // Spec: 66 0F 3A 61 C1 03 → PCMPESTRI xmm, xmm, imm8, length 6.
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x61, 0xC1, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PCMPESTRI);
        EXPECT_EQ(r.instrId.operand_count, 3);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::xmm);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x63, 0x00, 0x03 }, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PCMPISTRI);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m128);
    }
}

// PCLMULQDQ and AESKEYGENASSIST: 66-only imm8 rows.
TEST(SimdM5aTest, Pclmulqdq_Aeskeygenassist)
{
    ExpectImm8Row3A(0x44, OpcodeId::PCLMULQDQ);
    ExpectImm8Row3A(0xDF, OpcodeId::AESKEYGENASSIST);
    // Spec: PCLMULQDQ length includes the immediate (SIB form here).
    {
        const auto r = D64({ 0x66, 0x0F, 0x3A, 0x44, 0x44, 0x24, 0x08, 0x00 }, 8);
        EXPECT_EQ(r.length, 8);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PCLMULQDQ);
        EXPECT_EQ(r.instrId.operands.operand[2], Operand::imm8);
    }
    // The SHA row space stays out of scope: 66 0F 3A CC (SHA1RNDS4) is
    // undefined-instruction.
    ExpectUndefined(D64({ 0x66, 0x0F, 0x3A, 0xCC, 0x00, 0x0E }, 6));
}

// MPSADBW immediate row (uniform shape).
TEST(SimdM5aTest, Mpsadbw_ImmediateRow)
{
    ExpectImm8Row3A(0x42, OpcodeId::MPSADBW);
}

// Unenumerated 0F 3A third byte.
TEST(SimdM5aTest, Unenumerated_Opcode3_Undefined)
{
    ExpectUndefined(D64({ 0x66, 0x0F, 0x3A, 0xFE, 0x00, 0x1B }, 6));
    ExpectUndefined(D64({ 0x66, 0x0F, 0x3A, 0x19, 0x00, 0x1B }, 6));
}

// ── M5a 32-bit parity pins ──────────────────────────────────────────────────
TEST(SimdM5aTest, Mode32Parity)
{
    // Spec: 66 0F 3A 0F C1 02 through the 32-bit decoder → length 6.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x90, 0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x02, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PALIGNR);
    }
    // PEXTRD without REX (structurally absent in 32-bit mode) stays PEXTRD.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x90, 0x66, 0x0F, 0x3A, 0x16, 0xC0, 0x03, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PEXTRD);
        EXPECT_EQ(r.instrId.operands.operand[0], Operand::r32);
    }
    // Spec: PINSRD from memory through the 32-bit decoder.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x90, 0x66, 0x0F, 0x3A, 0x22, 0x00, 0x03, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PINSRD);
        EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32);
    }
    // MMX rejection parity on the imm8 rows.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x0F, 0x3A, 0x0F, 0xC1, 0x02, 0x90, 0x90, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 0, 5);
        EXPECT_EQ(r.length, kUndefined);
    }
    // CRC32 halfword parity lives in SimdM5bTest; AES/PCLMUL parity via the
    // 32-bit decoder.
    {
        constexpr std::array<uint8_t, 8> buf = { 0x90, 0x66, 0x0F, 0x3A, 0x44, 0x00, 0x00, 0x90 };
        const auto r = DisasmOffset<X86Traits>(buf, 1, 6);
        EXPECT_EQ(r.length, 6);
        EXPECT_EQ(r.instrId.opcode, OpcodeId::PCLMULQDQ);
    }
}

// Decode-level tests for the variant-driven VEX decoder's exceptional paths:
// no-ModR/M canonical variants (VZEROUPPER/VZEROALL), ModR/M.reg group entry
// selection behind the variant mask, and the preserved mode/shape errors.
// The complete C4/C5 direct-dispatch exhaustive tests and the existing group
// tests in test_vex_avx_forms.cpp cover the same paths byte-exhaustively;
// these tests pin the exact expected outcomes for the tricky corners.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <gsl/span>

#include <xendiza/detail/instruction.hpp>
#include <xendiza/detail/opcode_id.hpp>
#include <xendiza/xendiza.hpp>

namespace xendiza {
namespace {

using Bytes = std::array<uint8_t, 16>;

DecodedInstruction Decode(int mode, const Bytes& code, size_t size)
{
    const gsl::span<const uint8_t> input(code.data(), size);
    return mode == 64 ? Disasm<64>(input) : Disasm<32>(input);
}

void ExpectSuccess(int mode, const Bytes& code, size_t size, OpcodeId opcode,
    std::initializer_list<Operand> operands)
{
    const auto r = Decode(mode, code, size);
    ASSERT_EQ(r.length, size);
    EXPECT_EQ(r.instrId.opcode, opcode);
    ASSERT_EQ(r.instrId.operand_count, operands.size());
    size_t i = 0;
    for (const auto operand : operands)
        EXPECT_EQ(r.instrId.operands.operand[i++], operand);
}

void ExpectError(int mode, const Bytes& code, size_t size, ErrorCode error)
{
    EXPECT_EQ(Decode(mode, code, size).length, static_cast<uint8_t>(error));
}

// VZEROUPPER/VZEROALL carry no ModR/M: the canonical register-side variant is
// selected from the static shape alone, and the reserved-vvvv policy applies.
TEST(VexVariantDecode, NoModrmCanonicalVariant)
{
    for (int mode : { 32, 64 }) {
        // L=0 -> VZEROUPPER, L=1 -> VZEROALL, W ignored.
        ExpectSuccess(mode, Bytes{ 0xC5, 0xF8, 0x77 }, 3, OpcodeId::VZEROUPPER, {});
        ExpectSuccess(mode, Bytes{ 0xC5, 0xFC, 0x77 }, 3, OpcodeId::VZEROALL, {});
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x78, 0x77 }, 4, OpcodeId::VZEROUPPER, {});
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x7C, 0x77 }, 4, OpcodeId::VZEROALL, {});
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0xF8, 0x77 }, 4, OpcodeId::VZEROUPPER, {});
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0xFC, 0x77 }, 4, OpcodeId::VZEROALL, {});
        // The non-NDS descriptor requires the reserved vvvv value.
        ExpectError(mode, Bytes{ 0xC5, 0xF0, 0x77 }, 3, ErrorCode::UNDEFINED_INSTRUCTION);
        ExpectError(mode, Bytes{ 0xC4, 0xE1, 0x68, 0x77 }, 4, ErrorCode::UNDEFINED_INSTRUCTION);
        // Missing opcode byte after the VEX prefix.
        ExpectError(mode, Bytes{ 0xC5, 0xF8 }, 2, ErrorCode::INSUFFICIENT_BUFFER);
        ExpectError(mode, Bytes{ 0xC4, 0xE1, 0x78 }, 3, ErrorCode::INSUFFICIENT_BUFFER);
    }
}

// Group forms resolve the concrete entry from the selected per-L sub-table by
// the three-bit ModR/M.reg field, keeping absence/shape errors intact.
TEST(VexVariantDecode, GroupEntrySelectionBehindVariant)
{
    for (int mode : { 32, 64 }) {
        // VPSRLW xmm, imm8 (0x71 /2) and VPSLLQ ymm, imm8 (0x73 /6).
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x79, 0x71, 0xD0, 0x1B }, 6,
            OpcodeId::VPSRLW, { Operand::xmm, Operand::xmm, Operand::imm8 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x7D, 0x73, 0xF0, 0x1B }, 6,
            OpcodeId::VPSLLQ, { Operand::ymm, Operand::ymm, Operand::imm8 });
        // L=1 selects the ymm sub-table only when the descriptor allows it.
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x7D, 0x71, 0xD0, 0x1B }, 6,
            OpcodeId::VPSRLW, { Operand::ymm, Operand::ymm, Operand::imm8 });
        // Absent group entries stay undefined.
        ExpectError(mode, Bytes{ 0xC4, 0xE1, 0x79, 0x71, 0xC0, 0x1B }, 6,
            ErrorCode::UNDEFINED_INSTRUCTION);
        // Group entries are register-shaped: a memory ModR/M is rejected.
        ExpectError(mode, Bytes{ 0xC4, 0xE1, 0x79, 0x71, 0x10, 0x1B }, 6,
            ErrorCode::UNDEFINED_INSTRUCTION);
        // Groups require the reserved vvvv value.
        ExpectError(mode, Bytes{ 0xC4, 0xE1, 0x71, 0x71, 0xD0, 0x1B }, 6,
            ErrorCode::UNDEFINED_INSTRUCTION);
        // Truncation before the ModR/M byte keeps the buffer error.
        ExpectError(mode, Bytes{ 0xC4, 0xE1, 0x79, 0x71 }, 4,
            ErrorCode::INSUFFICIENT_BUFFER);
    }
}

// VLDMXCSR/VSTMXCSR (0xAE group, memory-only) go through the same variant
// gate but reject register ModR/M shapes and cover only the canonical L=0.
TEST(VexVariantDecode, MemoryOnlyGroupShapeAndMode)
{
    for (int mode : { 32, 64 }) {
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x78, 0xAE, 0x15, 0, 0, 0, 0 }, 9,
            OpcodeId::VLDMXCSR, { Operand::m32 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x78, 0xAE, 0x1D, 0, 0, 0, 0 }, 9,
            OpcodeId::VSTMXCSR, { Operand::m32 });
        // Register ModR/M violates the memory-only shape.
        ExpectError(mode, Bytes{ 0xC4, 0xE1, 0x78, 0xAE, 0xD5 }, 5,
            ErrorCode::UNDEFINED_INSTRUCTION);
        // The L=1 sub-table does not exist for this descriptor.
        ExpectError(mode, Bytes{ 0xC4, 0xE1, 0x7C, 0xAE, 0x15, 0, 0, 0, 0 }, 9,
            ErrorCode::UNDEFINED_INSTRUCTION);
    }
}

// The variant-driven path must retain every dynamic legality check after
// form selection: VSIB addressing restrictions, gather operand/overlap rules,
// exact trailing-byte bounds, and the 15-byte instruction limit.
TEST(VexVariantDecode, VsibAndGatherRestrictionsRetained)
{
    for (int mode : { 32, 64 }) {
        // Baseline valid gather: VPGATHERDD ymm0, [ymm2*1+disp32], ymm5
        // (vvvv field 1010 -> mask reg 5; dest=0, index=2, mask=5 distinct).
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE2, 0x55, 0x90, 0x04, 0x15, 0x78, 0x56, 0x34, 0x12 }, 10,
            OpcodeId::VPGATHERDD,
            { Operand::ymm, Operand::m32_vsib, Operand::ymm });
        // 67h in 32-bit mode forces 16-bit addressing, which VSIB forbids;
        // in 64-bit mode it selects (legal) 32-bit addressing, length 11.
        if (mode == 32) {
            ExpectError(mode, Bytes{ 0x67, 0xC4, 0xE2, 0x55, 0x90, 0x04, 0x15, 0x78, 0x56, 0x34, 0x12 }, 11,
                ErrorCode::UNDEFINED_INSTRUCTION);
        } else {
            ExpectSuccess(mode, Bytes{ 0x67, 0xC4, 0xE2, 0x55, 0x90, 0x04, 0x15, 0x78, 0x56, 0x34, 0x12 }, 11,
                OpcodeId::VPGATHERDD,
                { Operand::ymm, Operand::m32_vsib, Operand::ymm });
        }
        // A non-SIB ModR/M (rm != 100) is rejected for VSIB forms.
        ExpectError(mode, Bytes{ 0xC4, 0xE2, 0x55, 0x90, 0x00, 0x78, 0x56, 0x34, 0x12 }, 9,
            ErrorCode::UNDEFINED_INSTRUCTION);
        // Truncation between the ModR/M and the VSIB byte keeps the buffer error.
        ExpectError(mode, Bytes{ 0xC4, 0xE2, 0x55, 0x90, 0x04 }, 5,
            ErrorCode::INSUFFICIENT_BUFFER);
        // Gather overlap remains enforced: dest == mask here (reg 5, vvvv 5).
        ExpectError(mode, Bytes{ 0xC4, 0xE2, 0x55, 0x90, 0x2C, 0x15, 0x78, 0x56, 0x34, 0x12 }, 10,
            ErrorCode::UNDEFINED_INSTRUCTION);
    }
}

// Exact trailing-byte bounds after variant selection: an imm8 form cut before
// its immediate reports INSUFFICIENT_BUFFER even when the ModR/M is complete.
TEST(VexVariantDecode, TrailingByteBoundsRetained)
{
    for (int mode : { 32, 64 }) {
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x74, 0xC2, 0xD0, 0x08 }, 6,
            OpcodeId::VCMPPS, { Operand::ymm, Operand::ymm, Operand::ymm, Operand::imm8 });
        ExpectError(mode, Bytes{ 0xC4, 0xE1, 0x74, 0xC2, 0xD0 }, 5,
            ErrorCode::INSUFFICIENT_BUFFER);
        // /is4 forms take one trailing byte as well; the L=1 is4 slot is
        // modeled as ymm in this library (mirrors VBLENDVPD 0x75 tests).
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x75, 0x4A, 0xD0, 0x40 }, 6,
            OpcodeId::VBLENDVPS,
            { Operand::ymm, Operand::ymm, Operand::ymm, Operand::ymm });
        ExpectError(mode, Bytes{ 0xC4, 0xE3, 0x75, 0x4A, 0xD0 }, 5,
            ErrorCode::INSUFFICIENT_BUFFER);
    }
}

// The 15-byte architectural limit still applies after variant selection.
TEST(VexVariantDecode, FifteenByteLimitRetained)
{
    for (int mode : { 32, 64 }) {
        // 12 permitted 67h prefixes + C5 F8 77 -> exactly 15 bytes: valid.
        Bytes ok{};
        for (int i = 0; i < 12; ++i) ok[static_cast<size_t>(i)] = 0x67;
        ok[12] = 0xC5; ok[13] = 0xF8; ok[14] = 0x77;
        ExpectSuccess(mode, ok, 15, OpcodeId::VZEROUPPER, {});
        // One more prefix byte pushes the same instruction to 16 bytes.
        Bytes too_long = ok;
        too_long[12] = 0x67; too_long[13] = 0xC5; too_long[14] = 0xF8; too_long[15] = 0x77;
        ExpectError(mode, too_long, 16, ErrorCode::UNDEFINED_INSTRUCTION);
    }
}

} // namespace
} // namespace xendiza

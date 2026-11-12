// Focused tests over the precomputed VEX variant tables.
//
// These pin the tricky corners of the compile-time descriptor expansion before
// the production decoder is switched to variant selection:
//   - no-ModR/M forms (VZEROUPPER/VZEROALL) resolve only on the canonical
//     register-side variant and keep the descriptor-wide vvvv policy;
//   - WIG and LIG descriptors reuse one shared resolved form instead of
//     per-field copies;
//   - scalar moves (VMOVSS/VMOVSD) select the form-aware vvvv policy through
//     the reserved-vvvv variant bit;
//   - absent descriptors have no record and disallowed field combinations
//     have no speculative form.

#include <gtest/gtest.h>

#include <cstdint>
#include <gsl/span>

#include <xendiza/detail/instruction.hpp>
#include <xendiza/detail/vex.hpp>
#include <xendiza/detail/vex_decode.hpp>

namespace xendiza {
namespace {

using detail::kVexInvalidFormIndex;
using detail::VexVariantDescriptor;
using detail::VexVariantNoModrm;

auto Variant(const uint8_t L, const uint8_t W, const uint8_t reg, const uint8_t reserved) -> uint8_t
{
    return static_cast<uint8_t>((L << 3) | (W << 2) | (reg << 1) | reserved);
}

auto SlotOf(const VexVariantDescriptor& rec, const uint8_t variant) -> uint16_t
{
    return detail::VexVariantSlots()[rec.variant_base + variant];
}

auto MaskValid(const VexVariantDescriptor& rec, const uint8_t variant) -> bool
{
    return (rec.valid_mask & (1u << variant)) != 0;
}

TEST(VexVariantFocused, NoModrmCanonicalVariantAndVvvvPolicy)
{
    const auto* rec = detail::VexLookupVariantDescriptor(0x01, 0x77, 0); // VZEROUPPER/VZEROALL
    ASSERT_NE(rec, nullptr);
    EXPECT_TRUE(rec->flags & VexVariantNoModrm);

    for (uint8_t L = 0; L < 2; ++L) {
        for (uint8_t W = 0; W < 2; ++W) {
            // Canonical register-side variant is the only legal one.
            EXPECT_TRUE(MaskValid(*rec, Variant(L, W, 1, 1))) << "L=" << int(L) << " W=" << int(W);
            EXPECT_FALSE(MaskValid(*rec, Variant(L, W, 0, 1)));
            // The non-NDS descriptor requires the reserved vvvv value.
            EXPECT_FALSE(MaskValid(*rec, Variant(L, W, 1, 0)));
            EXPECT_FALSE(MaskValid(*rec, Variant(L, W, 0, 0)));

            const auto* form = detail::VexResolvedFormForVariant(*rec, Variant(L, W, 1, 1));
            ASSERT_NE(form, nullptr);
            EXPECT_EQ(form->opcode, L == 0 ? OpcodeId::VZEROUPPER : OpcodeId::VZEROALL);
            EXPECT_EQ(form->operand_count, 0);
            EXPECT_EQ(form->trailing_size, 0);
            EXPECT_EQ(form->allowed_modes, 0x03);
        }
    }
}

TEST(VexVariantFocused, WigAndLigReuseSharedForms)
{
    // VADDPS (0F 59 pp=0) is WIG: both W values share one resolved form.
    const auto* wig = detail::VexLookupVariantDescriptor(0x01, 0x59, 0);
    ASSERT_NE(wig, nullptr);
    for (uint8_t L = 0; L < 2; ++L) {
        for (uint8_t reg = 0; reg < 2; ++reg) {
            const auto slot_w0 = SlotOf(*wig, Variant(L, 0, reg, 0));
            const auto slot_w1 = SlotOf(*wig, Variant(L, 1, reg, 0));
            EXPECT_NE(slot_w0, kVexInvalidFormIndex);
            EXPECT_EQ(slot_w0, slot_w1) << "L=" << int(L) << " reg=" << int(reg);
        }
    }
    // VADDSS (0F 58 pp=2) is a scalar NDS form: LIG folds L=1 onto the L=0 form.
    const auto* lig = detail::VexLookupVariantDescriptor(0x01, 0x58, 2);
    ASSERT_NE(lig, nullptr);
    for (uint8_t W = 0; W < 2; ++W) {
        for (uint8_t reg = 0; reg < 2; ++reg) {
            const auto slot_l0 = SlotOf(*lig, Variant(0, W, reg, 0));
            const auto slot_l1 = SlotOf(*lig, Variant(1, W, reg, 0));
            EXPECT_NE(slot_l0, kVexInvalidFormIndex);
            EXPECT_EQ(slot_l0, slot_l1) << "W=" << int(W) << " reg=" << int(reg);
        }
    }
}

TEST(VexVariantFocused, ScalarMoveAppliesFormAwareVvvv)
{
    // VMOVSS load (0F 10 pp=2): register merge form needs a non-reserved vvvv
    // and carries the 3-operand NDS pattern; the memory load needs the
    // reserved value and carries the 2-operand pattern.
    const auto* rec = detail::VexLookupVariantDescriptor(0x01, 0x10, 2);
    ASSERT_NE(rec, nullptr);
    for (uint8_t L = 0; L < 2; ++L) {
        for (uint8_t W = 0; W < 2; ++W) {
            const auto* reg_form = detail::VexResolvedFormForVariant(*rec, Variant(L, W, 1, 0));
            ASSERT_NE(reg_form, nullptr) << "L=" << int(L) << " W=" << int(W);
            EXPECT_EQ(reg_form->opcode, OpcodeId::VMOVSS);
            EXPECT_EQ(reg_form->operand_count, 3);
            EXPECT_EQ(reg_form->operands[0], Operand::xmm);
            EXPECT_EQ(reg_form->operands[1], Operand::xmm);
            EXPECT_EQ(reg_form->operands[2], Operand::xmm);

            const auto* mem_form = detail::VexResolvedFormForVariant(*rec, Variant(L, W, 0, 1));
            ASSERT_NE(mem_form, nullptr);
            EXPECT_EQ(mem_form->opcode, OpcodeId::VMOVSS);
            EXPECT_EQ(mem_form->operand_count, 2);
            EXPECT_EQ(mem_form->operands[0], Operand::xmm);
            EXPECT_EQ(mem_form->operands[1], Operand::m32);

            // The mismatched vvvv/form combinations are invalid variants.
            EXPECT_FALSE(MaskValid(*rec, Variant(L, W, 1, 1)));
            EXPECT_FALSE(MaskValid(*rec, Variant(L, W, 0, 0)));
        }
    }
}

TEST(VexVariantFocused, InvalidFieldCombinationsHaveNoForm)
{
    // VPERMPD (0F3A 01 pp=66) is W=1 only: every W=0 slot is invalid and
    // carries no speculative resolved form.
    const auto* permpd = detail::VexLookupVariantDescriptor(0x03, 0x01, 1);
    ASSERT_NE(permpd, nullptr);
    for (uint8_t reg = 0; reg < 2; ++reg) {
        for (uint8_t reserved = 0; reserved < 2; ++reserved) {
            EXPECT_FALSE(MaskValid(*permpd, Variant(1, 0, reg, reserved)));
            EXPECT_EQ(SlotOf(*permpd, Variant(1, 0, reg, reserved)), kVexInvalidFormIndex);
        }
    }
    // VBROADCASTSD (0F38 19 pp=66) is L=1 only.
    const auto* bsd = detail::VexLookupVariantDescriptor(0x02, 0x19, 1);
    ASSERT_NE(bsd, nullptr);
    for (uint8_t W = 0; W < 2; ++W) {
        for (uint8_t reg = 0; reg < 2; ++reg) {
            for (uint8_t reserved = 0; reserved < 2; ++reserved) {
                EXPECT_FALSE(MaskValid(*bsd, Variant(0, W, reg, reserved)));
                EXPECT_EQ(SlotOf(*bsd, Variant(0, W, reg, reserved)), kVexInvalidFormIndex);
            }
        }
    }
    // W=1/L=1 slot resolves to the concrete form for the legal combination.
    const auto* form = detail::VexResolvedFormForVariant(*permpd, Variant(1, 1, 0, 1));
    ASSERT_NE(form, nullptr);
    EXPECT_EQ(form->opcode, OpcodeId::VPERMPD);
    EXPECT_EQ(form->operand_count, 3);
    EXPECT_EQ(form->trailing_size, 1);
}

TEST(VexVariantFocused, AbsentDescriptorHasNoRecord)
{
    // Unimplemented (map, opcode, pp) space stays empty: no record, and the
    // whole record array has no entry pointing at it.
    for (uint8_t pp = 0; pp < 4; ++pp) {
        EXPECT_EQ(detail::VexLookupVariantDescriptor(0x01, 0x30, pp), nullptr);
    }
    // NDS integer row gaps, e.g. 0F38 B2 (not a VEX opcode).
    EXPECT_EQ(detail::VexLookupVariantDescriptor(0x02, 0xB2, 1), nullptr);
    EXPECT_EQ(detail::VexLookupVariantDescriptor(0x03, 0x7F, 1), nullptr);
}

} // namespace
} // namespace xendiza

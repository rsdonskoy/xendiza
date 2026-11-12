// Differential oracle for the compile-time VEX variant expansion.
//
// The reference selector below mirrors the pre-change production selection
// cascade (per-W/per-L/LIG form precedence, shape checks, descriptor-wide and
// form-aware vvvv policies, memory-opcode and W-opcode overrides, gather
// operand patterns) as it existed before the variant tables.  It is written
// against the raw VexDescriptor model, independent of the expansion code in
// src/vex_decode.cpp.  For every descriptor and all 16 variants the test
// requires the precomputed variant data to agree with the reference on
// validity, error class, and the complete resolved result (final opcode, all
// four operand slots, trailing metadata, mode mask).  Group descriptors are
// compared on their sub-table identity plus the per-(L, W, vvvv) validity the
// variant mask can encode; group entry selection stays dynamic and is
// covered by the decode-level tests.

#include <gtest/gtest.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <gsl/span>

#include <xendiza/detail/instruction.hpp>
#include <xendiza/detail/vex.hpp>
#include <xendiza/detail/vex_decode.hpp>

namespace xendiza {
namespace {

using detail::kVexInvalidFormIndex;
using detail::VexDescriptor;
using detail::VexModrmShape;
using detail::VexOpForm;
using detail::VexRawDescriptorRef;
using detail::VexResolvedForm;
using detail::VexVariantDescriptor;
using detail::VexVariantGroup;
using detail::VexVariantNoModrm;
using detail::VexVariantVsib;

// ---- Reference selection (pre-change semantics, independently written) ----

enum class RefOutcome : uint8_t {
    kValid,       // Selection produced a concrete form.
    kUndefined,   // Selection rejected the encoding (UNDEFINED_INSTRUCTION).
};

struct RefSelection {
    RefOutcome outcome = RefOutcome::kUndefined;
    VexResolvedForm resolved{};
};

auto RefSelectBaseForm(const VexDescriptor& d, const uint8_t L, const uint8_t W) -> const VexOpForm*
{
    if (d.forms_by_W[W].has_value()) return &d.forms_by_W[W].value();
    if (d.forms_by_L[L].has_value()) return &d.forms_by_L[L].value();
    if (L == 1 && d.forms_by_L[0].has_value() && d.forms_by_reg[1] == nullptr) {
        // LIG: L=1 reuses the L=0 form when the descriptor explicitly allows it.
        return &d.forms_by_L[0].value();
    }
    return nullptr;
}

// Mirrors the pre-change vvvv policy for forms that read a ModR/M byte.
auto RefVvvvOkModrm(const VexDescriptor& d, const bool is_reg, const bool reserved) -> bool
{
    bool require_nonreserved = d.vvvv_required;
    bool require_reserved = !d.vvvv_required && d.vvvv_reserved;
    if (is_reg && d.reg_vvvv_required) {
        require_nonreserved = true;
        require_reserved = false;
    }
    if (!is_reg && d.mem_vvvv_reserved) {
        require_nonreserved = false;
        require_reserved = true;
    }
    if (require_nonreserved && reserved) return false;
    if (require_reserved && !reserved) return false;
    return true;
}

// Mirrors the operand/opcode resolution of the pre-change Decode tail.
auto RefResolveOperands(const VexDescriptor& d, const VexOpForm& f,
                        const uint8_t L, const uint8_t W, const bool is_reg) -> VexResolvedForm
{
    VexResolvedForm r{};
    r.trailing_size = f.trailing_size;
    r.trailing_role = f.trailing_role;
    r.allowed_modes = f.allowed_modes;
    if (d.uses_vsib && d.gather_operands_valid[W][L]) {
        r.opcode = d.opcode_by_W[W];
        const auto& g = d.gather_operands[W][L];
        r.operands = { g[0], g[1], g[2], Operand::noopr };
        r.operand_count = 3;
        return r;
    }
    r.opcode = d.opcode_by_W[W] != OpcodeId::INVALID_OPCODE ? d.opcode_by_W[W]
        : (!is_reg && f.mem_opcode != OpcodeId::INVALID_OPCODE) ? f.mem_opcode
        : f.opcode;
    if (is_reg) {
        r.operands = f.operands;
        r.operand_count = f.operand_count;
    } else {
        r.operands = f.mem_operands;
        r.operand_count = f.mem_operand_count;
        if (d.uses_vsib) {
            for (auto& op : r.operands) {
                if (op == Operand::m) op = d.vsib_op[W];
            }
        }
    }
    return r;
}

auto RefIsGroup(const VexDescriptor& d) -> bool
{
    return d.forms_by_reg[0] != nullptr || d.forms_by_reg[1] != nullptr;
}

// Full pre-change selection for one variant input.  Machine mode is not part
// of the variant; the pre-change mode check is folded into the
// `resolved.allowed_modes` field and verified field-by-field below.
auto RefSelect(const VexDescriptor& d, const uint8_t L, const uint8_t W,
             const bool is_reg, const bool reserved) -> RefSelection
{
    if ((d.allowed_L & (1u << L)) == 0) return {};
    if ((d.allowed_W & (1u << W)) == 0) return {};

    if (RefIsGroup(d)) {
        // Group entry selection needs ModR/M.reg (outside the variant); the
        // reference validates everything the variant mask encodes: the (L, W)
        // fields, the presence of the per-L sub-table, and the descriptor-level
        // vvvv policy.
        if (d.forms_by_reg[L] == nullptr) return {};
        if (!RefVvvvOkModrm(d, is_reg, reserved)) return {};
        return { RefOutcome::kValid, {} };
    }

    const VexOpForm* form = RefSelectBaseForm(d, L, W);
    if (form == nullptr) return {};
    if (form->shape == VexModrmShape::None) {
        // No-ModR/M forms only exist on the canonical register-side variant.
        if (!is_reg) return {};
        // ...and apply the descriptor-wide (non-form-aware) vvvv policy.
        if ((d.vvvv_required && reserved)
            || (!d.vvvv_required && d.vvvv_reserved && !reserved)) {
            return {};
        }
        RefSelection s{ RefOutcome::kValid, {} };
        s.resolved.opcode = form->opcode;
        s.resolved.operands = form->operands;
        s.resolved.operand_count = form->operand_count;
        s.resolved.trailing_size = form->trailing_size;
        s.resolved.trailing_role = form->trailing_role;
        s.resolved.allowed_modes = form->allowed_modes;
        return s;
    }
    if (form->shape == VexModrmShape::Reg && !is_reg) return {};
    if (form->shape == VexModrmShape::Mem && is_reg) return {};
    if (!RefVvvvOkModrm(d, is_reg, reserved)) return {};
    return { RefOutcome::kValid, RefResolveOperands(d, *form, L, W, is_reg) };
}

// ---- Comparison helpers ---------------------------------------------------

auto Describe(const VexRawDescriptorRef& ref) -> std::string
{
    std::ostringstream os;
    os << "map=0x" << int(ref.map) << " opcode=0x" << int(ref.opcode)
       << " pp=" << int(ref.pp);
    return os.str();
}

auto SameResolved(const VexResolvedForm& a, const VexResolvedForm& b) -> bool
{
    return a.opcode == b.opcode
        && a.operand_count == b.operand_count
        && a.operands == b.operands
        && a.trailing_size == b.trailing_size
        && a.trailing_role == b.trailing_role
        && a.allowed_modes == b.allowed_modes;
}

void ExpectRecordFlags(const VexRawDescriptorRef& ref, const VexVariantDescriptor& rec)
{
    const auto* d = ref.descriptor;
    bool any_no_modrm = false;
    for (const auto& f : d->forms_by_L) {
        any_no_modrm |= f.has_value() && f->shape == VexModrmShape::None;
    }
    for (const auto& f : d->forms_by_W) {
        any_no_modrm |= f.has_value() && f->shape == VexModrmShape::None;
    }
    EXPECT_EQ((rec.flags & VexVariantNoModrm) != 0, any_no_modrm) << Describe(ref);
    EXPECT_EQ((rec.flags & VexVariantGroup) != 0, RefIsGroup(*d)) << Describe(ref);
    EXPECT_EQ((rec.flags & VexVariantVsib) != 0, d->uses_vsib) << Describe(ref);
    const uint8_t field_mask = static_cast<uint8_t>(
        ((d->allowed_L & 1) && (d->allowed_W & 1) ? 0x01 : 0)
        | ((d->allowed_L & 1) && (d->allowed_W & 2) ? 0x02 : 0)
        | ((d->allowed_L & 2) && (d->allowed_W & 1) ? 0x04 : 0)
        | ((d->allowed_L & 2) && (d->allowed_W & 2) ? 0x08 : 0));
    EXPECT_EQ(rec.field_mask, field_mask) << Describe(ref);
}

// ---- Tests ----------------------------------------------------------------

TEST(VexVariantExpansion, EveryDescriptorVariantMatchesReference)
{
    const auto refs = detail::VexRawDescriptors();
    const auto records = detail::VexVariantDescriptors();
    const auto slots = detail::VexVariantSlots();
    const auto forms = detail::VexResolvedForms();
    ASSERT_EQ(refs.size(), records.size());

    for (size_t i = 0; i < refs.size(); ++i) {
        const auto& ref = refs[i];
        const auto& rec = records[i];
        ExpectRecordFlags(ref, rec);

        const auto* direct = detail::VexLookupVariantDescriptor(ref.map, ref.opcode, ref.pp);
        ASSERT_EQ(direct, &rec) << Describe(ref);

        const bool group = RefIsGroup(*ref.descriptor);

        for (uint8_t L = 0; L < 2; ++L) {
            for (uint8_t W = 0; W < 2; ++W) {
                for (uint8_t reg = 0; reg < 2; ++reg) {
                    for (uint8_t reserved = 0; reserved < 2; ++reserved) {
                        const uint8_t variant = static_cast<uint8_t>((L << 3) | (W << 2) | (reg << 1) | reserved);
                        const bool mask_valid = (rec.valid_mask & (1u << variant)) != 0;
                        const auto* actual = detail::VexResolvedFormForVariant(rec, variant);
                        const uint16_t slot = slots[rec.variant_base + variant];

                        const auto expect = RefSelect(*ref.descriptor, L, W, reg != 0, reserved != 0);
                        const bool expect_valid = expect.outcome == RefOutcome::kValid;

                        EXPECT_EQ(mask_valid, expect_valid)
                            << Describe(ref) << " L=" << int(L) << " W=" << int(W)
                            << " reg=" << int(reg) << " reserved=" << int(reserved);
                        if (!expect_valid) {
                            // Invalid variants carry no speculative form.
                            EXPECT_EQ(actual, nullptr) << Describe(ref);
                            EXPECT_EQ(slot, kVexInvalidFormIndex) << Describe(ref);
                            continue;
                        }
                        if (group) {
                            // Group forms resolve per ModR/M.reg entry at decode
                            // time; the variant only gates (L, W, vvvv).
                            EXPECT_EQ(actual, nullptr) << Describe(ref);
                            EXPECT_EQ(slot, kVexInvalidFormIndex) << Describe(ref);
                            continue;
                        }
                        ASSERT_NE(actual, nullptr) << Describe(ref);
                        ASSERT_NE(slot, kVexInvalidFormIndex) << Describe(ref);
                        ASSERT_LT(slot, forms.size()) << Describe(ref);
                        // Form identity + final opcode + all four operand slots +
                        // trailing metadata + mode mask must match the reference.
                        EXPECT_TRUE(SameResolved(*actual, expect.resolved))
                            << Describe(ref) << " L=" << int(L) << " W=" << int(W)
                            << " reg=" << int(reg) << " reserved=" << int(reserved);
                    }
                }
            }
        }
    }
}

// Group descriptors: the variant record must share the exact per-L sub-table
// pointers the reference selection uses, and every ModR/M.reg entry must
// obey the shape/mode semantics the decode path re-applies dynamically.
TEST(VexVariantExpansion, GroupEntriesMatchSubTableSemantics)
{
    const auto refs = detail::VexRawDescriptors();
    const auto records = detail::VexVariantDescriptors();
    ASSERT_EQ(refs.size(), records.size());

    bool saw_group = false;
    for (size_t i = 0; i < refs.size(); ++i) {
        const auto& ref = refs[i];
        const auto& d = *ref.descriptor;
        if (!RefIsGroup(d)) continue;
        saw_group = true;
        const auto& rec = records[i];
        ASSERT_TRUE((rec.flags & VexVariantGroup) != 0) << Describe(ref);

        for (uint8_t L = 0; L < 2; ++L) {
            const auto* sub = d.forms_by_reg[L];
            // The record exposes the identical sub-table object.
            EXPECT_EQ(rec.group_forms[L], sub) << Describe(ref);
            if (sub == nullptr) continue;
            for (uint8_t reg_field = 0; reg_field < 8; ++reg_field) {
                const auto& entry = (*sub)[reg_field];
                if (!entry.has_value()) continue;
                const auto& f = entry.value();
                // Register and memory sides both stay reachable so the decode
                // path can apply its shape check; both must carry complete
                // metadata (opcode, operands, trailing bytes, modes).
                EXPECT_NE(f.opcode, OpcodeId::INVALID_OPCODE) << Describe(ref);
                EXPECT_GT(f.operand_count, 0) << Describe(ref);
                for (bool is_reg : { false, true }) {
                    const uint8_t n = is_reg ? f.operand_count : f.mem_operand_count;
                    const auto& ops = is_reg ? f.operands : f.mem_operands;
                    for (uint8_t k = 0; k < n; ++k) {
                        EXPECT_NE(ops[k], Operand::noopr) << Describe(ref);
                    }
                    // Imm8/is4 group entries declare exactly one trailing byte.
                    if (f.trailing_size > 0) {
                        EXPECT_EQ(f.trailing_size, 1) << Describe(ref);
                    }
                }
            }
        }
    }
    EXPECT_TRUE(saw_group);
}

// Absent (map, opcode, pp) combinations have no variant record and decode as
// UNIMPLEMENTED_DISASM; invalid maps and pp values are rejected too.
TEST(VexVariantExpansion, AbsentDescriptorsHaveNoRecord)
{
    EXPECT_EQ(detail::VexLookupVariantDescriptor(0x00, 0x59, 0), nullptr);
    EXPECT_EQ(detail::VexLookupVariantDescriptor(0x04, 0x59, 0), nullptr);
    EXPECT_EQ(detail::VexLookupVariantDescriptor(0xFF, 0x59, 0), nullptr);
    EXPECT_EQ(detail::VexLookupVariantDescriptor(0x01, 0x59, 4), nullptr);
    // Known-empty slots in otherwise populated rows.
    EXPECT_EQ(detail::VexLookupVariantDescriptor(0x01, 0x00, 0), nullptr);
    EXPECT_EQ(detail::VexLookupVariantDescriptor(0x02, 0xFF, 3), nullptr);
    EXPECT_EQ(detail::VexLookupVariantDescriptor(0x03, 0x42, 2), nullptr);
    // Present sanity anchors.
    EXPECT_NE(detail::VexLookupVariantDescriptor(0x01, 0x59, 0), nullptr);
    EXPECT_NE(detail::VexLookupVariantDescriptor(0x02, 0x90, 1), nullptr);
    EXPECT_NE(detail::VexLookupVariantDescriptor(0x03, 0x18, 1), nullptr);
}

} // namespace
} // namespace xendiza

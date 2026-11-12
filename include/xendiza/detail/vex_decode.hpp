#ifndef XENDIZA_VEX_DECODE_HPP
#define XENDIZA_VEX_DECODE_HPP

#include "vex.hpp"
#include "xendiza_common.hpp"

#include <array>
#include <optional>

namespace xendiza::detail {

enum class VexModrmShape : uint8_t {
    None = 0,
    Reg  = 1,
    Mem  = 2,
    Both = 3,
};

enum class VexTrailingRole : uint8_t {
    None = 0,
    Imm8 = 1,
    Is4  = 2,
};

struct VexOpForm {
    OpcodeId opcode;
    uint8_t operand_count;
    std::array<Operand, 4> operands;      // register form (or the only form)
    std::array<Operand, 4> mem_operands;  // memory form; ignored unless shape == Mem/Both
    uint8_t mem_operand_count;
    VexModrmShape shape;
    uint8_t trailing_size;
    VexTrailingRole trailing_role;
    OpcodeId mem_opcode = OpcodeId::INVALID_OPCODE; // Optional memory-form mnemonic.
    uint8_t allowed_modes = 0x03;                   // bit 0: 32-bit, bit 1: 64-bit.
};

using VexGroupForms = std::array<std::optional<VexOpForm>, 8>;

struct VexDescriptor {
    // Bitmask of permitted L values: bit 0 -> L=0, bit 1 -> L=1.
    uint8_t allowed_L = 0;
    // Bitmask of permitted W values: bit 0 -> W=0, bit 1 -> W=1.
    uint8_t allowed_W = 0;
    // vvvv policy.  NDS forms require vvvv != 1111 everywhere.  Non-NDS forms
    // normally require the reserved value vvvv == 1111.  Scalar moves are the
    // exception: the register merge form is NDS (vvvv != 1111) while the memory
    // load/store forms require the reserved value, so the policy is form-aware.
    bool vvvv_required = false;      // vvvv != 1111 for both reg and memory forms
    bool vvvv_reserved = true;       // vvvv == 1111 for non-NDS forms (overridden below)
    bool reg_vvvv_required = false;  // register form specifically requires vvvv != 1111
    bool mem_vvvv_reserved = false;  // memory form specifically requires vvvv == 1111
    // If true, memory forms use a VSIB byte instead of an ordinary SIB.
    bool uses_vsib = false;
    // VSIB memory operand to emit for W=0 and W=1 (valid when uses_vsib is true).
    std::array<Operand, 2> vsib_op = { Operand::noopr, Operand::noopr };
    // Opcode indexed by W for forms whose mnemonic changes with the W bit
    // (e.g., AVX2 variable shifts, gather).  When a value is INVALID_OPCODE,
    // the form's own opcode is used unchanged.
    std::array<OpcodeId, 2> opcode_by_W = { OpcodeId::INVALID_OPCODE, OpcodeId::INVALID_OPCODE };
    // Gather-specific operand patterns indexed by [W][L].  Each entry stores the
    // three abstract operands in architectural order: destination, VSIB memory,
    // mask.  Needed because some gather forms (e.g., VPGATHERQD) use XMM
    // destination/mask with a YMM vector index in the L=1 case.
    std::array<std::array<std::array<Operand, 3>, 2>, 2> gather_operands = {};
    std::array<std::array<bool, 2>, 2> gather_operands_valid = {};
    // Per-L form.  Only entries with a bit set in allowed_L are populated.
    std::array<std::optional<VexOpForm>, 2> forms_by_L;
    // Optional per-W forms for encodings whose operands/mnemonic depend on W.
    std::array<std::optional<VexOpForm>, 2> forms_by_W;
    // Optional ModR/M.reg sub-tables indexed by L.  Used by group encodings.
    std::array<const VexGroupForms*, 2> forms_by_reg = {};
};

struct VexDecodeResult {
    DecodedInstruction result;
    uint8_t total_length;
};

// Resolved VEX form for one concrete variant (L, W, register/memory side, and
// reserved-vvvv state).  Produced at compile time by expanding the descriptor
// metadata; the hot path selects this record directly instead of re-running
// the descriptor interpretation cascade.
struct VexResolvedForm {
    OpcodeId opcode;                   // Final mnemonic after W/mem overrides.
    std::array<Operand, 4> operands;   // Concrete operand pattern for the variant.
    uint8_t operand_count;
    uint8_t trailing_size;
    VexTrailingRole trailing_role;
    uint8_t allowed_modes;           // bit 0: 32-bit, bit 1: 64-bit (checked at decode).

    bool operator==(const VexResolvedForm&) const = default;
};

// Variant-table invariants (produced by the compile-time expansion in
// vex_decode.cpp, consumed only by VexDecoder::Decode and the test accessors):
//
//  * Slot index within a descriptor is the four-bit variant
//        variant = L<<3 | W<<2 | register_side<<1 | reserved_vvvv
//    where register_side is the ModR/M mod==11 bit for ModR/M-bearing
//    forms and the canonical value 1 for NoModrm forms, and reserved_vvvv
//    is (VEX.vvvv == 0xF).
//  * valid_mask bit v is set iff the (L, W) fields are permitted, the form
//    selected by the W-priority -> L -> LIG-fallback cascade exists, the
//    reg/mem shape is allowed, and the descriptor/form vvvv policy holds for
//    the slot's reserved bit.  Decode tests this mask before reading beyond
//    the ModR/M byte, preserving the pre-change error order.
//  * field_mask bit (L<<1|W) is the descriptor-wide (L, W) gate; Decode checks
//    it before the ModR/M read so a disallowed field combination reports
//    UNDEFINED rather than INSUFFICIENT_BUFFER on truncated input.
//  * Variants that resolve to an identical VexResolvedForm share one interned
//    pool entry (WIG/LIG aliases and reg/mem forms with identical shapes), so
//    a descriptor's 16 slots reference at most a handful of distinct forms.
//  * Slots without a resolved form store kVexInvalidFormIndex: invalid
//    variants, and every slot of a Group descriptor, whose concrete form is
//    chosen dynamically by ModR/M.reg from the per-L sub-table so absence,
//    shape, and mode errors stay byte-exact.
//  * Group descriptor valid bits encode only "the per-L sub-table exists and
//    the vvvv policy passes"; the resolved form is assembled per decode.
//  * NoModrm descriptors resolve entirely from the static variant (canonical
//    register_side = 1); their vvvv policy still applies through the
//    reserved bit, so e.g. VZEROUPPER accepts only the reserved encoding.
//  * VSIB/gather checks (address-size, SIB presence, index/dest/mask overlap)
//    and the trailing-byte/15-byte bounds live in Decode, keyed off the
//    VexVariantVsib flag and the resolved form's trailing_size, unchanged
//    from the pre-change behavior.

// Descriptor-level flags carried by the precomputed variant table.
enum VexVariantFlags : uint8_t {
    VexVariantNone    = 0x00,
    VexVariantNoModrm = 0x01,  // Forms carry no ModR/M; variant uses the canonical reg=1 side.
    VexVariantGroup   = 0x02,  // ModR/M.reg selects a per-L group sub-table entry.
    VexVariantVsib    = 0x04,  // VSIB memory handling plus gather operand/overlap checks.
};

// One record per present (map, opcode, pp) descriptor in the flat index.
struct VexVariantDescriptor {
    uint16_t valid_mask;    // bit (L<<3 | W<<2 | reg<<1 | reserved): the variant is legal.
    uint16_t variant_base;  // Base index into the 16 contiguous slots of this descriptor.
    uint8_t field_mask;     // bit (L<<1 | W): permitted (L, W) field combination.
    uint8_t flags;          // VexVariantFlags.
    std::array<const VexGroupForms*, 2> group_forms;  // Per-L sub-tables (Group flag only).
};

// Sentinel stored in variant slots that have no resolved form (invalid
// variants and group descriptors, whose forms resolve per group entry).
inline constexpr uint16_t kVexInvalidFormIndex = 0xFFFF;

#ifdef XENDIZA_VEX_VARIANT_TEST_ACCESS
struct VexRawDescriptorRef {
    uint8_t map;
    uint8_t opcode;
    uint8_t pp;
    const VexDescriptor* descriptor;
};

// Test-only accessors over the precomputed variant data. The dedicated variant
// test target compiles the implementation with this interface enabled; normal
// library consumers do not retain raw descriptors or test accessor symbols.
auto VexRawDescriptors() noexcept -> gsl::span<const VexRawDescriptorRef>;
auto VexVariantDescriptors() noexcept -> gsl::span<const VexVariantDescriptor>;
auto VexVariantSlots() noexcept -> gsl::span<const uint16_t>;
auto VexResolvedForms() noexcept -> gsl::span<const VexResolvedForm>;
#endif

// Returns the variant record for (map, opcode, pp), or nullptr when the flat
// index has no descriptor (UNIMPLEMENTED_DISASM territory).
auto VexLookupVariantDescriptor(uint8_t map, uint8_t opcode, uint8_t pp) noexcept
    -> const VexVariantDescriptor*;

// Returns the resolved form of a valid variant slot, or nullptr when the
// variant is invalid or holds no resolved form (group descriptors resolve
// per group entry at decode time).
auto VexResolvedFormForVariant(const VexVariantDescriptor& desc, uint8_t variant) noexcept
    -> const VexResolvedForm*;

// Shared VEX decode engine.  Caller has already recognized a valid VEX prefix
// and supplies the VexInfo.
class VexDecoder {
public:
    static auto Decode(gsl::span<const uint8_t> buffer, const VexInfo& info) noexcept
        -> DecodedInstruction;
};

} // namespace xendiza::detail

#endif // XENDIZA_VEX_DECODE_HPP

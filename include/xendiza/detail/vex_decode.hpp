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

// Shared VEX decode engine.  Caller has already recognized a valid VEX prefix
// and supplies the VexInfo.
class VexDecoder {
public:
    static auto Decode(gsl::span<const uint8_t> buffer, const VexInfo& info) noexcept
        -> DecodedInstruction;
};

} // namespace xendiza::detail

#endif // XENDIZA_VEX_DECODE_HPP

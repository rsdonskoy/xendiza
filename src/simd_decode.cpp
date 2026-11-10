#include "xendiza/detail/simd_decode.hpp"

#include "xendiza/detail/xendiza_common.hpp"

#include <xendiza/xendiza_x64.hpp>
#include <xendiza/xendiza_x86.hpp>

namespace xendiza::detail {

namespace {

// Generic SIMD execution engine. Three uniform rules (design.md Decision 2):
//   1. mixed mandatory prefixes (66h + F2/F3) → UNDEFINED (enforced by the
//      slot selection at the dispatch helper, never reaches a slot);
//   2. REX.W applies only to operands the descriptor marks (rex_w_* masks)
//      plus any declared per-form mnemonic override; 66h never shrinks;
//      unmarked rows ignore REX.W entirely;
//   3. any INVALID mnemonic or operand in the selected slot → UNDEFINED.
// `modrm_len` comes from the caller (kLengthTable_ModRM + SIB base=5 fix);
// the returned length is relative to the start of the 0F byte.
// `apply_66_shrink` is set by size-override rows (MOVBE/CRC32) when a 66h
// operand-size override is present; the shrink then applies through the
// selected slot's shrink_66 mask, but only when REX.W is clear (REX.W takes
// precedence and widens instead).
auto DecodeSimdRow(const SimdRow& row, const uint8_t slot_index, const bool rex_w,
                   const uint8_t modrm, const uint8_t modrm_len,
                   const bool apply_66_shrink = false) noexcept
    -> DecodedInstruction
{
    const bool is_reg = (modrm & 0b11'000'000u) == 0b11'000'000u;
    // Reg-field sub-table rows (66 0F 71/72/73): the 66h slot's mod=11 forms
    // resolve through the sub-table; memory forms and the absent prefixes
    // (none/F3/F2, incl. the MMX forms) use the row slots (INVALID there).
    const auto& slot = (is_reg && row.reg_subtable != nullptr && slot_index == 1)
        ? (*row.reg_subtable)[(modrm >> 3) & 7u]
        : row.slots[slot_index];

    auto opcode = is_reg ? slot.opcode_reg : slot.opcode_mem;
    auto pair   = is_reg ? slot.pair_reg : slot.pair_mem;
    if (opcode == OpcodeId::INVALID_OPCODE || pair.operand[0] == Operand::invalid
        || pair.operand[1] == Operand::invalid) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    if (rex_w) {
        const auto override_op = is_reg ? slot.opcode_reg_w : slot.opcode_mem_w;
        if (override_op != OpcodeId::INVALID_OPCODE) {
            opcode = override_op;
        }
        const auto widen_mask = is_reg ? slot.rex_w_reg : slot.rex_w_mem;
        for (uint8_t i = 0; i < pair.operand.size(); ++i) {
            if (widen_mask & (1u << i)) {
                pair.operand[i] = SimdWidenOperandRexW(pair.operand[i]);
            }
        }
    } else if (apply_66_shrink) {
        const auto shrink_mask = slot.shrink_66;
        for (uint8_t i = 0; i < pair.operand.size(); ++i) {
            if (shrink_mask & (1u << i)) {
                pair.operand[i] = SimdShrinkOperand66(pair.operand[i]);
            }
        }
    }

    InstructionId id{};
    id.opcode   = opcode;
    id.operands = pair;
    // Pair operand count: single-operand shift forms carry {xmm}, all other
    // SSE rows carry two operands. The trailing immediate appends after them.
    id.operand_count = (pair.operand[1] == Operand::noopr) ? 1 : 2;

    // Trailing immediate occupies the first noopr slot (ordered operands).
    uint8_t imm_size = 0;
    if (row.imm_kind == SimdImmKind::imm8) {
        id.operands.operand[id.operand_count] = Operand::imm8;
        ++id.operand_count;
        imm_size = 1;
    }

    return { static_cast<uint8_t>(modrm_len + 1 + imm_size), id };
}

// Mandatory-prefix slot selection. Returns false for the mixed mandatory
// prefix rule (66h co-occurring with F2/F3) or an unknown REP byte.
template <typename PrefixInfoT>
auto SelectSimdSlot(const PrefixInfoT& prefix_info, uint8_t& slot_out) noexcept -> bool
{
    if (prefix_info.has_prefix.has_66 != 0 && prefix_info.has_prefix.has_rep != 0) {
        return false;
    }
    if (prefix_info.has_prefix.has_66 != 0) {
        slot_out = 1;
        return true;
    }
    if (prefix_info.has_prefix.has_rep != 0) {
        if (prefix_info.rep_byte == 0xF3) {
            slot_out = 2;
            return true;
        }
        if (prefix_info.rep_byte == 0xF2) {
            slot_out = 3;
            return true;
        }
        return false;
    }
    slot_out = 0;
    return true;
}

} // namespace

// Shared 2-byte SIMD dispatch: ModR/M read + SIB base=5 fix + engine call.
// Used by both the x64 and x86 Decode2ByteOpcode paths (dispatch codes 0x65
// and 0x66). `rex_w` is false in 32-bit mode (no REX prefixes there);
// `addr16` is true for the 32-bit path under a 67h prefix (16-bit addressing:
// no SIB byte, disp16 where the 32-bit form has none).
template <typename PrefixInfoT>
auto DecodeSimd2Byte(const PrefixInfoT& prefix_info, const gsl::span<const uint8_t> buffer,
                     const uint8_t opcode2, const bool rex_w, const bool addr16) noexcept
    -> DecodedInstruction
{
    if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    uint8_t slot_index = 0;
    if (!SelectSimdSlot(prefix_info, slot_index)) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    const auto modrm  = buffer[prefix_info.length + 2];
    uint8_t modrm_len = 0;
    if (addr16) {
        // 16-bit addressing: rm=100 is [SI], not a SIB escape; mod=00/rm=110
        // and mod=10 carry disp16; mod=01 carries disp8.
        modrm_len = kLengthTable_ModRM_Addr16[modrm];
    } else {
        modrm_len = kLengthTable_ModRM[modrm];

        // For mod=00,r/m=100, SIB is present. If SIB.base=101, disp32 is mandatory.
        if (ModrmHasSib(modrm)) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            if (const auto sib = buffer[prefix_info.length + 3];
                (modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
        }
    }

    const auto& row = kSimdOpcodeTable[opcode2];
    const auto [length, instrId] =
        DecodeSimdRow(row, slot_index, rex_w, modrm, modrm_len);
    if (length >= 0xE0) {
        return { length, instrId };
    }
    // The full encoding (prefixes, opcode bytes, ModR/M, SIB/displacement and
    // any trailing immediate) must be in-buffer before success, mirroring the
    // x86 modrm-with-immediate contract and rejecting truncated displacements.
    if (buffer.size() < static_cast<size_t>(prefix_info.length) + length) {
        return ERR_INSUFFICIENT_BUFFER;
    }
    return { static_cast<uint8_t>(prefix_info.length + length), instrId };
}

// Shared 3-byte (0F 38 / 0F 3A) dispatch: opcode3 table select, then the
// same ModR/M length conventions and full-encoding in-buffer contract as
// DecodeSimd2Byte, with +1 for the third opcode byte on successful lengths.
// Used by both the x64 and x86 Decode2ByteOpcode paths (dispatch code 0x3E).
// `rex_w` is false in 32-bit mode (no REX prefixes there); `addr16` is true
// for the 32-bit path under a 67h prefix (16-bit addressing: no SIB byte,
// disp16 where the 32-bit form has none).
template <typename PrefixInfoT>
auto Dispatch3ByteOpcode(const PrefixInfoT& prefix_info, const gsl::span<const uint8_t> buffer,
                         const uint8_t opcode2, const bool rex_w, const bool addr16) noexcept
    -> DecodedInstruction
{
    // opcode3 must be in-buffer before it is read.
    if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
        return ERR_INSUFFICIENT_BUFFER;
    }
    if (opcode2 != 0x38 && opcode2 != 0x3A) {
        return ERR_UNDEFINED_INSTRUCTION;
    }
    const auto opcode3 = buffer[prefix_info.length + 2];
    const auto& row = (opcode2 == 0x38) ? kDecodeTable_0F38[opcode3] : kDecodeTable_0F3A[opcode3];

    // LOCK is #UD on every 0F 38/0F 3A row (SDM exception tables: MOVBE,
    // CRC32 and all SIMD rows carry "#UD (LockPrefix)"). Rejected at the
    // shared entry for both tables and both prefix policies.
    if (prefix_info.has_prefix.has_lock != 0) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    // ModR/M must be in-buffer before it is read.
    if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    uint8_t slot_index = 0;
    const bool has_66 = prefix_info.has_prefix.has_66 != 0;
    if (row.prefix_policy == SimdPrefixPolicy::Default) {
        if (!SelectSimdSlot(prefix_info, slot_index)) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
    } else {
        // Size-override rows (MOVBE/CRC32): no REP → none slot (MOVBE),
        // F2 → F2 slot (CRC32), F3 → UNDEFINED. 66h does not select a slot.
        if (prefix_info.rep_byte == 0xF3) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        slot_index = (prefix_info.rep_byte == 0xF2) ? 3u : 0u;
    }

    const auto modrm  = buffer[prefix_info.length + 3];
    uint8_t modrm_len = 0;
    if (addr16) {
        // 16-bit addressing: no SIB byte; disp16 where the 32-bit form has none.
        modrm_len = kLengthTable_ModRM_Addr16[modrm];
    } else {
        modrm_len = kLengthTable_ModRM[modrm];

        // For mod=00,r/m=100, SIB is present. If SIB.base=101, disp32 is mandatory.
        if (ModrmHasSib(modrm)) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 4)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            if (const auto sib = buffer[prefix_info.length + 4];
                (modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
        }
    }

    const auto [length, instrId] = DecodeSimdRow(
        row, slot_index, rex_w, modrm, modrm_len,
        row.prefix_policy == SimdPrefixPolicy::SizeOverride && has_66);
    if (length >= 0xE0) {
        return { length, instrId };
    }
    // +1 for the third opcode byte on top of the engine's opcode2-relative
    // length; the full encoding (prefixes, all three opcode bytes, ModR/M,
    // SIB/displacement and any trailing immediate) must be in-buffer before
    // success, mirroring the two-byte SIMD path.
    const auto total = static_cast<uint8_t>(length + 1);
    if (buffer.size() < static_cast<size_t>(prefix_info.length) + total) {
        return ERR_INSUFFICIENT_BUFFER;
    }
    return { static_cast<uint8_t>(prefix_info.length + total), instrId };
}

template auto DecodeSimd2Byte<PrefixInfo>(const PrefixInfo&, gsl::span<const uint8_t>, uint8_t,
                                          bool, bool) -> DecodedInstruction;
template auto DecodeSimd2Byte<PrefixInfo32>(const PrefixInfo32&, gsl::span<const uint8_t>, uint8_t,
                                            bool, bool) -> DecodedInstruction;
template auto Dispatch3ByteOpcode<PrefixInfo>(const PrefixInfo&, gsl::span<const uint8_t>, uint8_t,
                                              bool, bool) -> DecodedInstruction;
template auto Dispatch3ByteOpcode<PrefixInfo32>(const PrefixInfo32&, gsl::span<const uint8_t>, uint8_t,
                                                bool, bool) -> DecodedInstruction;

} // namespace xendiza::detail

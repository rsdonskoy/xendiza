#include <xendiza/xendiza_x86.hpp>

namespace xendiza::detail {

namespace {

// x86-32 keeps an independent 0F-table view so per-mode semantic overrides
// don't leak into the shared x64 decode table.
constexpr auto kDecodeTable_1byte_opcode_32 = [] {
    auto table = kDecodeTable_1byte_opcode_shared;
    table[0x40] = DTE(0x01, IID(INC, r32));
    table[0x41] = DTE(0x01, IID(INC, r32));
    table[0x42] = DTE(0x01, IID(INC, r32));
    table[0x43] = DTE(0x01, IID(INC, r32));
    table[0x44] = DTE(0x01, IID(INC, r32));
    table[0x45] = DTE(0x01, IID(INC, r32));
    table[0x46] = DTE(0x01, IID(INC, r32));
    table[0x47] = DTE(0x01, IID(INC, r32));
    table[0x48] = DTE(0x01, IID(DEC, r32));
    table[0x49] = DTE(0x01, IID(DEC, r32));
    table[0x4A] = DTE(0x01, IID(DEC, r32));
    table[0x4B] = DTE(0x01, IID(DEC, r32));
    table[0x4C] = DTE(0x01, IID(DEC, r32));
    table[0x4D] = DTE(0x01, IID(DEC, r32));
    table[0x4E] = DTE(0x01, IID(DEC, r32));
    table[0x4F] = DTE(0x01, IID(DEC, r32));
    // AAM/AAD are valid in legacy x86-32 mode (invalid in 64-bit, where the
    // shared-table INVALID entries stay in effect).
    table[0xD4] = DTE(0xD4, IID(AAM, ax, imm8));
    table[0xD5] = DTE(0xD5, IID(AAD, ax, imm8));
    return table;
}();

constexpr auto kDecodeTable_2byte_opcode_32 = [] {
    auto table = kDecodeTable_2byte_opcode_shared;
    // 0F D6 is invalid in legacy x86-32 mode.
    table[0xD6] = DTE(0xD6, IID_INVALID);
    return table;
}();

// In 32-bit mode, shared x64 table entries that carry abstract 64-bit GPR
// forms are normalized to their 32-bit counterparts.
constexpr auto NormalizeOperandSize32(const Operand opr) noexcept -> Operand
{
    switch (opr) {
    case Operand::r64: return Operand::r32;
    case Operand::rax: return Operand::eax;
    case Operand::imm64: return Operand::imm32;
    case Operand::rm64: return Operand::rm32;
    default: return opr;
    }
}

constexpr auto ApplyOperandSize66(const Operand opr) noexcept -> Operand
{
    switch (opr) {
    case Operand::r32: return Operand::r16;
    case Operand::m32: return Operand::m16;
    case Operand::stack_m32: return Operand::stack_m16;
    case Operand::imm32: return Operand::imm16;
    case Operand::rel32: return Operand::rel16;
    case Operand::eax: return Operand::ax;
    case Operand::rm32: return Operand::rm16;
    default: return opr;
    }
}

constexpr auto ApplyAddressSize67(const Operand opr) noexcept -> Operand
{
    switch (opr) {
    case Operand::moffs32: return Operand::moffs16;
    default: return opr;
    }
}

constexpr auto IsMemoryOperand32(const Operand opr) noexcept -> bool
{
    switch (opr) {
    case Operand::m:
    case Operand::m8:
    case Operand::m16:
    case Operand::m32:
    case Operand::m64:
    case Operand::m128:
    case Operand::stack_m8:
    case Operand::stack_m16:
    case Operand::stack_m32:
    case Operand::stack_m64:
    case Operand::m32fp:
    case Operand::m64fp:
    case Operand::m80fp:
    case Operand::moffs8:
    case Operand::moffs16:
    case Operand::moffs32:
    case Operand::moffs64:
    case Operand::m16_32:
    case Operand::m16_64:
        return true;
    default:
        return false;
    }
}

constexpr auto SegmentByteToOperand32(const uint8_t seg_byte) noexcept -> Operand
{
    switch (seg_byte) {
    case static_cast<uint8_t>(Prefix32::ES_SEG): return Operand::es;
    case static_cast<uint8_t>(Prefix32::CS_SEG): return Operand::cs;
    case static_cast<uint8_t>(Prefix32::SS_SEG): return Operand::ss;
    case static_cast<uint8_t>(Prefix32::DS_SEG): return Operand::ds;
    case static_cast<uint8_t>(Prefix32::FS_SEG): return Operand::fs;
    case static_cast<uint8_t>(Prefix32::GS_SEG): return Operand::gs;
    default: return Operand::noopr;
    }
}

constexpr auto InjectSegmentForMemory(
    const InstructionId& instr_id, const Operand seg_operand) noexcept -> InstructionId
{
    // x86 mode: all six segment overrides produce composite memory operands.
    if (seg_operand == Operand::noopr) {
        return instr_id;
    }

    auto with_seg = instr_id;
    for (uint8_t i = 0; i < with_seg.operand_count; ++i) {
        if (IsMemoryOperand32(with_seg.operands.operand[i])) {
            with_seg.operands.operand[i] = MakeCompositeMemOperand(seg_operand, with_seg.operands.operand[i]);
            break;
        }
    }
    return with_seg;
}

constexpr auto ApplyPrefixSizes32(
    DecodedInstruction result, const PrefixInfo32& prefix_info) noexcept -> DecodedInstruction
{
    if (result.length >= 0xE0) {
        return result;
    }

    auto& ops = result.instrId.operands.operand;
    ops[0] = NormalizeOperandSize32(ops[0]);
    ops[1] = NormalizeOperandSize32(ops[1]);
    ops[2] = NormalizeOperandSize32(ops[2]);
    ops[3] = NormalizeOperandSize32(ops[3]);

    if (prefix_info.has_prefix.has_66 != 0) {
        // 66h shrinks imm32/rel32 payloads where operand-size override applies.
        for (uint8_t i = 0; i < result.instrId.operand_count; ++i) {
            if (result.instrId.operands.operand[i] == Operand::imm32 ||
                result.instrId.operands.operand[i] == Operand::rel32) {
                result.length = static_cast<uint8_t>(result.length - 2);
                break;
            }
        }

        ops[0] = ApplyOperandSize66(ops[0]);
        ops[1] = ApplyOperandSize66(ops[1]);
        ops[2] = ApplyOperandSize66(ops[2]);
        ops[3] = ApplyOperandSize66(ops[3]);
    }

    if (prefix_info.has_prefix.has_seg != 0) {
        result.instrId = InjectSegmentForMemory(
            result.instrId,
            SegmentByteToOperand32(prefix_info.seg_byte));
    }

    return result;
}

constexpr auto DecodeOpcodeExtension(const uint8_t dispatch_code, const uint8_t modrm_byte) noexcept
    -> DecodedInstruction
{
    switch (dispatch_code) {
    case 0x80: return GetInstructionDescriptor_opcode_extension_0x80(modrm_byte);
    case 0x81: return GetInstructionDescriptor_opcode_extension_0x81(modrm_byte);
    case 0x82: return GetInstructionDescriptor_opcode_extension_0x82(modrm_byte);
    case 0x83: return GetInstructionDescriptor_opcode_extension_0x83(modrm_byte);
    case 0x8F: return GetInstructionDescriptor_opcode_extension_0x8F(modrm_byte);
    case 0xC0: return GetInstructionDescriptor_opcode_extension_0xC0(modrm_byte);
    case 0xC1: return GetInstructionDescriptor_opcode_extension_0xC1(modrm_byte);
    case 0xC6: return GetInstructionDescriptor_opcode_extension_0xC6(modrm_byte);
    case 0xC7: return GetInstructionDescriptor_opcode_extension_0xC7(modrm_byte);
    case 0xD0: return GetInstructionDescriptor_opcode_extension_0xD0(modrm_byte);
    case 0xD1: return GetInstructionDescriptor_opcode_extension_0xD1(modrm_byte);
    case 0xD2: return GetInstructionDescriptor_opcode_extension_0xD2(modrm_byte);
    case 0xD3: return GetInstructionDescriptor_opcode_extension_0xD3(modrm_byte);
    case 0xF6: return GetInstructionDescriptor_opcode_extension_0xF6(modrm_byte);
    case 0xF7: return GetInstructionDescriptor_opcode_extension_0xF7(modrm_byte);
    case 0xFE: return GetInstructionDescriptor_opcode_extension_0xFE(modrm_byte);
    case 0xFF: return GetInstructionDescriptor_opcode_extension_0xFF(modrm_byte);
    default:
        return ERR_UNDEFINED_INSTRUCTION;
    }
}

constexpr auto DecodeOpcodeExtension_2byte(const uint8_t opcode2, const uint8_t modrm_byte) noexcept
    -> DecodedInstruction
{
    if (opcode2 == 0xBA) {
        return GetInstructionDescriptor_opcode_extension_0x0F_BA(modrm_byte);
    }
    return ERR_UNDEFINED_INSTRUCTION;
}

constexpr auto DecodeModrmWithImmediate(const PrefixInfo32& prefix_info,
    gsl::span<const uint8_t> buffer,
    const InstructionId& instr_id,
    const uint8_t immediate_size,
    const std::array<Operands, 256>& operand_form_table) noexcept -> DecodedInstruction
{
    if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    const bool addr16 = prefix_info.has_prefix.has_67 != 0;
    const auto modrm = buffer[prefix_info.length + 1];
    uint8_t modrm_len = addr16 ? kLengthTable_ModRM_Addr16[modrm] : kLengthTable_ModRM[modrm];

    const auto& [operand] = operand_form_table[modrm];
    const auto imm_operand = instr_id.operands.operand[1];
    InstructionId resolved_id = {
        instr_id.opcode,
        3,
        Operands{{ operand[0], operand[1], imm_operand, Operand::noopr }}
    };

    // rm=100 (and mod!=11) → SIB byte follows (32-bit addressing); resolve
    // stack markers. The mandatory disp32 (SIB.base=101) only applies at
    // mod=00. Under 67h there is no SIB byte: rm=100 form entries carry
    // unresolved Sib_M* markers, resolved to the plain memory classes.
    if (addr16) {
        resolved_id = ResolveSibMarkers(resolved_id, 0);
    } else if (ModrmHasSib(modrm)) {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto sib = buffer[prefix_info.length + 2];
        if ((modrm & 0b11'000'000u) == 0b00'000'000u
            && (sib & 0b000'000'111u) == 0b000'000'101u) {
            modrm_len = static_cast<uint8_t>(modrm_len + 4);
        }
        resolved_id = ResolveSibMarkers(resolved_id, sib);
    }

    auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + immediate_size);
    // Verify the full encoding (including the immediate) is in-buffer before
    // success. A 66h prefix shrinks an imm32 payload to imm16 (-2), so account
    // for that here to match the length ApplyPrefixSizes32 will report; the
    // check must not reject a buffer that is exactly large enough post-shrink.
    auto required_len = total_len;
    if (prefix_info.has_prefix.has_66 != 0 && imm_operand == Operand::imm32) {
        required_len = static_cast<uint8_t>(required_len - 2);
    }
    if (buffer.size() < static_cast<size_t>(required_len)) {
        return ERR_INSUFFICIENT_BUFFER;
    }
    return { total_len, resolved_id };
}

// SIB base=5 length correction helpers.
// When mod=00 and rm=100, a SIB byte follows the ModRM. If SIB.base=101 there
// is no base register and a disp32 is mandatory — kLengthTable_ModRM does not
// account for this extra +4, so the caller must adjust via these helpers.
// Returns true when the buffer is too short to read the SIB byte (caller should
// return ERR_INSUFFICIENT_BUFFER).
//
// 2-byte opcode form: modrm is at buffer[prefix_info.length + 2], SIB at +3.
auto AdjustModrmLenForSib_2byte(
    const PrefixInfo32& prefix_info,
    gsl::span<const uint8_t> buffer,
    const uint8_t modrm,
    uint8_t& modrm_len) noexcept -> bool
{
    if ((modrm & 0b11'000'111u) != 0b00'000'100u) {
        return false;
    }
    if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
        return true;
    }
    if (const auto sib = buffer[prefix_info.length + 3];
        (sib & 0b000'000'111u) == 0b000'000'101u) {
        modrm_len = static_cast<uint8_t>(modrm_len + 4);
    }
    return false;
}

// 1-byte opcode form: modrm is at buffer[prefix_info.length + 1], SIB at +2.
auto AdjustModrmLenForSib_1byte(
    const PrefixInfo32& prefix_info,
    gsl::span<const uint8_t> buffer,
    const uint8_t modrm,
    uint8_t& modrm_len) noexcept -> bool
{
    if ((modrm & 0b11'000'111u) != 0b00'000'100u) {
        return false;
    }
    if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
        return true;
    }
    if (const auto sib = buffer[prefix_info.length + 2];
        (sib & 0b000'000'111u) == 0b000'000'101u) {
        modrm_len = static_cast<uint8_t>(modrm_len + 4);
    }
    return false;
}

constexpr auto PrefixKind32(const uint8_t byte) noexcept -> Prefix32
{
    switch (byte) {
    case 0xF0: return Prefix32::LOCK;
    case 0xF2: return Prefix32::REPNE;
    case 0xF3: return Prefix32::REPE;
    case 0x2E: return Prefix32::CS_SEG;
    case 0x36: return Prefix32::SS_SEG;
    case 0x3E: return Prefix32::DS_SEG;
    case 0x26: return Prefix32::ES_SEG;
    case 0x64: return Prefix32::FS_SEG;
    case 0x65: return Prefix32::GS_SEG;
    case 0x66: return Prefix32::OPR_SIZE;
    case 0x67: return Prefix32::ADDR_SIZE;
    default:   return Prefix32::NONE;
    }
}

} // namespace

auto X86Traits::ProcessPrefix(gsl::span<const uint8_t> buffer) noexcept -> std::pair<PrefixInfo32, ErrorCode>
{
    PrefixInfo32 info{};
    if (buffer.empty()) {
        return { info, ErrorCode::INSUFFICIENT_BUFFER };
    }

    size_t pos { 0 };
    while (pos < buffer.size() && pos < MAX_INSTRUCTION_LENGTH) {
        const auto prefix_type = PrefixKind32(buffer[pos]);
        if (prefix_type == Prefix32::NONE || buffer[pos] == 0x0F) {
            break;
        }

        switch (prefix_type) {
        case Prefix32::LOCK:
            info.has_prefix.has_lock = 1;
            break;
        case Prefix32::REPNE:
        case Prefix32::REPE:
            info.has_prefix.has_rep = 1;
            info.rep_byte = buffer[pos];
            break;
        case Prefix32::CS_SEG:
        case Prefix32::SS_SEG:
        case Prefix32::DS_SEG:
        case Prefix32::ES_SEG:
        case Prefix32::FS_SEG:
        case Prefix32::GS_SEG:
            info.has_prefix.has_seg = 1;
            info.seg_byte = buffer[pos];
            break;
        case Prefix32::OPR_SIZE:
            info.has_prefix.has_66 = 1;
            break;
        case Prefix32::ADDR_SIZE:
            info.has_prefix.has_67 = 1;
            break;
        default:
            return { info, ErrorCode::UNDEFINED_INSTRUCTION };
        }

        ++info.length;
        ++pos;
    }

    if (pos >= MAX_INSTRUCTION_LENGTH) {
        return { info, ErrorCode::UNDEFINED_INSTRUCTION };
    }

    return { info, ErrorCode::OK };
}

auto X86Traits::Decode2ByteOpcode(const PrefixInfo32& prefix_info, gsl::span<const uint8_t> buffer) noexcept
    -> DecodedInstruction
{
    if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    const auto opcode2 = buffer[prefix_info.length + 1];
    const bool addr16 = prefix_info.has_prefix.has_67 != 0;
    switch (const auto [tag, instr_id] = kDecodeTable_2byte_opcode_32[opcode2]; tag.dispatch_code) {
    case 0x00: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        const uint8_t modrm_len = addr16 ? kLengthTable_ModRM_Addr16[modrm] : kLengthTable_ModRM[modrm];

        auto resolved_id = instr_id;
        if (const auto form_index = static_cast<size_t>(resolved_id.operands.operand[0]);
            form_index < kOperandFormTable_ModRM.size()) {
            if (const auto* form_table = kOperandFormTable_ModRM[form_index]; form_table != nullptr) {
                const auto& form = (*form_table)[modrm];
                if (form.operand[0] == Operand::invalid) {
                    return ERR_UNDEFINED_INSTRUCTION;
                }
                resolved_id.operands = form;
                resolved_id.operand_count = 2;
            }
        }
        // Under 67h rm=100 form entries carry unresolved SIB-dispatch markers
        // (no SIB byte exists); resolve them to the plain memory classes.
        if (addr16) {
            resolved_id = ResolveSibMarkers(resolved_id, 0);
        }
        const auto [length, instrId] = ApplyPrefixSizes32({ static_cast<uint8_t>(modrm_len + 1), resolved_id }, prefix_info);
        // Addr16 truncation check: the full encoding (with the 16-bit
        // displacement) must be in-buffer before reporting success.
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
        {
            const auto [length, instrId] = ApplyPrefixSizes32({ tag.instr_len, instr_id }, prefix_info);
            return { static_cast<uint8_t>(prefix_info.length + length), instrId };
        }

    // Gv_Eb: dest r32 (or r16 with 66h), src fixed at byte (r8 or m8); no REX.W in x86-32.
    case 0x56: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        const auto is_reg = (modrm & 0b11'000'000) == 0b11'000'000;
        const bool has_66 = prefix_info.has_prefix.has_66 != 0;
        auto resolved_id  = instr_id;
        resolved_id.operands.operand[0] = has_66 ? Operand::r16 : Operand::r32;
        Operand src = Operand::m8;
        if (!addr16 && !is_reg && (modrm & 0b00'000'111u) == 0b00'000'100u) { // rm=100 → SIB
            src = kSibStackForm_b[buffer[prefix_info.length + 3]];
        }
        resolved_id.operands.operand[1] = is_reg ? Operand::r8 : src;
        resolved_id.operands.operand[2] = Operand::noopr;
        resolved_id.operand_count       = 2;
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        if (addr16 && buffer.size() < static_cast<size_t>(total_len)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { total_len, resolved_id };
    }

    // Gv_Ew: dest r32 (or r16 with 66h), src fixed at word (r16 or m16); no REX.W in x86-32.
    case 0x57: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        const auto is_reg = (modrm & 0b11'000'000) == 0b11'000'000;
        const bool has_66 = prefix_info.has_prefix.has_66 != 0;
        auto resolved_id  = instr_id;
        resolved_id.operands.operand[0] = has_66 ? Operand::r16 : Operand::r32;
        Operand src = Operand::m16;
        if (!addr16 && !is_reg && (modrm & 0b00'000'111u) == 0b00'000'100u) { // rm=100 → SIB
            src = kSibStackForm_w[buffer[prefix_info.length + 3]];
        }
        resolved_id.operands.operand[1] = is_reg ? Operand::r16 : src;
        resolved_id.operands.operand[2] = Operand::noopr;
        resolved_id.operand_count       = 2;
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        if (addr16 && buffer.size() < static_cast<size_t>(total_len)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { total_len, resolved_id };
    }

    // Eb: single byte destination selected by ModR/M (r8 or m8); SETcc family.
    case 0x58: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        const auto is_reg = (modrm & 0b11'000'000) == 0b11'000'000;
        auto resolved_id  = instr_id;
        resolved_id.operands.operand[0] = is_reg ? Operand::r8 : Operand::m8;
        resolved_id.operands.operand[1] = Operand::noopr;
        resolved_id.operands.operand[2] = Operand::noopr;
        resolved_id.operand_count       = 1;
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        if (addr16 && buffer.size() < static_cast<size_t>(total_len)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { total_len, resolved_id };
    }

    // Direct two-byte register form: BSWAP r32 (no REX.W in x86-32 mode).
    case 0x59: {
        auto resolved_id = instr_id;
        resolved_id.operands.operand[0] = Operand::r32;
        const auto total_len = static_cast<uint8_t>(prefix_info.length + 2);
        return { total_len, resolved_id };
    }

    // ModR/M-based multibyte NOP (0F 1F /0)
    case 0x5A: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        if ((modrm & 0b00'111'000) != 0b00'000'000) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        if (addr16 && buffer.size() < static_cast<size_t>(total_len)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { total_len, instr_id };
    }

    // ModR/M-based Ev,Gv,imm8 forms (SHLD/SHRD Ev, Gv, imm8)
    case 0x5B: {
        // The shortest encoding after the prefixes is 0F + opcode + ModR/M + imm8.
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        const auto& form = kOperandFormTable_Ev_Gv[modrm];
        auto resolved_id = instr_id;
        resolved_id.operands = { { form.operand[0], form.operand[1], Operand::imm8 } };
        if (addr16) {
            resolved_id = ResolveSibMarkers(resolved_id, 0);
        } else if (ModrmHasSib(modrm)) {
            resolved_id = ResolveSibMarkers(resolved_id, buffer[prefix_info.length + 3]);
        }
        const auto [length, instrId] = ApplyPrefixSizes32(
            { static_cast<uint8_t>(modrm_len + 2), resolved_id }, prefix_info);
        // Addr16 truncation check: disp + trailing imm8 must be fully in-buffer.
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // ModR/M-based Ev,Gv,CL forms (SHLD/SHRD Ev, Gv, CL)
    case 0x5C: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        const auto& [operand] = kOperandFormTable_Ev_Gv[modrm];
        auto resolved_id = instr_id;
        resolved_id.operands = { { operand[0], operand[1], Operand::cl } };
        if (addr16) {
            resolved_id = ResolveSibMarkers(resolved_id, 0);
        } else if (ModrmHasSib(modrm)) {
            resolved_id = ResolveSibMarkers(resolved_id, buffer[prefix_info.length + 3]);
        }
        const auto [length, instrId] = ApplyPrefixSizes32(
            { static_cast<uint8_t>(modrm_len + 1), resolved_id }, prefix_info);
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // 0F AE Group 15: in x86-32 mode F3 variants (RDFSBASE etc.) are undefined.
    case 0x5D: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        const bool has_66 = prefix_info.has_prefix.has_66 != 0;

        // F3 register forms (RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE) are x64-only.
        if (prefix_info.rep_byte == static_cast<uint8_t>(Prefix32::REPE)) {
            return ERR_UNDEFINED_INSTRUCTION;
        }

        auto result = GetInstructionDescriptor_0F_AE(modrm, modrm_len, false, has_66);
        if (result.length >= 0xE0) {
            return result;
        }
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + result.length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + result.length), result.instrId };
    }

    // 0F 00 Group 6: SLDT/STR/LLDT/LTR/VERR/VERW; ApplyPrefixSizes32 handles 66h -> r16.
    case 0x5E: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        auto result = GetInstructionDescriptor_0F_00(modrm, modrm_len);
        if (result.length >= 0xE0) {
            return result;
        }
        const auto [length, instrId] = ApplyPrefixSizes32(result, prefix_info);
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // 0F 01 Group 7: SGDT/SIDT/LGDT/LIDT/SMSW/LMSW/INVLPG + register specials.
    case 0x5F: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        auto result = GetInstructionDescriptor_0F_01(modrm, modrm_len);
        if (result.length >= 0xE0) {
            return result;
        }
        const auto adjusted = ApplyPrefixSizes32(result, prefix_info);
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + adjusted.length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + adjusted.length), adjusted.instrId };
    }

    // 0F 20-23: MOV to/from control/debug registers; register-only.
    // In x86-32 the GPR operand is r32, not r64.
    case 0x60: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        if (const auto mod = static_cast<uint8_t>(modrm & 0b11'000'000u);
            mod != 0b11'000'000u) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        const uint8_t modrm_len = kLengthTable_ModRM[modrm];
        // Normalize r64 → r32 for 32-bit mode
        auto resolved_id = instr_id;
        resolved_id.operands.operand[0] = NormalizeOperandSize32(resolved_id.operands.operand[0]);
        resolved_id.operands.operand[1] = NormalizeOperandSize32(resolved_id.operands.operand[1]);
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        return { total_len, resolved_id };
    }

    // 0F C7 Group 9: CMPXCHG8B/RDRAND/RDSEED; no CMPXCHG16B in x86-32 (no REX.W).
    case 0x61: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        auto result = GetInstructionDescriptor_0F_C7(modrm, modrm_len);
        if (result.length >= 0xE0) {
            return result;
        }
        // RDRAND/RDSEED carry r32; apply 66h size override if present.
        const auto [length, instrId] = ApplyPrefixSizes32(result, prefix_info);
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // 0F 18 Group 16: PREFETCHNTA/T0/T1/T2 + PREFETCHW(0D) + CLDEMOTE(1C) + ENDBR(1E).
    case 0x62: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        const auto mod   = static_cast<uint8_t>(modrm & 0b11'000'000u);
        const auto reg   = static_cast<uint8_t>((modrm & 0b00'111'000u) >> 3);
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        if (addr16 && buffer.size() < static_cast<size_t>(total_len)) {
            return ERR_INSUFFICIENT_BUFFER;
        }

        if (opcode2 == 0x0D) {
            if (const bool is_reg = (mod == 0b11'000'000u);
                is_reg || reg != 1) {
                return ERR_UNDEFINED_INSTRUCTION;
            }
            return { total_len, IID(PREFETCHW, m8) };
        }

        if (opcode2 == 0x1E) {
            if (prefix_info.rep_byte != static_cast<uint8_t>(Prefix32::REPE)) {
                return ERR_UNDEFINED_INSTRUCTION;
            }
            switch (modrm) {
            case 0xFA: return { total_len, IID(ENDBR64) };
            case 0xFB: return { total_len, IID(ENDBR32) };
            default:   return ERR_UNDEFINED_INSTRUCTION;
            }
        }

        if (opcode2 == 0x1C) {
            if (const bool is_reg = (mod == 0b11'000'000u);
                is_reg || reg != 0) {
                return ERR_UNDEFINED_INSTRUCTION;
            }
            return { total_len, IID(CLDEMOTE, m8) };
        }

        // Register forms and /4-/7 memory forms are reserved NOPs.
        if (const bool is_reg = (mod == 0b11'000'000u); is_reg || reg >= 4) {
            return { total_len, IID(NOP) };
        }

        switch (reg) {
        case 0: return { total_len, IID(PREFETCHNTA, m8) };
        case 1: return { total_len, IID(PREFETCHT0,  m8) };
        case 2: return { total_len, IID(PREFETCHT1,  m8) };
        case 3: return { total_len, IID(PREFETCHT2,  m8) };
        default: return ERR_UNDEFINED_INSTRUCTION; // unreachable
        }
    }

    case 0x63: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        auto result = DecodeOpcodeExtension_2byte(opcode2, modrm);
        if (result.length >= 0xE0) {
            return result;
        }
        if (addr16) {
            // GetInstructionDescriptor_opcode_extension_0x0F_BA bakes
            // kLengthTable_ModRM + the imm8 into the returned length; replace
            // the ModR/M length component with the 16-bit-addressing length,
            // preserving the counted immediate. rm=100 entries carry
            // Sib_M* markers (no SIB byte exists) — resolve them synthetically.
            result.length = static_cast<uint8_t>(
                kLengthTable_ModRM_Addr16[modrm]
                + (result.length - kLengthTable_ModRM[modrm]));
            result.instrId = ResolveSibMarkers(result.instrId, 0);
        } else {
            // SIB base=5 post-correction: GetInstructionDescriptor_opcode_extension_0x0F_BA
            // bakes kLengthTable_ModRM into the returned length, so we add +4 here.
            if (ModrmHasSib(modrm)) {
                if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                    return ERR_INSUFFICIENT_BUFFER;
                }
                const auto sib = buffer[prefix_info.length + 3];
                if ((modrm & 0b11'000'000u) == 0b00'000'000u
                    && (sib & 0b000'000'111u) == 0b000'000'101u) {
                    result.length = static_cast<uint8_t>(result.length + 4);
                }
                result.instrId = ResolveSibMarkers(result.instrId, sib);
            }
        }
        result = ApplyPrefixSizes32(result, prefix_info);
        // Addr16 truncation check: the trailing imm8 must be fully in-buffer
        // (checked after ApplyPrefixSizes32 so a 66h shrink is reflected).
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + result.length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        result.length = static_cast<uint8_t>(prefix_info.length + result.length);
        return result;
    }

    // 0F C3 /r: MOVNTI m32, r32 (memory destination only); no REX.W upgrade in x86-32.
    case 0x64: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        if (const auto mod = static_cast<uint8_t>(modrm & 0b11'000'000u);
            mod == 0b11'000'000u) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_2byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        auto resolved_id = instr_id;
        // In x86-32 mode operands are always m32, r32.
        resolved_id.operands.operand[0] = Operand::m32;
        resolved_id.operands.operand[1] = Operand::r32;
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        if (addr16 && buffer.size() < static_cast<size_t>(total_len)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { total_len, resolved_id };
    }

    // SIMD rows: descriptor-table dispatch (kSimdOpcodeTable + DecodeSimd2Byte).
    // Same mandatory-prefix remap and rejections as the x64 path; no REX in
    // 32-bit mode. A 67h prefix switches to 16-bit addressing (no SIB, disp16).
    case 0x65:
    case 0x66:
        return DecodeSimd2Byte(prefix_info, buffer, opcode2, false,
                               prefix_info.has_prefix.has_67 != 0);

    // 0F 38/0F 3A: three-byte opcode space (SSSE3/SSE4.x/AES/PCLMUL/CRC32/
    // MOVBE) dispatched through kDecodeTable_0F38/_0F3A + Dispatch3ByteOpcode;
    // no REX in 32-bit mode, 67h switches to 16-bit addressing.
    case 0x3E:
        return Dispatch3ByteOpcode(prefix_info, buffer, opcode2, false,
                                   prefix_info.has_prefix.has_67 != 0);

    case 0xD6:
        return ERR_UNDEFINED_INSTRUCTION;

    case 0xE1:
        return ERR_UNIMPLEMENTED_DISASM;

    default:
        return ERR_UNDEFINED_INSTRUCTION;
    }
}

// Entry point: enforces the architectural 15-byte total-length limit on the
// fully decoded instruction (prefixes + opcode + ModRM/disp/imm), mirroring
// the #GP a CPU raises for over-long instructions. Error results
// (length >= 0xE0) pass through unchanged.
auto X86Traits::Disasm(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction
{
    auto result = DecodeInstruction(buffer);
    if (result.length >= 0xE0) {
        return result;
    }
    if (result.length > MAX_INSTRUCTION_LENGTH) {
        return ERR_UNDEFINED_INSTRUCTION;
    }
    return result;
}

auto X86Traits::DecodeInstruction(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction
{
    if (buffer.empty()) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    const auto [prefix_info, prefix_error] = ProcessPrefix(buffer);
    if (prefix_error != ErrorCode::OK) {
        if (prefix_error == ErrorCode::INSUFFICIENT_BUFFER) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return ERR_UNDEFINED_INSTRUCTION;
    }

    if (buffer.size() <= prefix_info.length) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    const auto opcode = buffer[prefix_info.length];
    const bool addr16 = prefix_info.has_prefix.has_67 != 0;
    switch (const auto [tag, instr_id] = kDecodeTable_1byte_opcode_32[opcode]; tag.dispatch_code) {
    case 0x00: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 1];
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_1byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        auto resolved_id = instr_id;

        if (const auto form_index = static_cast<size_t>(resolved_id.operands.operand[0]);
            form_index < kOperandFormTable_ModRM.size()) {
            if (const auto* form_table = kOperandFormTable_ModRM[form_index]; form_table != nullptr) {
                const auto& form = (*form_table)[modrm];
                if (form.operand[0] == Operand::invalid) {
                    return ERR_UNDEFINED_INSTRUCTION;
                }
                resolved_id.operands = form;
                resolved_id.operand_count = 2;
            }
        }

        // rm=100 (and mod!=11) → SIB byte follows (32-bit addressing); resolve
        // stack markers (m* vs stack_m*) before size fixups.
        // AdjustModrmLenForSib_1byte already verified the SIB byte is in-buffer.
        // Under 67h there is no SIB byte: rm=100 form entries carry unresolved
        // Sib_M* markers, resolved to the plain memory classes.
        if (addr16) {
            resolved_id = ResolveSibMarkers(resolved_id, 0);
        } else if (ModrmHasSib(modrm)) {
            const auto sib = buffer[prefix_info.length + 2];
            resolved_id = ResolveSibMarkers(resolved_id, sib);
        }

        const auto [length, instrId] = ApplyPrefixSizes32({ modrm_len, resolved_id }, prefix_info);
        // Addr16 truncation check: the 16-bit displacement must be in-buffer.
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    case 0xA1: {
        auto di = DecodeModrmWithImmediate(prefix_info, buffer, instr_id, 1, kOperandFormTable_Gv_Ev);
        if (di.length >= 0xE0) {
            return di;
        }
        auto [length, instrId] = ApplyPrefixSizes32({ static_cast<uint8_t>(di.length - prefix_info.length), di.instrId }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    case 0xA4: {
        auto di = DecodeModrmWithImmediate(prefix_info, buffer, instr_id, 4, kOperandFormTable_Gv_Ev);
        if (di.length >= 0xE0) {
            return di;
        }
        auto [length, instrId] = ApplyPrefixSizes32({ static_cast<uint8_t>(di.length - prefix_info.length), di.instrId }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    case 0xEE: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 1];
        auto result = DecodeOpcodeExtension(opcode, modrm);
        if (result.length >= 0xE0) {
            return result;
        }
        if (addr16) {
            // The extension helpers (0x80…0xFF) bake kLengthTable_ModRM plus
            // any immediates into the returned length; replace the ModR/M
            // length component with the 16-bit-addressing length, preserving
            // the counted immediates. rm=100 entries carry Sib_M* markers (no
            // SIB byte exists) — resolve them synthetically, never reading a
            // SIB byte.
            result.length = static_cast<uint8_t>(
                kLengthTable_ModRM_Addr16[modrm]
                + (result.length - kLengthTable_ModRM[modrm]));
            result.instrId = ResolveSibMarkers(result.instrId, 0);
        } else if (ModrmHasSib(modrm)) {
            // rm=100 (and mod!=11) → SIB byte follows; resolve stack markers.
            // The mandatory disp32 (SIB.base=101) only applies at mod=00.
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            const auto sib = buffer[prefix_info.length + 2];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) {
                result.length = static_cast<uint8_t>(result.length + 4);
            }
            // Resolve SIB-dispatch markers (m* vs stack_m*) before size fixups.
            result.instrId = ResolveSibMarkers(result.instrId, sib);
            // FF /2,/4,/6 and 8F /0 force the memory operand to m64 in the shared
            // helper, bypassing the marker; recover the ESP/RSP-base stack form
            // (SIB.base=100) here so it matches every other memory operand.
            if ((opcode == 0xFF || opcode == 0x8F)
                && (sib & 0b000'000'111u) == 0b000'000'100u) {
                for (uint8_t i = 0; i < result.instrId.operand_count; ++i) {
                    if (result.instrId.operands.operand[i] == Operand::m64) {
                        result.instrId.operands.operand[i] = Operand::stack_m64;
                    }
                }
            }
        }
        // FF /2,/4,/6 and 8F /0 carry the long-mode-default m64 memory form
        // (or stack_m64 once a SIB ESP base is resolved); downgrade to the
        // 32-bit form here. Done after SIB resolution so the stack form is
        // covered. (The r64 register form is normalized by NormalizeOperandSize32;
        // fixed-width m64 ops like CMPXCHG8B/FILD do not reach this path, so the
        // rewrite is scoped to these two opcodes.)
        if (opcode == 0xFF || opcode == 0x8F) {
            for (uint8_t i = 0; i < result.instrId.operand_count; ++i) {
                if (result.instrId.operands.operand[i] == Operand::m64) {
                    result.instrId.operands.operand[i] = Operand::m32;
                } else if (result.instrId.operands.operand[i] == Operand::stack_m64) {
                    result.instrId.operands.operand[i] = Operand::stack_m32;
                }
            }
        }
        result = ApplyPrefixSizes32(result, prefix_info);
        // The extension groups add immediate (and SIB disp32) bytes to the
        // length; verify the full encoding is in-buffer before success. Checked
        // after ApplyPrefixSizes32 so a 66h imm32->imm16 shrink is reflected.
        if (buffer.size() < static_cast<size_t>(prefix_info.length + result.length)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        result.length = static_cast<uint8_t>(prefix_info.length + result.length);
        return result;
    }

    case 0xAC: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 1];
        const auto form_index = static_cast<uint8_t>(instr_id.operands.operand[0]);
        const auto* form_table = kOperandFormTable_ModRM[form_index];
        if (form_table == nullptr) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        const auto& form = (*form_table)[modrm];
        if (form.operand[0] == Operand::invalid) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        uint8_t modrm_len;
        if (addr16) {
            modrm_len = kLengthTable_ModRM_Addr16[modrm];
        } else {
            modrm_len = kLengthTable_ModRM[modrm];
            if (AdjustModrmLenForSib_1byte(prefix_info, buffer, modrm, modrm_len)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
        }
        InstructionId resolved = { instr_id.opcode, 2, form };
        if (addr16) {
            // rm=100 form entries carry unresolved Sib_M* markers under 67h
            // (no SIB byte exists); resolve them to the plain memory classes.
            resolved = ResolveSibMarkers(resolved, 0);
        } else if (ModrmHasSib(modrm)) {
            resolved = ResolveSibMarkers(resolved, buffer[prefix_info.length + 2]);
        }
        const auto [length, instrId] = ApplyPrefixSizes32({ modrm_len, resolved }, prefix_info);
        // Addr16 truncation check: the 16-bit displacement must be in-buffer.
        if (addr16 && buffer.size() < static_cast<size_t>(prefix_info.length) + length) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    case 0x87: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 1];
        auto result = GetInstructionDescriptor_x87(
            opcode, modrm, addr16 ? kLengthTable_ModRM_Addr16[modrm] : kLengthTable_ModRM[modrm]);
        if (result.length >= 0xE0) {
            return result;
        }
        // SIB base=5 post-correction for x87 memory forms (32-bit addressing
        // only; under 67h no SIB byte exists and the x87 memory table carries
        // fixed operand classes, so nothing to resolve).
        if (!addr16 && (modrm & 0b11'000'111u) == 0b00'000'100u) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            if (const auto sib = buffer[prefix_info.length + 2];
                (sib & 0b000'000'111u) == 0b000'000'101u) {
                result.length = static_cast<uint8_t>(result.length + 4);
            }
        }
        // The SIB base=5 disp32 bytes are counted above but not yet verified to
        // be in-buffer; reject a truncated encoding before reporting success.
        if (buffer.size() < static_cast<size_t>(prefix_info.length + result.length)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        result = ApplyPrefixSizes32(result, prefix_info);
        result.length = static_cast<uint8_t>(prefix_info.length + result.length);
        return result;
    }

    case 0xE2:
        return Decode2ByteOpcode(prefix_info, buffer);

    case 0xD4:
    case 0xD5:
        // AAM/AAD imm8: truncated encodings must report INSUFFICIENT_BUFFER.
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        return { static_cast<uint8_t>(prefix_info.length + 2), instr_id };

    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x09:
        {
            // A0-A3 are moffs forms: length depends on address-size (67h), not a fixed shared-table length.
            if (opcode >= 0xA0 && opcode <= 0xA3) {
                auto resolved_id = instr_id;
                const bool has_67 = prefix_info.has_prefix.has_67 != 0;
                if (has_67) {
                    auto& ops = resolved_id.operands.operand;
                    ops[0] = ApplyAddressSize67(ops[0]);
                    ops[1] = ApplyAddressSize67(ops[1]);
                    ops[2] = ApplyAddressSize67(ops[2]);
                }

                const auto raw_len = static_cast<uint8_t>(1 + (has_67 ? 2 : 4));
                if (buffer.size() < static_cast<size_t>(prefix_info.length + raw_len)) {
                    return ERR_INSUFFICIENT_BUFFER;
                }

                const auto [length, instrId] = ApplyPrefixSizes32({ raw_len, resolved_id }, prefix_info);
                return { static_cast<uint8_t>(prefix_info.length + length), instrId };
            }

            const auto [length, instrId] = ApplyPrefixSizes32({ tag.instr_len, instr_id }, prefix_info);
            return { static_cast<uint8_t>(prefix_info.length + length), instrId };
        }

    case 0xB8: {
        auto iid = instr_id;
        iid.operands.operand[0] = Operand::r32;
        iid.operands.operand[1] = Operand::imm32;
        const auto adjusted = ApplyPrefixSizes32({ 5, iid }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + adjusted.length), adjusted.instrId };
    }

    default:
        return ERR_UNDEFINED_INSTRUCTION;
    }
}

} // namespace xendiza::detail



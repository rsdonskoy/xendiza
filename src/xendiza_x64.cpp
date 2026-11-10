#include <xendiza/xendiza_x64.hpp>
#include <xendiza/detail/vex.hpp>
#include <xendiza/detail/vex_decode.hpp>
#include <xendiza/detail/simd_decode.hpp>

#if defined(_MSC_VER)
#define XENDIZA_FORCEINLINE __forceinline
#define XENDIZA_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define XENDIZA_FORCEINLINE inline __attribute__((always_inline))
#define XENDIZA_NOINLINE __attribute__((noinline))
#else
#define XENDIZA_FORCEINLINE inline
#define XENDIZA_NOINLINE
#endif

namespace xendiza::detail {

namespace {

constexpr auto ToErrorInstruction(const ErrorCode code) noexcept -> DecodedInstruction
{
    switch (code) {
    case ErrorCode::INSUFFICIENT_BUFFER:
        return ERR_INSUFFICIENT_BUFFER;
    case ErrorCode::UNIMPLEMENTED_DISASM:
        return ERR_UNIMPLEMENTED_DISASM;
    case ErrorCode::UNDEFINED_INSTRUCTION:
    case ErrorCode::UNKNOWN_ERROR:
    case ErrorCode::OK:
    default:
        return ERR_UNDEFINED_INSTRUCTION;
    }
}

// Maps a single operand to its REX.W or 66h variant.
// 8-bit, 64-bit, and non-register operands pass through unchanged.
constexpr auto ResolveOperandSize(
    const Operand opr, const bool rex_w, const bool has_66) noexcept -> Operand
{
    if (rex_w) {
        switch (opr) {
        case Operand::r32:  return Operand::r64;
        case Operand::m32:  return Operand::m64;
        case Operand::stack_m32: return Operand::stack_m64;
        case Operand::eax:  return Operand::rax;
        default:            return opr;
        }
    }
    if (has_66) {
        switch (opr) {
        case Operand::r32:   return Operand::r16;
        case Operand::m32:   return Operand::m16;
        case Operand::stack_m32: return Operand::stack_m16;
        case Operand::imm32: return Operand::imm16;
        case Operand::eax:   return Operand::ax;
        default:             return opr;
        }
    }
    return opr;
}

constexpr auto IsMemoryOperand(const Operand opr) noexcept -> bool
{
    switch (opr) {
    case Operand::m:
    case Operand::m8:
    case Operand::m16:
    case Operand::m32:
    case Operand::m64:
    case Operand::m128:
    case Operand::m32fp:
    case Operand::m64fp:
    case Operand::m80fp:
    case Operand::moffs8:
    case Operand::moffs16:
    case Operand::moffs32:
    case Operand::moffs64:
    case Operand::m16_32:
    case Operand::m16_64:
    case Operand::stack_m8:
    case Operand::stack_m16:
    case Operand::stack_m32:
    case Operand::stack_m64:
    // Composite segment-prefixed memory operands are also memory operands.
    case Operand::es_m8:   case Operand::cs_m8:   case Operand::ss_m8:   case Operand::ds_m8:   case Operand::fs_m8:   case Operand::gs_m8:
    case Operand::es_m16:  case Operand::cs_m16:  case Operand::ss_m16:  case Operand::ds_m16:  case Operand::fs_m16:  case Operand::gs_m16:
    case Operand::es_m32:  case Operand::cs_m32:  case Operand::ss_m32:  case Operand::ds_m32:  case Operand::fs_m32:  case Operand::gs_m32:
    case Operand::es_m64:  case Operand::cs_m64:  case Operand::ss_m64:  case Operand::ds_m64:  case Operand::fs_m64:  case Operand::gs_m64:
    case Operand::es_moffs8:  case Operand::cs_moffs8:  case Operand::ss_moffs8:  case Operand::ds_moffs8:  case Operand::fs_moffs8:  case Operand::gs_moffs8:
    case Operand::es_moffs16: case Operand::cs_moffs16: case Operand::ss_moffs16: case Operand::ds_moffs16: case Operand::fs_moffs16: case Operand::gs_moffs16:
    case Operand::es_moffs32: case Operand::cs_moffs32: case Operand::ss_moffs32: case Operand::ds_moffs32: case Operand::fs_moffs32: case Operand::gs_moffs32:
    case Operand::es_moffs64: case Operand::cs_moffs64: case Operand::ss_moffs64: case Operand::ds_moffs64: case Operand::fs_moffs64: case Operand::gs_moffs64:
        return true;
    default:
        return false;
    }
}

constexpr auto SegmentByteToOperand64(const uint8_t seg_byte) noexcept -> Operand
{
    switch (seg_byte) {
    case static_cast<uint8_t>(Prefix::ES_SEG): return Operand::es;
    case static_cast<uint8_t>(Prefix::CS_SEG): return Operand::cs;
    case static_cast<uint8_t>(Prefix::SS_SEG): return Operand::ss;
    case static_cast<uint8_t>(Prefix::DS_SEG): return Operand::ds;
    case static_cast<uint8_t>(Prefix::FS_SEG): return Operand::fs;
    case static_cast<uint8_t>(Prefix::GS_SEG): return Operand::gs;
    default: return Operand::noopr;
    }
}

constexpr auto InjectSegmentForMemory(
    const InstructionId& instr_id, const Operand seg_operand) noexcept -> InstructionId
{
    // x64 mode: only fs/gs segment overrides produce composite memory operands.
    if (seg_operand != Operand::fs && seg_operand != Operand::gs) {
        return instr_id;
    }

    auto with_seg = instr_id;
    for (uint8_t i = 0; i < with_seg.operand_count; ++i) {
        if (IsMemoryOperand(with_seg.operands.operand[i])) {
            with_seg.operands.operand[i] = MakeCompositeMemOperand(seg_operand, with_seg.operands.operand[i]);
            break;
        }
    }
    return with_seg;
}

// Applies REX.W / 66h operand-size effects to a decoded instruction.
// Remaps operands and, when 66h converts imm32 → imm16, subtracts 2 from length.
// The length in 'result' must NOT yet include prefix_info.length.
// Error results (length >= 0xE0) are passed through unchanged.
constexpr auto ApplyPrefixSizes(
    DecodedInstruction result, const PrefixInfo& prefix_info) noexcept -> DecodedInstruction
{
    if (result.length >= 0xE0) {
        return result;
    }

    const auto rex_w = prefix_info.rex_w();
    const auto has_66 = prefix_info.has_prefix.has_66 != 0;
    const auto has_seg = prefix_info.has_prefix.has_seg != 0;
    if (!rex_w && !has_66 && !has_seg) {
        return result;
    }

    // Subtract 2 if 66h converts imm32 → imm16 (shrinks the encoding).
    // Note: rel32 is NOT shrunk — in 64-bit mode Intel ignores the 66h prefix
    // for near branches (rel32 stays rel32); the rel16 form only exists in
    // 16/32-bit modes, handled by the x86 path.
    if (has_66) {
        for (uint8_t i = 0; i < result.instrId.operand_count; ++i) {
            if (result.instrId.operands.operand[i] == Operand::imm32) {
                result.length = static_cast<uint8_t>(result.length - 2);
                break;
            }
        }
    }

    auto& ops = result.instrId.operands.operand;
    ops[0] = ResolveOperandSize(ops[0], rex_w, has_66);
    ops[1] = ResolveOperandSize(ops[1], rex_w, has_66);
    ops[2] = ResolveOperandSize(ops[2], rex_w, has_66);
    ops[3] = ResolveOperandSize(ops[3], rex_w, has_66);

    if (has_seg) {
        result.instrId = InjectSegmentForMemory(
            result.instrId,
            SegmentByteToOperand64(prefix_info.seg_byte));
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

// Two-byte (0F-prefixed) opcode group extension dispatch.
// Mirrors DecodeOpcodeExtension() but for groups in the 0F opcode space.
// Each case uses the same 256-entry ModRM-indexed table pattern as the 1-byte
// extension tables; the returned length is relative to the start of the 0F byte.
constexpr auto DecodeOpcodeExtension_2byte(const uint8_t opcode2, const uint8_t modrm_byte) noexcept
    -> DecodedInstruction
{
    if (opcode2 == 0xBA) {
        return GetInstructionDescriptor_opcode_extension_0x0F_BA(modrm_byte);
    }
    return ERR_UNDEFINED_INSTRUCTION;
}

} // namespace

auto X64Traits::Decode2ByteOpcode(
    const PrefixInfo& prefix_info, gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction
{
    if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    const auto opcode2  = buffer[prefix_info.length + 1];
    switch (const auto [tag, instr_id] = kDecodeTable_2byte_opcode[opcode2]; tag.dispatch_code) {

    // ModR/M-based two-byte forms (Gv_Ev and similar, uniform source/dest size).
    // P2 keeps these operands abstract and does not map REX.B/R/X to concrete ids.
    case 0x00: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm        = buffer[prefix_info.length + 2];
        uint8_t modrm_len       = kLengthTable_ModRM[modrm];

        auto resolved_id = instr_id;
        const bool has_f3 =
            prefix_info.rep_byte == static_cast<uint8_t>(Prefix::REPE);

        // F3-mandatory and F3-remapped bit-count family:
        //   F3 0F B8 /r -> POPCNT
        //   F3 0F BC /r -> TZCNT (otherwise BSF)
        //   F3 0F BD /r -> LZCNT (otherwise BSR)
        if (opcode2 == 0xB8) {
            if (!has_f3) {
                return ERR_UNDEFINED_INSTRUCTION;
            }
        } else if (has_f3) {
            if (opcode2 == 0xBC) {
                resolved_id.opcode = OpcodeId::TZCNT;
            } else if (opcode2 == 0xBD) {
                resolved_id.opcode = OpcodeId::LZCNT;
            }
        }

        if (const auto form_index = static_cast<uint32_t>(resolved_id.operands.operand[0]);
            form_index - 1 < 4 || form_index - 6 < 3) {
            const auto& form = kOperandFormTable_ModRM_Flat[form_index * 256 + modrm];
            if (form.operand[0] == Operand::invalid) {
                return ERR_UNDEFINED_INSTRUCTION;
            }
            resolved_id.operands     = form;
            resolved_id.operand_count = 2;
        }
        // rm=100 (and mod!=11) → SIB byte follows; resolve stack markers. The
        // mandatory disp32 (SIB.base=101) only applies at mod=00.
        if (ModrmHasSib(modrm)) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            const auto sib = buffer[prefix_info.length + 3];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
            resolved_id = ResolveSibMarkers(resolved_id, sib);
        }
        // modrm_len counts second opcode + modrm (+disp/SIB); +1 for 0x0F escape
        const auto [length, instrId] = ApplyPrefixSizes(
            { static_cast<uint8_t>(modrm_len + 1), resolved_id }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // Direct fixed-length 2-byte entries
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09: {
        if (opcode2 == 0x09 &&
            prefix_info.rep_byte == static_cast<uint8_t>(Prefix::REPE)) {
            return { static_cast<uint8_t>(prefix_info.length + tag.instr_len), IID(WBNOINVD) };
        }
        const auto adjusted = ApplyPrefixSizes({ tag.instr_len, instr_id }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + adjusted.length), adjusted.instrId };
    }

    // Gv_Eb: dest r32 (modified by REX.W/66h), src fixed at byte (r8 or m8).
    case 0x56: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm        = buffer[prefix_info.length + 2];
        uint8_t modrm_len       = kLengthTable_ModRM[modrm];
        const auto is_reg       = (modrm & 0b11'000'000) == 0b11'000'000;
        const auto rex_w        = prefix_info.rex_w();
        const auto has_66       = prefix_info.has_prefix.has_66 != 0;
        auto resolved_id        = instr_id;
        resolved_id.operands.operand[0] = ResolveOperandSize(Operand::r32, rex_w, has_66);
        Operand src = Operand::m8;
        if (!is_reg && (modrm & 0b00'000'111u) == 0b00'000'100u) { // rm=100 → SIB
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            const auto sib = buffer[prefix_info.length + 3];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) modrm_len = static_cast<uint8_t>(modrm_len + 4);
            src = kSibStackForm_b[sib];
        }
        resolved_id.operands.operand[1] = is_reg ? Operand::r8 : src;
        resolved_id.operands.operand[2] = Operand::noopr;
        resolved_id.operand_count       = 2;
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        return { total_len, resolved_id };
    }

    // Gv_Ew: dest r32 (modified by REX.W/66h), src fixed at word (r16 or m16).
    case 0x57: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm        = buffer[prefix_info.length + 2];
        uint8_t modrm_len       = kLengthTable_ModRM[modrm];
        const auto is_reg       = (modrm & 0b11'000'000) == 0b11'000'000;
        const auto rex_w        = prefix_info.rex_w();
        const auto has_66       = prefix_info.has_prefix.has_66 != 0;
        auto resolved_id        = instr_id;
        resolved_id.operands.operand[0] = ResolveOperandSize(Operand::r32, rex_w, has_66);
        Operand src = Operand::m16;
        if (!is_reg && (modrm & 0b00'000'111u) == 0b00'000'100u) { // rm=100 → SIB
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            const auto sib = buffer[prefix_info.length + 3];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) modrm_len = static_cast<uint8_t>(modrm_len + 4);
            src = kSibStackForm_w[sib];
        }
        resolved_id.operands.operand[1] = is_reg ? Operand::r16 : src;
        resolved_id.operands.operand[2] = Operand::noopr;
        resolved_id.operand_count       = 2;
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        return { total_len, resolved_id };
    }

    // Eb: single byte destination selected by ModR/M (r8 or m8).
    case 0x58: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm        = buffer[prefix_info.length + 2];
        const uint8_t modrm_len = kLengthTable_ModRM[modrm];
        const auto is_reg       = (modrm & 0b11'000'000) == 0b11'000'000;
        auto resolved_id        = instr_id;
        resolved_id.operands.operand[0] = is_reg ? Operand::r8 : Operand::m8;
        resolved_id.operands.operand[1] = Operand::noopr;
        resolved_id.operands.operand[2] = Operand::noopr;
        resolved_id.operand_count       = 1;
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        return { total_len, resolved_id };
    }

    // direct two-byte register form; only REX.W upgrades operand size
    case 0x59: {
        auto resolved_id = instr_id;
        if (prefix_info.rex_w()) {
            resolved_id.operands.operand[0] = ResolveOperandSize(Operand::r32, true, false);
        }
        const auto total_len = static_cast<uint8_t>(prefix_info.length + 2);
        return { total_len, resolved_id };
    }

    // ModR/M-based Ev,Gv,imm8 forms
    case 0x5B: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len = kLengthTable_ModRM[modrm];
        const auto& form = kOperandFormTable_Ev_Gv[modrm];
        auto resolved_id = instr_id;
        resolved_id.operands = { { form.operand[0], form.operand[1], Operand::imm8 } };
        if (ModrmHasSib(modrm)) {
            const auto sib = buffer[prefix_info.length + 3];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) modrm_len = static_cast<uint8_t>(modrm_len + 4);
            resolved_id = ResolveSibMarkers(resolved_id, sib);
        }
        const auto [length, instrId] = ApplyPrefixSizes(
            { static_cast<uint8_t>(modrm_len + 2), resolved_id }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // ModR/M-based Ev,Gv,CL forms
    case 0x5C: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        uint8_t modrm_len = kLengthTable_ModRM[modrm];
        const auto& form = kOperandFormTable_Ev_Gv[modrm];
        auto resolved_id = instr_id;
        resolved_id.operands = { { form.operand[0], form.operand[1], Operand::cl } };
        if (ModrmHasSib(modrm)) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            const auto sib = buffer[prefix_info.length + 3];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) modrm_len = static_cast<uint8_t>(modrm_len + 4);
            resolved_id = ResolveSibMarkers(resolved_id, sib);
        }
        const auto [length, instrId] = ApplyPrefixSizes(
            { static_cast<uint8_t>(modrm_len + 1), resolved_id }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // 0F AE group: prefix-selected table dispatch (see kInstrIdTable_0F_AE_*)
    case 0x5D: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm  = buffer[prefix_info.length + 2];
        uint8_t modrm_len = kLengthTable_ModRM[modrm];

        // For mod=00,r/m=100, SIB is present. If SIB.base=101, disp32 is mandatory.
        if ((modrm & 0b11'000'111u) == 0b00'000'100u) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            if (const auto sib = buffer[prefix_info.length + 3];
                (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
        }

        const bool has_66 = prefix_info.has_prefix.has_66 != 0;
        const bool has_f3 = prefix_info.rep_byte == static_cast<uint8_t>(Prefix::REPE);

        auto result = GetInstructionDescriptor_0F_AE(modrm, modrm_len, has_f3, has_66);
        if (result.length >= 0xE0) {
            return result;
        }
        // F3 register forms (RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE) carry r32;
        // ApplyPrefixSizes upgrades to r64 when REX.W is present.
        // CLRSSBSY m64 is unaffected by ApplyPrefixSizes.
        if (has_f3) {
            const auto [length, instrId] = ApplyPrefixSizes(result, prefix_info);
            return { static_cast<uint8_t>(prefix_info.length + length), instrId };
        }
        return { static_cast<uint8_t>(prefix_info.length + result.length), result.instrId };
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
        auto modrm_len = kLengthTable_ModRM[modrm];

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

        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        return { total_len, instr_id };
    }

    // 0F 00 group: SLDT/STR/LLDT/LTR/VERR/VERW — table-driven, ApplyPrefixSizes post-lookup
    case 0x5E: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm  = buffer[prefix_info.length + 2];
        uint8_t modrm_len = kLengthTable_ModRM[modrm];

        // For mod=00,r/m=100, SIB is present. If SIB.base=101, disp32 is mandatory.
        if ((modrm & 0b11'000'111u) == 0b00'000'100u) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            if (const auto sib = buffer[prefix_info.length + 3];
                (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
        }

        auto result = GetInstructionDescriptor_0F_00(modrm, modrm_len);
        if (result.length >= 0xE0) {
            return result;
        }
        // SLDT r32 / STR r32 are upgraded to r64 by REX.W; r16/m16 are unaffected.
        const auto [length, instrId] = ApplyPrefixSizes(result, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // 0F 01 group: table-driven; ApplyPrefixSizes upgrades SMSW r32→r64, others unaffected
    case 0x5F: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm  = buffer[prefix_info.length + 2];
        uint8_t modrm_len = kLengthTable_ModRM[modrm];

        // For mod=00,r/m=100, SIB is present. If SIB.base=101, disp32 is mandatory.
        if ((modrm & 0b11'000'111u) == 0b00'000'100u) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            if (const auto sib = buffer[prefix_info.length + 3];
                (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
        }

        auto result = GetInstructionDescriptor_0F_01(modrm, modrm_len);
        if (result.length >= 0xE0) {
            return result;
        }
        const auto [length, instrId] = ApplyPrefixSizes(result, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // 0F 20-23: MOV to/from control registers (0F 20/22) and debug registers (0F 21/23)
    // These encodings are register-only in this decoder.
    case 0x60: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm        = buffer[prefix_info.length + 2];
        if (const auto mod = static_cast<uint8_t>(modrm & 0b11'000'000u);
            mod != 0b11'000'000u) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        const uint8_t modrm_len = kLengthTable_ModRM[modrm];
        // In 64-bit mode the GPR operand is always 64-bit; instr_id already carries r64.
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        return { total_len, instr_id };
    }

    // 0F C7 Group 9: table-driven; post-table fixups for REX.W (CMPXCHG16B) and F3 (RDPID)
    case 0x61: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm  = buffer[prefix_info.length + 2];
        uint8_t modrm_len = kLengthTable_ModRM[modrm];

        // For mod=00,r/m=100, SIB is present. If SIB.base=101, disp32 is mandatory.
        if ((modrm & 0b11'000'111u) == 0b00'000'100u) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            if (const auto sib = buffer[prefix_info.length + 3];
                (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
        }

        auto result = GetInstructionDescriptor_0F_C7(modrm, modrm_len);
        if (result.length >= 0xE0) {
            return result;
        }

        // REX.W on CMPXCHG8B → CMPXCHG16B m128 (identity + operand both change)
        if (result.instrId.opcode == OpcodeId::CMPXCHG8B && prefix_info.rex_w()) {
            return { static_cast<uint8_t>(prefix_info.length + result.length),
                     IID(CMPXCHG16B, m128) };
        }
        // F3 on RDSEED → RDPID r32 (identity change; still apply size upgrade)
        if (result.instrId.opcode == OpcodeId::RDSEED &&
            prefix_info.rep_byte == static_cast<uint8_t>(Prefix::REPE)) {
            const auto [length, instrId] = ApplyPrefixSizes(
                { result.length, IID(RDPID, r32) }, prefix_info);
            return { static_cast<uint8_t>(prefix_info.length + length), instrId };
        }
        // RDRAND/RDSEED carry r32 → ApplyPrefixSizes upgrades to r64 (REX.W) or r16 (66h)
        // Memory operands (m, m64) pass through ApplyPrefixSizes unchanged.
        const auto [length, instrId] = ApplyPrefixSizes(result, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // 0F 18 Group 16: PREFETCHNTA/T0/T1/T2 (mem forms /0-/3); reserved-NOP for all other encodings
    case 0x62: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm        = buffer[prefix_info.length + 2];
        const auto mod          = static_cast<uint8_t>(modrm & 0b11'000'000u);
        const auto reg          = static_cast<uint8_t>((modrm & 0b00'111'000u) >> 3);
        uint8_t modrm_len       = kLengthTable_ModRM[modrm];

        // For mod=00,r/m=100 a SIB byte is present. If SIB.base=101, disp32 is mandatory.
        // kLengthTable_ModRM is keyed by ModR/M only, so account for this SIB-specific +4 here.
        if ((modrm & 0b11'000'111u) == 0b00'000'100u) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            if (const auto sib = buffer[prefix_info.length + 3];
                (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
        }

        const auto total_len    = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);

        if (opcode2 == 0x0D) {
            const bool is_reg = (mod == 0b11'000'000u);
            if (is_reg || reg != 1) {
                return ERR_UNDEFINED_INSTRUCTION;
            }
            return { total_len, IID(PREFETCHW, m8) };
        }

        if (opcode2 == 0x1E) {
            // ENDBR64/ENDBR32 are fixed encodings requiring F3 prefix.
            if (prefix_info.rep_byte != static_cast<uint8_t>(Prefix::REPE)) {
                return ERR_UNDEFINED_INSTRUCTION;
            }
            switch (modrm) {
            case 0xFA: return { total_len, IID(ENDBR64) };
            case 0xFB: return { total_len, IID(ENDBR32) };
            default:   return ERR_UNDEFINED_INSTRUCTION;
            }
        }

        if (opcode2 == 0x1C) {
            const bool is_reg = (mod == 0b11'000'000u);
            if (is_reg || reg != 0) {
                return ERR_UNDEFINED_INSTRUCTION;
            }
            return { total_len, IID(CLDEMOTE, m8) };
        }

        // Register forms and /4-/7 memory forms are reserved; processors treat them as NOP.
        if (const bool is_reg = (mod == 0b11'000'000u);
            is_reg || reg >= 4) {
            return { total_len, IID(NOP) };
        }

        // Memory forms /0-/3: PREFETCHNTA, PREFETCHT0, PREFETCHT1, PREFETCHT2
        switch (reg) {
        case 0: return { total_len, IID(PREFETCHNTA, m8) };
        case 1: return { total_len, IID(PREFETCHT0,  m8) };
        case 2: return { total_len, IID(PREFETCHT1,  m8) };
        case 3: return { total_len, IID(PREFETCHT2,  m8) };
        default: return ERR_UNDEFINED_INSTRUCTION; // unreachable
        }
    }

    // 0F opcode-extension dispatch via 256-entry ModRM-indexed tables
    // (same pattern as 1-byte extension tables; see DecodeOpcodeExtension_2byte)
    case 0x63: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        auto result = DecodeOpcodeExtension_2byte(opcode2, modrm);
        if (result.length >= 0xE0) {
            return result;
        }
        // mod!=11,r/m=100 → SIB byte follows; resolve stack markers and the
        // mandatory disp32 when SIB.base=101.
        if (ModrmHasSib(modrm)) {
            const auto sib = buffer[prefix_info.length + 3];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) {
                result.length = static_cast<uint8_t>(result.length + 4);
            }
            result.instrId = ResolveSibMarkers(result.instrId, sib);
        }
        const auto [length, instrId] = ApplyPrefixSizes(result, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + length), instrId };
    }

    // 0F C3 /r: MOVNTI m32,r32 (memory destination only), REX.W -> m64,r64
    case 0x64: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const auto modrm = buffer[prefix_info.length + 2];
        if (const auto mod = static_cast<uint8_t>(modrm & 0b11'000'000u);
            mod == 0b11'000'000u) {
            return ERR_UNDEFINED_INSTRUCTION;
        }

        uint8_t modrm_len = kLengthTable_ModRM[modrm];

        // For mod=00,r/m=100, SIB is present. If SIB.base=101, disp32 is mandatory.
        if ((modrm & 0b11'000'111u) == 0b00'000'100u) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 3)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            if (const auto sib = buffer[prefix_info.length + 3];
                (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
        }

        auto resolved_id = instr_id;
        if (prefix_info.rex_w()) {
            resolved_id.operands.operand[0] = ResolveOperandSize(Operand::m32, true, false);
            resolved_id.operands.operand[1] = ResolveOperandSize(Operand::r32, true, false);
        }

        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + 1);
        return { total_len, resolved_id };
    }

    // SIMD rows: descriptor-table dispatch (kSimdOpcodeTable + DecodeSimd2Byte).
    //   0x65 rows: P2.4 moves/compares (none-only, plus 66h UCOMISD/COMISD).
    //   0x66 rows: mandatory-prefix arithmetic families.
    // Operands remain abstract (xmm/m128/m64/m32); no concrete register-id mapping.
    case 0x65:
    case 0x66:
        return DecodeSimd2Byte(prefix_info, buffer, opcode2, prefix_info.rex_w());

    // 0F 38/0F 3A: three-byte opcode space (SSSE3/SSE4.x/AES/PCLMUL/CRC32/
    // MOVBE) dispatched through kDecodeTable_0F38/_0F3A + Dispatch3ByteOpcode.
    case 0x3E:
        return Dispatch3ByteOpcode(prefix_info, buffer, opcode2, prefix_info.rex_w());

    case 0xD6:
        return ERR_UNDEFINED_INSTRUCTION;

    case 0xE1:
        return ERR_UNIMPLEMENTED_DISASM;

    default:
        return ERR_UNDEFINED_INSTRUCTION;
    }
}

static constexpr auto DecodeModrmWithImmediate(const PrefixInfo& prefix_info,
    gsl::span<const uint8_t> buffer,
    const InstructionId& instr_id,
    const uint8_t immediate_size,
    const std::array<Operands, 256>& operand_form_table) noexcept -> DecodedInstruction
{
    if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    const auto modrm = buffer[prefix_info.length + 1];
    uint8_t modrm_len = kLengthTable_ModRM[modrm];

    const auto& [operand] = operand_form_table[modrm];
    const auto imm_operand = instr_id.operands.operand[1]; // e.g. imm8 or imm32
    InstructionId resolved_id = {
        instr_id.opcode,
        3,
        Operands{{ operand[0], operand[1], imm_operand, Operand::noopr }}
    };

    // rm=100 (and mod!=11) → SIB byte follows; resolve stack markers. The
    // mandatory disp32 (SIB.base=101) only applies at mod=00.
    if (ModrmHasSib(modrm)) {
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

    const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len + immediate_size);
    return { total_len, resolved_id };
}



inline auto X64Traits::ProcessPrefix(gsl::span<const uint8_t> buffer) noexcept -> std::pair<PrefixInfo, ErrorCode>
{
    PrefixInfo info{};

    if (buffer.empty()) {
        return { info, ErrorCode::INSUFFICIENT_BUFFER };
    }

    size_t pos { 0 };
    while (pos < buffer.size() && pos < MAX_INSTRUCTION_LENGTH) {
        const uint8_t byte = buffer[pos];
        const Prefix prefix_type = X64Traits::kPrefixTable[byte];

        // 0x0F is an opcode escape, not a consumed legacy prefix.
        if (prefix_type == Prefix::NONE || prefix_type == Prefix::OPC_2BYTE) {
            break;
        }

        if (byte >= 0x40 && byte <= 0x4F) {
            // Repeated REX prefixes are accepted; the last one wins.
            info.has_prefix.has_rex = 1;
            info.rex_byte = byte;
            ++info.length;
            ++pos;
            continue;
        }

        switch (prefix_type) {
        case Prefix::REX_BASE:
        case Prefix::REX_B:
        case Prefix::REX_X:
        case Prefix::REX_XB:
        case Prefix::REX_R:
        case Prefix::REX_RB:
        case Prefix::REX_RX:
        case Prefix::REX_RXB:
        case Prefix::REX_W:
        case Prefix::REX_WB:
        case Prefix::REX_WX:
        case Prefix::REX_WXB:
        case Prefix::REX_WR:
        case Prefix::REX_WRB:
        case Prefix::REX_WRX:
        case Prefix::REX_WRXB:
            // REX prefixes are handled by the fast path above.
            break;

        case Prefix::LOCK:
            info.has_prefix.has_lock = 1;
            break;

        case Prefix::REPNE:
            [[fallthrough]];
        case Prefix::REPE:
            info.has_prefix.has_rep = 1;
            info.rep_byte = byte;
            break;

        case Prefix::ES_SEG:
        case Prefix::CS_SEG:
        case Prefix::SS_SEG:
        case Prefix::DS_SEG:
        case Prefix::FS_SEG:
        case Prefix::GS_SEG:
            info.has_prefix.has_seg = 1;
            info.seg_byte = byte;
            break;

        case Prefix::OPR_SIZE:
            info.has_prefix.has_66 = 1;
            break;

        case Prefix::ADDR_SIZE:
            info.has_prefix.has_67 = 1;
            break;

        case Prefix::VEX_2BYTE:
        case Prefix::VEX_3BYTE:
        case Prefix::EVEX:
            return { info, ErrorCode::UNIMPLEMENTED_DISASM };

        default:
            return { info, ErrorCode::UNDEFINED_INSTRUCTION };
        }

        // A REX prefix is only valid as the last prefix; any legacy prefix
        // consumed after it invalidates it entirely (bits are dropped, the
        // instruction still decodes) - same semantics as Zydis.
        if (info.has_prefix.has_rex == 1) {
            info.has_prefix.has_rex = 0;
            info.rex_byte = 0;
        }

        ++info.length;
        ++pos;
    }

    if (pos >= MAX_INSTRUCTION_LENGTH) {
        return { info, ErrorCode::UNDEFINED_INSTRUCTION };
    }

    return { info, ErrorCode::OK };
}

// Entry point: enforces the architectural 15-byte total-length limit on the
// fully decoded instruction (prefixes + opcode + ModRM/disp/imm), mirroring
// the #GP a CPU raises for over-long instructions. Error results
// (length >= 0xE0) pass through unchanged.
auto X64Traits::Disasm(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction
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

// Builds the PrefixInfo for a single leading legacy/REX prefix byte, exactly
// as ProcessPrefix would after consuming one byte (and stopping at a
// following plain opcode or 0x0F escape). Callers must guarantee kind is a
// legacy or REX prefix (VEX/EVEX excluded).
constexpr auto PrefixInfoForSinglePrefix(const Prefix kind, const uint8_t byte) noexcept -> PrefixInfo
{
    PrefixInfo info{};
    info.length = 1;
    if (byte >= 0x40 && byte <= 0x4F) {
        info.has_prefix.has_rex = 1;
        info.rex_byte = byte;
        return info;
    }
    switch (kind) {
    case Prefix::LOCK:      info.has_prefix.has_lock = 1; break;
    case Prefix::REPNE:
    case Prefix::REPE:      info.has_prefix.has_rep = 1; info.rep_byte = byte; break;
    case Prefix::ES_SEG:
    case Prefix::CS_SEG:
    case Prefix::SS_SEG:
    case Prefix::DS_SEG:
    case Prefix::FS_SEG:
    case Prefix::GS_SEG:    info.has_prefix.has_seg = 1; info.seg_byte = byte; break;
    case Prefix::OPR_SIZE:  info.has_prefix.has_66 = 1; break;
    case Prefix::ADDR_SIZE: info.has_prefix.has_67 = 1; break;
    default: break;
    }
    return info;
}

XENDIZA_NOINLINE
auto X64Traits::DecodeInstructionSlowPath(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction
{
    if (buffer.empty()) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    // VEX prefix recognition runs before legacy prefix parsing so that
    // disallowed prefix combinations and effective address-size selection are
    // handled by the VEX path, not the legacy REX/66 fixups.
    const auto [vex_status, vex_info] = VexRecognizer::Recognize(buffer, true, 64);
    if (vex_status == VexStatus::Valid) {
        return VexDecoder::Decode(buffer, vex_info);
    }
    if (vex_status == VexStatus::NeedMore) {
        return ERR_INSUFFICIENT_BUFFER;
    }
    if (vex_status == VexStatus::Invalid) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    const auto [prefix_info, prefix_error] = ProcessPrefix(buffer);
    if (prefix_error != ErrorCode::OK) {
        return ToErrorInstruction(prefix_error);
    }
    return Decode1Byte(prefix_info, buffer);
}

auto X64Traits::DecodeInstruction(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction
{
    // Leaf fast path: decode without calling ProcessPrefix whenever the
    // prefix shape is "zero or one legacy/REX prefix, then a plain opcode or
    // the 0x0F escape" — the overwhelmingly common shape in real x86-64
    // code (including REX-prefixed and 66h/F3-prefixed forms). Stacked
    // prefixes, VEX/EVEX, and empty/tiny buffers take the slow path.
    if (!buffer.empty()) {
        const auto first_kind = X64Traits::kPrefixTable[buffer[0]];
        if (first_kind == Prefix::NONE || first_kind == Prefix::OPC_2BYTE) {
            return Decode1Byte(PrefixInfo{}, buffer);
        }
        if (buffer.size() >= 2) {
            const auto second_kind = X64Traits::kPrefixTable[buffer[1]];
            if ((second_kind == Prefix::NONE || second_kind == Prefix::OPC_2BYTE)
                && first_kind != Prefix::VEX_2BYTE
                && first_kind != Prefix::VEX_3BYTE
                && first_kind != Prefix::EVEX) {
                return Decode1Byte(PrefixInfoForSinglePrefix(first_kind, buffer[0]), buffer);
            }
        }
    }
    return DecodeInstructionSlowPath(buffer);
}

XENDIZA_FORCEINLINE
auto X64Traits::Decode1Byte(const PrefixInfo& prefix_info, gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction
{
    if (buffer.size() <= prefix_info.length) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    const auto opcode = buffer[prefix_info.length];
    switch (const auto [tag, instr_id] = kDecodeTable_1byte_opcode[opcode]; tag.dispatch_code) {
    // dispatch based on ModR/M byte; P2 returns abstract operand classes.
    case 0x00: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
            return { ERR(INSUFFICIENT_BUFFER), IID_INVALID };
        }

        const auto modrm = buffer[prefix_info.length + 1];
        uint8_t modrm_len = kLengthTable_ModRM[modrm];
        bool has_sib = false;
        uint8_t sib = 0;

        // rm=100 (and mod!=11) → a SIB byte follows. Read it for marker
        // resolution; the mandatory disp32 (SIB.base=101) only applies at mod=00.
        if (ModrmHasSib(modrm)) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            has_sib = true;
            sib = buffer[prefix_info.length + 2];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
        }

        auto resolved_id = instr_id;
        const auto form_index = static_cast<uint32_t>(resolved_id.operands.operand[0]);
        // Valid tables sit at slots 1-4 and 6-8 (0 and 5 are nullptr above);
        // any other marker value leaves the operands untouched.
        if (form_index - 1 < 4 || form_index - 6 < 3) {
            const auto& form = kOperandFormTable_ModRM_Flat[form_index * 256 + modrm];
            if (form.operand[0] == Operand::invalid) {
                return ERR_UNDEFINED_INSTRUCTION;
            }
            resolved_id.operands = form;
            resolved_id.operand_count = 2;
        }

        // Resolve SIB-dispatch markers (m* vs stack_m*) before size fixups.
        if (has_sib) {
            resolved_id = ResolveSibMarkers(resolved_id, sib);
        }

        DecodedInstruction out;
        if (!prefix_info.has_prefix.HasOverriding()) {
            // No 66h/67h/segment/REX prefix: ApplyPrefixSizes is a no-op
            // (LOCK/REP prefixes never reach its fixups), so skip the call
            // and the DecodedInstruction copy entirely.
            out = { static_cast<uint8_t>(prefix_info.length + modrm_len), resolved_id };
        } else {
            out = ApplyPrefixSizes({ modrm_len, resolved_id }, prefix_info);
            out.length = static_cast<uint8_t>(prefix_info.length + out.length);
        }
        return out;
    }

    // length depends on ModR/M and includes a 1-byte immediate
    case 0xA1: {
        auto di = DecodeModrmWithImmediate(prefix_info, buffer, instr_id, 1, kOperandFormTable_Gv_Ev);
        if (di.length >= 0xE0) return di;
        auto raw = ApplyPrefixSizes({ static_cast<uint8_t>(di.length - prefix_info.length), di.instrId }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + raw.length), raw.instrId };
    }

    // length depends on ModR/M and includes a 4-byte immediate
    case 0xA4: {
        auto di = DecodeModrmWithImmediate(prefix_info, buffer, instr_id, 4, kOperandFormTable_Gv_Ev);
        if (di.length >= 0xE0) return di;
        auto raw = ApplyPrefixSizes({ static_cast<uint8_t>(di.length - prefix_info.length), di.instrId }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + raw.length), raw.instrId };
    }

    // opcode has opcode-extension dispatch based on ModR/M
    case 0xEE: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
            return ERR_INSUFFICIENT_BUFFER;
        }

        const auto modrm = buffer[prefix_info.length + 1];
        auto dispatch_result = DecodeOpcodeExtension(opcode, modrm);
        if (dispatch_result.length >= 0xE0) {
            return dispatch_result;
        }

        // rm=100 (and mod!=11) → a SIB byte follows ModRM. Read it for marker
        // resolution; the mandatory disp32 (SIB.base=101) only applies at mod=00.
        if (ModrmHasSib(modrm)) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            const auto sib = buffer[prefix_info.length + 2];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) {
                dispatch_result.length = static_cast<uint8_t>(dispatch_result.length + 4);
            }
            // Resolve SIB-dispatch markers (m* vs stack_m*) before size fixups.
            dispatch_result.instrId = ResolveSibMarkers(dispatch_result.instrId, sib);
            // FF /2,/4,/6 and 8F /0 force the memory operand to m64 in the shared
            // helper, bypassing the marker; recover the RSP-base stack form
            // (SIB.base=100) here so it matches every other memory operand.
            if ((opcode == 0xFF || opcode == 0x8F)
                && (sib & 0b000'000'111u) == 0b000'000'100u) {
                for (uint8_t i = 0; i < dispatch_result.instrId.operand_count; ++i) {
                    if (dispatch_result.instrId.operands.operand[i] == Operand::m64) {
                        dispatch_result.instrId.operands.operand[i] = Operand::stack_m64;
                    }
                }
            }
        }

        dispatch_result = ApplyPrefixSizes(dispatch_result, prefix_info);
        dispatch_result.length = static_cast<uint8_t>(prefix_info.length + dispatch_result.length);
        return dispatch_result;
    }

    // x87 floating-point family (D8-DF), dispatched by opcode + ModR/M.
    case 0x87: {
        if (buffer.size() <= static_cast<size_t>(prefix_info.length + 1)) {
            return ERR_INSUFFICIENT_BUFFER;
        }

        const auto x87_opcode = buffer[prefix_info.length];
        const auto modrm = buffer[prefix_info.length + 1];
        auto result = GetInstructionDescriptor_x87(x87_opcode, modrm, kLengthTable_ModRM[modrm]);
        if (result.length >= 0xE0) {
            return result;
        }

        // For mod=00,r/m=100, SIB is present. If SIB.base=101, disp32 is mandatory.
        if ((modrm & 0b11'000'111u) == 0b00'000'100u) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            const auto sib = buffer[prefix_info.length + 2];
            if ((sib & 0b000'000'111u) == 0b000'000'101u) {
                result.length = static_cast<uint8_t>(result.length + 4);
            }
        }
        result.length = static_cast<uint8_t>(prefix_info.length + result.length);
        return result;
    }

    // MOV r/m16, Sreg (0x8C) and MOV Sreg, r/m16 (0x8E)
    // instr_id.operands.operand[0] is the abstract form (Sw_Ev or Ev_Sw), used as
    // index into kOperandFormTable_ModRM to select the correct per-ModRM operand table
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
        uint8_t modrm_len = kLengthTable_ModRM[modrm];
        InstructionId resolved = { instr_id.opcode, 2, form };
        // rm=100 (and mod!=11) → SIB byte follows; resolve stack markers. The
        // mandatory disp32 (SIB.base=101) only applies at mod=00.
        if (ModrmHasSib(modrm)) {
            if (buffer.size() <= static_cast<size_t>(prefix_info.length + 2)) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            const auto sib = buffer[prefix_info.length + 2];
            if ((modrm & 0b11'000'000u) == 0b00'000'000u
                && (sib & 0b000'000'111u) == 0b000'000'101u) {
                modrm_len = static_cast<uint8_t>(modrm_len + 4);
            }
            resolved = ResolveSibMarkers(resolved, sib);
        }
        const auto total_len = static_cast<uint8_t>(prefix_info.length + modrm_len);
        return { total_len, resolved };
    }

    // explicit invalid instruction marker
    case 0xD6:
        return ERR_UNDEFINED_INSTRUCTION;

    // B8+rd MOV: P2 keeps opcode-embedded destination as abstract GPR class.
    // No concrete register-number mapping from opcode low bits / REX.B is emitted here.
    // Default:  MOV r32, imm32  (5 bytes: opcode + 4-byte immediate)
    // REX.W:    MOV r64, imm64  (10 bytes: REX + opcode + 8-byte immediate)
    // 66h:      MOV r16, imm16  (4 bytes: 0x66 + opcode + 2-byte immediate)
    case 0xB8: {
        const auto rex_w = prefix_info.rex_w();
        const auto has_66 = prefix_info.has_prefix.has_66 != 0;
        auto iid = instr_id;
        iid.operands.operand[0] = Operand::r32;
        uint8_t imm_size { 0 };
        if (rex_w) {
            iid.operands.operand[0] = Operand::r64;
            iid.operands.operand[1] = Operand::imm64;
            imm_size = 8;
        } else if (has_66) {
            iid.operands.operand[0] = Operand::r16;
            iid.operands.operand[1] = Operand::imm16;
            imm_size = 2;
        } else {
            imm_size = 4; // default: imm32
        }
        const auto total_len = static_cast<uint8_t>(prefix_info.length + 1 + imm_size);
        return { total_len, iid };
    }

    // escapes to 2-byte opcode map
    case 0xE2:
        return Decode2ByteOpcode(prefix_info, buffer);

    // no dispatch - instruction length is fixed and does not depend on ModR/M byte
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x09: {
        if (opcode == 0x90 && prefix_info.rep_byte == static_cast<uint8_t>(Prefix::REPE)) {
            return { static_cast<uint8_t>(prefix_info.length + 1), IID(PAUSE) };
        }
        const auto adjusted = ApplyPrefixSizes({ tag.instr_len, instr_id }, prefix_info);
        return { static_cast<uint8_t>(prefix_info.length + adjusted.length), adjusted.instrId };
    }

    default:
        return ERR_UNDEFINED_INSTRUCTION;
    }
}

} // namespace xendiza::detail

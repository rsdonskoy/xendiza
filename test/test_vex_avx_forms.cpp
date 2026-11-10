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

TEST(VexForms, ImmediateShiftGroupsBothModesAndLengths)
{
    struct ShiftForm { uint8_t opcode; uint8_t reg; OpcodeId id; };
    constexpr ShiftForm forms[] = {
        { 0x71, 2, OpcodeId::VPSRLW }, { 0x71, 4, OpcodeId::VPSRAW }, { 0x71, 6, OpcodeId::VPSLLW },
        { 0x72, 2, OpcodeId::VPSRLD }, { 0x72, 4, OpcodeId::VPSRAD }, { 0x72, 6, OpcodeId::VPSLLD },
        { 0x73, 2, OpcodeId::VPSRLQ }, { 0x73, 3, OpcodeId::VPSRLDQ },
        { 0x73, 6, OpcodeId::VPSLLQ }, { 0x73, 7, OpcodeId::VPSLLDQ },
    };
    for (int mode : { 32, 64 }) {
        for (const auto& form : forms) {
            for (uint8_t l = 0; l < 2; ++l) {
                Bytes code{ 0xC4, 0xE1, uint8_t(0x79 | (l << 2)), form.opcode,
                    uint8_t(0xC0 | (form.reg << 3) | 1), 0x1B };
                const Operand vec = l ? Operand::ymm : Operand::xmm;
                ExpectSuccess(mode, code, 6, form.id, { vec, vec, Operand::imm8 });
                ExpectError(mode, code, 5, ErrorCode::INSUFFICIENT_BUFFER);
                code[2] = uint8_t(0x01 | (l << 2)); // Non-reserved vvvv must be rejected.
                ExpectError(mode, code, 6, ErrorCode::UNDEFINED_INSTRUCTION);
            }
        }
    }
}

TEST(VexForms, ImmediateShiftGroupsRejectReservedRegFields)
{
    struct Group { uint8_t opcode; uint8_t valid_mask; };
    constexpr Group groups[] = {
        { 0x71, uint8_t((1u << 2) | (1u << 4) | (1u << 6)) },
        { 0x72, uint8_t((1u << 2) | (1u << 4) | (1u << 6)) },
        { 0x73, uint8_t((1u << 2) | (1u << 3) | (1u << 6) | (1u << 7)) },
    };
    for (int mode : { 32, 64 }) {
        for (const auto& group : groups) {
            for (uint8_t reg = 0; reg < 8; ++reg) {
                if (group.valid_mask & (1u << reg)) continue;
                Bytes code{ 0xC4, 0xE1, 0x79, group.opcode,
                    uint8_t(0xC0 | (reg << 3) | 1), 0x1B };
                ExpectError(mode, code, 6, ErrorCode::UNDEFINED_INSTRUCTION);
            }
        }
    }
}

TEST(VexForms, MovdMovqWFormsAndModeRestrictions)
{
    for (int mode : { 32, 64 }) {
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x79, 0x6E, 0xC2 }, 5,
            OpcodeId::VMOVD, { Operand::xmm, Operand::r32 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x79, 0x7E, 0x05, 0, 0, 0, 0 }, 9,
            OpcodeId::VMOVD, { Operand::m32, Operand::xmm });
        if (mode == 32)
            ExpectError(32, Bytes{ 0xC4, 0xE1, 0xF9, 0x6E, 0xC2 }, 5,
                ErrorCode::UNDEFINED_INSTRUCTION);
        if (mode == 64) {
            ExpectSuccess(64, Bytes{ 0xC4, 0xE1, 0xF9, 0x6E, 0xC2 }, 5,
                OpcodeId::VMOVQ, { Operand::xmm, Operand::r64 });
            ExpectSuccess(64, Bytes{ 0xC4, 0xE1, 0xF9, 0x7E, 0x05, 0, 0, 0, 0 }, 9,
                OpcodeId::VMOVQ, { Operand::m64, Operand::xmm });
        }
    }
}

TEST(VexForms, IntegerConversionWFormsAndModeRestrictions)
{
    for (int mode : { 32, 64 }) {
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x72, 0x2A, 0xC2 }, 5,
            OpcodeId::VCVTSI2SS, { Operand::xmm, Operand::xmm, Operand::r32 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, 0x7B, 0x2D, 0x05, 0, 0, 0, 0 }, 9,
            OpcodeId::VCVTSD2SI, { Operand::r32, Operand::m64 });
        if (mode == 32) {
            ExpectError(32, Bytes{ 0xC4, 0xE1, 0xF2, 0x2A, 0xC2 }, 5,
                ErrorCode::UNDEFINED_INSTRUCTION);
            ExpectError(32, Bytes{ 0xC4, 0xE1, 0xFA, 0x2C, 0xC2 }, 5,
                ErrorCode::UNDEFINED_INSTRUCTION);
        }
        if (mode == 64) {
            ExpectSuccess(64, Bytes{ 0xC4, 0xE1, 0xF2, 0x2A, 0xC2 }, 5,
                OpcodeId::VCVTSI2SS, { Operand::xmm, Operand::xmm, Operand::r64 });
            ExpectSuccess(64, Bytes{ 0xC4, 0xE1, 0xFA, 0x2C, 0xC2 }, 5,
                OpcodeId::VCVTTSS2SI, { Operand::r64, Operand::xmm });
        }
    }
}

TEST(VexForms, ExtractAndInsertWFormsAndModeRestrictions)
{
    for (int mode : { 32, 64 }) {
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x79, 0x16, 0xC2, 0x03 }, 6,
            OpcodeId::VPEXTRD, { Operand::r32, Operand::xmm, Operand::imm8 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x71, 0x22, 0xC2, 0x03 }, 6,
            OpcodeId::VPINSRD, { Operand::xmm, Operand::xmm, Operand::r32, Operand::imm8 });
        if (mode == 32) {
            ExpectError(32, Bytes{ 0xC4, 0xE3, 0xF9, 0x16, 0xC2, 0x03 }, 6,
                ErrorCode::UNDEFINED_INSTRUCTION);
            ExpectError(32, Bytes{ 0xC4, 0xE3, 0xF1, 0x22, 0xC2, 0x03 }, 6,
                ErrorCode::UNDEFINED_INSTRUCTION);
        }
        if (mode == 64) {
            ExpectSuccess(64, Bytes{ 0xC4, 0xE3, 0xF9, 0x16, 0xC2, 0x03 }, 6,
                OpcodeId::VPEXTRQ, { Operand::r64, Operand::xmm, Operand::imm8 });
            ExpectSuccess(64, Bytes{ 0xC4, 0xE3, 0xF1, 0x22, 0xC2, 0x03 }, 6,
                OpcodeId::VPINSRQ, { Operand::xmm, Operand::xmm, Operand::r64, Operand::imm8 });
        }
    }
}

TEST(VexForms, PackedMovesSelectRegisterAndMemoryMnemonics)
{
    for (int mode : { 32, 64 }) {
        ExpectSuccess(mode, Bytes{ 0xC5, 0xF0, 0x12, 0xC2 }, 4,
            OpcodeId::VMOVHLPS, { Operand::xmm, Operand::xmm, Operand::xmm });
        ExpectSuccess(mode, Bytes{ 0xC5, 0xF0, 0x12, 0x05, 0, 0, 0, 0 }, 8,
            OpcodeId::VMOVLPS, { Operand::xmm, Operand::xmm, Operand::m64 });
        ExpectSuccess(mode, Bytes{ 0xC5, 0xF0, 0x16, 0xC2 }, 4,
            OpcodeId::VMOVLHPS, { Operand::xmm, Operand::xmm, Operand::xmm });
        ExpectSuccess(mode, Bytes{ 0xC5, 0xF0, 0x16, 0x05, 0, 0, 0, 0 }, 8,
            OpcodeId::VMOVHPS, { Operand::xmm, Operand::xmm, Operand::m64 });
    }
}

TEST(VexForms, BroadcastAndMaskMoveOperands)
{
    for (int mode : { 32, 64 }) {
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE2, 0x7D, 0x18, 0xC2 }, 5,
            OpcodeId::VBROADCASTSS, { Operand::ymm, Operand::xmm });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE2, 0x7D, 0x19, 0x05, 0, 0, 0, 0 }, 9,
            OpcodeId::VBROADCASTSD, { Operand::ymm, Operand::m64 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE2, 0x71, 0x2C, 0x05, 0, 0, 0, 0 }, 9,
            OpcodeId::VMASKMOVPS, { Operand::xmm, Operand::xmm, Operand::m128 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE2, 0x71, 0x2E, 0x05, 0, 0, 0, 0 }, 9,
            OpcodeId::VMASKMOVPS, { Operand::m128, Operand::xmm, Operand::xmm });
    }
}

TEST(VexForms, NonTemporalStoresAreMemoryOnly)
{
    struct Form { uint8_t pp; uint8_t opcode; OpcodeId id; };
    constexpr Form forms[] = {
        { 0x78, 0x2B, OpcodeId::VMOVNTPS },
        { 0x79, 0x2B, OpcodeId::VMOVNTPD },
        { 0x79, 0xE7, OpcodeId::VMOVNTDQ },
    };
    for (int mode : { 32, 64 }) {
        for (const auto& form : forms) {
            ExpectSuccess(mode, Bytes{ 0xC4, 0xE1, form.pp, form.opcode, 0x05, 0, 0, 0, 0 }, 9,
                form.id, { Operand::m128, Operand::xmm });
            ExpectError(mode, Bytes{ 0xC4, 0xE1, form.pp, form.opcode, 0xC2 }, 5,
                ErrorCode::UNDEFINED_INSTRUCTION);
        }
    }
}

TEST(VexForms, StringCompareAndIntegerLaneForms)
{
    for (int mode : { 32, 64 }) {
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x79, 0x60, 0xC2, 0x01 }, 6,
            OpcodeId::VPCMPESTRM, { Operand::xmm, Operand::xmm, Operand::imm8 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x79, 0x61, 0x05, 0, 0, 0, 0, 0x01 }, 10,
            OpcodeId::VPCMPESTRI, { Operand::xmm, Operand::m128, Operand::imm8 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x79, 0x62, 0xC2, 0x01 }, 6,
            OpcodeId::VPCMPISTRM, { Operand::xmm, Operand::xmm, Operand::imm8 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x79, 0x63, 0xC2, 0x01 }, 6,
            OpcodeId::VPCMPISTRI, { Operand::xmm, Operand::xmm, Operand::imm8 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x75, 0x38, 0xC2, 0x01 }, 6,
            OpcodeId::VINSERTI128, { Operand::ymm, Operand::ymm, Operand::xmm, Operand::imm8 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x7D, 0x39, 0x05, 0, 0, 0, 0, 0x01 }, 10,
            OpcodeId::VEXTRACTI128, { Operand::m128, Operand::ymm, Operand::imm8 });
        ExpectSuccess(mode, Bytes{ 0xC4, 0xE3, 0x75, 0x46, 0xC2, 0x01 }, 6,
            OpcodeId::VPERM2I128, { Operand::ymm, Operand::ymm, Operand::ymm, Operand::imm8 });
    }
}

} // namespace
} // namespace xendiza

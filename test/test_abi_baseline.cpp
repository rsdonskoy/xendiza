#include <gtest/gtest.h>

#include <cstdint>

#include <xendiza/detail/instruction.hpp>
#include <xendiza/detail/opcode_id.hpp>
#include <xendiza/detail/xendiza_common.hpp>
#include <xendiza/xendiza_c.h>

namespace xendiza {

// Pin a representative set of pre-existing opcode identifiers so accidental
// renumbering is caught immediately.
TEST(AbiBaseline, OpcodeIdValuesStable)
{
    EXPECT_EQ(static_cast<uint16_t>(OpcodeId::INVALID_OPCODE), 0x0000u);
    EXPECT_EQ(static_cast<uint16_t>(OpcodeId::NOP), 0x01B1u);      // alphabetical position
    EXPECT_EQ(static_cast<uint16_t>(OpcodeId::MOVUPS), 0x01A6u);
    EXPECT_EQ(static_cast<uint16_t>(OpcodeId::XTEST), 0x0498u);
}

TEST(AbiBaseline, NewAvxOpcodeIdsAreAppended)
{
    // New VEX forms must not reuse or shift existing values.
    EXPECT_GT(static_cast<uint16_t>(OpcodeId::VMOVUPS), static_cast<uint16_t>(OpcodeId::XTEST));
    EXPECT_GT(static_cast<uint16_t>(OpcodeId::VADDPS), static_cast<uint16_t>(OpcodeId::VMOVUPS));
    EXPECT_GT(static_cast<uint16_t>(OpcodeId::VPADDB), static_cast<uint16_t>(OpcodeId::VADDPS));
    EXPECT_GT(static_cast<uint16_t>(OpcodeId::VBLENDVPS), static_cast<uint16_t>(OpcodeId::VPADDB));
    EXPECT_GT(static_cast<uint16_t>(OpcodeId::VPBLENDVB), static_cast<uint16_t>(OpcodeId::VBLENDVPS));
}

TEST(AbiBaseline, OperandValuesStable)
{
    EXPECT_EQ(static_cast<uint16_t>(Operand::noopr), 0x0000u);
    EXPECT_EQ(static_cast<uint16_t>(Operand::xmm), 0x0059u);
    EXPECT_EQ(static_cast<uint16_t>(Operand::m128), 0x006Au);
    // Pre-existing segment, control, and debug registers must retain their
    // original numeric values; AVX operands are appended after them.
    EXPECT_EQ(static_cast<uint16_t>(Operand::sreg), 0x0078u);
    EXPECT_EQ(static_cast<uint16_t>(Operand::es), 0x0079u);
    EXPECT_EQ(static_cast<uint16_t>(Operand::gs), 0x007Eu);
    EXPECT_EQ(static_cast<uint16_t>(Operand::creg), 0x00AFu);
    EXPECT_EQ(static_cast<uint16_t>(Operand::cr0), 0x00B0u);
    EXPECT_EQ(static_cast<uint16_t>(Operand::dr), 0x00B4u);
    EXPECT_EQ(static_cast<uint16_t>(Operand::dr7), 0x00BAu);
}

TEST(AbiBaseline, NewAvxOperandsAreAppended)
{
    // YMM, m256 and VSIB forms are appended after all pre-existing values.
    // Pin their exact numeric values so any future insertion before the end
    // breaks the build rather than silently renumbering public constants.
    EXPECT_EQ(static_cast<uint16_t>(Operand::ymm), 0x00BBu);
    EXPECT_EQ(static_cast<uint16_t>(Operand::m256), 0x00BCu);
    EXPECT_EQ(static_cast<uint16_t>(Operand::m32_vsib), 0x00BDu);
    EXPECT_EQ(static_cast<uint16_t>(Operand::m64_vsib), 0x00BEu);
    EXPECT_EQ(static_cast<uint16_t>(Operand::m128_vsib), 0x00BFu);
    EXPECT_EQ(static_cast<uint16_t>(Operand::m256_vsib), 0x00C0u);
}

TEST(AbiBaseline, LayoutSizesStable)
{
    // The C and C++ structures are the public contract.  Exact sizes include
    // the compiler's padding and must stay stable.
    EXPECT_EQ(sizeof(Operands), 4 * sizeof(Operand));
    EXPECT_EQ(sizeof(InstructionId), size_t{12});
    EXPECT_EQ(sizeof(DecodedInstruction), size_t{14});
    EXPECT_EQ(sizeof(xendiza_decoded_instruction_t), size_t{14});
}

} // namespace xendiza

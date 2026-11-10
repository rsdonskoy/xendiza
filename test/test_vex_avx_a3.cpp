#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/detail/instruction.hpp>
#include <xendiza/detail/opcode_id.hpp>
#include <xendiza/xendiza.hpp>

namespace xendiza {

namespace {

auto Disasm64(const std::array<uint8_t, 16>& code, size_t n) noexcept -> DecodedInstruction
{
    return Disasm<64>(gsl::span<const uint8_t>(code.data(), n));
}

auto Disasm32(const std::array<uint8_t, 16>& code, size_t n) noexcept -> DecodedInstruction
{
    return Disasm<32>(gsl::span<const uint8_t>(code.data(), n));
}

} // namespace

TEST(VexA3, Vpgatherdd128)
{
    // C4 E2 71 90 04 15 00 00 00 00
    // VPGATHERDD xmm1, m32_vsib, xmm2 (mask=xmm2) with SIB=04 15:
    // scale=0, index=010 (XMM2), base=101 + disp32.
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x71, 0x90, 0x04, 0x15, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPGATHERDD);
    EXPECT_EQ(r.length, 10);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32_vsib);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
}

TEST(VexA3, Vpgatherdq256)
{
    // C4 E2 F5 90 04 15 ...
    // VPGATHERDQ ymm2, m64_vsib, ymm1 (W=1, L=1, mask=ymm1).
    // vvvv=~1=0xE -> byte3=0xF5
    // modrm=04 (mod=00, reg=0, rm=100)
    // SIB=15 (scale=0, index=010 XMM2, base=101)
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0xF5, 0x90, 0x04, 0x15, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPGATHERDQ);
    EXPECT_EQ(r.length, 10);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::ymm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64_vsib);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::ymm);
}

TEST(VexA3, Vgatherdps256)
{
    // C4 E2 75 92 04 15 ...
    // VGATHERDPS ymm0, m32_vsib, ymm1
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x75, 0x92, 0x04, 0x15, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VGATHERDPS);
    EXPECT_EQ(r.length, 10);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32_vsib);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::ymm);
}

TEST(VexA3, Vgatherqpd128)
{
    // C4 E2 B1 93 04 15 ...
    // VGATHERQPD xmm0, m64_vsib, xmm1 (W=1)
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0xB1, 0x93, 0x04, 0x15, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VGATHERQPD);
    EXPECT_EQ(r.length, 10);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m64_vsib);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
}

TEST(VexA3, Vpgatherqd256MixedWidth)
{
    // VPGATHERQD L=1 uses XMM destination/mask with YMM vector index.
    // mask = xmm1 -> vvvv=0xE, byte3 = 0x71 (W=0, vvvv=E, L=1, pp=1).
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x71, 0x91, 0x04, 0x15, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPGATHERQD);
    EXPECT_EQ(r.length, 10);
    EXPECT_EQ(r.instrId.operand_count, 3);
    EXPECT_EQ(r.instrId.operands.operand[0], Operand::xmm);
    EXPECT_EQ(r.instrId.operands.operand[1], Operand::m32_vsib);
    EXPECT_EQ(r.instrId.operands.operand[2], Operand::xmm);
}

TEST(VexA3, GatherOverlapDestMask)
{
    // dest reg = 0, mask = 0 -> overlap.
    // vvvv_src=0 -> vvvv_raw=0xF -> byte3 = 0x79 (W=0, vvvv=F, L=0, pp=1)
    // modrm reg=0, rm=100 -> 0x04
    // SIB=15 (index=2) so only dest/mask overlap is checked.
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x79, 0x90, 0x04, 0x15, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

TEST(VexA3, GatherOverlapDestIndex)
{
    // dest reg = 0, mask = 1, index = 0 -> overlap.
    // vvvv_src=1 -> byte3=0x71 (W=0, vvvv=E, L=0, pp=1)
    // modrm reg=0, rm=100 -> 0x04
    // SIB: index=0 (XMM0/YMM0), scale=0, base=101 -> 0x05
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x71, 0x90, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

TEST(VexA3, GatherOverlapMaskIndex)
{
    // dest reg = 2, mask = 0, index = 0 -> mask==index overlap.
    // vvvv_src=0 -> byte3=0x79
    // modrm reg=2 -> 0x14 (mod=00, reg=2, rm=100)
    // SIB index=0, base=101 -> 0x05
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x79, 0x90, 0x14, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

TEST(VexA3, GatherNoSib)
{
    // modrm rm=101 (no SIB) should be undefined for gather.
    std::array<uint8_t, 16> code{ 0xC4, 0xE2, 0x71, 0x90, 0x05, 0x00, 0x00, 0x00, 0x00 };
    auto r = Disasm64(code, 9);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::INVALID_OPCODE);
}

TEST(VexA3, GatherIndexLowBits100UsesVexX)
{
    // X=0 selects XMM12, which is valid; X=1 makes index=100 mean no index.
    constexpr std::array<uint8_t, 16> valid{ 0xC4, 0x82, 0x71, 0x90, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00 };
    constexpr std::array<uint8_t, 16> invalid{ 0xC4, 0xE2, 0x71, 0x90, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00 };
    // In 32-bit mode C4 with X=0 falls back to LES because the second byte's
    // mod bits are not 11; the extended vector index is therefore x64-only.
    const auto r = Disasm64(valid, 10);
    EXPECT_EQ(r.instrId.opcode, OpcodeId::VPGATHERDD);
    EXPECT_EQ(r.length, 10);
    for (const auto& r : { Disasm32(invalid, 10), Disasm64(invalid, 10) }) {
        EXPECT_EQ(r.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
    }
}

} // namespace xendiza

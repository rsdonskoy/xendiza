// test_x86_prefixes.cpp
// Unit tests for the 32-bit prefix processing (ProcessPrefix), the no-operand
// single-byte instructions (case 0x01 direct dispatch), and the 32-bit-only
// INC/DEC short forms (0x40-0x4F). Also covers the segment-override composite
// memory operand injection (InjectSegmentForMemory / MakeCompositeMemOperand)
// across all six segment prefixes, the 0x66 operand-size and 0x67 address-size
// overrides, duplicate-prefix error detection, and legacy opcodes that the
// shared decode table marks invalid in 32-bit mode (PUSH/POP ES, PUSHA/POPA,
// CALL/JMP far, LES/LDS, BCD-adjusts, etc.).
//
// All tests use the public xendiza::Disasm<32> entry point. 32-bit mode has no
// REX prefix, so 0x40-0x4F are INC/DEC on the eight GPRs (not REX prefixes as
// in x64) - this is the single biggest 32-vs-64 mode divergence and is
// explicitly tested here.

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <gsl/span>

#include <xendiza/xendiza.hpp>

using namespace xendiza;

template <size_t N>
static DecodedInstruction Disasm32(const std::array<uint8_t, N>& buf)
{
    return xendiza::Disasm<32>(gsl::span<const uint8_t>(buf.data(), N));
}

// =============================================================================
// 32-bit-only INC/DEC short forms: 0x40-0x4F.
// In 32-bit mode these are single-byte INC/DEC on the 8 GPRs (r32 by default,
// r16 under 0x66). This is the inverse of x64 where 0x40-0x4F are REX prefixes.
// =============================================================================

TEST(X86IncDecTest, INC_0x40_to_0x47_all_r32)
{
    for (uint8_t opc = 0x40; opc <= 0x47; ++opc) {
        auto result = Disasm32(std::array<uint8_t, 1>{opc});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::INC) << "opc=" << std::hex << (int)opc;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(result.length, 1);
    }
}

TEST(X86IncDecTest, DEC_0x48_to_0x4F_all_r32)
{
    for (uint8_t opc = 0x48; opc <= 0x4F; ++opc) {
        auto result = Disasm32(std::array<uint8_t, 1>{opc});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::DEC) << "opc=" << std::hex << (int)opc;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(result.length, 1);
    }
}

TEST(X86IncDecTest, INC_0x40_with_66h_shrinks_to_r16)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0x66, 0x40}); // INC ax
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INC);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::r16);
    EXPECT_EQ(result.length, 2);
}

// =============================================================================
// PUSH/POP r32 short forms: 0x50-0x5F (shared table has r64 -> normalized to r32)
// =============================================================================

TEST(X86NoOperandTest, PUSH_0x50_to_0x57_all_r32_normalized)
{
    for (uint8_t opc = 0x50; opc <= 0x57; ++opc) {
        auto result = Disasm32(std::array<uint8_t, 1>{opc});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH) << "opc=" << std::hex << (int)opc;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(result.length, 1);
    }
}

TEST(X86NoOperandTest, POP_0x58_to_0x5F_all_r32_normalized)
{
    for (uint8_t opc = 0x58; opc <= 0x5F; ++opc) {
        auto result = Disasm32(std::array<uint8_t, 1>{opc});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::POP) << "opc=" << std::hex << (int)opc;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::r32);
        EXPECT_EQ(result.length, 1);
    }
}

// =============================================================================
// No-operand single-byte instructions (case 0x01 direct dispatch).
// Verify operand_count == 0 and length == 1.
// =============================================================================

TEST(X86NoOperandTest, NOP_0x90)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(X86NoOperandTest, RET_0xC3)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0xC3});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RET);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(X86NoOperandTest, Flags_single_byte_ops)
{
    const struct { uint8_t op; OpcodeId id; } cases[] = {
        {0xF8, OpcodeId::CLC}, {0xF9, OpcodeId::STC},
        {0xFA, OpcodeId::CLI}, {0xFB, OpcodeId::STI},
        {0xFC, OpcodeId::CLD}, {0xFD, OpcodeId::STD},
        {0xF5, OpcodeId::CMC}, {0xF4, OpcodeId::HLT},
    };
    for (const auto& c : cases) {
        auto result = Disasm32(std::array<uint8_t, 1>{c.op});
        EXPECT_EQ(result.instrId.opcode, c.id) << "op=" << std::hex << (int)c.op;
        EXPECT_EQ(result.instrId.operand_count, 0);
        EXPECT_EQ(result.length, 1);
    }
}

TEST(X86NoOperandTest, CWDE_and_CDQ)
{
    auto cwde = Disasm32(std::array<uint8_t, 1>{0x98});
    EXPECT_EQ(cwde.instrId.opcode, OpcodeId::CWDE);
    EXPECT_EQ(cwde.instrId.operand_count, 0);
    EXPECT_EQ(cwde.length, 1);

    auto cdq = Disasm32(std::array<uint8_t, 1>{0x99});
    EXPECT_EQ(cdq.instrId.opcode, OpcodeId::CDQ);
    EXPECT_EQ(cdq.instrId.operand_count, 0);
    EXPECT_EQ(cdq.length, 1);
}

TEST(X86NoOperandTest, PUSHFQ_and_POPFQ)
{
    auto pushf = Disasm32(std::array<uint8_t, 1>{0x9C});
    EXPECT_EQ(pushf.instrId.opcode, OpcodeId::PUSHFQ);
    EXPECT_EQ(pushf.instrId.operand_count, 0);
    EXPECT_EQ(pushf.length, 1);

    auto popf = Disasm32(std::array<uint8_t, 1>{0x9D});
    EXPECT_EQ(popf.instrId.opcode, OpcodeId::POPFQ);
    EXPECT_EQ(popf.instrId.operand_count, 0);
    EXPECT_EQ(popf.length, 1);
}

TEST(X86NoOperandTest, SAHF_LAHF)
{
    auto sahf = Disasm32(std::array<uint8_t, 1>{0x9E});
    EXPECT_EQ(sahf.instrId.opcode, OpcodeId::SAHF);
    EXPECT_EQ(sahf.length, 1);

    auto lahf = Disasm32(std::array<uint8_t, 1>{0x9F});
    EXPECT_EQ(lahf.instrId.opcode, OpcodeId::LAHF);
    EXPECT_EQ(lahf.length, 1);
}

TEST(X86NoOperandTest, XLAT_0xD7)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0xD7});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::XLAT);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(X86NoOperandTest, INT3_0xCC)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0xCC});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INT3);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(X86NoOperandTest, IRETD_0xCF_is_32bit_form)
{
    // In 32-bit mode 0xCF is IRETD (the shared table hardcodes IRETD).
    auto result = Disasm32(std::array<uint8_t, 1>{0xCF});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::IRETD);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(X86NoOperandTest, LEAVE_0xC9)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0xC9});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::LEAVE);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

TEST(X86NoOperandTest, RETF_0xCB)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0xCB});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::RETF);
    EXPECT_EQ(result.instrId.operand_count, 0);
    EXPECT_EQ(result.length, 1);
}

// =============================================================================
// Legacy opcodes invalid in this implementation (shared table marks them
// DTE(0xD6, IID_INVALID) -> UNDEFINED_INSTRUCTION). These are opcodes that are
// nominally legal in real i386 but the xendiza shared table reserves them
// (e.g. because x64 reuses the slot for VEX/REX). Asserting current behavior.
// =============================================================================

TEST(X86InvalidTest, PUSHA_POPA_0x60_0x61_undefined)
{
    for (const auto op : std::array<uint8_t, 2>{0x60, 0x61}) {
        auto result = Disasm32(std::array<uint8_t, 1>{op});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE) << "op=" << std::hex << (int)op;
        EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
    }
}

TEST(X86InvalidTest, PUSH_POP_ES_0x06_0x07_undefined)
{
    for (const auto op : std::array<uint8_t, 2>{0x06, 0x07}) {
        auto result = Disasm32(std::array<uint8_t, 1>{op});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE) << "op=" << std::hex << (int)op;
        EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
    }
}

TEST(X86InvalidTest, PUSH_CS_0x0E_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0x0E});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(X86InvalidTest, BCD_adjusts_undefined)
{
    // 0x27 DAA, 0x2F DAS, 0x37 AAA, 0x3F AAS
    for (const auto op : std::array<uint8_t, 4>{0x27, 0x2F, 0x37, 0x3F}) {
        auto result = Disasm32(std::array<uint8_t, 1>{op});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE) << "op=" << std::hex << (int)op;
        EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
    }
}

TEST(X86InvalidTest, CALL_far_0x9A_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0x9A});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(X86InvalidTest, JMP_far_0xEA_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0xEA});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(X86InvalidTest, INTO_0xCE_undefined)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0xCE});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

TEST(X86InvalidTest, LES_LDS_0xC4_0xC5_decode_as_invalid_short)
{
    // With VEX support, a lone C4/C5 in 32-bit mode is no longer decodable as a
    // length-1 LES/LDS instruction because the second byte is required to
    // disambiguate VEX (mod=11) from legacy LES/LDS. It now reports
    // INSUFFICIENT_BUFFER, while C4/C5 followed by a non-VEX second byte still
    // falls back to the legacy path.
    for (const auto op : std::array<uint8_t, 2>{0xC4, 0xC5}) {
        auto result = Disasm32(std::array<uint8_t, 1>{op});
        EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER)) << "op=" << std::hex << (int)op;
    }
}

// =============================================================================
// ProcessPrefix: repeated legacy prefixes are accepted (same semantics as
// Zydis) - the flag is set, redundant occurrences are harmless, and state
// bytes (rep/seg) follow last-one-wins.
// =============================================================================

TEST(X86PrefixTest, Duplicate_LOCK_ignored)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0xF0, 0xF0, 0x01, 0x00}); // ADD m32,r32
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::m32);
    EXPECT_EQ(result.length, 4);
}

TEST(X86PrefixTest, Duplicate_REP_last_wins)
{
    // F2 then F3: rep_byte ends as F3; 32-bit mode has no F3 90 -> PAUSE remap.
    auto result = Disasm32(std::array<uint8_t, 3>{0xF2, 0xF3, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

TEST(X86PrefixTest, Duplicate_REPNE_same_byte_ok)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0xF2, 0xF2, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

TEST(X86PrefixTest, Duplicate_66h_ok)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x66, 0x66, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

TEST(X86PrefixTest, Duplicate_67h_ok)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x67, 0x67, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 3);
}

// =============================================================================
// ProcessPrefix: 15-byte total instruction-length limit. A 7x-66h multi-prefix
// nop is exactly 15 bytes (the architectural maximum); one more prefix byte
// pushes the total to 16 and must be rejected.
// =============================================================================

TEST(X86PrefixTest, MultiPrefix_15ByteNop)
{
    auto result = Disasm32(std::array<uint8_t, 15>{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                                   0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 15);
}

TEST(X86PrefixTest, Over15Byte_66x8_rejected)
{
    auto result = Disasm32(std::array<uint8_t, 16>{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                                   0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// =============================================================================
// ProcessPrefix: valid prefix combinations (last-segment-wins for seg, others
// combine). These should decode normally.
// =============================================================================

TEST(X86PrefixTest, LOCK_prefix_consumed_in_length)
{
    // F0 01 C8 -> LOCK ADD eax, ecx (length 3: prefix + opcode + modrm)
    auto result = Disasm32(std::array<uint8_t, 3>{0xF0, 0x01, 0xC8});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.length, 3);
}

TEST(X86PrefixTest, REP_prefix_consumed_in_length)
{
    // F3 90 -> REP NOP (PAUSE); decoder just consumes the prefix
    auto result = Disasm32(std::array<uint8_t, 2>{0xF3, 0x90});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::NOP);
    EXPECT_EQ(result.length, 2);
}

TEST(X86PrefixTest, Two_seg_prefixes_last_wins)
{
    // 26 (ES) then 2E (CS) on ADD m32,r32 -> CS wins, operand cs_m32
    auto result = Disasm32(std::array<uint8_t, 4>{0x26, 0x2E, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::cs_m32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r32);
    EXPECT_EQ(result.length, 4);
}

TEST(X86PrefixTest, Mixed_66_and_seg_prefix_decodes)
{
    // 66 64 01 00 -> fs: ADD m16, r16 (66 shrinks, fs composites)
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x64, 0x01, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::fs_m16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
    EXPECT_EQ(result.length, 4);
}

// =============================================================================
// Segment override composite memory operands: all 6 segments x multiple widths.
// InjectSegmentForMemory rewrites the FIRST memory operand via
// MakeCompositeMemOperand. The composite forms are produced for m8/m16/m32/m64
// and the moffs family; m/m128/m32fp/m64fp/m80fp are NOT composited (they fall
// through and return unchanged).
// =============================================================================

TEST(X86SegOverrideTest, ES_m8_via_ADD_0x00)
{
    // 26 00 00 -> ADD es:[eax], al  (Eb_Gb: m8 first operand)
    auto result = Disasm32(std::array<uint8_t, 3>{0x26, 0x00, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::es_m8);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r8);
    EXPECT_EQ(result.length, 3);
}

TEST(X86SegOverrideTest, CS_m8_via_ADD_0x00)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x2E, 0x00, 0x00});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::cs_m8);
}

TEST(X86SegOverrideTest, SS_m8_via_ADD_0x00)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x36, 0x00, 0x00});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::ss_m8);
}

TEST(X86SegOverrideTest, DS_m8_via_ADD_0x00)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x3E, 0x00, 0x00});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::ds_m8);
}

TEST(X86SegOverrideTest, FS_m8_via_ADD_0x00)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x64, 0x00, 0x00});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::fs_m8);
}

TEST(X86SegOverrideTest, GS_m8_via_ADD_0x00)
{
    auto result = Disasm32(std::array<uint8_t, 3>{0x65, 0x00, 0x00});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::gs_m8);
}

TEST(X86SegOverrideTest, all_segments_m32_via_ADD_0x01)
{
    const struct { uint8_t prefix; Operand expected; } cases[] = {
        {0x26, Operand::es_m32}, {0x2E, Operand::cs_m32},
        {0x36, Operand::ss_m32}, {0x3E, Operand::ds_m32},
        {0x64, Operand::fs_m32}, {0x65, Operand::gs_m32},
    };
    for (const auto& c : cases) {
        auto result = Disasm32(std::array<uint8_t, 3>{c.prefix, 0x01, 0x00});
        EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD) << "prefix=" << std::hex << (int)c.prefix;
        EXPECT_EQ(result.instrId.operands.operand[0], c.expected) << "prefix=" << std::hex << (int)c.prefix;
        EXPECT_EQ(result.length, 3);
    }
}

TEST(X86SegOverrideTest, FS_m16_via_ADD_with_66h)
{
    // 66 64 01 00 -> ADD fs:m16, r16
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x64, 0x01, 0x00});
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::fs_m16);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::r16);
}

TEST(X86SegOverrideTest, GS_m64_via_CMPXCHG8B_0F_C7)
{
    // 65 0F C7 08 -> GS: CMPXCHG8B gs:[eax] (m64)
    auto result = Disasm32(std::array<uint8_t, 4>{0x65, 0x0F, 0xC7, 0x08});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CMPXCHG8B);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::gs_m64);
    EXPECT_EQ(result.length, 4);
}

// =============================================================================
// Segment override on moffs forms (A0-A3): MOV al/eax <-> moffs.
// Composite via MakeCompositeMemOperand on moffs8/16/32/64.
// =============================================================================

TEST(X86SegOverrideTest, FS_moffs32_via_MOV_A1)
{
    // 64 A1 78 56 34 12 -> MOV eax, fs:[moffs32]  (already covered in basic,
    // re-asserted here for the composite test suite)
    auto result = Disasm32(std::array<uint8_t, 6>{0x64, 0xA1, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::fs_moffs32);
    EXPECT_EQ(result.length, 6);
}

TEST(X86SegOverrideTest, GS_moffs8_via_MOV_A0)
{
    // 65 A0 78 56 34 12 -> MOV al, gs:[moffs8]
    auto result = Disasm32(std::array<uint8_t, 6>{0x65, 0xA0, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::al);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::gs_moffs8);
    EXPECT_EQ(result.length, 6);
}

TEST(X86SegOverrideTest, CS_moffs32_via_MOV_A3)
{
    // 2E A3 78 56 34 12 -> MOV cs:[moffs32], eax
    auto result = Disasm32(std::array<uint8_t, 6>{0x2E, 0xA3, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::cs_moffs32);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::eax);
    EXPECT_EQ(result.length, 6);
}

// =============================================================================
// Segment override does NOT composite non-m{8,16,32,64}/moffs forms.
// x87 m32fp/m64fp, m, m128 fall through and stay un-prefixed (operand unchanged).
// =============================================================================

TEST(X86SegOverrideTest, FS_does_not_composite_x87_m32fp)
{
    // 64 D8 00 -> FADD st0, [eax] with FS prefix; m32fp is NOT composited
    auto result = Disasm32(std::array<uint8_t, 3>{0x64, 0xD8, 0x00});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::FADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::st0);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::m32fp); // unchanged
    EXPECT_EQ(result.length, 3);
}

// =============================================================================
// 0x67 address-size override: shrinks moffs32 -> moffs16 (disp16), length 3.
// Only the moffs operand is affected; registers stay at default size.
// =============================================================================

TEST(X86AddrSizeTest, MOV_A1_with_67h_shrinks_moffs_to_moffs16)
{
    // 67 A1 34 12 -> MOV eax, [moffs16]  (disp16). Total length = 1 (prefix)
    // + 1 (opcode) + 2 (disp16) = 4. The moffs operand shrinks to moffs16;
    // the register operand (eax) is unaffected by the address-size override.
    auto result = Disasm32(std::array<uint8_t, 4>{0x67, 0xA1, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::moffs16);
    EXPECT_EQ(result.length, 4);
}

TEST(X86AddrSizeTest, MOV_A1_default_is_moffs32_length_5)
{
    auto result = Disasm32(std::array<uint8_t, 5>{0xA1, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::eax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::moffs32);
    EXPECT_EQ(result.length, 5);
}

TEST(X86AddrSizeTest, MOV_A0_with_67h_moffs8_unchanged)
{
    // 0x67 does not affect moffs8 (only moffs32 is remapped). Length = 1
    // (prefix) + 1 (opcode) + 2 (disp16 for moffs8 in this impl) = 4.
    auto result = Disasm32(std::array<uint8_t, 4>{0x67, 0xA0, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::al);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::moffs8);
    EXPECT_EQ(result.length, 4);
}

// =============================================================================
// 0x66 operand-size override on moffs MOV: register shrinks (eax->ax), the
// address size stays at default 32 bits.
// =============================================================================

TEST(X86OperandSizeTest, MOV_A1_with_66h_shrinks_register_to_ax)
{
    // 66 A1 78 56 34 12 -> MOV ax, [moffs32]  (disp32, register shrunk)
    auto result = Disasm32(std::array<uint8_t, 6>{0x66, 0xA1, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::MOV);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::ax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::moffs32);
    EXPECT_EQ(result.length, 6);
}

TEST(X86OperandSizeTest, PUSH_imm32_0x68_default)
{
    auto result = Disasm32(std::array<uint8_t, 5>{0x68, 0x78, 0x56, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm32);
    EXPECT_EQ(result.length, 5);
}

TEST(X86OperandSizeTest, PUSH_imm32_0x68_with_66h_shrinks_to_imm16)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x68, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::PUSH);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::imm16);
    EXPECT_EQ(result.length, 4);
}

// =============================================================================
// Jcc rel8 short forms (0x70-0x7F): verify mnemonic loop and rel8 operand.
// =============================================================================

TEST(X86JccTest, Jcc_0x70_to_0x7F_all_rel8)
{
    const OpcodeId expected[] = {
        OpcodeId::JO,  OpcodeId::JNO, OpcodeId::JB,  OpcodeId::JAE,
        OpcodeId::JZ,  OpcodeId::JNZ, OpcodeId::JBE, OpcodeId::JA,
        OpcodeId::JS,  OpcodeId::JNS, OpcodeId::JP,  OpcodeId::JNP,
        OpcodeId::JL,  OpcodeId::JGE, OpcodeId::JLE, OpcodeId::JG,
    };
    for (uint8_t opc = 0x70; opc <= 0x7F; ++opc) {
        auto result = Disasm32(std::array<uint8_t, 2>{opc, 0x10});
        EXPECT_EQ(result.instrId.opcode, expected[opc - 0x70]) << "opc=" << std::hex << (int)opc;
        EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel8);
        EXPECT_EQ(result.length, 2);
    }
}

// =============================================================================
// Empty buffer and all-prefix-no-opcode error paths
// =============================================================================

TEST(X86PrefixTest, EmptyBuffer_insufficient)
{
    auto result = xendiza::Disasm<32>(gsl::span<const uint8_t>());
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(X86PrefixTest, Only_prefix_no_opcode_undefined)
{
    // 0x66 is consumed as a prefix; when the buffer then runs out (no opcode
    // byte), the dispatcher falls through to the UNDEFINED path rather than
    // INSUFFICIENT_BUFFER. Asserting actual behavior.
    auto result = Disasm32(std::array<uint8_t, 1>{0x66});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// =============================================================================
// AAM/AAD (0xD4/0xD5): valid in 32-bit mode (ax, imm8), invalid in 64-bit mode.
// DAA/DAS/AAA/AAS remain intentionally unsupported per the existing scope
// decision (see X86InvalidTest.BCD_adjusts_undefined above).
// =============================================================================

TEST(X86AamAadTest, AAM_0xD4_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD4, 0x0A});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::AAM);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::ax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

TEST(X86AamAadTest, AAD_0xD5_imm8)
{
    auto result = Disasm32(std::array<uint8_t, 2>{0xD5, 0x0A});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::AAD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::ax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm8);
    EXPECT_EQ(result.length, 2);
}

TEST(X86AamAadTest, AAM_truncated_reports_insufficient_buffer)
{
    auto result = Disasm32(std::array<uint8_t, 1>{0xD4});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::INSUFFICIENT_BUFFER));
}

TEST(X86AamAadTest, AAM_AAD_undefined_in_64bit)
{
    // The shared table keeps 0xD4/0xD5 invalid for the 64-bit path.
    const auto buf = std::array<uint8_t, 2>{0xD4, 0x0A};
    auto result = xendiza::Disasm<64>(gsl::span<const uint8_t>(buf.data(), buf.size()));
    EXPECT_EQ(result.instrId.opcode, OpcodeId::INVALID_OPCODE);
    EXPECT_EQ(result.length, static_cast<uint8_t>(ErrorCode::UNDEFINED_INSTRUCTION));
}

// =============================================================================
// 0x66 operand-size override on near branches and the accumulator-immediate
// family in 32-bit mode (rel16 / ax,imm16; contrast with x64 which ignores
// 0x66 on near branches).
// =============================================================================

TEST(X86PrefixTest, CALL_0xE8_with_66h_rel16)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0xE8, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::CALL);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel16);
    EXPECT_EQ(result.length, 4);
}

TEST(X86PrefixTest, JZ_0F84_with_66h_rel16)
{
    auto result = Disasm32(std::array<uint8_t, 5>{0x66, 0x0F, 0x84, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::JZ);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::rel16);
    EXPECT_EQ(result.length, 5);
}

TEST(X86PrefixTest, ADD_0x05_with_66h_imm16)
{
    auto result = Disasm32(std::array<uint8_t, 4>{0x66, 0x05, 0x34, 0x12});
    EXPECT_EQ(result.instrId.opcode, OpcodeId::ADD);
    EXPECT_EQ(result.instrId.operands.operand[0], Operand::ax);
    EXPECT_EQ(result.instrId.operands.operand[1], Operand::imm16);
    EXPECT_EQ(result.length, 4);
}

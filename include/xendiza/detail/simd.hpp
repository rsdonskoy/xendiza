#ifndef XENDIZA_SIMD_HPP
#define XENDIZA_SIMD_HPP

#include "xendiza_common.hpp"

namespace xendiza::detail {

// ── SIMD descriptor schema + tables (mandatory-prefix remap) ─────────────
// Migrated from byte-identical copies in xendiza_x64.cpp / xendiza_x86.cpp.
// One-time 32/64 semantic identity check (2026-11-03): the two copies were
// byte-identical and both dispatch sites apply the same prefix-slot order
// (none, 66h, F3, F2) and the same operand shapes (xmm, xmm/mem), so the
// table is mode-neutral and lives here once. If a mode difference ever
// appears, derive a per-mode view and override rows; do not duplicate.
// The decode engine consuming these tables lives in src/simd_decode.cpp.
//
// Descriptor schema (dual-form matrix): each opcode-2 row carries one slot
// per mandatory-prefix variant {none, 66h, F3, F2}; each slot carries the
// mod=11 and mod!=11 mnemonics plus full operand pairs for both forms.
// Store-direction rows (0F 11/29), dual-name rows (0F 12) and REX.W
// overrides are all slot data — no per-opcode cases.

enum class SimdImmKind : uint8_t {
    none, // no trailing immediate
    imm8  // one trailing imm8 byte counted in the length
};

// Prefix-slot resolution policy (add-0f38-0f3a-support design Decision 3).
//   Default: mandatory-prefix slot table via SelectSimdSlot — none/66h/F3/F2
//     select slots 0-3; 66h together with F2/F3 is UNDEFINED; 66h never
//     shrinks (it is a mandatory prefix, not an operand-size override).
//   SizeOverride: shared MOVBE/CRC32 rows — no REP prefix selects the none
//     slot (MOVBE), F2 selects the F2 slot (CRC32), F3 is UNDEFINED; 66h
//     never selects a slot, it is an operand-size override applied through
//     the selected slot's shrink_66 masks when REX.W is clear, and is legal
//     together with F2 (CRC32 r/m16).
enum class SimdPrefixPolicy : uint8_t {
    Default,
    SizeOverride
};

struct SimdSlot {
    OpcodeId opcode_reg;  // mod=11 mnemonic; INVALID_OPCODE = form illegal
    OpcodeId opcode_mem;  // mod!=11 mnemonic; INVALID_OPCODE = form illegal
    Operands pair_reg;    // full operand pair, mod=11
    OpcodeId opcode_reg_w = OpcodeId::INVALID_OPCODE; // optional REX.W mnemonic override (reg form)
    OpcodeId opcode_mem_w = OpcodeId::INVALID_OPCODE; // optional REX.W mnemonic override (mem form)
    uint8_t rex_w_reg = 0; // bitmask: operand positions widened by REX.W (reg form)
    uint8_t rex_w_mem = 0; // bitmask: operand positions widened by REX.W (mem form)
    Operands pair_mem;    // full operand pair, mod!=11
    uint8_t shrink_66 = 0; // bitmask: operand positions shrunk r32→r16 / m32→m16
                           // under a 66h operand-size override (size-override rows
                           // only; REX.W clear — REX.W takes precedence)
};

// Operand pair for illegal forms (reg-only / mem-only slot halves).
inline constexpr Operands kSimdNoOperands = {
    { Operand::invalid, Operand::invalid, Operand::invalid, Operand::invalid } };

struct SimdRow {
    std::array<SimdSlot, 4> slots = [] { // index: 0=none, 1=66h, 2=F3, 3=F2
        std::array<SimdSlot, 4> s{};
        s.fill({ OpcodeId::INVALID_OPCODE, OpcodeId::INVALID_OPCODE,
                 kSimdNoOperands,
                 OpcodeId::INVALID_OPCODE, OpcodeId::INVALID_OPCODE, 0, 0,
                 kSimdNoOperands });
        return s;
    }();
    SimdImmKind imm_kind = SimdImmKind::none;
    SimdPrefixPolicy prefix_policy = SimdPrefixPolicy::Default;
    // Optional 8-entry reg-field sub-table (66 0F 71/72/73 shift groups): the
    // reg field selects the slot for mod=11 forms; memory forms fall through
    // to the row slots, which stay INVALID for these rows (reg-only).
    const std::array<SimdSlot, 8>* reg_subtable = nullptr;
};

// Slot whose mnemonics are identical for both forms.
constexpr auto SimdSlotForm(const OpcodeId op, const Operands pair_reg, const Operands pair_mem) noexcept
    -> SimdSlot
{
    SimdSlot slot{};
    slot.opcode_reg = op;
    slot.opcode_mem = op;
    slot.pair_reg   = pair_reg;
    slot.pair_mem   = pair_mem;
    return slot;
}

// Dual-name slot: the register and memory forms report different mnemonics
// (0F 12 MOVHLPS vs MOVLPS, store-direction rows, reg-only / mem-only slots).
constexpr auto SimdSlotDual(const OpcodeId op_reg, const Operands pair_reg, const OpcodeId op_mem,
                            const Operands pair_mem) noexcept -> SimdSlot
{
    SimdSlot slot{};
    slot.opcode_reg = op_reg;
    slot.opcode_mem = op_mem;
    slot.pair_reg   = pair_reg;
    slot.pair_mem   = pair_mem;
    return slot;
}

// Slot with a REX.W mnemonic override plus per-form operand-widening masks
// (MOVD/MOVQ, CVTSI2SS/SD, CVT*2SI). `rex_w` here is always `op_w`; masks are
// bit i = operand position i widens (r32→r64, m32→m64) under REX.W.
constexpr auto SimdSlotRexW(const OpcodeId op, const OpcodeId op_w, const Operands pair_reg,
                            const Operands pair_mem, const uint8_t mask_reg,
                            const uint8_t mask_mem) noexcept -> SimdSlot
{
    SimdSlot slot = SimdSlotForm(op, pair_reg, pair_mem);
    slot.opcode_reg_w = op_w;
    slot.opcode_mem_w = op_w;
    slot.rex_w_reg    = mask_reg;
    slot.rex_w_mem    = mask_mem;
    return slot;
}

// Row with only the none (PS) and 66h (PD) slots filled; both m128 sources.
constexpr auto SimdPsPdRow(const OpcodeId ps_op, const OpcodeId pd_op) noexcept -> SimdRow
{
    SimdRow row{};
    row.slots[0] = SimdSlotForm(ps_op, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    row.slots[1] = SimdSlotForm(pd_op, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    return row;
}

// Row where a single prefix slot decodes (dual-name capable), all others INVALID.
constexpr auto SimdSingleSlotRow(const uint8_t slot_index, const OpcodeId op_reg,
                                 const Operands pair_reg, const OpcodeId op_mem,
                                 const Operands pair_mem) noexcept -> SimdRow
{
    SimdRow row{};
    auto&       slot      = row.slots[slot_index];
    slot.opcode_reg       = op_reg;
    slot.opcode_mem       = op_mem;
    slot.pair_reg         = pair_reg;
    slot.pair_mem         = pair_mem;
    return row;
}

// Classic PS/PD/SS/SD family row: none→ps, 66h→pd, F3→ss, F2→sd; every slot
// decodes both forms with the packed/scalar memory class.
constexpr auto SimdFamilyRow(const OpcodeId ps, const OpcodeId pd, const OpcodeId ss,
                             const OpcodeId sd) noexcept -> SimdRow
{
    SimdRow row{};
    row.slots[0] = SimdSlotForm(ps, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    row.slots[1] = SimdSlotForm(pd, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    row.slots[2] = SimdSlotForm(ss, OPRS2(xmm, xmm), OPRS2(xmm, m32));
    row.slots[3] = SimdSlotForm(sd, OPRS2(xmm, xmm), OPRS2(xmm, m64));
    return row;
}

// Widens a marked operand under REX.W only; the SIMD engine never applies a
// 66h shrink (66h here is a mandatory prefix, not an operand-size override).
constexpr auto SimdWidenOperandRexW(const Operand op) noexcept -> Operand
{
    switch (op) {
    case Operand::r32:       return Operand::r64;
    case Operand::m32:       return Operand::m64;
    case Operand::stack_m32: return Operand::stack_m64;
    default:                 return op;
    }
}

// Shrinks a marked operand under a 66h operand-size override (size-override
// rows only: MOVBE/CRC32, where 66h is not a mandatory prefix). Applies only
// when REX.W is clear — REX.W takes precedence and widens instead.
constexpr auto SimdShrinkOperand66(const Operand op) noexcept -> Operand
{
    switch (op) {
    case Operand::r32: return Operand::r16;
    case Operand::m32: return Operand::m16;
    default:           return op;
    }
}

// Reg-field sub-table slot for the 66 0F 71/72/73 shift groups: single xmm
// destination; the trailing imm8 is appended by the engine (imm_kind).
constexpr auto SimdSubSlot(const OpcodeId op) noexcept -> SimdSlot
{
    SimdSlot slot{};
    slot.opcode_reg = op;
    slot.pair_reg   = { { Operand::xmm, Operand::noopr, Operand::noopr, Operand::noopr } };
    return slot;
}

constexpr auto SimdShiftSubTableFill() noexcept -> std::array<SimdSlot, 8>
{
    std::array<SimdSlot, 8> t{};
    t.fill({ OpcodeId::INVALID_OPCODE, OpcodeId::INVALID_OPCODE, kSimdNoOperands,
             OpcodeId::INVALID_OPCODE, OpcodeId::INVALID_OPCODE, 0, 0, kSimdNoOperands });
    return t;
}

// /2 PSRLW, /4 PSRAW, /6 PSLLW; other reg slots reserved.
inline constexpr auto kSimdShiftSub71 = [] {
    auto t = SimdShiftSubTableFill();
    t[2] = SimdSubSlot(OpcodeId::PSRLW);
    t[4] = SimdSubSlot(OpcodeId::PSRAW);
    t[6] = SimdSubSlot(OpcodeId::PSLLW);
    return t;
}();

// /2 PSRLD, /4 PSRAD, /6 PSLLD.
inline constexpr auto kSimdShiftSub72 = [] {
    auto t = SimdShiftSubTableFill();
    t[2] = SimdSubSlot(OpcodeId::PSRLD);
    t[4] = SimdSubSlot(OpcodeId::PSRAD);
    t[6] = SimdSubSlot(OpcodeId::PSLLD);
    return t;
}();

// /2 PSRLQ, /3 PSRLDQ, /6 PSLLQ, /7 PSLLDQ.
inline constexpr auto kSimdShiftSub73 = [] {
    auto t = SimdShiftSubTableFill();
    t[2] = SimdSubSlot(OpcodeId::PSRLQ);
    t[3] = SimdSubSlot(OpcodeId::PSRLDQ);
    t[6] = SimdSubSlot(OpcodeId::PSLLQ);
    t[7] = SimdSubSlot(OpcodeId::PSLLDQ);
    return t;
}();

// 66-mandatory reg-field shift-group row: register forms resolve through the
// sub-table; all four prefix slots stay INVALID so memory forms (and the
// no-66 MMX forms) decode undefined.
constexpr auto SimdShiftGroupRow(const std::array<SimdSlot, 8>* subtable) noexcept -> SimdRow
{
    SimdRow row{};
    row.imm_kind      = SimdImmKind::imm8;
    row.reg_subtable  = subtable;
    return row;
}

// Uniform 66-mandatory packed-integer row: the 66 slot decodes xmm, xmm/m128;
// the none/F3/F2 slots stay INVALID (the MMX forms are strictly rejected).
constexpr auto SimdPackedRow(const OpcodeId op) noexcept -> SimdRow
{
    SimdRow row{};
    row.slots[1] = SimdSlotForm(op, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    return row;
}

// Index by second opcode byte. Rows not listed are INVALID in every slot and
// decode as undefined-instruction.
inline constexpr auto kSimdOpcodeTable = [] {
    std::array<SimdRow, 256> table{};

    // 0F 10/11: full SSE1/SSE2 remap — MOVUPS/MOVUPD (none/66h, m128),
    // MOVSS/MOVSD (F3/F2, m32/m64); 0F 11 is the store-direction counterpart.
    table[0x10].slots[0] = SimdSlotForm(OpcodeId::MOVUPS, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x10].slots[1] = SimdSlotForm(OpcodeId::MOVUPD, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x10].slots[2] = SimdSlotForm(OpcodeId::MOVSS, OPRS2(xmm, xmm), OPRS2(xmm, m32));
    table[0x10].slots[3] = SimdSlotForm(OpcodeId::MOVSD, OPRS2(xmm, xmm), OPRS2(xmm, m64));
    table[0x11].slots[0] = SimdSlotForm(OpcodeId::MOVUPS, OPRS2(xmm, xmm), OPRS2(m128, xmm));
    table[0x11].slots[1] = SimdSlotForm(OpcodeId::MOVUPD, OPRS2(xmm, xmm), OPRS2(m128, xmm));
    table[0x11].slots[2] = SimdSlotForm(OpcodeId::MOVSS, OPRS2(xmm, xmm), OPRS2(m32, xmm));
    table[0x11].slots[3] = SimdSlotForm(OpcodeId::MOVSD, OPRS2(xmm, xmm), OPRS2(m64, xmm));
    // 0F 28/29 MOVAPS/MOVAPD: none/66h only (m128); F3/F2 absent.
    table[0x28].slots[0] = SimdSlotForm(OpcodeId::MOVAPS, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x28].slots[1] = SimdSlotForm(OpcodeId::MOVAPD, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x29].slots[0] = SimdSlotForm(OpcodeId::MOVAPS, OPRS2(xmm, xmm), OPRS2(m128, xmm));
    table[0x29].slots[1] = SimdSlotForm(OpcodeId::MOVAPD, OPRS2(xmm, xmm), OPRS2(m128, xmm));
    // 0F 2E/2F UCOMIS/COMIS: none → SS (m32), 66h → SD (m64); REP forms rejected.
    table[0x2E] = SimdSingleSlotRow(0, OpcodeId::UCOMISS, OPRS2(xmm, xmm), OpcodeId::UCOMISS, OPRS2(xmm, m32));
    table[0x2E].slots[1] = SimdSlotForm(OpcodeId::UCOMISD, OPRS2(xmm, xmm), OPRS2(xmm, m64));
    table[0x2F] = SimdSingleSlotRow(0, OpcodeId::COMISS, OPRS2(xmm, xmm), OpcodeId::COMISS, OPRS2(xmm, m32));
    table[0x2F].slots[1] = SimdSlotForm(OpcodeId::COMISD, OPRS2(xmm, xmm), OPRS2(xmm, m64));

    // Arithmetic families with full mandatory-prefix remap.
    table[0x58] = SimdFamilyRow(OpcodeId::ADDPS, OpcodeId::ADDPD, OpcodeId::ADDSS, OpcodeId::ADDSD);
    table[0x59] = SimdFamilyRow(OpcodeId::MULPS, OpcodeId::MULPD, OpcodeId::MULSS, OpcodeId::MULSD);
    table[0x5C] = SimdFamilyRow(OpcodeId::SUBPS, OpcodeId::SUBPD, OpcodeId::SUBSS, OpcodeId::SUBSD);
    table[0x5E] = SimdFamilyRow(OpcodeId::DIVPS, OpcodeId::DIVPD, OpcodeId::DIVSS, OpcodeId::DIVSD);

    // ── M1: prefix-remap binary rows ─────────────────────────────────────
    // 0F 51 sqrt: full remap.
    table[0x51] = SimdFamilyRow(OpcodeId::SQRTPS, OpcodeId::SQRTPD, OpcodeId::SQRTSS, OpcodeId::SQRTSD);
    // 0F 52 rsqrt / 0F 53 rcp: none = packed (m128), F3 = scalar RSQRTSS /
    // RCPSS (m32, SDM-verified 2026-11-04); 66h and F2 are absent variants.
    table[0x52].slots[0] = SimdSlotForm(OpcodeId::RSQRTPS, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x52].slots[2] = SimdSlotForm(OpcodeId::RSQRTSS, OPRS2(xmm, xmm), OPRS2(xmm, m32));
    table[0x53].slots[0] = SimdSlotForm(OpcodeId::RCPPS, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x53].slots[2] = SimdSlotForm(OpcodeId::RCPSS, OPRS2(xmm, xmm), OPRS2(xmm, m32));
    // 0F 54-57 logical: PS + PD only (F3/F2 absent).
    table[0x54] = SimdPsPdRow(OpcodeId::ANDPS, OpcodeId::ANDPD);
    table[0x55] = SimdPsPdRow(OpcodeId::ANDNPS, OpcodeId::ANDNPD);
    table[0x56] = SimdPsPdRow(OpcodeId::ORPS, OpcodeId::ORPD);
    table[0x57] = SimdPsPdRow(OpcodeId::XORPS, OpcodeId::XORPD);
    // 0F 5A packed/scalar CVT: reg form always xmm,xmm; memory class per slot
    // (PS2PD reads m64, PD2PS reads m128, SS2SD reads m32, SD2SS reads m64).
    table[0x5A].slots[0] = SimdSlotForm(OpcodeId::CVTPS2PD, OPRS2(xmm, xmm), OPRS2(xmm, m64));
    table[0x5A].slots[1] = SimdSlotForm(OpcodeId::CVTPD2PS, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x5A].slots[2] = SimdSlotForm(OpcodeId::CVTSS2SD, OPRS2(xmm, xmm), OPRS2(xmm, m32));
    table[0x5A].slots[3] = SimdSlotForm(OpcodeId::CVTSD2SS, OPRS2(xmm, xmm), OPRS2(xmm, m64));
    // 0F 5B int<->ps CVT: none/66/F3 packed m128; F2 absent.
    table[0x5B].slots[0] = SimdSlotForm(OpcodeId::CVTDQ2PS, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x5B].slots[1] = SimdSlotForm(OpcodeId::CVTPS2DQ, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x5B].slots[2] = SimdSlotForm(OpcodeId::CVTTPS2DQ, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    // 0F 5D min / 0F 5F max: full remap.
    table[0x5D] = SimdFamilyRow(OpcodeId::MINPS, OpcodeId::MINPD, OpcodeId::MINSS, OpcodeId::MINSD);
    table[0x5F] = SimdFamilyRow(OpcodeId::MAXPS, OpcodeId::MAXPD, OpcodeId::MAXSS, OpcodeId::MAXSD);
    // 66/F2/F3 0F E6 double/int CVT: none absent; F3 reads m64, others m128.
    table[0xE6].slots[1] = SimdSlotForm(OpcodeId::CVTPD2DQ, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0xE6].slots[2] = SimdSlotForm(OpcodeId::CVTDQ2PD, OPRS2(xmm, xmm), OPRS2(xmm, m64));
    table[0xE6].slots[3] = SimdSlotForm(OpcodeId::CVTTPD2DQ, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    // SSE3 riders: 66/F2 0F D0 ADDSUB, 66/F2 0F 7C/7D HADD/HSUB; none/F3 absent.
    table[0xD0].slots[1] = SimdSlotForm(OpcodeId::ADDSUBPD, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0xD0].slots[3] = SimdSlotForm(OpcodeId::ADDSUBPS, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x7C].slots[1] = SimdSlotForm(OpcodeId::HADDPD, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x7C].slots[3] = SimdSlotForm(OpcodeId::HADDPS, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x7D].slots[1] = SimdSlotForm(OpcodeId::HSUBPD, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x7D].slots[3] = SimdSlotForm(OpcodeId::HSUBPS, OPRS2(xmm, xmm), OPRS2(xmm, m128));

    // ── M2: irregular MOV/CVT/GPR rows ───────────────────────────────────
    // 0F 12: dual-name (reg MOVHLPS / mem MOVLPS m64); 66h MOVLPD both forms;
    // F3 MOVSLDUP (SSE3 rider). 0F 16 mirrors with MOVLHPS/MOVHPS/MOVHPD/
    // MOVSHDUP. (F2 0F 12/16 MOVDDUP is not in this change's rider list.)
    table[0x12].slots[0] = SimdSlotDual(OpcodeId::MOVHLPS, OPRS2(xmm, xmm), OpcodeId::MOVLPS, OPRS2(xmm, m64));
    // 66 0F 12 MOVLPD: memory source only — the register form is reserved (#UD).
    table[0x12].slots[1] = SimdSlotDual(OpcodeId::INVALID_OPCODE, kSimdNoOperands,
                                        OpcodeId::MOVLPD, OPRS2(xmm, m64));
    table[0x12].slots[2] = SimdSlotForm(OpcodeId::MOVSLDUP, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x13].slots[0] = SimdSlotDual(OpcodeId::INVALID_OPCODE,
                                        kSimdNoOperands,
                                        OpcodeId::MOVLPS, OPRS2(m64, xmm));
    table[0x13].slots[1] = SimdSlotDual(OpcodeId::INVALID_OPCODE,
                                        kSimdNoOperands,
                                        OpcodeId::MOVLPD, OPRS2(m64, xmm));
    table[0x16].slots[0] = SimdSlotDual(OpcodeId::MOVLHPS, OPRS2(xmm, xmm), OpcodeId::MOVHPS, OPRS2(xmm, m64));
    // 66 0F 16 MOVHPD: memory source only — the register form is reserved (#UD).
    table[0x16].slots[1] = SimdSlotDual(OpcodeId::INVALID_OPCODE, kSimdNoOperands,
                                        OpcodeId::MOVHPD, OPRS2(xmm, m64));
    table[0x16].slots[2] = SimdSlotForm(OpcodeId::MOVSHDUP, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x17].slots[0] = SimdSlotDual(OpcodeId::INVALID_OPCODE,
                                        kSimdNoOperands,
                                        OpcodeId::MOVHPS, OPRS2(m64, xmm));
    table[0x17].slots[1] = SimdSlotDual(OpcodeId::INVALID_OPCODE,
                                        kSimdNoOperands,
                                        OpcodeId::MOVHPD, OPRS2(m64, xmm));
    // 0F 50: MOVMSKPS/MOVMSKPD r32, xmm — register-form only; REX.W ignored
    // (Decision 12: no upgraded encodings exist).
    table[0x50].slots[0] = SimdSlotDual(OpcodeId::MOVMSKPS, OPRS2(r32, xmm), OpcodeId::INVALID_OPCODE,
                                        { { Operand::invalid, Operand::invalid, Operand::invalid, Operand::invalid } });
    table[0x50].slots[1] = SimdSlotDual(OpcodeId::MOVMSKPD, OPRS2(r32, xmm), OpcodeId::INVALID_OPCODE,
                                        { { Operand::invalid, Operand::invalid, Operand::invalid, Operand::invalid } });
    // F2/F3 0F 2A CVTSI2SS/SD xmm, r32/m32 — REX.W upgrades the GPR source in
    // both forms (r32→r64, m32→m64). none/66 slots are the MMX forms (INVALID).
    table[0x2A].slots[2] = SimdSlotRexW(OpcodeId::CVTSI2SS, OpcodeId::CVTSI2SS, OPRS2(xmm, r32),
                                        OPRS2(xmm, m32), 0x02, 0x02);
    table[0x2A].slots[3] = SimdSlotRexW(OpcodeId::CVTSI2SD, OpcodeId::CVTSI2SD, OPRS2(xmm, r32),
                                        OPRS2(xmm, m32), 0x02, 0x02);
    // F2/F3 0F 2C/2D CVTT*/CVT* to GPR — REX.W widens only the destination
    // (source stays xmm/m32 for F3, xmm/m64 for F2). none/66 slots are MMX.
    table[0x2C].slots[2] = SimdSlotRexW(OpcodeId::CVTTSS2SI, OpcodeId::CVTTSS2SI, OPRS2(r32, xmm),
                                        OPRS2(r32, m32), 0x01, 0x01);
    table[0x2C].slots[3] = SimdSlotRexW(OpcodeId::CVTTSD2SI, OpcodeId::CVTTSD2SI, OPRS2(r32, xmm),
                                        OPRS2(r32, m64), 0x01, 0x01);
    table[0x2D].slots[2] = SimdSlotRexW(OpcodeId::CVTSS2SI, OpcodeId::CVTSS2SI, OPRS2(r32, xmm),
                                        OPRS2(r32, m32), 0x01, 0x01);
    table[0x2D].slots[3] = SimdSlotRexW(OpcodeId::CVTSD2SI, OpcodeId::CVTSD2SI, OPRS2(r32, xmm),
                                        OPRS2(r32, m64), 0x01, 0x01);
    // 66 0F 6E/7E MOVD <-> MOVQ under REX.W (mnemonic override + widening) in
    // both directions. F3 0F 7E is the XMM quadword load; unprefixed MMX forms are rejected.
    table[0x6E].slots[1] = SimdSlotRexW(OpcodeId::MOVD, OpcodeId::MOVQ, OPRS2(xmm, r32),
                                        OPRS2(xmm, m32), 0x02, 0x02);
    table[0x7E].slots[1] = SimdSlotRexW(OpcodeId::MOVD, OpcodeId::MOVQ, OPRS2(r32, xmm),
                                        OPRS2(m32, xmm), 0x01, 0x01);
    table[0x7E].slots[2] = SimdSlotForm(OpcodeId::MOVQ, OPRS2(xmm, xmm), OPRS2(xmm, m64));
    // 66 0F D6 MOVQ xmm2/m64, xmm1: BOTH forms are legal — the register form
    // (MOVQ xmm, xmm) is the canonical reg-reg copy; F2/F3 D6 are the MMX
    // MOVQ2DQ/DQ2Q variants (INVALID).
    table[0xD6].slots[1] = SimdSlotForm(OpcodeId::MOVQ, OPRS2(xmm, xmm), OPRS2(m64, xmm));
    // 66 0F D7 PMOVMSKB r32, xmm — register-form only; REX.W ignored (Decision 12).
    table[0xD7].slots[1] = SimdSlotDual(OpcodeId::PMOVMSKB, OPRS2(r32, xmm), OpcodeId::INVALID_OPCODE,
                                        { { Operand::invalid, Operand::invalid, Operand::invalid, Operand::invalid } });
    // 66 0F E7 MOVNTDQ m128, xmm — memory destination only.
    table[0xE7].slots[1] = SimdSlotDual(OpcodeId::INVALID_OPCODE,
                                        kSimdNoOperands,
                                        OpcodeId::MOVNTDQ, OPRS2(m128, xmm));
    // 66 0F F7 MASKMOVDQU xmm, xmm — register form only.
    table[0xF7].slots[1] = SimdSlotDual(OpcodeId::MASKMOVDQU, OPRS2(xmm, xmm), OpcodeId::INVALID_OPCODE,
                                        { { Operand::invalid, Operand::invalid, Operand::invalid, Operand::invalid } });

    // ── M3: trailing-immediate rows ──────────────────────────────────────
    // 0F C2 compare predicate: full PS/PD/SS/SD remap, trailing imm8.
    table[0xC2] = SimdFamilyRow(OpcodeId::CMPPS, OpcodeId::CMPPD, OpcodeId::CMPSS, OpcodeId::CMPSD);
    table[0xC2].imm_kind = SimdImmKind::imm8;
    // 0F C6 shuffle: PS + PD only, trailing imm8; F3/F2 absent.
    table[0xC6].slots[0] = SimdSlotForm(OpcodeId::SHUFPS, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0xC6].slots[1] = SimdSlotForm(OpcodeId::SHUFPD, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0xC6].imm_kind = SimdImmKind::imm8;
    // 0F 70 packed shuffle: 66 PSHUFD, F3 PSHUFHW, F2 PSHUFLW; none absent (MMX).
    table[0x70].slots[1] = SimdSlotForm(OpcodeId::PSHUFD, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x70].slots[2] = SimdSlotForm(OpcodeId::PSHUFHW, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x70].slots[3] = SimdSlotForm(OpcodeId::PSHUFLW, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x70].imm_kind = SimdImmKind::imm8;
    // 66 0F C4 PINSRW xmm, r32/m16, imm8 (REX.W ignored — no upgraded encoding).
    table[0xC4].slots[1] = SimdSlotForm(OpcodeId::PINSRW, OPRS2(xmm, r32), OPRS2(xmm, m16));
    table[0xC4].imm_kind = SimdImmKind::imm8;
    // 66 0F C5 PEXTRW r32, xmm, imm8 — register form only (REX.W ignored,
    // spec scenario; PEXTRQ exists only as SSE4.1 66 0F 3A 16, out of scope).
    table[0xC5].slots[1] = SimdSlotDual(OpcodeId::PEXTRW, OPRS2(r32, xmm), OpcodeId::INVALID_OPCODE,
                                        { { Operand::invalid, Operand::invalid, Operand::invalid, Operand::invalid } });
    table[0xC5].imm_kind = SimdImmKind::imm8;
    // 66 0F 71/72/73 shift groups: reg-field sub-mnemonics, register form
    // only, trailing imm8 (design.md Decision 6).
    table[0x71] = SimdShiftGroupRow(&kSimdShiftSub71);
    table[0x72] = SimdShiftGroupRow(&kSimdShiftSub72);
    table[0x73] = SimdShiftGroupRow(&kSimdShiftSub73);

    // ── M4: SSE2 packed-integer block (explicit enumeration, design.md
    // Decision 11) ──────────────────────────────────────────────────────────
    // Derivation (2026-11-04): the row list below was derived from the SDM
    // opcode-map tables (per-instruction encoding tables on an SDM-derived
    // reference) and cross-checked against the bundled vectors; the corpus
    // carries direct vector coverage only for 66 0F D6/D7 (capstone x86.yaml
    // #46, x86_64-encoding.s.yaml #55), which match. Ranges NOT listed here
    // (70, 71-73, 77, D0, D6, D7, E6, E7, F0, F7, FF) carry dedicated rows
    // from earlier milestones or stay INVALID (77 EMMS / FF UD0).
    // Verified uniform xmm, xmm/m128 rows under mandatory 66h:
    table[0x60] = SimdPackedRow(OpcodeId::PUNPCKLBW);
    table[0x61] = SimdPackedRow(OpcodeId::PUNPCKLWD);
    table[0x62] = SimdPackedRow(OpcodeId::PUNPCKLDQ);
    table[0x63] = SimdPackedRow(OpcodeId::PACKSSWB);
    table[0x64] = SimdPackedRow(OpcodeId::PCMPGTB);
    table[0x65] = SimdPackedRow(OpcodeId::PCMPGTW);
    table[0x66] = SimdPackedRow(OpcodeId::PCMPGTD);
    table[0x67] = SimdPackedRow(OpcodeId::PACKUSWB);
    table[0x68] = SimdPackedRow(OpcodeId::PUNPCKHBW);
    table[0x69] = SimdPackedRow(OpcodeId::PUNPCKHWD);
    table[0x6A] = SimdPackedRow(OpcodeId::PUNPCKHDQ);
    table[0x6B] = SimdPackedRow(OpcodeId::PACKSSDW);
    table[0x6C] = SimdPackedRow(OpcodeId::PUNPCKLQDQ);
    table[0x6D] = SimdPackedRow(OpcodeId::PUNPCKHQDQ);
    // 6F MOVDQA load + F3 MOVDQU load (66/F3 only; none is the MMX MOVQ).
    table[0x6F].slots[1] = SimdSlotForm(OpcodeId::MOVDQA, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    table[0x6F].slots[2] = SimdSlotForm(OpcodeId::MOVDQU, OPRS2(xmm, xmm), OPRS2(xmm, m128));
    // 74-76 PCMPEQB/W/D (77 EMMS is MMX-only and stays on the 1-byte path).
    table[0x74] = SimdPackedRow(OpcodeId::PCMPEQB);
    table[0x75] = SimdPackedRow(OpcodeId::PCMPEQW);
    table[0x76] = SimdPackedRow(OpcodeId::PCMPEQD);
    // 7F store-direction counterparts: register form {xmm, xmm}, memory form
    // {m128, xmm} (66 MOVDQA, F3 MOVDQU).
    table[0x7F].slots[1] = SimdSlotForm(OpcodeId::MOVDQA, OPRS2(xmm, xmm), OPRS2(m128, xmm));
    table[0x7F].slots[2] = SimdSlotForm(OpcodeId::MOVDQU, OPRS2(xmm, xmm), OPRS2(m128, xmm));
    table[0xD1] = SimdPackedRow(OpcodeId::PSRLW);
    table[0xD2] = SimdPackedRow(OpcodeId::PSRLD);
    table[0xD3] = SimdPackedRow(OpcodeId::PSRLQ);
    table[0xD4] = SimdPackedRow(OpcodeId::PADDQ);
    table[0xD5] = SimdPackedRow(OpcodeId::PMULLW);
    table[0xD8] = SimdPackedRow(OpcodeId::PSUBUSB);
    table[0xD9] = SimdPackedRow(OpcodeId::PSUBUSW);
    table[0xDA] = SimdPackedRow(OpcodeId::PMINUB);
    table[0xDB] = SimdPackedRow(OpcodeId::PAND);
    table[0xDC] = SimdPackedRow(OpcodeId::PADDUSB);
    table[0xDD] = SimdPackedRow(OpcodeId::PADDUSW);
    table[0xDE] = SimdPackedRow(OpcodeId::PMAXUB);
    table[0xDF] = SimdPackedRow(OpcodeId::PANDN);
    table[0xE0] = SimdPackedRow(OpcodeId::PAVGB);
    table[0xE1] = SimdPackedRow(OpcodeId::PSRAW);
    table[0xE2] = SimdPackedRow(OpcodeId::PSRAD);
    table[0xE3] = SimdPackedRow(OpcodeId::PAVGW);
    table[0xE4] = SimdPackedRow(OpcodeId::PMULHUW);
    table[0xE5] = SimdPackedRow(OpcodeId::PMULHW);
    table[0xE8] = SimdPackedRow(OpcodeId::PSUBSB);
    table[0xE9] = SimdPackedRow(OpcodeId::PSUBSW);
    table[0xEA] = SimdPackedRow(OpcodeId::PMINSW);
    table[0xEB] = SimdPackedRow(OpcodeId::POR);
    table[0xEC] = SimdPackedRow(OpcodeId::PADDSB);
    table[0xED] = SimdPackedRow(OpcodeId::PADDSW);
    table[0xEE] = SimdPackedRow(OpcodeId::PMAXSW);
    table[0xEF] = SimdPackedRow(OpcodeId::PXOR);
    table[0xF1] = SimdPackedRow(OpcodeId::PSLLW);
    table[0xF2] = SimdPackedRow(OpcodeId::PSLLD);
    table[0xF3] = SimdPackedRow(OpcodeId::PSLLQ);
    table[0xF4] = SimdPackedRow(OpcodeId::PMULUDQ);
    table[0xF5] = SimdPackedRow(OpcodeId::PMADDWD);
    table[0xF6] = SimdPackedRow(OpcodeId::PSADBW);
    table[0xF8] = SimdPackedRow(OpcodeId::PSUBB);
    table[0xF9] = SimdPackedRow(OpcodeId::PSUBW);
    table[0xFA] = SimdPackedRow(OpcodeId::PSUBD);
    table[0xFB] = SimdPackedRow(OpcodeId::PSUBQ);
    table[0xFC] = SimdPackedRow(OpcodeId::PADDB);
    table[0xFD] = SimdPackedRow(OpcodeId::PADDW);
    table[0xFE] = SimdPackedRow(OpcodeId::PADDD);
    // F2 0F F0 LDDQU xmm1, m128 (SSE3 rider): memory source only — the
    // register form is reserved (#UD); every other prefix undefined.
    table[0xF0].slots[3] = SimdSlotDual(OpcodeId::INVALID_OPCODE, kSimdNoOperands,
                                        OpcodeId::LDDQU, OPRS2(xmm, m128));

    return table;
}();

// ── Three-byte opcode tables (0F 38 / 0F 3A), keyed by the third byte ────
// Same SimdRow schema as kSimdOpcodeTable; add-0f38-0f3a-support Decision 1.
// Rows are filled by explicit SDM-derived enumeration (M4 Decision 11
// process: local dump .ref/sdm-md/ cross-checked against the bundled
// Zydis/Capstone vectors, never from memory); unlisted rows stay INVALID in
// every slot and decode as undefined-instruction.
//
// Schema outcomes recorded per the change design (Decisions 2/3):
//   - Row prefix policy: 66-mandatory SIMD rows use SimdPrefixPolicy::Default
//     (SelectSimdSlot). The shared MOVBE/CRC32 rows (38 F0/F1) use
//     SimdPrefixPolicy::SizeOverride — MOVBE in the none slot, CRC32 in the
//     F2 slot, F3 undefined, and 66h acting as an operand-size override via
//     the per-slot shrink_66 masks (MOVBE: both operands; CRC32 F1: source
//     only; CRC32 F0: neither), with REX.W precedence through rex_w_* masks.
//   - Memory-mandatory rows (MOVBE load/store, MOVNTDQA) set opcode_reg =
//     INVALID_OPCODE, so mod=11 resolves UNDEFINED through the existing rule.
//   - PEXTR*/PINSR* 64-bit forms use opcode_reg_w/opcode_mem_w mnemonic
//     overrides plus rex_w_* widening masks.
//   - Implied-register policy: the architectural implied operands of
//     PCMPESTR*/PCMPISTR* (EAX/EDX(/ECX)) and the BLENDV* XMM0 mask are NOT
//     reported — rows carry their two explicit operands (+imm8) only.
//   - LOCK (F0h) is #UD on every 0F 38/0F 3A row per the SDM exception
//     tables; Dispatch3ByteOpcode rejects it at the shared entry.
inline constexpr auto kDecodeTable_0F38 = [] {
    std::array<SimdRow, 256> table{};

    // ── M5b: 0F 38 rows (SDM enumeration in the change design checklist;
    // all rows Valid in 64-bit AND compat/leg mode) ─────────────────────────
    // SSSE3 packed-integer block: 66-mandatory uniform xmm, xmm/m128 rows
    // (the no-66 forms are MMX and stay rejected).
    table[0x00] = SimdPackedRow(OpcodeId::PSHUFB);
    table[0x01] = SimdPackedRow(OpcodeId::PHADDW);
    table[0x02] = SimdPackedRow(OpcodeId::PHADDD);
    table[0x03] = SimdPackedRow(OpcodeId::PHADDSW);
    table[0x04] = SimdPackedRow(OpcodeId::PMADDUBSW);
    table[0x05] = SimdPackedRow(OpcodeId::PHSUBW);
    table[0x06] = SimdPackedRow(OpcodeId::PHSUBD);
    table[0x07] = SimdPackedRow(OpcodeId::PHSUBSW);
    table[0x08] = SimdPackedRow(OpcodeId::PSIGNB);
    table[0x09] = SimdPackedRow(OpcodeId::PSIGNW);
    table[0x0A] = SimdPackedRow(OpcodeId::PSIGND);
    table[0x0B] = SimdPackedRow(OpcodeId::PMULHRSW);
    table[0x1C] = SimdPackedRow(OpcodeId::PABSB);
    table[0x1D] = SimdPackedRow(OpcodeId::PABSW);
    table[0x1E] = SimdPackedRow(OpcodeId::PABSD);

    // SSE4.1 blend-with-implied-mask + PTEST rows: 66-only; the architectural
    // XMM0 mask of 10/14/15 is NOT part of the reported operand contract.
    table[0x10] = SimdPackedRow(OpcodeId::PBLENDVB);
    table[0x14] = SimdPackedRow(OpcodeId::BLENDVPS);
    table[0x15] = SimdPackedRow(OpcodeId::BLENDVPD);
    table[0x17] = SimdPackedRow(OpcodeId::PTEST);

    // SSE4.1 sign/zero-extension loads: 66-only; the memory class narrows per
    // row (PMOVSX/PMOVZX pages: *BW/*WD/*DQ m64, *BD/*WQ m32, *BQ m16).
    table[0x20] = SimdSingleSlotRow(1, OpcodeId::PMOVSX, OPRS2(xmm, xmm), OpcodeId::PMOVSX, OPRS2(xmm, m64));
    table[0x21] = SimdSingleSlotRow(1, OpcodeId::PMOVSX, OPRS2(xmm, xmm), OpcodeId::PMOVSX, OPRS2(xmm, m32));
    table[0x22] = SimdSingleSlotRow(1, OpcodeId::PMOVSX, OPRS2(xmm, xmm), OpcodeId::PMOVSX, OPRS2(xmm, m16));
    table[0x23] = SimdSingleSlotRow(1, OpcodeId::PMOVSX, OPRS2(xmm, xmm), OpcodeId::PMOVSX, OPRS2(xmm, m64));
    table[0x24] = SimdSingleSlotRow(1, OpcodeId::PMOVSX, OPRS2(xmm, xmm), OpcodeId::PMOVSX, OPRS2(xmm, m32));
    table[0x25] = SimdSingleSlotRow(1, OpcodeId::PMOVSX, OPRS2(xmm, xmm), OpcodeId::PMOVSX, OPRS2(xmm, m64));
    table[0x30] = SimdSingleSlotRow(1, OpcodeId::PMOVZX, OPRS2(xmm, xmm), OpcodeId::PMOVZX, OPRS2(xmm, m64));
    table[0x31] = SimdSingleSlotRow(1, OpcodeId::PMOVZX, OPRS2(xmm, xmm), OpcodeId::PMOVZX, OPRS2(xmm, m32));
    table[0x32] = SimdSingleSlotRow(1, OpcodeId::PMOVZX, OPRS2(xmm, xmm), OpcodeId::PMOVZX, OPRS2(xmm, m16));
    table[0x33] = SimdSingleSlotRow(1, OpcodeId::PMOVZX, OPRS2(xmm, xmm), OpcodeId::PMOVZX, OPRS2(xmm, m64));
    table[0x34] = SimdSingleSlotRow(1, OpcodeId::PMOVZX, OPRS2(xmm, xmm), OpcodeId::PMOVZX, OPRS2(xmm, m32));
    table[0x35] = SimdSingleSlotRow(1, OpcodeId::PMOVZX, OPRS2(xmm, xmm), OpcodeId::PMOVZX, OPRS2(xmm, m64));

    // Uniform 66-mandatory packed rows.
    table[0x28] = SimdPackedRow(OpcodeId::PMULDQ);
    table[0x29] = SimdPackedRow(OpcodeId::PCMPEQQ);
    table[0x2B] = SimdPackedRow(OpcodeId::PACKUSDW);
    table[0x37] = SimdPackedRow(OpcodeId::PCMPGTQ); // SSE4.2
    table[0x40] = SimdPackedRow(OpcodeId::PMULLD);
    table[0x41] = SimdPackedRow(OpcodeId::PHMINPOSUW);

    // 66 0F 38 2A MOVNTDQA xmm1, m128: memory-source-only — the register form
    // is reserved (#UD); opcode_reg = INVALID resolves mod=11 UNDEFINED.
    table[0x2A] = SimdSingleSlotRow(1, OpcodeId::INVALID_OPCODE, kSimdNoOperands,
                                    OpcodeId::MOVNTDQA, OPRS2(xmm, m128));

    // AES-NI round/inverse rows: 66-only xmm, xmm/m128.
    table[0xDB] = SimdPackedRow(OpcodeId::AESIMC);
    table[0xDC] = SimdPackedRow(OpcodeId::AESENC);
    table[0xDD] = SimdPackedRow(OpcodeId::AESENCLAST);
    table[0xDE] = SimdPackedRow(OpcodeId::AESDEC);
    table[0xDF] = SimdPackedRow(OpcodeId::AESDECLAST);

    // Shared MOVBE/CRC32 rows (38 F0 load / 38 F1 store), SizeOverride policy
    // (design Decision 3): no REP → MOVBE slot, F2 → CRC32 slot, F3 →
    // UNDEFINED. 66h never selects a slot: with REX.W clear it shrinks
    // through shrink_66 (MOVBE both operands; CRC32 F1 source only; CRC32 F0
    // none), with REX.W set it loses precedence and rex_w_* widens instead.
    // Both MOVBE directions are memory-only (opcode_reg = INVALID; Valid in
    // both modes); CRC32 is register+memory legal, Valid in both modes.
    {
        auto& row = table[0xF0];
        row.prefix_policy = SimdPrefixPolicy::SizeOverride;
        {
            auto& movbe = row.slots[0]; // NFx 0F 38 F0: MOVBE r32, m32 (load)
            movbe.opcode_reg = OpcodeId::INVALID_OPCODE;
            movbe.pair_reg   = kSimdNoOperands;
            movbe.opcode_mem = OpcodeId::MOVBE;
            movbe.pair_mem   = OPRS2(r32, m32);
            movbe.shrink_66  = 0b11; // 66h: r16, m16
            movbe.rex_w_mem  = 0b11; // REX.W: r64, m64
        }
        {
            auto& crc = row.slots[3]; // F2 0F 38 F0: CRC32 r32, r/m8
            crc.opcode_reg = OpcodeId::CRC32;
            crc.pair_reg   = OPRS2(r32, r8);
            crc.opcode_mem = OpcodeId::CRC32;
            crc.pair_mem   = OPRS2(r32, m8);
            crc.shrink_66  = 0b00; // 66h: r32, r/m8 unchanged
            crc.rex_w_reg  = 0b01; // REX.W: r64, r8 (destination only)
            crc.rex_w_mem  = 0b01; // REX.W: r64, m8
        }
    }
    {
        auto& row = table[0xF1];
        row.prefix_policy = SimdPrefixPolicy::SizeOverride;
        {
            auto& movbe = row.slots[0]; // NFx 0F 38 F1: MOVBE m32, r32 (store)
            movbe.opcode_reg = OpcodeId::INVALID_OPCODE;
            movbe.pair_reg   = kSimdNoOperands;
            movbe.opcode_mem = OpcodeId::MOVBE;
            movbe.pair_mem   = OPRS2(m32, r32);
            movbe.shrink_66  = 0b11; // 66h: m16, r16
            movbe.rex_w_mem  = 0b11; // REX.W: m64, r64
        }
        {
            auto& crc = row.slots[3]; // F2 0F 38 F1: CRC32 r32, r/m32
            crc.opcode_reg = OpcodeId::CRC32;
            crc.pair_reg   = OPRS2(r32, r32);
            crc.opcode_mem = OpcodeId::CRC32;
            crc.pair_mem   = OPRS2(r32, m32);
            crc.shrink_66  = 0b10; // 66h: source shrinks to r16/m16
            crc.rex_w_reg  = 0b11; // REX.W: r64, r64
            crc.rex_w_mem  = 0b11; // REX.W: r64, m64
        }
    }

    // Not enumerated (stay INVALID in every slot): 0F 38 F6/F7 ADCX/ADOX
    // (design Non-Goal), the SHA rows (38 C8-CD, 3A CC belongs to the 3A
    // space's SHA1RNDS4 anyway), and every reserved third byte.
    return table;
}();

inline constexpr auto kDecodeTable_0F3A = [] {
    std::array<SimdRow, 256> table{};

    // ── M5a: 0F 3A rows (SDM enumeration in the change design checklist;
    // all rows 66-mandatory with trailing imm8, Valid in both modes) ────────
    // ROUND family: none/F2/F3 absent; memory classes m128/m128/m32/m64.
    table[0x08] = SimdSingleSlotRow(1, OpcodeId::ROUNDPS, OPRS2(xmm, xmm), OpcodeId::ROUNDPS, OPRS2(xmm, m128));
    table[0x09] = SimdSingleSlotRow(1, OpcodeId::ROUNDPD, OPRS2(xmm, xmm), OpcodeId::ROUNDPD, OPRS2(xmm, m128));
    table[0x0A] = SimdSingleSlotRow(1, OpcodeId::ROUNDSS, OPRS2(xmm, xmm), OpcodeId::ROUNDSS, OPRS2(xmm, m32));
    table[0x0B] = SimdSingleSlotRow(1, OpcodeId::ROUNDSD, OPRS2(xmm, xmm), OpcodeId::ROUNDSD, OPRS2(xmm, m64));
    // BLEND/PALIGNR: uniform xmm, xmm/m128 + imm8.
    table[0x0C] = SimdPackedRow(OpcodeId::BLENDPS);
    table[0x0D] = SimdPackedRow(OpcodeId::BLENDPD);
    table[0x0E] = SimdPackedRow(OpcodeId::PBLENDW);
    table[0x0F] = SimdPackedRow(OpcodeId::PALIGNR);
    // Extract family: destination selected by the ModR/M; trailing imm8.
    // PEXTRD/PINSRD gain REX.W mnemonic overrides (PEXTRQ/PINSRQ) plus
    // widening masks; those forms are 64-bit-only (no REX in 32-bit mode).
    table[0x14] = SimdSingleSlotRow(1, OpcodeId::PEXTRB, OPRS2(r32, xmm), OpcodeId::PEXTRB, OPRS2(m8, xmm));
    table[0x15] = SimdSingleSlotRow(1, OpcodeId::PEXTRW, OPRS2(r32, xmm), OpcodeId::PEXTRW, OPRS2(m16, xmm));
    table[0x16] = SimdSingleSlotRow(1, OpcodeId::PEXTRD, OPRS2(r32, xmm), OpcodeId::PEXTRD, OPRS2(m32, xmm));
    table[0x16].slots[1].opcode_reg_w = OpcodeId::PEXTRQ;
    table[0x16].slots[1].opcode_mem_w = OpcodeId::PEXTRQ;
    table[0x16].slots[1].rex_w_reg    = 0b01;
    table[0x16].slots[1].rex_w_mem    = 0b01;
    table[0x17] = SimdSingleSlotRow(1, OpcodeId::EXTRACTPS, OPRS2(r32, xmm), OpcodeId::EXTRACTPS, OPRS2(m32, xmm));
    // Insert family: the SDM source classes (PINSRB r32/m8, INSERTPS
    // xmm/m32, PINSRD r32/m32 → PINSRQ r64/m64 under REX.W).
    table[0x20] = SimdSingleSlotRow(1, OpcodeId::PINSRB, OPRS2(xmm, r32), OpcodeId::PINSRB, OPRS2(xmm, m8));
    table[0x21] = SimdSingleSlotRow(1, OpcodeId::INSERTPS, OPRS2(xmm, xmm), OpcodeId::INSERTPS, OPRS2(xmm, m32));
    table[0x22] = SimdSingleSlotRow(1, OpcodeId::PINSRD, OPRS2(xmm, r32), OpcodeId::PINSRD, OPRS2(xmm, m32));
    table[0x22].slots[1].opcode_reg_w = OpcodeId::PINSRQ;
    table[0x22].slots[1].opcode_mem_w = OpcodeId::PINSRQ;
    table[0x22].slots[1].rex_w_reg    = 0b10; // source widens; the xmm stays xmm
    table[0x22].slots[1].rex_w_mem    = 0b10;
    // Uniform imm8 rows: DPPS/DPPD/MPSADBW/PCLMULQDQ, the SSE4.2 string
    // group (60-63; implied XMM0/ECX destinations are NOT reported — the
    // operand contract is the two explicit operands + imm8), and the AES-NI
    // key generation assist (66 0F 3A DF; 3A CC is SHA1RNDS4, out of scope).
    table[0x40] = SimdPackedRow(OpcodeId::DPPS);
    table[0x41] = SimdPackedRow(OpcodeId::DPPD);
    table[0x42] = SimdPackedRow(OpcodeId::MPSADBW);
    table[0x44] = SimdPackedRow(OpcodeId::PCLMULQDQ);
    table[0x60] = SimdPackedRow(OpcodeId::PCMPESTRM);
    table[0x61] = SimdPackedRow(OpcodeId::PCMPESTRI);
    table[0x62] = SimdPackedRow(OpcodeId::PCMPISTRM);
    table[0x63] = SimdPackedRow(OpcodeId::PCMPISTRI);
    table[0xDF] = SimdPackedRow(OpcodeId::AESKEYGENASSIST);

    // imm8 on every defined row (the imm_kind default is none, so it is set
    // explicitly here).
    for (const auto op3 : { 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x14, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22,
                            0x40, 0x41, 0x42, 0x44,
                            0x60, 0x61, 0x62, 0x63, 0xDF }) {
        table[op3].imm_kind = SimdImmKind::imm8;
    }

    // Not enumerated (stay INVALID in every slot): the SHA rows (3A CC
    // SHA1RNDS4), the AMD two-immediate EXTRQ/INSERTQ forms (verified to live
    // in the two-byte space, 66/F2 0F 78/79), and every reserved third byte.
    return table;
}();

} // namespace xendiza::detail

#endif // XENDIZA_SIMD_HPP

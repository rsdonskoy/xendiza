#ifndef XENDIZA_COMMON_HPP
#define XENDIZA_COMMON_HPP

#include "instruction.hpp"

#include <array>

namespace xendiza {

enum class ErrorCode : uint8_t {
    OK = 0x0,
    UNKNOWN_ERROR = 0xE0,
    INSUFFICIENT_BUFFER,
    UNDEFINED_INSTRUCTION,
    UNIMPLEMENTED_DISASM
};

#define ERR(code) (static_cast<uint8_t>(ErrorCode::code))

struct Operands {
    std::array<Operand, 4> operand; // Up to 4 operands
};

struct InstructionId {
    OpcodeId opcode; // Abstracted opcode identifier
    uint8_t operand_count; // Number of operands (0-4)
    Operands operands; // Up to 4 operands
};

struct DecodedInstruction {
    uint8_t length; // Length of the instruction in bytes
    InstructionId instrId; // Abstracted instruction identifier
};

struct DecodeTableEntry {
    union {
        uint8_t instr_len; // Length of the instruction
        uint8_t dispatch_code; //
    } tag;
    InstructionId instr_id; // Abstracted instruction identifier
};

#define INVOPR { Operand::invalid, Operand::invalid, Operand::invalid, Operand::invalid }

#define OPRS2(opr1, opr2) \
    { Operand::opr1, Operand::opr2, Operand::noopr, Operand::noopr }

#define DTE(tag_val, iid_expr) \
    { {tag_val}, iid_expr }

namespace detail {

inline constexpr InstructionId kInvalidInstructionId = {
    OpcodeId::INVALID_OPCODE,
    0,
    { { Operand::noopr, Operand::noopr, Operand::noopr, Operand::noopr } }
};

inline constexpr DecodedInstruction ERR_UNDEFINED_INSTRUCTION = {
    ERR(UNDEFINED_INSTRUCTION),
    kInvalidInstructionId
};
inline constexpr DecodedInstruction ERR_INSUFFICIENT_BUFFER = {
    ERR(INSUFFICIENT_BUFFER),
    kInvalidInstructionId
};
inline constexpr DecodedInstruction ERR_UNIMPLEMENTED_DISASM = {
    ERR(UNIMPLEMENTED_DISASM),
    kInvalidInstructionId
};

// ...existing code...

// ── SIB-dispatch rewriting ───────────────────────────────────────────────
// A ModR/M byte with mod!=11 and rm=100 is followed by a SIB byte; only then
// can the effective-address base be RSP/ESP (a stack access). The operand
// tables cannot encode that (they are indexed by ModR/M, which has no SIB
// field), so for those entries we replace the memory operand with a
// SIB-dispatch marker (Sib_Mb / Sib_Mv). The decode dispatch later reads the
// SIB byte and resolves the marker to a plain m*/stack_m* via kSibStackForm_*.
//
// WithSibDispatch() applies this rewrite at compile time so each table still
// "holds" the markers, without hand-editing every rm=100 entry.

constexpr auto MemToSibMarker(const Operand op) noexcept -> Operand
{
    switch (op) {
    case Operand::m8:  return Operand::Sib_Mb;
    case Operand::m16: return Operand::Sib_Mw;
    case Operand::m32:
    case Operand::m64: return Operand::Sib_Mv;
    default:           return op;
    }
}

// True for ModR/M bytes that carry a SIB byte: mod != 11 and rm == 100.
constexpr auto ModrmHasSib(const int modrm) noexcept -> bool
{
    return (modrm & 0b11'000'000) != 0b11'000'000
        && (modrm & 0b00'000'111) == 0b00'000'100;
}

constexpr auto WithSibDispatch(std::array<Operands, 256> t) noexcept
    -> std::array<Operands, 256>
{
    for (int i = 0; i < 256; ++i) {
        if (!ModrmHasSib(i)) continue;
        t[i].operand[0] = MemToSibMarker(t[i].operand[0]);
        t[i].operand[1] = MemToSibMarker(t[i].operand[1]);
    }
    return t;
}

constexpr auto WithSibDispatch(std::array<InstructionId, 256> t) noexcept
    -> std::array<InstructionId, 256>
{
    for (int i = 0; i < 256; ++i) {
        if (!ModrmHasSib(i)) continue;
        t[i].operands.operand[0] = MemToSibMarker(t[i].operands.operand[0]);
        t[i].operands.operand[1] = MemToSibMarker(t[i].operands.operand[1]);
    }
    return t;
}

// kSibStackForm_*[sib]: resolve a SIB-dispatch marker once the SIB byte is
// known. base (low 3 bits) == 100 selects RSP/ESP → stack form.
static constexpr std::array<Operand, 256> kSibStackForm_b = [] {
    std::array<Operand, 256> t{};
    for (int s = 0; s < 256; ++s)
        t[s] = ((s & 0b00'000'111) == 0b00'000'100) ? Operand::stack_m8 : Operand::m8;
    return t;
}();

static constexpr std::array<Operand, 256> kSibStackForm_v = [] {
    std::array<Operand, 256> t{};
    for (int s = 0; s < 256; ++s)
        t[s] = ((s & 0b00'000'111) == 0b00'000'100) ? Operand::stack_m32 : Operand::m32;
    return t;
}();

static constexpr std::array<Operand, 256> kSibStackForm_w = [] {
    std::array<Operand, 256> t{};
    for (int s = 0; s < 256; ++s)
        t[s] = ((s & 0b00'000'111) == 0b00'000'100) ? Operand::stack_m16 : Operand::m16;
    return t;
}();

// Resolve a single SIB-dispatch marker to a concrete memory operand using the
// already-read SIB byte. Non-marker operands pass through unchanged.
constexpr auto ResolveSibMarker(const Operand op, const uint8_t sib) noexcept -> Operand
{
    switch (op) {
    case Operand::Sib_Mb: return kSibStackForm_b[sib];
    case Operand::Sib_Mv: return kSibStackForm_v[sib];
    case Operand::Sib_Mw: return kSibStackForm_w[sib];
    default:              return op;
    }
}

// Resolve any SIB-dispatch markers in an instruction's operand slots in place.
// Call from a decode dispatch site after the SIB byte is known.
constexpr auto ResolveSibMarkers(InstructionId id, const uint8_t sib) noexcept -> InstructionId
{
    id.operands.operand[0] = ResolveSibMarker(id.operands.operand[0], sib);
    id.operands.operand[1] = ResolveSibMarker(id.operands.operand[1], sib);
    return id;
}

constexpr auto HasSibMarker(const InstructionId& id) noexcept -> bool
{
    for (const auto op : id.operands.operand)
        if (op == Operand::Sib_Mb || op == Operand::Sib_Mv || op == Operand::Sib_Mw) return true;
    return false;
}

static constexpr std::array<Operands, 256> kOperandFormTable_Eb_Gb = WithSibDispatch(std::array<Operands, 256>{ {
    /*       0              1              2              3              4              5              6              7              8              9              A              B              C              D              E              F             */
    /* 00 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* 10 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* 20 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* 30 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* 40 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* 50 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* 60 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* 70 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* 80 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* 90 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* A0 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* B0 */ OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8), OPRS2(m8, r8),
    /* C0 */ OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8),
    /* D0 */ OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8),
    /* E0 */ OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8),
    /* F0 */ OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8),
} });

static constexpr std::array<Operands, 256> kOperandFormTable_Ev_Gv = WithSibDispatch(std::array<Operands, 256>{ {
    /*       0                1                2                3                4                5                6                7                8                9                A                B                C                D                E                F              */
    /* 00 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* 10 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* 20 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* 30 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* 40 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* 50 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* 60 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* 70 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* 80 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* 90 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* A0 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* B0 */ OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32), OPRS2(m32, r32),
    /* C0 */ OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32),
    /* D0 */ OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32),
    /* E0 */ OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32),
    /* F0 */ OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32),
} });

static constexpr std::array<Operands, 256> kOperandFormTable_Gb_Eb = WithSibDispatch(std::array<Operands, 256>{ {
    /*       0              1              2              3              4              5              6              7              8              9              A              B              C              D              E              F             */
    /* 00 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* 10 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* 20 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* 30 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* 40 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* 50 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* 60 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* 70 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* 80 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* 90 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* A0 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* B0 */ OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8), OPRS2(r8, m8),
    /* C0 */ OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8),
    /* D0 */ OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8),
    /* E0 */ OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8),
    /* F0 */ OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8), OPRS2(r8, r8),
} });

static constexpr std::array<Operands, 256> kOperandFormTable_Gv_Ev = WithSibDispatch(std::array<Operands, 256>{ {
    /*       0                1                2                3                4                5                6                7                8                9                A                B                C                D                E                F              */
    /* 00 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 10 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 20 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 30 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 40 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 50 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 60 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 70 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 80 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 90 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* A0 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* B0 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* C0 */ OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32),
    /* D0 */ OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32),
    /* E0 */ OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32),
    /* F0 */ OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32), OPRS2(r32, r32),
} });

static constexpr std::array<Operands, 256> kOperandFormTable_Ev_Sw = WithSibDispatch(std::array<Operands, 256>{ {
    /* MOV Ev, Sw - Move segment register TO memory/register (0x8C) */
    /* reg field determines source segment register: 000=ES, 001=CS, 010=SS, 011=DS, 100=FS, 101=GS, 110/111=invalid */
    /*       0                 1                 2                 3                 4                 5                 6                 7                 8                 9                 A                 B                 C                 D                 E                 F              */
    /* 00 */ OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg),
    /* 10 */ OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg),
    /* 20 */ OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg),
    /* 30 */ INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* 40 */ OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg),
    /* 50 */ OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg),
    /* 60 */ OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg),
    /* 70 */ INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* 80 */ OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg),
    /* 90 */ OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg),
    /* A0 */ OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg), OPRS2(m16, sreg),
    /* B0 */ INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* C0 */ OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg),
    /* D0 */ OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg),
    /* E0 */ OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg), OPRS2(r16, sreg),
    /* F0 */ INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
} });

static constexpr std::array<Operands, 256> kOperandFormTable_Sw_Ev = WithSibDispatch(std::array<Operands, 256>{ {
    /* MOV Sw, Ev - Move FROM memory/register to segment register (0x8E) */
    /* reg field determines destination segment register: 000=ES, 001=CS(invalid), 010=SS, 011=DS, 100=FS, 101=GS, 110/111=invalid */
    /*       0                 1                 2                 3                 4                 5                 6                 7                 8                 9                 A                 B                 C                 D                 E                 F              */
    /* 00 */ OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* 10 */ OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16),
    /* 20 */ OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16),
    /* 30 */ INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* 40 */ OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* 50 */ OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16),
    /* 60 */ OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16),
    /* 70 */ INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* 80 */ OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* 90 */ OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16),
    /* A0 */ OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16), OPRS2(sreg, m16),
    /* B0 */ INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* C0 */ OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
    /* D0 */ OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16),
    /* E0 */ OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16), OPRS2(sreg, r16),
    /* F0 */ INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,           INVOPR,
} });

static constexpr std::array<Operands, 256> kOperandFormTable_Gv_M = WithSibDispatch(std::array<Operands, 256>{ {
    /* Gv, M - General register (32-bit) from memory operand */
    /* This is used for instructions like LEA where the source must be memory (not register) */
    /*       0                1                2                3                4                5                6                7                8                9                A                B                C                D                E                F              */
    /* 00 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 10 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 20 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 30 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 40 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 50 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 60 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 70 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 80 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* 90 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* A0 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* B0 */ OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32), OPRS2(r32, m32),
    /* C0 */ INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,
    /* D0 */ INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,
    /* E0 */ INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,
    /* F0 */ INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,          INVOPR,
} });

static constexpr std::array<const std::array<Operands, 256>*, 9> kOperandFormTable_ModRM = { {
    nullptr,
    &kOperandFormTable_Eb_Gb,
    &kOperandFormTable_Ev_Gv,
    &kOperandFormTable_Gb_Eb,
    &kOperandFormTable_Gv_Ev,
    nullptr,
    &kOperandFormTable_Ev_Sw,
    &kOperandFormTable_Sw_Ev,
    &kOperandFormTable_Gv_M
} };

// Flattened form tables indexed by (form_index * 256 + modrm), eliminating
// the pointer indirection through kOperandFormTable_ModRM (one dependent
// load less on the hot ModR/M path). Slots 0 and 5 have no table (nullptr
// above); they are left as INVOPR and must be guarded at the call site to
// preserve the "no table → no resolution" semantics.
static constexpr std::array<Operands, 9 * 256> kOperandFormTable_ModRM_Flat = [] {
    std::array<Operands, 9 * 256> flat{};
    for (size_t i = 0; i < 256; ++i) {
        for (size_t slot : { size_t{0}, size_t{5} }) {
            flat[slot * 256 + i] = Operands{ { Operand::invalid, Operand::invalid,
                                               Operand::invalid, Operand::invalid } };
        }
    }
    for (size_t t = 0; t < kOperandFormTable_ModRM.size(); ++t) {
        if (kOperandFormTable_ModRM[t] == nullptr) {
            continue;
        }
        for (size_t i = 0; i < 256; ++i) {
            flat[t * 256 + i] = (*kOperandFormTable_ModRM[t])[i];
        }
    }
    return flat;
}();

static constexpr std::array<uint8_t, 256> kLengthTable_ModRM = { {
/*     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F */
/*00*/ 2, 2, 2, 2, 3, 6, 2, 2, 2, 2, 2, 2, 3, 6, 2, 2,
/*10*/ 2, 2, 2, 2, 3, 6, 2, 2, 2, 2, 2, 2, 3, 6, 2, 2,
/*20*/ 2, 2, 2, 2, 3, 6, 2, 2, 2, 2, 2, 2, 3, 6, 2, 2,
/*30*/ 2, 2, 2, 2, 3, 6, 2, 2, 2, 2, 2, 2, 3, 6, 2, 2,
/*40*/ 3, 3, 3, 3, 4, 3, 3, 3, 3, 3, 3, 3, 4, 3, 3, 3,
/*50*/ 3, 3, 3, 3, 4, 3, 3, 3, 3, 3, 3, 3, 4, 3, 3, 3,
/*60*/ 3, 3, 3, 3, 4, 3, 3, 3, 3, 3, 3, 3, 4, 3, 3, 3,
/*70*/ 3, 3, 3, 3, 4, 3, 3, 3, 3, 3, 3, 3, 4, 3, 3, 3,
/*80*/ 6, 6, 6, 6, 7, 6, 6, 6, 6, 6, 6, 6, 7, 6, 6, 6,
/*90*/ 6, 6, 6, 6, 7, 6, 6, 6, 6, 6, 6, 6, 7, 6, 6, 6,
/*A0*/ 6, 6, 6, 6, 7, 6, 6, 6, 6, 6, 6, 6, 7, 6, 6, 6,
/*B0*/ 6, 6, 6, 6, 7, 6, 6, 6, 6, 6, 6, 6, 7, 6, 6, 6,
/*C0*/ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
/*D0*/ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
/*E0*/ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
/*F0*/ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
} };

// Maps (segment_register, memory_operand) to the composite segment-prefixed memory operand.
// Returns the original memory operand unchanged if no composite mapping exists.
constexpr auto MakeCompositeMemOperand(const Operand seg, const Operand mem) noexcept -> Operand
{
    switch (mem) {
    case Operand::m8:
        switch (seg) {
        case Operand::es: return Operand::es_m8;
        case Operand::cs: return Operand::cs_m8;
        case Operand::ss: return Operand::ss_m8;
        case Operand::ds: return Operand::ds_m8;
        case Operand::fs: return Operand::fs_m8;
        case Operand::gs: return Operand::gs_m8;
        default: return mem;
        }
    case Operand::m16:
        switch (seg) {
        case Operand::es: return Operand::es_m16;
        case Operand::cs: return Operand::cs_m16;
        case Operand::ss: return Operand::ss_m16;
        case Operand::ds: return Operand::ds_m16;
        case Operand::fs: return Operand::fs_m16;
        case Operand::gs: return Operand::gs_m16;
        default: return mem;
        }
    case Operand::m32:
        switch (seg) {
        case Operand::es: return Operand::es_m32;
        case Operand::cs: return Operand::cs_m32;
        case Operand::ss: return Operand::ss_m32;
        case Operand::ds: return Operand::ds_m32;
        case Operand::fs: return Operand::fs_m32;
        case Operand::gs: return Operand::gs_m32;
        default: return mem;
        }
    case Operand::m64:
        switch (seg) {
        case Operand::es: return Operand::es_m64;
        case Operand::cs: return Operand::cs_m64;
        case Operand::ss: return Operand::ss_m64;
        case Operand::ds: return Operand::ds_m64;
        case Operand::fs: return Operand::fs_m64;
        case Operand::gs: return Operand::gs_m64;
        default: return mem;
        }
    case Operand::moffs8:
        switch (seg) {
        case Operand::es: return Operand::es_moffs8;
        case Operand::cs: return Operand::cs_moffs8;
        case Operand::ss: return Operand::ss_moffs8;
        case Operand::ds: return Operand::ds_moffs8;
        case Operand::fs: return Operand::fs_moffs8;
        case Operand::gs: return Operand::gs_moffs8;
        default: return mem;
        }
    case Operand::moffs16:
        switch (seg) {
        case Operand::es: return Operand::es_moffs16;
        case Operand::cs: return Operand::cs_moffs16;
        case Operand::ss: return Operand::ss_moffs16;
        case Operand::ds: return Operand::ds_moffs16;
        case Operand::fs: return Operand::fs_moffs16;
        case Operand::gs: return Operand::gs_moffs16;
        default: return mem;
        }
    case Operand::moffs32:
        switch (seg) {
        case Operand::es: return Operand::es_moffs32;
        case Operand::cs: return Operand::cs_moffs32;
        case Operand::ss: return Operand::ss_moffs32;
        case Operand::ds: return Operand::ds_moffs32;
        case Operand::fs: return Operand::fs_moffs32;
        case Operand::gs: return Operand::gs_moffs32;
        default: return mem;
        }
    case Operand::moffs64:
        switch (seg) {
        case Operand::es: return Operand::es_moffs64;
        case Operand::cs: return Operand::cs_moffs64;
        case Operand::ss: return Operand::ss_moffs64;
        case Operand::ds: return Operand::ds_moffs64;
        case Operand::fs: return Operand::fs_moffs64;
        case Operand::gs: return Operand::gs_moffs64;
        default: return mem;
        }
    default:
        return mem;
    }
}

#define IID_0(opcode_id) \
    { OpcodeId::opcode_id, 0, {Operand::noopr, Operand::noopr, Operand::noopr, Operand::noopr} }

#define IID_1(opcode_id, opr1) \
    { OpcodeId::opcode_id, 1, {Operand::opr1, Operand::noopr, Operand::noopr, Operand::noopr} }

#define IID_2(opcode_id, opr1, opr2) \
    { OpcodeId::opcode_id, 2, {Operand::opr1, Operand::opr2, Operand::noopr, Operand::noopr} }

#define IID_3(opcode_id, opr1, opr2, opr3) \
    { OpcodeId::opcode_id, 3, {Operand::opr1, Operand::opr2, Operand::opr3, Operand::noopr} }

#define IID_4(opcode_id, opr1, opr2, opr3, opr4) \
    { OpcodeId::opcode_id, 4, {Operand::opr1, Operand::opr2, Operand::opr3, Operand::opr4} }

#define IID_DISPATCH(_1, _2, _3, _4, _5, NAME, ...) NAME
#define IID_EXPAND(x) x
#define IID(...) IID_EXPAND(IID_DISPATCH(__VA_ARGS__, IID_4, IID_3, IID_2, IID_1, IID_0))(__VA_ARGS__)
#define IID_INVALID { OpcodeId::INVALID_OPCODE, 0, {Operand::noopr, Operand::noopr, Operand::noopr, Operand::noopr} }

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0x80 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                    1                    2                    3                    4                    5                    6                    7                    8                   9                   A                   B                   C                   D                   E                   F              */
    /* 00 */ IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8),
    /* 10 */ IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8),
    /* 20 */ IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8),
    /* 30 */ IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8),
    /* 40 */ IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8),
    /* 50 */ IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8),
    /* 60 */ IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8),
    /* 70 */ IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8),
    /* 80 */ IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(ADD, m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8), IID(OR,  m8, imm8),
    /* 90 */ IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(ADC, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8), IID(SBB, m8, imm8),
    /* A0 */ IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(AND, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8), IID(SUB, m8, imm8),
    /* B0 */ IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(XOR, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8), IID(CMP, m8, imm8),
    /* C0 */ IID(ADD, r8, imm8), IID(ADD, r8, imm8), IID(ADD, r8, imm8), IID(ADD, r8, imm8), IID(ADD, r8, imm8), IID(ADD, r8, imm8), IID(ADD, r8, imm8), IID(ADD, r8, imm8), IID(OR,  r8, imm8), IID(OR,  r8, imm8), IID(OR,  r8, imm8), IID(OR,  r8, imm8), IID(OR,  r8, imm8), IID(OR,  r8, imm8), IID(OR,  r8, imm8), IID(OR,  r8, imm8),
    /* D0 */ IID(ADC, r8, imm8), IID(ADC, r8, imm8), IID(ADC, r8, imm8), IID(ADC, r8, imm8), IID(ADC, r8, imm8), IID(ADC, r8, imm8), IID(ADC, r8, imm8), IID(ADC, r8, imm8), IID(SBB, r8, imm8), IID(SBB, r8, imm8), IID(SBB, r8, imm8), IID(SBB, r8, imm8), IID(SBB, r8, imm8), IID(SBB, r8, imm8), IID(SBB, r8, imm8), IID(SBB, r8, imm8),
    /* E0 */ IID(AND, r8, imm8), IID(AND, r8, imm8), IID(AND, r8, imm8), IID(AND, r8, imm8), IID(AND, r8, imm8), IID(AND, r8, imm8), IID(AND, r8, imm8), IID(AND, r8, imm8), IID(SUB, r8, imm8), IID(SUB, r8, imm8), IID(SUB, r8, imm8), IID(SUB, r8, imm8), IID(SUB, r8, imm8), IID(SUB, r8, imm8), IID(SUB, r8, imm8), IID(SUB, r8, imm8),
    /* F0 */ IID(XOR, r8, imm8), IID(XOR, r8, imm8), IID(XOR, r8, imm8), IID(XOR, r8, imm8), IID(XOR, r8, imm8), IID(XOR, r8, imm8), IID(XOR, r8, imm8), IID(XOR, r8, imm8), IID(CMP, r8, imm8), IID(CMP, r8, imm8), IID(CMP, r8, imm8), IID(CMP, r8, imm8), IID(CMP, r8, imm8), IID(CMP, r8, imm8), IID(CMP, r8, imm8), IID(CMP, r8, imm8),
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0x80(const uint8_t byte) noexcept -> DecodedInstruction
{
    const uint8_t len = kLengthTable_ModRM[byte] + 1; // +1 for the opcode byte itself
    return { len, kInstrIdTable_opcode_extension_0x80[byte] };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0x81 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                     1                     2                     3                     4                     5                     6                     7                     8                     9                     A                     B                     C                     D                     E                     F               */
    /* 00 */ IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32),
    /* 10 */ IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32),
    /* 20 */ IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32),
    /* 30 */ IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32),
    /* 40 */ IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32),
    /* 50 */ IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32),
    /* 60 */ IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32),
    /* 70 */ IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32),
    /* 80 */ IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(ADD, m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32), IID(OR,  m32, imm32),
    /* 90 */ IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(ADC, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32), IID(SBB, m32, imm32),
    /* A0 */ IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(AND, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32), IID(SUB, m32, imm32),
    /* B0 */ IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(XOR, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32), IID(CMP, m32, imm32),
    /* C0 */ IID(ADD, r32, imm32), IID(ADD, r32, imm32), IID(ADD, r32, imm32), IID(ADD, r32, imm32), IID(ADD, r32, imm32), IID(ADD, r32, imm32), IID(ADD, r32, imm32), IID(ADD, r32, imm32), IID(OR,  r32, imm32), IID(OR,  r32, imm32), IID(OR,  r32, imm32), IID(OR,  r32, imm32), IID(OR,  r32, imm32), IID(OR,  r32, imm32), IID(OR,  r32, imm32), IID(OR,  r32, imm32),
    /* D0 */ IID(ADC, r32, imm32), IID(ADC, r32, imm32), IID(ADC, r32, imm32), IID(ADC, r32, imm32), IID(ADC, r32, imm32), IID(ADC, r32, imm32), IID(ADC, r32, imm32), IID(ADC, r32, imm32), IID(SBB, r32, imm32), IID(SBB, r32, imm32), IID(SBB, r32, imm32), IID(SBB, r32, imm32), IID(SBB, r32, imm32), IID(SBB, r32, imm32), IID(SBB, r32, imm32), IID(SBB, r32, imm32),
    /* E0 */ IID(AND, r32, imm32), IID(AND, r32, imm32), IID(AND, r32, imm32), IID(AND, r32, imm32), IID(AND, r32, imm32), IID(AND, r32, imm32), IID(AND, r32, imm32), IID(AND, r32, imm32), IID(SUB, r32, imm32), IID(SUB, r32, imm32), IID(SUB, r32, imm32), IID(SUB, r32, imm32), IID(SUB, r32, imm32), IID(SUB, r32, imm32), IID(SUB, r32, imm32), IID(SUB, r32, imm32),
    /* F0 */ IID(XOR, r32, imm32), IID(XOR, r32, imm32), IID(XOR, r32, imm32), IID(XOR, r32, imm32), IID(XOR, r32, imm32), IID(XOR, r32, imm32), IID(XOR, r32, imm32), IID(XOR, r32, imm32), IID(CMP, r32, imm32), IID(CMP, r32, imm32), IID(CMP, r32, imm32), IID(CMP, r32, imm32), IID(CMP, r32, imm32), IID(CMP, r32, imm32), IID(CMP, r32, imm32), IID(CMP, r32, imm32),
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0x81(const uint8_t byte) noexcept -> DecodedInstruction
{
    const uint8_t len = kLengthTable_ModRM[byte] + 4; // +4 for 32-bit immediate
    return { len, kInstrIdTable_opcode_extension_0x81[byte] };
}

static constexpr auto GetInstructionDescriptor_opcode_extension_0x82([[maybe_unused]] const uint8_t byte) noexcept -> DecodedInstruction
{
    // 0x82 is invalid in 64-bit mode - return error
    return { ERR(UNDEFINED_INSTRUCTION), {} };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0x83 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                    1                    2                    3                    4                    5                    6                    7                    8                    9                    A                    B                    C                    D                    E                    F               */
    /* 00 */ IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8),
    /* 10 */ IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8),
    /* 20 */ IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8),
    /* 30 */ IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8),
    /* 40 */ IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8),
    /* 50 */ IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8),
    /* 60 */ IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8),
    /* 70 */ IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8),
    /* 80 */ IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(ADD, m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8), IID(OR,  m32, imm8),
    /* 90 */ IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(ADC, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8), IID(SBB, m32, imm8),
    /* A0 */ IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(AND, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8), IID(SUB, m32, imm8),
    /* B0 */ IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(XOR, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8), IID(CMP, m32, imm8),
    /* C0 */ IID(ADD, r32, imm8), IID(ADD, r32, imm8), IID(ADD, r32, imm8), IID(ADD, r32, imm8), IID(ADD, r32, imm8), IID(ADD, r32, imm8), IID(ADD, r32, imm8), IID(ADD, r32, imm8), IID(OR,  r32, imm8), IID(OR,  r32, imm8), IID(OR,  r32, imm8), IID(OR,  r32, imm8), IID(OR,  r32, imm8), IID(OR,  r32, imm8), IID(OR,  r32, imm8), IID(OR,  r32, imm8),
    /* D0 */ IID(ADC, r32, imm8), IID(ADC, r32, imm8), IID(ADC, r32, imm8), IID(ADC, r32, imm8), IID(ADC, r32, imm8), IID(ADC, r32, imm8), IID(ADC, r32, imm8), IID(ADC, r32, imm8), IID(SBB, r32, imm8), IID(SBB, r32, imm8), IID(SBB, r32, imm8), IID(SBB, r32, imm8), IID(SBB, r32, imm8), IID(SBB, r32, imm8), IID(SBB, r32, imm8), IID(SBB, r32, imm8),
    /* E0 */ IID(AND, r32, imm8), IID(AND, r32, imm8), IID(AND, r32, imm8), IID(AND, r32, imm8), IID(AND, r32, imm8), IID(AND, r32, imm8), IID(AND, r32, imm8), IID(AND, r32, imm8), IID(SUB, r32, imm8), IID(SUB, r32, imm8), IID(SUB, r32, imm8), IID(SUB, r32, imm8), IID(SUB, r32, imm8), IID(SUB, r32, imm8), IID(SUB, r32, imm8), IID(SUB, r32, imm8),
    /* F0 */ IID(XOR, r32, imm8), IID(XOR, r32, imm8), IID(XOR, r32, imm8), IID(XOR, r32, imm8), IID(XOR, r32, imm8), IID(XOR, r32, imm8), IID(XOR, r32, imm8), IID(XOR, r32, imm8), IID(CMP, r32, imm8), IID(CMP, r32, imm8), IID(CMP, r32, imm8), IID(CMP, r32, imm8), IID(CMP, r32, imm8), IID(CMP, r32, imm8), IID(CMP, r32, imm8), IID(CMP, r32, imm8)
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0x83(const uint8_t byte) noexcept -> DecodedInstruction
{
    const uint8_t len = kLengthTable_ModRM[byte] + 1; // +1 for 8-bit immediate
    return { len, kInstrIdTable_opcode_extension_0x83[byte] };
}

static constexpr auto GetInstructionDescriptor_opcode_extension_0x8F(const uint8_t byte) noexcept -> DecodedInstruction
{
    // /0 is the only valid opcode extension for POP.
    if ((byte & 0b00'111'000) == 0b00'000'000) {
        const uint8_t len = kLengthTable_ModRM[byte];
        const auto mod = byte & 0b11'000'000;
        return { len,
                 (mod == 0b11'000'000)
                     ? InstructionId{ OpcodeId::POP, 1, { { Operand::r64, Operand::noopr, Operand::noopr, Operand::noopr } } }
                     : InstructionId{ OpcodeId::POP, 1, { { Operand::m64, Operand::noopr, Operand::noopr, Operand::noopr } } } };
    }

    return { ERR(UNDEFINED_INSTRUCTION), {} };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xC0 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                    1                    2                    3                    4                    5                    6                    7                    8                    9                    A                    B                    C                    D                    E                    F             */
    /* 00 */ IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8),
    /* 10 */ IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8),
    /* 20 */ IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8),
    /* 30 */ IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8),
    /* 40 */ IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8),
    /* 50 */ IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8),
    /* 60 */ IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8),
    /* 70 */ IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8),
    /* 80 */ IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROL, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8), IID(ROR, m8, imm8),
    /* 90 */ IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCL, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8), IID(RCR, m8, imm8),
    /* A0 */ IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHL, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8), IID(SHR, m8, imm8),
    /* B0 */ IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAL, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8), IID(SAR, m8, imm8),
    /* C0 */ IID(ROL, r8, imm8), IID(ROL, r8, imm8), IID(ROL, r8, imm8), IID(ROL, r8, imm8), IID(ROL, r8, imm8), IID(ROL, r8, imm8), IID(ROL, r8, imm8), IID(ROL, r8, imm8), IID(ROR, r8, imm8), IID(ROR, r8, imm8), IID(ROR, r8, imm8), IID(ROR, r8, imm8), IID(ROR, r8, imm8), IID(ROR, r8, imm8), IID(ROR, r8, imm8), IID(ROR, r8, imm8),
    /* D0 */ IID(RCL, r8, imm8), IID(RCL, r8, imm8), IID(RCL, r8, imm8), IID(RCL, r8, imm8), IID(RCL, r8, imm8), IID(RCL, r8, imm8), IID(RCL, r8, imm8), IID(RCL, r8, imm8), IID(RCR, r8, imm8), IID(RCR, r8, imm8), IID(RCR, r8, imm8), IID(RCR, r8, imm8), IID(RCR, r8, imm8), IID(RCR, r8, imm8), IID(RCR, r8, imm8), IID(RCR, r8, imm8),
    /* E0 */ IID(SHL, r8, imm8), IID(SHL, r8, imm8), IID(SHL, r8, imm8), IID(SHL, r8, imm8), IID(SHL, r8, imm8), IID(SHL, r8, imm8), IID(SHL, r8, imm8), IID(SHL, r8, imm8), IID(SHR, r8, imm8), IID(SHR, r8, imm8), IID(SHR, r8, imm8), IID(SHR, r8, imm8), IID(SHR, r8, imm8), IID(SHR, r8, imm8), IID(SHR, r8, imm8), IID(SHR, r8, imm8),
    /* F0 */ IID(SAL, r8, imm8), IID(SAL, r8, imm8), IID(SAL, r8, imm8), IID(SAL, r8, imm8), IID(SAL, r8, imm8), IID(SAL, r8, imm8), IID(SAL, r8, imm8), IID(SAL, r8, imm8), IID(SAR, r8, imm8), IID(SAR, r8, imm8), IID(SAR, r8, imm8), IID(SAR, r8, imm8), IID(SAR, r8, imm8), IID(SAR, r8, imm8), IID(SAR, r8, imm8), IID(SAR, r8, imm8)
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xC0(const uint8_t byte) noexcept -> DecodedInstruction
{
    const uint8_t len = kLengthTable_ModRM[byte] + 1; // +1 for 8-bit immediate
    return { len, kInstrIdTable_opcode_extension_0xC0[byte] };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xC1 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                     1                     2                     3                     4                     5                     6                     7                     8                     9                     A                     B                     C                     D                     E                     F             */
    /* 00 */ IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8),
    /* 10 */ IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8),
    /* 20 */ IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8),
    /* 30 */ IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8),
    /* 40 */ IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8),
    /* 50 */ IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8),
    /* 60 */ IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8),
    /* 70 */ IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8),
    /* 80 */ IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROL, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8), IID(ROR, m32, imm8),
    /* 90 */ IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCL, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8), IID(RCR, m32, imm8),
    /* A0 */ IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHL, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8), IID(SHR, m32, imm8),
    /* B0 */ IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAL, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8), IID(SAR, m32, imm8),
    /* C0 */ IID(ROL, r32, imm8), IID(ROL, r32, imm8), IID(ROL, r32, imm8), IID(ROL, r32, imm8), IID(ROL, r32, imm8), IID(ROL, r32, imm8), IID(ROL, r32, imm8), IID(ROL, r32, imm8), IID(ROR, r32, imm8), IID(ROR, r32, imm8), IID(ROR, r32, imm8), IID(ROR, r32, imm8), IID(ROR, r32, imm8), IID(ROR, r32, imm8), IID(ROR, r32, imm8), IID(ROR, r32, imm8),
    /* D0 */ IID(RCL, r32, imm8), IID(RCL, r32, imm8), IID(RCL, r32, imm8), IID(RCL, r32, imm8), IID(RCL, r32, imm8), IID(RCL, r32, imm8), IID(RCL, r32, imm8), IID(RCL, r32, imm8), IID(RCR, r32, imm8), IID(RCR, r32, imm8), IID(RCR, r32, imm8), IID(RCR, r32, imm8), IID(RCR, r32, imm8), IID(RCR, r32, imm8), IID(RCR, r32, imm8), IID(RCR, r32, imm8),
    /* E0 */ IID(SHL, r32, imm8), IID(SHL, r32, imm8), IID(SHL, r32, imm8), IID(SHL, r32, imm8), IID(SHL, r32, imm8), IID(SHL, r32, imm8), IID(SHL, r32, imm8), IID(SHL, r32, imm8), IID(SHR, r32, imm8), IID(SHR, r32, imm8), IID(SHR, r32, imm8), IID(SHR, r32, imm8), IID(SHR, r32, imm8), IID(SHR, r32, imm8), IID(SHR, r32, imm8), IID(SHR, r32, imm8),
    /* F0 */ IID(SAL, r32, imm8), IID(SAL, r32, imm8), IID(SAL, r32, imm8), IID(SAL, r32, imm8), IID(SAL, r32, imm8), IID(SAL, r32, imm8), IID(SAL, r32, imm8), IID(SAL, r32, imm8), IID(SAR, r32, imm8), IID(SAR, r32, imm8), IID(SAR, r32, imm8), IID(SAR, r32, imm8), IID(SAR, r32, imm8), IID(SAR, r32, imm8), IID(SAR, r32, imm8), IID(SAR, r32, imm8)
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xC1(const uint8_t byte) noexcept -> DecodedInstruction
{
    const uint8_t len = kLengthTable_ModRM[byte] + 1; // +1 for 8-bit immediate
    return { len, kInstrIdTable_opcode_extension_0xC1[byte] };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xD0 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                   1                   2                   3                   4                   5                   6                   7                   8                   9                   A                   B                   C                   D                   E                   F             */
    /* 00 */ IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1),
    /* 10 */ IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1),
    /* 20 */ IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1),
    /* 30 */ IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1),
    /* 40 */ IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1),
    /* 50 */ IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1),
    /* 60 */ IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1),
    /* 70 */ IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1),
    /* 80 */ IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROL, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1), IID(ROR, m8, lit1),
    /* 90 */ IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCL, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1), IID(RCR, m8, lit1),
    /* A0 */ IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHL, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1), IID(SHR, m8, lit1),
    /* B0 */ IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAL, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1), IID(SAR, m8, lit1),
    /* C0 */ IID(ROL, r8, lit1), IID(ROL, r8, lit1), IID(ROL, r8, lit1), IID(ROL, r8, lit1), IID(ROL, r8, lit1), IID(ROL, r8, lit1), IID(ROL, r8, lit1), IID(ROL, r8, lit1), IID(ROR, r8, lit1), IID(ROR, r8, lit1), IID(ROR, r8, lit1), IID(ROR, r8, lit1), IID(ROR, r8, lit1), IID(ROR, r8, lit1), IID(ROR, r8, lit1), IID(ROR, r8, lit1),
    /* D0 */ IID(RCL, r8, lit1), IID(RCL, r8, lit1), IID(RCL, r8, lit1), IID(RCL, r8, lit1), IID(RCL, r8, lit1), IID(RCL, r8, lit1), IID(RCL, r8, lit1), IID(RCL, r8, lit1), IID(RCR, r8, lit1), IID(RCR, r8, lit1), IID(RCR, r8, lit1), IID(RCR, r8, lit1), IID(RCR, r8, lit1), IID(RCR, r8, lit1), IID(RCR, r8, lit1), IID(RCR, r8, lit1),
    /* E0 */ IID(SHL, r8, lit1), IID(SHL, r8, lit1), IID(SHL, r8, lit1), IID(SHL, r8, lit1), IID(SHL, r8, lit1), IID(SHL, r8, lit1), IID(SHL, r8, lit1), IID(SHL, r8, lit1), IID(SHR, r8, lit1), IID(SHR, r8, lit1), IID(SHR, r8, lit1), IID(SHR, r8, lit1), IID(SHR, r8, lit1), IID(SHR, r8, lit1), IID(SHR, r8, lit1), IID(SHR, r8, lit1),
    /* F0 */ IID(SAL, r8, lit1), IID(SAL, r8, lit1), IID(SAL, r8, lit1), IID(SAL, r8, lit1), IID(SAL, r8, lit1), IID(SAL, r8, lit1), IID(SAL, r8, lit1), IID(SAL, r8, lit1), IID(SAR, r8, lit1), IID(SAR, r8, lit1), IID(SAR, r8, lit1), IID(SAR, r8, lit1), IID(SAR, r8, lit1), IID(SAR, r8, lit1), IID(SAR, r8, lit1), IID(SAR, r8, lit1)
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xD0(const uint8_t byte) noexcept -> DecodedInstruction
{
    const uint8_t len = kLengthTable_ModRM[byte]; // no immediate byte (count is implicit literal 1)
    return { len, kInstrIdTable_opcode_extension_0xD0[byte] };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xD1 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                    1                    2                    3                    4                    5                    6                    7                    8                    9                    A                    B                    C                    D                    E                    F             */
    /* 00 */ IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1),
    /* 10 */ IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1),
    /* 20 */ IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1),
    /* 30 */ IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1),
    /* 40 */ IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1),
    /* 50 */ IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1),
    /* 60 */ IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1),
    /* 70 */ IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1),
    /* 80 */ IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROL, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1), IID(ROR, m32, lit1),
    /* 90 */ IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCL, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1), IID(RCR, m32, lit1),
    /* A0 */ IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHL, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1), IID(SHR, m32, lit1),
    /* B0 */ IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAL, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1), IID(SAR, m32, lit1),
    /* C0 */ IID(ROL, r32, lit1), IID(ROL, r32, lit1), IID(ROL, r32, lit1), IID(ROL, r32, lit1), IID(ROL, r32, lit1), IID(ROL, r32, lit1), IID(ROL, r32, lit1), IID(ROL, r32, lit1), IID(ROR, r32, lit1), IID(ROR, r32, lit1), IID(ROR, r32, lit1), IID(ROR, r32, lit1), IID(ROR, r32, lit1), IID(ROR, r32, lit1), IID(ROR, r32, lit1), IID(ROR, r32, lit1),
    /* D0 */ IID(RCL, r32, lit1), IID(RCL, r32, lit1), IID(RCL, r32, lit1), IID(RCL, r32, lit1), IID(RCL, r32, lit1), IID(RCL, r32, lit1), IID(RCL, r32, lit1), IID(RCL, r32, lit1), IID(RCR, r32, lit1), IID(RCR, r32, lit1), IID(RCR, r32, lit1), IID(RCR, r32, lit1), IID(RCR, r32, lit1), IID(RCR, r32, lit1), IID(RCR, r32, lit1), IID(RCR, r32, lit1),
    /* E0 */ IID(SHL, r32, lit1), IID(SHL, r32, lit1), IID(SHL, r32, lit1), IID(SHL, r32, lit1), IID(SHL, r32, lit1), IID(SHL, r32, lit1), IID(SHL, r32, lit1), IID(SHL, r32, lit1), IID(SHR, r32, lit1), IID(SHR, r32, lit1), IID(SHR, r32, lit1), IID(SHR, r32, lit1), IID(SHR, r32, lit1), IID(SHR, r32, lit1), IID(SHR, r32, lit1), IID(SHR, r32, lit1),
    /* F0 */ IID(SAL, r32, lit1), IID(SAL, r32, lit1), IID(SAL, r32, lit1), IID(SAL, r32, lit1), IID(SAL, r32, lit1), IID(SAL, r32, lit1), IID(SAL, r32, lit1), IID(SAL, r32, lit1), IID(SAR, r32, lit1), IID(SAR, r32, lit1), IID(SAR, r32, lit1), IID(SAR, r32, lit1), IID(SAR, r32, lit1), IID(SAR, r32, lit1), IID(SAR, r32, lit1), IID(SAR, r32, lit1)
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xD1(const uint8_t byte) noexcept -> DecodedInstruction
{
    const uint8_t len = kLengthTable_ModRM[byte]; // no immediate byte (count is implicit literal 1)
    return { len, kInstrIdTable_opcode_extension_0xD1[byte] };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xD2 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                  1                  2                  3                  4                  5                  6                  7                  8                  9                  A                  B                  C                  D                  E                  F            */
    /* 00 */ IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl),
    /* 10 */ IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl),
    /* 20 */ IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl),
    /* 30 */ IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl),
    /* 40 */ IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl),
    /* 50 */ IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl),
    /* 60 */ IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl),
    /* 70 */ IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl),
    /* 80 */ IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROL, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl), IID(ROR, m8, cl),
    /* 90 */ IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCL, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl), IID(RCR, m8, cl),
    /* A0 */ IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHL, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl), IID(SHR, m8, cl),
    /* B0 */ IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAL, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl), IID(SAR, m8, cl),
    /* C0 */ IID(ROL, r8, cl), IID(ROL, r8, cl), IID(ROL, r8, cl), IID(ROL, r8, cl), IID(ROL, r8, cl), IID(ROL, r8, cl), IID(ROL, r8, cl), IID(ROL, r8, cl), IID(ROR, r8, cl), IID(ROR, r8, cl), IID(ROR, r8, cl), IID(ROR, r8, cl), IID(ROR, r8, cl), IID(ROR, r8, cl), IID(ROR, r8, cl), IID(ROR, r8, cl),
    /* D0 */ IID(RCL, r8, cl), IID(RCL, r8, cl), IID(RCL, r8, cl), IID(RCL, r8, cl), IID(RCL, r8, cl), IID(RCL, r8, cl), IID(RCL, r8, cl), IID(RCL, r8, cl), IID(RCR, r8, cl), IID(RCR, r8, cl), IID(RCR, r8, cl), IID(RCR, r8, cl), IID(RCR, r8, cl), IID(RCR, r8, cl), IID(RCR, r8, cl), IID(RCR, r8, cl),
    /* E0 */ IID(SHL, r8, cl), IID(SHL, r8, cl), IID(SHL, r8, cl), IID(SHL, r8, cl), IID(SHL, r8, cl), IID(SHL, r8, cl), IID(SHL, r8, cl), IID(SHL, r8, cl), IID(SHR, r8, cl), IID(SHR, r8, cl), IID(SHR, r8, cl), IID(SHR, r8, cl), IID(SHR, r8, cl), IID(SHR, r8, cl), IID(SHR, r8, cl), IID(SHR, r8, cl),
    /* F0 */ IID(SAL, r8, cl), IID(SAL, r8, cl), IID(SAL, r8, cl), IID(SAL, r8, cl), IID(SAL, r8, cl), IID(SAL, r8, cl), IID(SAL, r8, cl), IID(SAL, r8, cl), IID(SAR, r8, cl), IID(SAR, r8, cl), IID(SAR, r8, cl), IID(SAR, r8, cl), IID(SAR, r8, cl), IID(SAR, r8, cl), IID(SAR, r8, cl), IID(SAR, r8, cl)
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xD2(const uint8_t byte) noexcept -> DecodedInstruction
{
    const uint8_t len = kLengthTable_ModRM[byte]; // no immediate byte (count is in CL register)
    return { len, kInstrIdTable_opcode_extension_0xD2[byte] };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xD3 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                   1                   2                   3                   4                   5                   6                   7                   8                   9                   A                   B                   C                   D                   E                   F            */
    /* 00 */ IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl),
    /* 10 */ IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl),
    /* 20 */ IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl),
    /* 30 */ IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl),
    /* 40 */ IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl),
    /* 50 */ IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl),
    /* 60 */ IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl),
    /* 70 */ IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl),
    /* 80 */ IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROL, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl), IID(ROR, m32, cl),
    /* 90 */ IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCL, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl), IID(RCR, m32, cl),
    /* A0 */ IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHL, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl), IID(SHR, m32, cl),
    /* B0 */ IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAL, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl), IID(SAR, m32, cl),
    /* C0 */ IID(ROL, r32, cl), IID(ROL, r32, cl), IID(ROL, r32, cl), IID(ROL, r32, cl), IID(ROL, r32, cl), IID(ROL, r32, cl), IID(ROL, r32, cl), IID(ROL, r32, cl), IID(ROR, r32, cl), IID(ROR, r32, cl), IID(ROR, r32, cl), IID(ROR, r32, cl), IID(ROR, r32, cl), IID(ROR, r32, cl), IID(ROR, r32, cl), IID(ROR, r32, cl),
    /* D0 */ IID(RCL, r32, cl), IID(RCL, r32, cl), IID(RCL, r32, cl), IID(RCL, r32, cl), IID(RCL, r32, cl), IID(RCL, r32, cl), IID(RCL, r32, cl), IID(RCL, r32, cl), IID(RCR, r32, cl), IID(RCR, r32, cl), IID(RCR, r32, cl), IID(RCR, r32, cl), IID(RCR, r32, cl), IID(RCR, r32, cl), IID(RCR, r32, cl), IID(RCR, r32, cl),
    /* E0 */ IID(SHL, r32, cl), IID(SHL, r32, cl), IID(SHL, r32, cl), IID(SHL, r32, cl), IID(SHL, r32, cl), IID(SHL, r32, cl), IID(SHL, r32, cl), IID(SHL, r32, cl), IID(SHR, r32, cl), IID(SHR, r32, cl), IID(SHR, r32, cl), IID(SHR, r32, cl), IID(SHR, r32, cl), IID(SHR, r32, cl), IID(SHR, r32, cl), IID(SHR, r32, cl),
    /* F0 */ IID(SAL, r32, cl), IID(SAL, r32, cl), IID(SAL, r32, cl), IID(SAL, r32, cl), IID(SAL, r32, cl), IID(SAL, r32, cl), IID(SAL, r32, cl), IID(SAL, r32, cl), IID(SAR, r32, cl), IID(SAR, r32, cl), IID(SAR, r32, cl), IID(SAR, r32, cl), IID(SAR, r32, cl), IID(SAR, r32, cl), IID(SAR, r32, cl), IID(SAR, r32, cl)
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xD3(const uint8_t byte) noexcept -> DecodedInstruction
{
    const uint8_t len = kLengthTable_ModRM[byte]; // no immediate byte (count is in CL register)
    return { len, kInstrIdTable_opcode_extension_0xD3[byte] };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xF6 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                     1                     2                     3                     4                     5                     6                     7                     8                     9                     A                     B                     C                     D                     E                     F              */
    /* 00 */ IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),
    /* 10 */ IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),
    /* 20 */ IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),
    /* 30 */ IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),
    /* 40 */ IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),
    /* 50 */ IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),
    /* 60 */ IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),
    /* 70 */ IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),
    /* 80 */ IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),  IID(TEST, m8, imm8),
    /* 90 */ IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NOT,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),        IID(NEG,  m8),
    /* A0 */ IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(MUL,  m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),        IID(IMUL, m8),
    /* B0 */ IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(DIV,  m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),        IID(IDIV, m8),
    /* C0 */ IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),  IID(TEST, r8, imm8),
    /* D0 */ IID(NOT,  r8),        IID(NOT,  r8),        IID(NOT,  r8),        IID(NOT,  r8),        IID(NOT,  r8),        IID(NOT,  r8),        IID(NOT,  r8),        IID(NOT,  r8),        IID(NEG,  r8),        IID(NEG,  r8),        IID(NEG,  r8),        IID(NEG,  r8),        IID(NEG,  r8),        IID(NEG,  r8),        IID(NEG,  r8),        IID(NEG,  r8),
    /* E0 */ IID(MUL,  r8),        IID(MUL,  r8),        IID(MUL,  r8),        IID(MUL,  r8),        IID(MUL,  r8),        IID(MUL,  r8),        IID(MUL,  r8),        IID(MUL,  r8),        IID(IMUL, r8),        IID(IMUL, r8),        IID(IMUL, r8),        IID(IMUL, r8),        IID(IMUL, r8),        IID(IMUL, r8),        IID(IMUL, r8),        IID(IMUL, r8),
    /* F0 */ IID(DIV,  r8),        IID(DIV,  r8),        IID(DIV,  r8),        IID(DIV,  r8),        IID(DIV,  r8),        IID(DIV,  r8),        IID(DIV,  r8),        IID(DIV,  r8),        IID(IDIV, r8),        IID(IDIV, r8),        IID(IDIV, r8),        IID(IDIV, r8),        IID(IDIV, r8),        IID(IDIV, r8),        IID(IDIV, r8),        IID(IDIV, r8)
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xF6(const uint8_t byte) noexcept -> DecodedInstruction
{
    const bool is_test = (byte & 0b00'111'000) <= 0b00'001'000; // reg=0 or reg=1
    const uint8_t len = kLengthTable_ModRM[byte] + (is_test ? 1 : 0); // +1 for imm8 (TEST only)
    return { len, kInstrIdTable_opcode_extension_0xF6[byte] };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xF7 = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                      1                      2                      3                      4                      5                      6                      7                      8                      9                      A                      B                      C                      D                      E                      F              */
    /* 00 */ IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32),
    /* 10 */ IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),
    /* 20 */ IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),
    /* 30 */ IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),
    /* 40 */ IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32),
    /* 50 */ IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),
    /* 60 */ IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),
    /* 70 */ IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),
    /* 80 */ IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32), IID(TEST, m32, imm32),
    /* 90 */ IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NOT,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),        IID(NEG,  m32),
    /* A0 */ IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(MUL,  m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),        IID(IMUL, m32),
    /* B0 */ IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(DIV,  m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),        IID(IDIV, m32),
    /* C0 */ IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32), IID(TEST, r32, imm32),
    /* D0 */ IID(NOT,  r32),        IID(NOT,  r32),        IID(NOT,  r32),        IID(NOT,  r32),        IID(NOT,  r32),        IID(NOT,  r32),        IID(NOT,  r32),        IID(NOT,  r32),        IID(NEG,  r32),        IID(NEG,  r32),        IID(NEG,  r32),        IID(NEG,  r32),        IID(NEG,  r32),        IID(NEG,  r32),        IID(NEG,  r32),        IID(NEG,  r32),
    /* E0 */ IID(MUL,  r32),        IID(MUL,  r32),        IID(MUL,  r32),        IID(MUL,  r32),        IID(MUL,  r32),        IID(MUL,  r32),        IID(MUL,  r32),        IID(MUL,  r32),        IID(IMUL, r32),        IID(IMUL, r32),        IID(IMUL, r32),        IID(IMUL, r32),        IID(IMUL, r32),        IID(IMUL, r32),        IID(IMUL, r32),        IID(IMUL, r32),
    /* F0 */ IID(DIV,  r32),        IID(DIV,  r32),        IID(DIV,  r32),        IID(DIV,  r32),        IID(DIV,  r32),        IID(DIV,  r32),        IID(DIV,  r32),        IID(DIV,  r32),        IID(IDIV, r32),        IID(IDIV, r32),        IID(IDIV, r32),        IID(IDIV, r32),        IID(IDIV, r32),        IID(IDIV, r32),        IID(IDIV, r32),        IID(IDIV, r32)
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xF7(const uint8_t byte) noexcept -> DecodedInstruction
{
    const bool is_test = (byte & 0b00'111'000) <= 0b00'001'000; // reg=0 or reg=1
    const uint8_t len = kLengthTable_ModRM[byte] + (is_test ? 4 : 0); // +4 for imm32 (TEST only)
    return { len, kInstrIdTable_opcode_extension_0xF7[byte] };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xFE = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0              1              2              3              4              5              6              7              8              9              A              B              C              D              E              F         */
    /* 00 */ IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8),
    /* 10 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* 20 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* 30 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* 40 */ IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8),
    /* 50 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* 60 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* 70 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* 80 */ IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(INC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8), IID(DEC, m8),
    /* 90 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* A0 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* B0 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* C0 */ IID(INC, r8), IID(INC, r8), IID(INC, r8), IID(INC, r8), IID(INC, r8), IID(INC, r8), IID(INC, r8), IID(INC, r8), IID(DEC, r8), IID(DEC, r8), IID(DEC, r8), IID(DEC, r8), IID(DEC, r8), IID(DEC, r8), IID(DEC, r8), IID(DEC, r8),
    /* D0 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* E0 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,
    /* F0 */ IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID,   IID_INVALID
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xFE(const uint8_t byte) noexcept -> DecodedInstruction
{
    const auto& iid = kInstrIdTable_opcode_extension_0xFE[byte];
    if (iid.opcode == OpcodeId::INVALID_OPCODE) {
        return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
    }
    const uint8_t len = kLengthTable_ModRM[byte];
    return { len, iid };
}

static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0xFF = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                 1                 2                 3                 4                 5                 6                 7                 8                 9                 A                 B                 C                 D                 E                 F              */
    /* 00 */ IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),
    /* 10 */ IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* 20 */ IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* 30 */ IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* 40 */ IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),
    /* 50 */ IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* 60 */ IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* 70 */ IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* 80 */ IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(INC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),   IID(DEC,  m32),
    /* 90 */ IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID(CALL, m32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* A0 */ IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID(JMP,  m32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* B0 */ IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID(PUSH, m32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* C0 */ IID(INC,  r32),   IID(INC,  r32),   IID(INC,  r32),   IID(INC,  r32),   IID(INC,  r32),   IID(INC,  r32),   IID(INC,  r32),   IID(INC,  r32),   IID(DEC,  r32),   IID(DEC,  r32),   IID(DEC,  r32),   IID(DEC,  r32),   IID(DEC,  r32),   IID(DEC,  r32),   IID(DEC,  r32),   IID(DEC,  r32),
    /* D0 */ IID(CALL, r32),   IID(CALL, r32),   IID(CALL, r32),   IID(CALL, r32),   IID(CALL, r32),   IID(CALL, r32),   IID(CALL, r32),   IID(CALL, r32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* E0 */ IID(JMP,  r32),   IID(JMP,  r32),   IID(JMP,  r32),   IID(JMP,  r32),   IID(JMP,  r32),   IID(JMP,  r32),   IID(JMP,  r32),   IID(JMP,  r32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* F0 */ IID(PUSH, r32),   IID(PUSH, r32),   IID(PUSH, r32),   IID(PUSH, r32),   IID(PUSH, r32),   IID(PUSH, r32),   IID(PUSH, r32),   IID(PUSH, r32),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID
} });

static constexpr auto GetInstructionDescriptor_opcode_extension_0xFF(const uint8_t byte) noexcept -> DecodedInstruction
{
    auto iid = kInstrIdTable_opcode_extension_0xFF[byte];
    if (iid.opcode == OpcodeId::INVALID_OPCODE) {
        return { ERR(UNDEFINED_INSTRUCTION), {} };
    }

    // In long mode, FF /2 (CALL), /4 (JMP), and /6 (PUSH) use r/m64 by default.
    if (const auto reg = static_cast<uint8_t>((byte >> 3) & 0b111u);
        reg == 0b010u || reg == 0b100u || reg == 0b110u) {
        const bool is_reg = (byte & 0b11'000'000u) == 0b11'000'000u;
        iid.operands.operand[0] = is_reg ? Operand::r64 : Operand::m64;
    }

    const uint8_t len = kLengthTable_ModRM[byte];
    return { len, iid };
}

static constexpr auto GetInstructionDescriptor_opcode_extension_0xC6(const uint8_t byte) noexcept -> DecodedInstruction
{
    if ((byte & 0b00'111'000) != 0b00'000'000) // only /0 (MOV) is valid
        return { ERR(UNDEFINED_INSTRUCTION), {} };
    const uint8_t len = kLengthTable_ModRM[byte] + 1; // +1 for imm8
    if ((byte & 0b11'000'000) == 0b11'000'000)
        return { len, IID(MOV, r8, imm8) };
    // rm=100 → a SIB byte follows; defer to the SIB-dispatch marker so the
    // decode site can resolve m8 vs stack_m8 from the base register.
    if (ModrmHasSib(byte))
        return { len, IID(MOV, Sib_Mb, imm8) };
    return { len, IID(MOV, m8, imm8) };
}

static constexpr auto GetInstructionDescriptor_opcode_extension_0xC7(const uint8_t byte) noexcept -> DecodedInstruction
{
    if ((byte & 0b00'111'000) != 0b00'000'000) // only /0 (MOV) is valid
        return { ERR(UNDEFINED_INSTRUCTION), {} };
    const uint8_t len = kLengthTable_ModRM[byte] + 4; // +4 for imm32
    if ((byte & 0b11'000'000) == 0b11'000'000)
        return { len, IID(MOV, r32, imm32) };
    if (ModrmHasSib(byte))
        return { len, IID(MOV, Sib_Mv, imm32) };
    return { len, IID(MOV, m32, imm32) };
}

// Two-byte (0F-prefixed) opcode extension tables.
// These follow the same pattern as the 1-byte extension tables above:
//   - 256 entries, indexed by the full ModRM byte
//   - mod bits [7:6] select memory vs register operand form
//   - reg bits [5:3] select the operation
//
// Length formula (returned by the dispatch function, relative to start of 0F):

// ─────────────────────────────────────────────────────────────────────────────
// 0F 01 Group 7 — SGDT/SIDT/LGDT/LIDT/SMSW/LMSW/INVLPG + fixed register forms
//
// Memory forms (mod=00/01/10):
//   /0=SGDT m  /1=SIDT m  /2=LGDT m  /3=LIDT m
//   /4=SMSW m16  /5=INVALID  /6=LMSW m16  /7=INVLPG m8
//
// Register forms (mod=11) — specific per-modrm:
//   /0 all INVALID
//   /1  0xC8=MONITOR  0xC9=MWAIT  0xCA=CLAC  0xCB=STAC  (rest INVALID)
//   /2  0xD0=XGETBV   0xD1=XSETBV  0xD6=XTEST  (rest INVALID)
//   /3  all INVALID
//   /4  0xE0-0xE7=SMSW r32  — carries r32 so ApplyPrefixSizes upgrades to r64
//   /5  0xE8=SERIALIZE  0xEE=RDPKRU  0xEF=WRPKRU  (rest INVALID)
//   /6  0xF0-0xF7=LMSW r16  (r16 is not upgraded by any prefix)
//   /7  0xF8=SWAPGS  0xF9=RDTSCP  (rest INVALID)
// ─────────────────────────────────────────────────────────────────────────────

static constexpr std::array<InstructionId, 256> kInstrIdTable_0F_01 = { {
    /* mod=00 (/0-/3 valid, /4=SMSW, /5=INVALID, /6=LMSW, /7=INVLPG) ------------ */
    /* 00 */ IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),
    /* 10 */ IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),
    /* 20 */ IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* 30 */ IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),
    /* mod=01 ------------------------------------------------------------------- */
    /* 40 */ IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),
    /* 50 */ IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),
    /* 60 */ IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* 70 */ IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),
    /* mod=10 ------------------------------------------------------------------- */
    /* 80 */ IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SGDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),   IID(SIDT,   m),
    /* 90 */ IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LGDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),   IID(LIDT,   m),
    /* A0 */ IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID(SMSW,   m16), IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* B0 */ IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(LMSW,   m16), IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),  IID(INVLPG, m8),
    /* mod=11: register-only fixed encodings ------------------------------------ */
    /* C0 */ IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID(MONITOR),     IID(MWAIT),       IID(CLAC),        IID(STAC),        IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* D0 */ IID(XGETBV),      IID(XSETBV),      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID(XTEST),       IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
    /* E0 */ IID(SMSW,   r32), IID(SMSW,   r32), IID(SMSW,   r32), IID(SMSW,   r32), IID(SMSW,   r32), IID(SMSW,   r32), IID(SMSW,   r32), IID(SMSW,   r32), IID(SERIALIZE),   IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID(RDPKRU),      IID(WRPKRU),
    /* F0 */ IID(LMSW,   r16), IID(LMSW,   r16), IID(LMSW,   r16), IID(LMSW,   r16), IID(LMSW,   r16), IID(LMSW,   r16), IID(LMSW,   r16), IID(LMSW,   r16), IID(SWAPGS),      IID(RDTSCP),      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,      IID_INVALID,
} };

// SMSW r32 carries r32 so ApplyPrefixSizes can upgrade it to r64 (REX.W).
// All other operand types (m, m16, m8, r16, none) are unaffected by ApplyPrefixSizes.
static constexpr auto GetInstructionDescriptor_0F_01(
    const uint8_t modrm, const uint8_t modrm_len) noexcept -> DecodedInstruction
{
    const auto& iid = kInstrIdTable_0F_01[modrm];
    if (iid.opcode == OpcodeId::INVALID_OPCODE) {
        return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
    }
    return { static_cast<uint8_t>(modrm_len + 1), iid }; // +1 for 0F escape
}

//   kLengthTable_ModRM[modrm] + 1 (for 0F escape) + <extra immediates>

// ─────────────────────────────────────────────────────────────────────────────
// 0F 00 Group 6 — SLDT / STR / LLDT / LTR / VERR / VERW
//
// Memory forms (mod=00/01/10) → m16 operand for all six mnemonics.
// Register forms (mod=11):
//   /0 SLDT r32, /1 STR r32 — r32 payload so ApplyPrefixSizes can upgrade to r64.
//   /2-/5 LLDT/LTR/VERR/VERW r16 — 16-bit fixed; ApplyPrefixSizes leaves r16 intact.
//   /6 /7 — INVALID.
// ─────────────────────────────────────────────────────────────────────────────

static constexpr std::array<InstructionId, 256> kInstrIdTable_0F_00 = { {
    /* mod=00 (/0-/5 valid, /6-/7 INVALID) ----------------------------------------- */
    /* 00 */ IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),
    /* 10 */ IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),
    /* 20 */ IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),
    /* 30 */ IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,
    /* mod=01 ---------------------------------------------------------------------- */
    /* 40 */ IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),
    /* 50 */ IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),
    /* 60 */ IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),
    /* 70 */ IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,
    /* mod=10 ---------------------------------------------------------------------- */
    /* 80 */ IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(SLDT, m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),  IID(STR,  m16),
    /* 90 */ IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LLDT, m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),  IID(LTR,  m16),
    /* A0 */ IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERR, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),  IID(VERW, m16),
    /* B0 */ IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,
    /* mod=11: /0=SLDT r32 /1=STR r32 /2=LLDT r16 /3=LTR r16 /4=VERR r16 /5=VERW r16 */
    /* C0 */ IID(SLDT, r32),  IID(SLDT, r32),  IID(SLDT, r32),  IID(SLDT, r32),  IID(SLDT, r32),  IID(SLDT, r32),  IID(SLDT, r32),  IID(SLDT, r32),  IID(STR,  r32),  IID(STR,  r32),  IID(STR,  r32),  IID(STR,  r32),  IID(STR,  r32),  IID(STR,  r32),  IID(STR,  r32),  IID(STR,  r32),
    /* D0 */ IID(LLDT, r16),  IID(LLDT, r16),  IID(LLDT, r16),  IID(LLDT, r16),  IID(LLDT, r16),  IID(LLDT, r16),  IID(LLDT, r16),  IID(LLDT, r16),  IID(LTR,  r16),  IID(LTR,  r16),  IID(LTR,  r16),  IID(LTR,  r16),  IID(LTR,  r16),  IID(LTR,  r16),  IID(LTR,  r16),  IID(LTR,  r16),
    /* E0 */ IID(VERR, r16),  IID(VERR, r16),  IID(VERR, r16),  IID(VERR, r16),  IID(VERR, r16),  IID(VERR, r16),  IID(VERR, r16),  IID(VERR, r16),  IID(VERW, r16),  IID(VERW, r16),  IID(VERW, r16),  IID(VERW, r16),  IID(VERW, r16),  IID(VERW, r16),  IID(VERW, r16),  IID(VERW, r16),
    /* F0 */ IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,     IID_INVALID,
} };

// modrm_len = caller-adjusted kLengthTable_ModRM[modrm] (SIB base=5 already added).
// SLDT r32 / STR r32 carry r32 so the caller's ApplyPrefixSizes can upgrade to r64.
static constexpr auto GetInstructionDescriptor_0F_00(
    const uint8_t modrm, const uint8_t modrm_len) noexcept -> DecodedInstruction
{
    const auto& iid = kInstrIdTable_0F_00[modrm];
    if (iid.opcode == OpcodeId::INVALID_OPCODE) {
        return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
    }
    return { static_cast<uint8_t>(modrm_len + 1), iid }; // +1 for 0F escape
}

// ─────────────────────────────────────────────────────────────────────────────
// 0F C7 Group 9 — CMPXCHG8B/XRSTORS/XSAVEC/XSAVES/RDRAND/RDSEED
//
// Memory forms: /1=CMPXCHG8B m64  /3=XRSTORS m  /4=XSAVEC m  /5=XSAVES m
// Register forms: /6=RDRAND r32   /7=RDSEED r32
//
// Post-table prefix fixups (handled by the caller, not by this function):
//   CMPXCHG8B + REX.W → CMPXCHG16B m128  (identity change, not just size)
//   RDSEED    + F3    → RDPID r32         (identity change)
//   RDRAND/RDSEED/RDPID + REX.W/66h → r64/r16 via ApplyPrefixSizes
// ─────────────────────────────────────────────────────────────────────────────

static constexpr std::array<InstructionId, 256> kInstrIdTable_0F_C7 = { {
    /* mod=00: /0 INVALID /1 CMPXCHG8B /2 INVALID /3-/5 XRSTORS/XSAVEC/XSAVES /6-/7 INVALID */
    /* 00 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),
    /* 10 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),
    /* 20 */ IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),
    /* 30 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* mod=01 -------------------------------------------------------------------- */
    /* 40 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),
    /* 50 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),
    /* 60 */ IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),
    /* 70 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* mod=10 -------------------------------------------------------------------- */
    /* 80 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),  IID(CMPXCHG8B, m64),
    /* 90 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),      IID(XRSTORS, m),
    /* A0 */ IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVEC, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),       IID(XSAVES, m),
    /* B0 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* mod=11: /0-/5 INVALID /6=RDRAND r32 /7=RDSEED r32 ------------------------ */
    /* C0 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* D0 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* E0 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* F0 */ IID(RDRAND, r32),     IID(RDRAND, r32),     IID(RDRAND, r32),     IID(RDRAND, r32),     IID(RDRAND, r32),     IID(RDRAND, r32),     IID(RDRAND, r32),     IID(RDRAND, r32),     IID(RDSEED, r32),     IID(RDSEED, r32),     IID(RDSEED, r32),     IID(RDSEED, r32),     IID(RDSEED, r32),     IID(RDSEED, r32),     IID(RDSEED, r32),     IID(RDSEED, r32),
} };

// Table lookup only — prefix fixups (REX.W for CMPXCHG16B, F3 for RDPID) are
// handled inline by the caller after inspecting the returned iid.opcode.
static constexpr auto GetInstructionDescriptor_0F_C7(
    const uint8_t modrm, const uint8_t modrm_len) noexcept -> DecodedInstruction
{
    const auto& iid = kInstrIdTable_0F_C7[modrm];
    if (iid.opcode == OpcodeId::INVALID_OPCODE) {
        return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
    }
    return { static_cast<uint8_t>(modrm_len + 1), iid }; // +1 for 0F escape
}

// ─────────────────────────────────────────────────────────────────────────────
// 0F AE Group 15 — prefix-selected dispatch tables
//
// Three variants, chosen at runtime by the legacy prefix field:
//   nopfx  no prefix  → fences + memory save/restore/CSR/XSAVE family
//   f3     F3 prefix  → RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE (register /0-/3,
//                        r32 payload so ApplyPrefixSizes can REX.W-upgrade)
//                        plus CLRSSBSY (/6 memory only, m64)
//   66     66h prefix → CLWB (/6 mem) and CLFLUSHOPT (/7 mem) only
//
// Length returned by GetInstructionDescriptor_0F_AE = modrm_len + 1
//   where modrm_len is passed in (caller may have already adjusted for the
//   SIB base=5 + disp32 special case).
// ─────────────────────────────────────────────────────────────────────────────

// No-prefix table: memory forms /0-/7 for mod=00/01/10; fences for mod=11 /5-/7
static constexpr std::array<InstructionId, 256> kInstrIdTable_0F_AE_nopfx = { {
    /* mod=00 --------------------------------------------------------------------- */
    /* 00 */ IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),
    /* 10 */ IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),
    /* 20 */ IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),
    /* 30 */ IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),
    /* mod=01 --------------------------------------------------------------------- */
    /* 40 */ IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),
    /* 50 */ IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),
    /* 60 */ IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),
    /* 70 */ IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),
    /* mod=10 --------------------------------------------------------------------- */
    /* 80 */ IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXSAVE,   m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),    IID(FXRSTOR,  m),
    /* 90 */ IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(LDMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),  IID(STMXCSR,  m32),
    /* A0 */ IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XSAVE,    m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),    IID(XRSTOR,   m),
    /* B0 */ IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(XSAVEOPT, m),    IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),   IID(CLFLUSH,  m8),
    /* mod=11: /0-/4 INVALID; /5=LFENCE /6=MFENCE /7=SFENCE --------------------- */
    /* C0 */ IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,
    /* D0 */ IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,
    /* E0 */ IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID_INVALID,         IID(LFENCE),         IID(LFENCE),         IID(LFENCE),         IID(LFENCE),         IID(LFENCE),         IID(LFENCE),         IID(LFENCE),         IID(LFENCE),
    /* F0 */ IID(MFENCE),         IID(MFENCE),         IID(MFENCE),         IID(MFENCE),         IID(MFENCE),         IID(MFENCE),         IID(MFENCE),         IID(MFENCE),         IID(SFENCE),         IID(SFENCE),         IID(SFENCE),         IID(SFENCE),         IID(SFENCE),         IID(SFENCE),         IID(SFENCE),         IID(SFENCE),
} };

// Dispatch: prefix determines decode path; only the dense no-prefix case uses a table.
// F3 (4 reg entries + 1 mem entry) and 66h (2 valid mem-only entries) are handled with
// direct branch logic to avoid allocating two mostly-empty 256-entry tables.
//
// modrm_len = caller-adjusted kLengthTable_ModRM[modrm] (SIB base=5 already added).
// Returned length is relative to the 0F escape byte (= modrm_len + 1).
// F3 entries carry r32 operands so the caller can apply ApplyPrefixSizes for REX.W.
static constexpr auto GetInstructionDescriptor_0F_AE(
    const uint8_t modrm, const uint8_t modrm_len,
    const bool has_f3, const bool has_66) noexcept -> DecodedInstruction
{
    const auto    len    = static_cast<uint8_t>(modrm_len + 1); // +1 for 0F escape
    const auto    reg    = static_cast<uint8_t>((modrm >> 3) & 7u);
    const bool    is_reg = (modrm & 0b11'000'000u) == 0b11'000'000u;

    // F3: /0-/3 register forms and /6 memory form
    //   mod=11, /0-/3 -> RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE
    //   mod!=11, /6   -> CLRSSBSY m64
    if (has_f3) {
        if (has_66) { return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID }; }
        if (is_reg) {
            switch (reg) {
            case 0: return { len, IID(RDFSBASE, r32) };
            case 1: return { len, IID(RDGSBASE, r32) };
            case 2: return { len, IID(WRFSBASE, r32) };
            case 3: return { len, IID(WRGSBASE, r32) };
            default: return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
            }
        }
        if (reg == 6) {
            return { len, IID(CLRSSBSY, m64) };
        }
        return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
    }

    // 66h: memory-only forms, /6 → CLWB, /7 → CLFLUSHOPT
    if (has_66) {
        if (is_reg) { return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID }; }
        switch (reg) {
        case 6: return { len, IID(CLWB,      m8) };
        case 7: return { len, IID(CLFLUSHOPT, m8) };
        default: return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
        }
    }

    // No prefix: dense table covers all 256 ModRM values
    const auto& iid = kInstrIdTable_0F_AE_nopfx[modrm];
    if (iid.opcode == OpcodeId::INVALID_OPCODE) {
        return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
    }
    return { len, iid };
}

// 0F BA / Group 8 — BT/BTS/BTR/BTC Ev, imm8  (/0-/3 reserved, /4-/7 used)
static constexpr std::array<InstructionId, 256> kInstrIdTable_opcode_extension_0x0F_BA = WithSibDispatch(std::array<InstructionId, 256>{ {
    /*       0                     1                     2                     3                     4                     5                     6                     7                     8                     9                     A                     B                     C                     D                     E                     F              */
    /* 00 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* 10 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* 20 */ IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),
    /* 30 */ IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),
    /* 40 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* 50 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* 60 */ IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),
    /* 70 */ IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),
    /* 80 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* 90 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* A0 */ IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BT,  m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),  IID(BTS, m32, imm8),
    /* B0 */ IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTR, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),  IID(BTC, m32, imm8),
    /* C0 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* D0 */ IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,          IID_INVALID,
    /* E0 */ IID(BT,  r32, imm8),  IID(BT,  r32, imm8),  IID(BT,  r32, imm8),  IID(BT,  r32, imm8),  IID(BT,  r32, imm8),  IID(BT,  r32, imm8),  IID(BT,  r32, imm8),  IID(BT,  r32, imm8),  IID(BTS, r32, imm8),  IID(BTS, r32, imm8),  IID(BTS, r32, imm8),  IID(BTS, r32, imm8),  IID(BTS, r32, imm8),  IID(BTS, r32, imm8),  IID(BTS, r32, imm8),  IID(BTS, r32, imm8),
    /* F0 */ IID(BTR, r32, imm8),  IID(BTR, r32, imm8),  IID(BTR, r32, imm8),  IID(BTR, r32, imm8),  IID(BTR, r32, imm8),  IID(BTR, r32, imm8),  IID(BTR, r32, imm8),  IID(BTR, r32, imm8),  IID(BTC, r32, imm8),  IID(BTC, r32, imm8),  IID(BTC, r32, imm8),  IID(BTC, r32, imm8),  IID(BTC, r32, imm8),  IID(BTC, r32, imm8),  IID(BTC, r32, imm8),  IID(BTC, r32, imm8),
} });

// Length = kLengthTable_ModRM[modrm] + 1 (0F escape) + 1 (imm8) = modrm_len + 2
static constexpr auto GetInstructionDescriptor_opcode_extension_0x0F_BA(const uint8_t byte) noexcept -> DecodedInstruction
{
    const auto& iid = kInstrIdTable_opcode_extension_0x0F_BA[byte];
    if (iid.opcode == OpcodeId::INVALID_OPCODE) {
        return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
    }
    const uint8_t len = kLengthTable_ModRM[byte] + 2; // +1 for 0F escape, +1 for imm8
    return { len, iid };
}

// x87 memory-form decode matrix (D8-DF, mod != 11): indexed by [opcode-0xD8][reg].
// Invalid/reserved forms remain IID_INVALID and are reported as UNDEFINED_INSTRUCTION.
static constexpr std::array<std::array<InstructionId, 8>, 8> kInstrIdTable_x87_mem_8x8 = {{
    // D8 /0-/7
    {{ IID(FADD,  st0, m32fp), IID(FMUL,  st0, m32fp), IID(FCOM,  m32fp), IID(FCOMP, m32fp),
       IID(FSUB,  st0, m32fp), IID(FSUBR, st0, m32fp), IID(FDIV,  st0, m32fp), IID(FDIVR, st0, m32fp) }},
    // D9 /0-/7
    {{ IID(FLD,   m32fp),      IID_INVALID,            IID(FST,   m32fp), IID(FSTP,  m32fp),
       IID(FLDENV, m),         IID(FLDCW,  m16),       IID(FNSTENV, m),   IID(FNSTCW, m16) }},
    // DA /0-/7
    {{ IID(FIADD, m32),        IID(FIMUL, m32),        IID(FICOM, m32),   IID(FICOMP, m32),
       IID(FISUB, m32),        IID(FISUBR, m32),       IID(FIDIV, m32),   IID(FIDIVR, m32) }},
    // DB /0-/7
    {{ IID(FILD,  m32),        IID_INVALID,            IID(FIST,  m32),   IID(FISTP, m32),
       IID_INVALID,            IID(FLD,   m80fp),      IID_INVALID,       IID(FSTP,  m80fp) }},
    // DC /0-/7
    {{ IID(FADD,  st0, m64fp), IID(FMUL,  st0, m64fp), IID(FCOM,  m64fp), IID(FCOMP, m64fp),
       IID(FSUB,  st0, m64fp), IID(FSUBR, st0, m64fp), IID(FDIV,  st0, m64fp), IID(FDIVR, st0, m64fp) }},
    // DD /0-/7
    {{ IID(FLD,   m64fp),      IID_INVALID,            IID(FST,   m64fp), IID(FSTP,  m64fp),
       IID(FRSTOR, m),         IID_INVALID,            IID(FSAVE, m),     IID(FNSTSW, m16) }},
    // DE /0-/7
    {{ IID(FIADD, m16),        IID(FIMUL, m16),        IID(FICOM, m16),   IID(FICOMP, m16),
       IID(FISUB, m16),        IID(FISUBR, m16),       IID(FIDIV, m16),   IID(FIDIVR, m16) }},
    // DF /0-/7
    {{ IID(FILD,  m16),        IID(FISTTP, m16),       IID(FIST,  m16),   IID(FISTP, m16),
       IID(FBLD,  m80fp),      IID(FILD,   m64),       IID(FBSTP, m80fp), IID(FISTP, m64) }},
}};

// x87 D9 register forms keyed by ModR/M.reg (mod=11 only).
static constexpr std::array<InstructionId, 8> kInstrIdTable_x87_reg_D9_by_reg = {{
    IID(FLD, sti),
    IID(FXCH, sti),
    IID_INVALID,
    IID_INVALID,
    IID_INVALID,
    IID_INVALID,
    IID_INVALID,
    IID_INVALID,
}};

// x87 D9 fixed register-special forms keyed by full ModR/M byte (mod=11 only).
static constexpr auto kInstrIdTable_x87_reg_D9_by_modrm = [] {
    std::array<InstructionId, 256> table{};
    for (auto& iid : table) {
        iid = IID_INVALID;
    }
    table[0xD0] = IID(FNOP);
    table[0xE0] = IID(FCHS);
    table[0xE1] = IID(FABS);
    table[0xE4] = IID(FTST);
    table[0xE5] = IID(FXAM);
    table[0xE8] = IID(FLD1);
    table[0xE9] = IID(FLDL2T);
    table[0xEA] = IID(FLDL2E);
    table[0xEB] = IID(FLDPI);
    table[0xEC] = IID(FLDLG2);
    table[0xED] = IID(FLDLN2);
    table[0xEE] = IID(FLDZ);
    table[0xF0] = IID(F2XM1);
    table[0xF1] = IID(FYL2X);
    table[0xF2] = IID(FPTAN);
    table[0xF3] = IID(FPATAN);
    table[0xF4] = IID(FXTRACT);
    table[0xF5] = IID(FPREM1);
    table[0xF6] = IID(FDECSTP);
    table[0xF7] = IID(FINCSTP);
    table[0xF8] = IID(FPREM);
    table[0xF9] = IID(FYL2XP1);
    table[0xFA] = IID(FSQRT);
    table[0xFB] = IID(FSINCOS);
    table[0xFC] = IID(FRNDINT);
    table[0xFD] = IID(FSCALE);
    table[0xFE] = IID(FSIN);
    table[0xFF] = IID(FCOS);
    return table;
}();

// x87 one-byte opcode family (D8-DF), dispatched by opcode + ModR/M.
// Length is supplied by caller (kLengthTable_ModRM[modrm], optionally SIB-adjusted).
static constexpr auto GetInstructionDescriptor_x87(
    const uint8_t opcode, const uint8_t modrm, const uint8_t modrm_len) noexcept -> DecodedInstruction
{
    const bool is_reg = (modrm & 0b11'000'000u) == 0b11'000'000u;
    const uint8_t reg = static_cast<uint8_t>((modrm >> 3) & 0x07u);

    if (!is_reg) {
        if (opcode < 0xD8 || opcode > 0xDF) {
            return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
        }
        const auto& iid = kInstrIdTable_x87_mem_8x8[opcode - 0xD8][reg];
        if (iid.opcode == OpcodeId::INVALID_OPCODE) {
            return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
        }
        return { modrm_len, iid };
    }

    switch (opcode) {
    case 0xD8:
        switch (reg) {
        case 0: return { modrm_len, IID(FADD,  st0, sti) };
        case 1: return { modrm_len, IID(FMUL,  st0, sti) };
        case 2: return { modrm_len, IID(FCOM,  sti) };
        case 3: return { modrm_len, IID(FCOMP, sti) };
        case 4: return { modrm_len, IID(FSUB,  st0, sti) };
        case 5: return { modrm_len, IID(FSUBR, st0, sti) };
        case 6: return { modrm_len, IID(FDIV,  st0, sti) };
        case 7: return { modrm_len, IID(FDIVR, st0, sti) };
        default: break;
        }
        break;
    case 0xD9:
        if (const auto& by_reg = kInstrIdTable_x87_reg_D9_by_reg[reg];
            by_reg.opcode != OpcodeId::INVALID_OPCODE) {
            return { modrm_len, by_reg };
        }
        if (const auto& by_modrm = kInstrIdTable_x87_reg_D9_by_modrm[modrm];
            by_modrm.opcode != OpcodeId::INVALID_OPCODE) {
            return { modrm_len, by_modrm };
        }
        break;
    case 0xDA:
        if (reg <= 3) return { modrm_len, IID(FCMOVcc, st0, sti) };
        if (modrm == 0xE9) return { modrm_len, IID(FUCOMPP) };
        break;
    case 0xDB:
        switch (modrm) {
        case 0xE2: return { modrm_len, IID(FNCLEX) };
        case 0xE3: return { modrm_len, IID(FNINIT) };
        default: break;
        }
        if (reg == 5) return { modrm_len, IID(FUCOMI, st0, sti) };
        if (reg == 6) return { modrm_len, IID(FCOMI,  st0, sti) };
        break;
    case 0xDC:
        switch (reg) {
        case 0: return { modrm_len, IID(FADD,  sti, st0) };
        case 1: return { modrm_len, IID(FMUL,  sti, st0) };
        case 2: return { modrm_len, IID(FCOM,  sti) };
        case 3: return { modrm_len, IID(FCOMP, sti) };
        case 4: return { modrm_len, IID(FSUBR, sti, st0) };
        case 5: return { modrm_len, IID(FSUB,  sti, st0) };
        case 6: return { modrm_len, IID(FDIVR, sti, st0) };
        case 7: return { modrm_len, IID(FDIV,  sti, st0) };
        default: break;
        }
        break;
    case 0xDD:
        switch (reg) {
        case 0: return { modrm_len, IID(FFREE,  sti) };
        case 2: return { modrm_len, IID(FST,    sti) };
        case 3: return { modrm_len, IID(FSTP,   sti) };
        case 4: return { modrm_len, IID(FUCOM,  sti) };
        case 5: return { modrm_len, IID(FUCOMP, sti) };
        default: break;
        }
        break;
    case 0xDE:
        if (modrm == 0xD9) return { modrm_len, IID(FCOMPP) };
        switch (reg) {
        case 0: return { modrm_len, IID(FADDP,  sti, st0) };
        case 1: return { modrm_len, IID(FMULP,  sti, st0) };
        case 4: return { modrm_len, IID(FSUBRP, sti, st0) };
        case 5: return { modrm_len, IID(FSUBP,  sti, st0) };
        case 6: return { modrm_len, IID(FDIVRP, sti, st0) };
        case 7: return { modrm_len, IID(FDIVP,  sti, st0) };
        default: break;
        }
        break;
    case 0xDF:
        if (modrm == 0xE0) return { modrm_len, IID(FNSTSW, ax) };
        if (reg == 5) return { modrm_len, IID(FUCOMIP, st0, sti) };
        if (reg == 6) return { modrm_len, IID(FCOMIP,  st0, sti) };
        break;
    default:
        break;
    }

    return { ERR(UNDEFINED_INSTRUCTION), IID_INVALID };
}

static constexpr std::array<DecodeTableEntry, 256> kDecodeTable_1byte_opcode_shared{ {
    /*
       tag field is used for dispatching instruction lookup:
         0x01-0x0E = direct instruction length and decoded instruction
         0x00 = ModR/M byte follows, lookup length in length table (returns abstract operand form)
         0x87 = x87 floating-point opcode family dispatch (D8-DF)
         0xA1 = has 1 byte immediate, but length depends on ModR/M (e.g. for shift instructions)
         0xA4 = has 4 byte immediate, but length depends on ModR/M (e.g. for IMUL r32, r/m32, imm32)
         0xAC = ModR/M follows, resolve operands via kOperandFormTable_ModRM[instr_id.operands.operand[0]]
         0xB8 = B8+rd MOV: abstract GPR class + variable immediate (4/8/2 bytes for default/REX.W/66h)
         0xD6 = invalid instruction
         0xE2 = the opcode is for escaping to 2-byte opcode
         0xEE = the opcode has opcode extensions
    */
    /*       0                                1                                  2                                 3                                  4                               5                                6                               7                               8                                   9                                 A                                B                                C                                D                                E                                F                               */
    /* 00 */ DTE(0x00, IID(ADD, Eb_Gb)),      DTE(0x00, IID(ADD, Ev_Gv)),        DTE(0x00, IID(ADD, Gb_Eb)),       DTE(0x00, IID(ADD, Gv_Ev)),        DTE(0x02, IID(ADD, al, imm8)),  DTE(0x05, IID(ADD, eax, imm32)), DTE(0xD6, IID_INVALID),         DTE(0xD6, IID_INVALID),         DTE(0x00, IID(OR, Eb_Gb)),          DTE(0x00, IID(OR, Ev_Gv)),        DTE(0x00, IID(OR, Gb_Eb)),       DTE(0x00, IID(OR, Gv_Ev)),       DTE(0x02, IID(OR, al, imm8)),    DTE(0x05, IID(OR, eax, imm32)),  DTE(0xD6, IID_INVALID),          DTE(0xE2, IID_INVALID),
    /* 10 */ DTE(0x00, IID(ADC, Eb_Gb)),      DTE(0x00, IID(ADC, Ev_Gv)),        DTE(0x00, IID(ADC, Gb_Eb)),       DTE(0x00, IID(ADC, Gv_Ev)),        DTE(0x02, IID(ADC, al, imm8)),  DTE(0x05, IID(ADC, eax, imm32)), DTE(0xD6, IID_INVALID),         DTE(0xD6, IID_INVALID),         DTE(0x00, IID(SBB, Eb_Gb)),         DTE(0x00, IID(SBB, Ev_Gv)),       DTE(0x00, IID(SBB, Gb_Eb)),      DTE(0x00, IID(SBB, Gv_Ev)),      DTE(0x02, IID(SBB, al, imm8)),   DTE(0x05, IID(SBB, eax, imm32)), DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),
    /* 20 */ DTE(0x00, IID(AND, Eb_Gb)),      DTE(0x00, IID(AND, Ev_Gv)),        DTE(0x00, IID(AND, Gb_Eb)),       DTE(0x00, IID(AND, Gv_Ev)),        DTE(0x02, IID(AND, al, imm8)),  DTE(0x05, IID(AND, eax, imm32)), DTE(0x26, IID_INVALID),         DTE(0xD6, IID_INVALID),         DTE(0x00, IID(SUB, Eb_Gb)),         DTE(0x00, IID(SUB, Ev_Gv)),       DTE(0x00, IID(SUB, Gb_Eb)),      DTE(0x00, IID(SUB, Gv_Ev)),      DTE(0x02, IID(SUB, al, imm8)),   DTE(0x05, IID(SUB, eax, imm32)), DTE(0x2E, IID_INVALID),          DTE(0xD6, IID_INVALID),
    /* 30 */ DTE(0x00, IID(XOR, Eb_Gb)),      DTE(0x00, IID(XOR, Ev_Gv)),        DTE(0x00, IID(XOR, Gb_Eb)),       DTE(0x00, IID(XOR, Gv_Ev)),        DTE(0x02, IID(XOR, al, imm8)),  DTE(0x05, IID(XOR, eax, imm32)), DTE(0x36, IID_INVALID),         DTE(0xD6, IID_INVALID),         DTE(0x00, IID(CMP, Eb_Gb)),         DTE(0x00, IID(CMP, Ev_Gv)),       DTE(0x00, IID(CMP, Gb_Eb)),      DTE(0x00, IID(CMP, Gv_Ev)),      DTE(0x02, IID(CMP, al, imm8)),   DTE(0x05, IID(CMP, eax, imm32)), DTE(0x3E, IID_INVALID),          DTE(0xD6, IID_INVALID),
    /* 40 */ DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),            DTE(0xD6, IID_INVALID),           DTE(0xD6, IID_INVALID),            DTE(0xD6, IID_INVALID),         DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),         DTE(0xD6, IID_INVALID),         DTE(0xD6, IID_INVALID),             DTE(0xD6, IID_INVALID),           DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),
    /* 50 */ DTE(0x01, IID(PUSH, r64)),       DTE(0x01, IID(PUSH, r64)),         DTE(0x01, IID(PUSH, r64)),        DTE(0x01, IID(PUSH, r64)),         DTE(0x01, IID(PUSH, r64)),      DTE(0x01, IID(PUSH, r64)),       DTE(0x01, IID(PUSH, r64)),      DTE(0x01, IID(PUSH, r64)),      DTE(0x01, IID(POP, r64)),           DTE(0x01, IID(POP, r64)),         DTE(0x01, IID(POP, r64)),        DTE(0x01, IID(POP, r64)),        DTE(0x01, IID(POP, r64)),        DTE(0x01, IID(POP, r64)),        DTE(0x01, IID(POP, r64)),        DTE(0x01, IID(POP, r64)),
    /* 60 */ DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),            DTE(0xD6, IID_INVALID),           DTE(0x00, IID(MOVSXD, Gv_Ev)),     DTE(0x64, IID_INVALID),         DTE(0x65, IID_INVALID),          DTE(0x66, IID_INVALID),         DTE(0x67, IID_INVALID),         DTE(0x05, IID(PUSH, imm32)),        DTE(0xA4, IID(IMUL, Gv_Ev, imm32)), DTE(0x02, IID(PUSH, imm8)),      DTE(0xA1, IID(IMUL, Gv_Ev, imm8)), DTE(0x01, IID(INSB)),     DTE(0x01, IID(INSW)),     DTE(0x01, IID(OUTSB)),    DTE(0x01, IID(OUTSW)),
    /* 70 */ DTE(0x02, IID(JO, rel8)),        DTE(0x02, IID(JNO, rel8)),         DTE(0x02, IID(JB, rel8)),         DTE(0x02, IID(JAE, rel8)),         DTE(0x02, IID(JZ, rel8)),       DTE(0x02, IID(JNZ, rel8)),       DTE(0x02, IID(JBE, rel8)),      DTE(0x02, IID(JA, rel8)),       DTE(0x02, IID(JS, rel8)),           DTE(0x02, IID(JNS, rel8)),        DTE(0x02, IID(JP, rel8)),        DTE(0x02, IID(JNP, rel8)),       DTE(0x02, IID(JL, rel8)),        DTE(0x02, IID(JGE, rel8)),       DTE(0x02, IID(JLE, rel8)),       DTE(0x02, IID(JG, rel8)),
    /* 80 */ DTE(0xEE, IID_INVALID),          DTE(0xEE, IID_INVALID),            DTE(0xEE, IID_INVALID),           DTE(0xEE, IID_INVALID),            DTE(0x00, IID(TEST, Eb_Gb)),    DTE(0x00, IID(TEST, Ev_Gv)),     DTE(0x00, IID(XCHG, Eb_Gb)),    DTE(0x00, IID(XCHG, Ev_Gv)),    DTE(0x00, IID(MOV, Eb_Gb)),         DTE(0x00, IID(MOV, Ev_Gv)),       DTE(0x00, IID(MOV, Gb_Eb)),      DTE(0x00, IID(MOV, Gv_Ev)),      DTE(0xAC, IID(MOV, Ev_Sw)),      DTE(0x00, IID(LEA, Gv_M)),       DTE(0xAC, IID(MOV, Sw_Ev)),      DTE(0xEE, IID_INVALID),
    /* 90 */ DTE(0x01, IID(NOP)),             DTE(0x01, IID(XCHG, r64, rax)),    DTE(0x01, IID(XCHG, r64, rax)),   DTE(0x01, IID(XCHG, r64, rax)),    DTE(0x01, IID(XCHG, r64, rax)), DTE(0x01, IID(XCHG, r64, rax)),  DTE(0x01, IID(XCHG, r64, rax)), DTE(0x01, IID(XCHG, r64, rax)), DTE(0x01, IID(CWDE)),              DTE(0x01, IID(CDQ)),             DTE(0xD6, IID_INVALID),          DTE(0x01, IID(FWAIT)),    DTE(0x01, IID(PUSHFQ)),   DTE(0x01, IID(POPFQ)),    DTE(0x01, IID(SAHF)),     DTE(0x01, IID(LAHF)),
    /* A0 */ DTE(0x09, IID(MOV, al, moffs8)), DTE(0x09, IID(MOV, eax, moffs32)), DTE(0x09, IID(MOV, moffs8, al)),  DTE(0x09, IID(MOV, moffs32, eax)), DTE(0x01, IID(MOVSB)),   DTE(0x01, IID(MOVSD)),    DTE(0x01, IID(CMPSB)),   DTE(0x01, IID(CMPSD)),   DTE(0x02, IID(TEST, al, imm8)),     DTE(0x05, IID(TEST, eax, imm32)), DTE(0x01, IID(STOSB)),    DTE(0x01, IID(STOSD)),    DTE(0x01, IID(LODSB)),    DTE(0x01, IID(LODSD)),    DTE(0x01, IID(SCASB)),    DTE(0x01, IID(SCASD)),
    /* B0 */ DTE(0x02, IID(MOV, r8, imm8)),   DTE(0x02, IID(MOV, r8, imm8)),     DTE(0x02, IID(MOV, r8, imm8)),    DTE(0x02, IID(MOV, r8, imm8)),     DTE(0x02, IID(MOV, r8, imm8)),  DTE(0x02, IID(MOV, r8, imm8)),   DTE(0x02, IID(MOV, r8, imm8)),  DTE(0x02, IID(MOV, r8, imm8)),  DTE(0xB8, IID(MOV, r32, imm32)),    DTE(0xB8, IID(MOV, r32, imm32)),  DTE(0xB8, IID(MOV, r32, imm32)), DTE(0xB8, IID(MOV, r32, imm32)), DTE(0xB8, IID(MOV, r32, imm32)), DTE(0xB8, IID(MOV, r32, imm32)), DTE(0xB8, IID(MOV, r32, imm32)), DTE(0xB8, IID(MOV, r32, imm32)),
    /* C0 */ DTE(0xEE, IID_INVALID),          DTE(0xEE, IID_INVALID),            DTE(0x03, IID(RET, imm16)),       DTE(0x01, IID(RET)),              DTE(0x01, IID_INVALID),         DTE(0x01, IID_INVALID),          DTE(0xEE, IID_INVALID),         DTE(0xEE, IID_INVALID),         DTE(0x04, IID(ENTER, imm16, imm8)), DTE(0x01, IID(LEAVE)),      DTE(0x03, IID(RETF, imm16)),     DTE(0x01, IID(RETF)),     DTE(0x01, IID(INT3)),     DTE(0x02, IID(INT, imm8)),       DTE(0xD6, IID_INVALID),          DTE(0x01, IID(IRETD)),
    /* D0 */ DTE(0xEE, IID_INVALID),          DTE(0xEE, IID_INVALID),            DTE(0xEE, IID_INVALID),           DTE(0xEE, IID_INVALID),            DTE(0xD6, IID_INVALID),         DTE(0xD6, IID_INVALID),          DTE(0xD6, IID_INVALID),         DTE(0x01, IID(XLAT)),           DTE(0x87, IID_INVALID),             DTE(0x87, IID_INVALID),           DTE(0x87, IID_INVALID),          DTE(0x87, IID_INVALID),          DTE(0x87, IID_INVALID),          DTE(0x87, IID_INVALID),          DTE(0x87, IID_INVALID),          DTE(0x87, IID_INVALID),
    /* E0 */ DTE(0x02, IID(LOOPNE, rel8)),    DTE(0x02, IID(LOOPE, rel8)),       DTE(0x02, IID(LOOP, rel8)),       DTE(0x02, IID(JRCXZ, rel8)),       DTE(0x02, IID(IN, al, imm8)),   DTE(0x02, IID(IN, eax, imm8)),   DTE(0x02, IID(OUT, imm8, al)),  DTE(0x02, IID(OUT, imm8, eax)), DTE(0x05, IID(CALL, rel32)),        DTE(0x05, IID(JMP, rel32)),       DTE(0xD6, IID_INVALID),          DTE(0x02, IID(JMP, rel8)),       DTE(0x01, IID(IN, al, dx)),      DTE(0x01, IID(IN, eax, dx)),     DTE(0x01, IID(OUT, dx, al)),     DTE(0x01, IID(OUT, dx, eax)),
    /* F0 */ DTE(0xF0, IID_INVALID),          DTE(0x01, IID(INT1)),              DTE(0xF2, IID_INVALID),           DTE(0xF3, IID_INVALID),            DTE(0x01, IID(HLT)),            DTE(0x01, IID(CMC)),            DTE(0xEE, IID_INVALID),         DTE(0xEE, IID_INVALID),         DTE(0x01, IID(CLC)),               DTE(0x01, IID(STC)),             DTE(0x01, IID(CLI)),             DTE(0x01, IID(STI)),     DTE(0x01, IID(CLD)),      DTE(0x01, IID(STD)),      DTE(0xEE, IID_INVALID),          DTE(0xEE, IID_INVALID),
} };

static constexpr std::array<DecodeTableEntry, 256> kDecodeTable_2byte_opcode_shared{ {
    /*
       0xE1 = valid 0x0F opcode space but decode path is not implemented yet.
       0x56 = ModR/M follows; dest = r32 modified by REX.W/66h, src fixed at byte (m8 or r8).
       0x57 = ModR/M follows; dest = r32 modified by REX.W/66h, src fixed at word (m16 or r16).
       0x58 = ModR/M follows; single Eb operand (m8 or r8), prefix size has no operand effect.
       0x59 = direct 2-byte opcode with register operand that is upgraded by REX.W only.
       0x5A = ModR/M follows; valid only for /0, decoded as multibyte NOP.
       0x5B = ModR/M follows; Ev/Gv resolved via table, trailing imm8 follows.
       0x5C = ModR/M follows; Ev/Gv resolved via table, implicit CL operand.
       0x5D = 0F AE group dispatch.
       0x5E = 0F 00 group dispatch.
       0x5F = 0F 01 group dispatch.
       0x60 = 0F 20-23 MOV to/from control/debug registers.
       0x61 = 0F C7 group 9.
       0x62 = 0F 18 group 16.
       0x63 = 0F opcode-extension dispatch (currently 0F BA).
       0x64 = 0F C3 /r MOVNTI.
       0x65 = minimal SIMD ModR/M path.
       0x66 = SIMD arithmetic families with prefix remap.
    */
    /*       0                                    1                                 2                                 3                              4                                    5                                 6                                 7                                 8                              9                                    A                                 B                              C                                    D                                 E                                 F                              */
    /* 00 */ DTE(0x5E, IID_INVALID),        DTE(0x5F, IID_INVALID),        DTE(0x57, IID(LAR, r32, r16)), DTE(0x57, IID(LSL, r32, r16)), DTE(0xE1, IID_INVALID),        DTE(0x02, IID(SYSCALL)), DTE(0x02, IID(CLTS)),    DTE(0x02, IID(SYSRET)),  DTE(0x02, IID(INVD)),    DTE(0x02, IID(WBINVD)),  DTE(0xE1, IID_INVALID),        DTE(0x02, IID(UD)),      DTE(0xE1, IID_INVALID),        DTE(0x62, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),
    /* 10 */ DTE(0x65, IID(MOVUPS)),        DTE(0x65, IID(MOVUPS)),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x62, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x62, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x62, IID_INVALID),        DTE(0x5A, IID(NOP)),
    /* 20 */ DTE(0x60, IID(MOV, r64, creg)), DTE(0x60, IID(MOV, r64, dr)),   DTE(0x60, IID(MOV, creg, r64)), DTE(0x60, IID(MOV, dr, r64)),   DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x65, IID(MOVAPS)),        DTE(0x65, IID(MOVAPS)),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x65, IID(UCOMISS)),       DTE(0x65, IID(COMISS)),
    /* 30 */ DTE(0x02, IID(WRMSR)),         DTE(0x02, IID(RDTSC)),          DTE(0x02, IID(RDMSR)),          DTE(0x02, IID(RDPMC)),          DTE(0x02, IID(SYSENTER)),       DTE(0x02, IID(SYSEXIT)),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),
    /* 40 */ DTE(0x00, IID(CMOVO, Gv_Ev)),  DTE(0x00, IID(CMOVNO, Gv_Ev)), DTE(0x00, IID(CMOVB, Gv_Ev)),  DTE(0x00, IID(CMOVAE, Gv_Ev)), DTE(0x00, IID(CMOVZ, Gv_Ev)),  DTE(0x00, IID(CMOVNZ, Gv_Ev)), DTE(0x00, IID(CMOVBE, Gv_Ev)), DTE(0x00, IID(CMOVA,  Gv_Ev)), DTE(0x00, IID(CMOVS,  Gv_Ev)), DTE(0x00, IID(CMOVNS, Gv_Ev)), DTE(0x00, IID(CMOVP,  Gv_Ev)), DTE(0x00, IID(CMOVNP, Gv_Ev)), DTE(0x00, IID(CMOVL,  Gv_Ev)), DTE(0x00, IID(CMOVGE, Gv_Ev)), DTE(0x00, IID(CMOVLE, Gv_Ev)), DTE(0x00, IID(CMOVG,  Gv_Ev)),
    /* 50 */ DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x66, IID(ADDPS)),         DTE(0x66, IID(MULPS)),         DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x66, IID(SUBPS)),         DTE(0xE1, IID_INVALID),        DTE(0x66, IID(DIVPS)),         DTE(0xE1, IID_INVALID),
    /* 60 */ DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),
    /* 70 */ DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x02, IID(EMMS)),          DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),
    /* 80 */ DTE(0x06, IID(JO, rel32)),     DTE(0x06, IID(JNO, rel32)),    DTE(0x06, IID(JB, rel32)),     DTE(0x06, IID(JAE, rel32)),    DTE(0x06, IID(JZ, rel32)),     DTE(0x06, IID(JNZ, rel32)),    DTE(0x06, IID(JBE, rel32)),    DTE(0x06, IID(JA,  rel32)),    DTE(0x06, IID(JS,  rel32)),    DTE(0x06, IID(JNS, rel32)),    DTE(0x06, IID(JP,  rel32)),    DTE(0x06, IID(JNP, rel32)),    DTE(0x06, IID(JL,  rel32)),    DTE(0x06, IID(JGE, rel32)),    DTE(0x06, IID(JLE, rel32)),    DTE(0x06, IID(JG,  rel32)),
    /* 90 */ DTE(0x58, IID(SETO, r8)),      DTE(0x58, IID(SETNO, r8)),     DTE(0x58, IID(SETB, r8)),      DTE(0x58, IID(SETAE, r8)),     DTE(0x58, IID(SETZ, r8)),      DTE(0x58, IID(SETNZ, r8)),     DTE(0x58, IID(SETBE, r8)),     DTE(0x58, IID(SETA, r8)),      DTE(0x58, IID(SETS, r8)),      DTE(0x58, IID(SETNS, r8)),     DTE(0x58, IID(SETP, r8)),      DTE(0x58, IID(SETNP, r8)),     DTE(0x58, IID(SETL, r8)),      DTE(0x58, IID(SETGE, r8)),     DTE(0x58, IID(SETLE, r8)),     DTE(0x58, IID(SETG, r8)),
    /* A0 */ DTE(0x02, IID(PUSH, fs)),      DTE(0x02, IID(POP, fs)),       DTE(0x02, IID(CPUID, noopr)),  DTE(0x00, IID(BT, Ev_Gv)),     DTE(0x5B, IID(SHLD, Ev_Gv, imm8)), DTE(0x5C, IID(SHLD, Ev_Gv, cl)), DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x02, IID(PUSH, gs)),      DTE(0x02, IID(POP, gs)),       DTE(0x02, IID(RSM)),           DTE(0x00, IID(BTS, Ev_Gv)),    DTE(0x5B, IID(SHRD, Ev_Gv, imm8)), DTE(0x5C, IID(SHRD, Ev_Gv, cl)), DTE(0x5D, IID_INVALID),        DTE(0x00, IID(IMUL, Gv_Ev)),
    /* B0 */ DTE(0x00, IID(CMPXCHG, Eb_Gb)), DTE(0x00, IID(CMPXCHG, Ev_Gv)), DTE(0x00, IID(LSS, Gv_M)),     DTE(0x00, IID(BTR, Ev_Gv)),    DTE(0x00, IID(LFS, Gv_M)),     DTE(0x00, IID(LGS, Gv_M)),     DTE(0x56, IID(MOVZX, r32, r8)), DTE(0x57, IID(MOVZX, r32, r16)), DTE(0x00, IID(POPCNT, Gv_Ev)), DTE(0xE1, IID_INVALID),        DTE(0x63, IID_INVALID),        DTE(0x00, IID(BTC, Ev_Gv)),    DTE(0x00, IID(BSF, Gv_Ev)),    DTE(0x00, IID(BSR, Gv_Ev)),    DTE(0x56, IID(MOVSX, r32, r8)), DTE(0x57, IID(MOVSX, r32, r16)),
    /* C0 */ DTE(0x00, IID(XADD, Eb_Gb)),    DTE(0x00, IID(XADD, Ev_Gv)),    DTE(0xE1, IID_INVALID),        DTE(0x64, IID(MOVNTI, m32, r32)), DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0x61, IID_INVALID),        DTE(0x59, IID(BSWAP, r32)),    DTE(0x59, IID(BSWAP, r32)),    DTE(0x59, IID(BSWAP, r32)),    DTE(0x59, IID(BSWAP, r32)),    DTE(0x59, IID(BSWAP, r32)),    DTE(0x59, IID(BSWAP, r32)),    DTE(0x59, IID(BSWAP, r32)),    DTE(0x59, IID(BSWAP, r32)),
    /* D0 */ DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),
    /* E0 */ DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),
    /* F0 */ DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xE1, IID_INVALID),        DTE(0xD6, IID_INVALID),
} };

} // namespace detail

} // namespace xendiza

#endif // XENDIZA_COMMON_HPP

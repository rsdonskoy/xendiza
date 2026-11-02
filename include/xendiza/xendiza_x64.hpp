#ifndef XENDIZA_X64_HPP
#define XENDIZA_X64_HPP

#include "detail/xendiza_common.hpp"
#include <bit>
#include <gsl/span>


namespace xendiza::detail {

enum class Prefix : uint8_t {
    // Legacy prefixes
    LOCK = 0xF0,                   // Lock prefix
    REPNE = 0xF2,                  // REPNE/REPNZ prefix
    REPE = 0xF3,                   // REP/REPE/REPZ prefix

    // Segment override prefixes
    CS_SEG = 0x2E,            // CS segment override
    SS_SEG = 0x36,            // SS segment override
    DS_SEG = 0x3E,            // DS segment override
    ES_SEG = 0x26,            // ES segment override
    FS_SEG = 0x64,            // FS segment override
    GS_SEG = 0x65,            // GS segment override

    // Operand/Address size overrides
    OPR_SIZE = 0x66,   // 16-bit operand size in 32/64-bit mode
    ADDR_SIZE = 0x67,   // Address size override

    // REX prefixes (0x40-0x4F in 64-bit mode)
    REX_BASE = 0x40,               // Base REX prefix
    REX_B = 0x41,                  // REX.B (Extension of ModR/M r/m field)
    REX_X = 0x42,                  // REX.X (Extension of SIB index field)
    REX_XB = 0x43,                 // REX.X + REX.B
    REX_R = 0x44,                  // REX.R (Extension of ModR/M reg field)
    REX_RB = 0x45,                 // REX.R + REX.B
    REX_RX = 0x46,                 // REX.R + REX.X
    REX_RXB = 0x47,                // REX.R + REX.X + REX.B
    REX_W = 0x48,                  // REX.W (64-bit operand size)
    REX_WB = 0x49,                 // REX.W + REX.B
    REX_WX = 0x4A,                 // REX.W + REX.X
    REX_WXB = 0x4B,                // REX.W + REX.X + REX.B
    REX_WR = 0x4C,                 // REX.W + REX.R
    REX_WRB = 0x4D,                // REX.W + REX.R + REX.B
    REX_WRX = 0x4E,                // REX.W + REX.R + REX.X
    REX_WRXB = 0x4F,               // REX.W + REX.R + REX.X + REX.B (all bits set)

    // Two-byte and three-byte opcode prefixes
    OPC_2BYTE = 0x0F,              // Two-byte opcode prefix

    // VEX/EVEX prefixes (for AVX/AVX2/AVX-512)
    VEX_2BYTE = 0xC5,              // 2-byte VEX prefix
    VEX_3BYTE = 0xC4,              // 3-byte VEX prefix
    EVEX = 0x62,                   // EVEX prefix (AVX-512)

    // Special values
    NONE = 0xFE,                   // No prefix
    INVALID = 0xFF                 // Invalid prefix
};

struct HasPrefix {
    uint8_t has_66 : 1;           // 0x66 prefix
    uint8_t has_67 : 1;           // 0x67 prefix
    uint8_t has_seg : 1;          // Segment override present
    uint8_t has_rex : 1;          // REX prefix present
    uint8_t has_lock : 1;         // 0xF0 prefix
    uint8_t has_rep : 1;          // 0xF2/0xF3 prefix
    uint8_t reserved : 2;         // Reserved bits for future use

    // Implicit conversion to bool - true if any prefixes are present
    explicit operator bool() const noexcept
    {
        return std::bit_cast<const uint8_t>(*this) != 0;
    }

    // Check for overriding prefixes only (excluding LOCK and REP)
    [[nodiscard]] bool HasOverriding() const noexcept
    {
        constexpr uint8_t kOverridingMask = 0x0F; // bits 0-3: has_66, has_67, has_seg, has_rex
        return (std::bit_cast<const uint8_t>(*this) & kOverridingMask) != 0;
    }
};

struct PrefixInfo {
    uint8_t length = 0;           // Total length of all prefixes
    HasPrefix has_prefix{};       // Packed prefix flags (1 byte)
    uint8_t rex_byte = 0;         // REX prefix value (0 if none)
    uint8_t seg_byte = 0;         // Segment override byte (0 if none)
    uint8_t rep_byte = 0;         // REP prefix byte (0 if none)

    // REX bit accessors
    [[nodiscard]] constexpr bool rex_w() const noexcept { return (rex_byte & 0x08) != 0; }
    [[nodiscard]] constexpr bool rex_r() const noexcept { return (rex_byte & 0x04) != 0; }
    [[nodiscard]] constexpr bool rex_x() const noexcept { return (rex_byte & 0x02) != 0; }
    [[nodiscard]] constexpr bool rex_b() const noexcept { return (rex_byte & 0x01) != 0; }
};

class X64Traits {
    friend class X86Traits;

    static constexpr std::array<Prefix, 256> kPrefixTable = { {
        /*      0                 1              2              3               4                  5                  6                 7                  8              9               A               B                C               D                E                F                 */
        /* 0 */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::OPC_2BYTE,
        /* 1 */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* 2 */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::ES_SEG,   Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::CS_SEG,  Prefix::NONE,
        /* 3 */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::SS_SEG,   Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::DS_SEG,  Prefix::NONE,
        /* 4 */ Prefix::REX_BASE, Prefix::REX_B, Prefix::REX_X, Prefix::REX_XB, Prefix::REX_R,     Prefix::REX_RB,    Prefix::REX_RX,   Prefix::REX_RXB,   Prefix::REX_W, Prefix::REX_WB, Prefix::REX_WX, Prefix::REX_WXB, Prefix::REX_WR, Prefix::REX_WRB, Prefix::REX_WRX, Prefix::REX_WRXB,
        /* 5 */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* 6 */ Prefix::NONE,     Prefix::NONE,  Prefix::EVEX,  Prefix::NONE,   Prefix::FS_SEG,    Prefix::GS_SEG,    Prefix::OPR_SIZE, Prefix::ADDR_SIZE, Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* 7 */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* 8 */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* 9 */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* A */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* B */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* C */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::VEX_3BYTE, Prefix::VEX_2BYTE, Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* D */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* E */ Prefix::NONE,     Prefix::NONE,  Prefix::NONE,  Prefix::NONE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE,
        /* F */ Prefix::LOCK,     Prefix::NONE,  Prefix::REPNE, Prefix::REPE,   Prefix::NONE,      Prefix::NONE,      Prefix::NONE,     Prefix::NONE,      Prefix::NONE,  Prefix::NONE,   Prefix::NONE,   Prefix::NONE,    Prefix::NONE,   Prefix::NONE,    Prefix::NONE,    Prefix::NONE
    } };

    // Reuse shared decode tables from xendiza_common.hpp to avoid x64/x86 duplication.
    static constexpr const std::array<DecodeTableEntry, 256>& kDecodeTable_1byte_opcode =
        kDecodeTable_1byte_opcode_shared;
    static constexpr const std::array<DecodeTableEntry, 256>& kDecodeTable_2byte_opcode =
        kDecodeTable_2byte_opcode_shared;

    static inline auto ProcessPrefix(gsl::span<const uint8_t> buffer) noexcept -> std::pair<PrefixInfo, ErrorCode>;
    static auto Decode2ByteOpcode(const PrefixInfo& prefix_info, gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction;
    // 1-byte opcode decode core, shared by the fast leaf dispatcher and the
    // prefix-parsing slow path. Must stay free of calls (besides the cold
    // 0x0F tail) so the no-prefix hot path compiles to a leaf function.
    static auto Decode1Byte(const PrefixInfo& prefix_info, gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction;
    static auto DecodeInstructionSlowPath(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction;
    static auto DecodeInstruction(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction;

public:

    static auto Disasm(gsl::span<const uint8_t> buffer) noexcept -> DecodedInstruction;
};

} // namespace xendiza::detail

#endif // XENDIZA_X64_HPP

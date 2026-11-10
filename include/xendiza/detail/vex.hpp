#ifndef XENDIZA_VEX_HPP
#define XENDIZA_VEX_HPP

#include "instruction.hpp"

#include <gsl/span>
#include <utility>

namespace xendiza::detail {

enum class VexStatus : uint8_t {
    NotVex,      // Byte sequence is not a VEX prefix; use legacy path.
    NeedMore,    // Insufficient bytes to decide VEX vs legacy (32-bit C4/C5).
    Valid,       // Recognized VEX prefix.
    Invalid,     // Disallowed prefix combination; undefined instruction.
};

struct VexInfo {
    uint8_t prefix_length = 0; // Length of permitted legacy prefixes before VEX.
    uint8_t vex_length = 0;    // 2 for C5, 3 for C4.
    uint8_t map = 0;           // VEX map: 0x01 (0F), 0x02 (0F38), 0x03 (0F3A).
    uint8_t pp = 0;            // 0=none, 1=66, 2=F3, 4=F2 (raw VEX.pp).
    uint8_t L = 0;             // 0=128-bit, 1=256-bit.
    uint8_t W = 0;             // REX.W analog.
    uint8_t vvvv = 0;          // Inverted source register specifier.
    bool R = false;            // Inverted R extension bit.
    bool X = false;            // Inverted X extension bit.
    bool B = false;            // Inverted B extension bit.
    bool is_64bit = false;     // Decoding mode, independent of address size.
    uint8_t addr_size = 0;     // Effective address size in bits (16/32/64).
    uint8_t opcode_offset = 0; // Offset of opcode byte within buffer.
};

// Mode-aware VEX recognizer.  In 64-bit mode any C4/C5 after permitted prefixes
// is a VEX candidate.  In 32-bit mode C4/C5 requires the second byte to have
// mod=11; otherwise NotVex is returned so the original buffer can use the
// legacy path.  A lone C4/C5 in 32-bit mode returns NeedMore.
struct VexRecognizer {
    static auto Recognize(gsl::span<const uint8_t> buffer, bool is_64bit, uint8_t default_addr_size) noexcept
        -> std::pair<VexStatus, VexInfo>;
};

} // namespace xendiza::detail

#endif // XENDIZA_VEX_HPP

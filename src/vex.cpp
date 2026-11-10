#include "xendiza/detail/vex.hpp"

namespace xendiza::detail {

auto VexRecognizer::Recognize(gsl::span<const uint8_t> buffer, const bool is_64bit, const uint8_t default_addr_size) noexcept
    -> std::pair<VexStatus, VexInfo>
{
    VexInfo info{};
    info.is_64bit = is_64bit;
    info.addr_size = default_addr_size;

    // Scan the prefix chain that may appear before a VEX candidate:
    //   permitted:  67h, segment overrides
    //   disallowed: 66h, F0h, F2h, F3h (only an error if followed by C4/C5)
    //   terminator: REX (x64 only), any other non-prefix byte
    bool has_disallowed_prefix = false;
    size_t i = 0;
    while (i < buffer.size()) {
        const uint8_t b = buffer[i];
        if (b == 0x67) {
            info.addr_size = (default_addr_size == 64) ? 32 : ((default_addr_size == 32) ? 16 : 32);
            ++i;
            continue;
        }
        if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            ++i;
            continue;
        }
        if (b == 0x66 || b == 0xF0 || b == 0xF2 || b == 0xF3) {
            has_disallowed_prefix = true;
            ++i;
            continue;
        }
        break;
    }

    info.prefix_length = static_cast<uint8_t>(i);

    // The whole buffer consists of prefixes with no opcode/VEX candidate:
    // hand back to the legacy path so its all-prefix error semantics apply.
    if (i >= buffer.size()) {
        return { VexStatus::NotVex, info };
    }

    // In x64 mode, a REX byte immediately before a VEX candidate is undefined.
    // Do not consume the REX byte; the legacy path still needs to see it for
    // ordinary REX-prefixed instructions.
    if (is_64bit && buffer[i] >= 0x40 && buffer[i] <= 0x4F) {
        if (i + 1 < buffer.size()) {
            const uint8_t after_rex = buffer[i + 1];
            if (after_rex == 0xC4 || after_rex == 0xC5) {
                return { VexStatus::Invalid, info };
            }
        }
        return { VexStatus::NotVex, info };
    }

    const uint8_t first = buffer[i];

    if (first != 0xC4 && first != 0xC5) {
        return { VexStatus::NotVex, info };
    }

    // A disallowed prefix followed by a VEX candidate is undefined.
    if (has_disallowed_prefix) {
        return { VexStatus::Invalid, info };
    }

    // Need at least the byte after C4/C5 to decide anything.
    if (i + 1 >= buffer.size()) {
        return { VexStatus::NeedMore, info };
    }

    const uint8_t second = buffer[i + 1];

    if (!is_64bit) {
        // In 32-bit mode C4/C5 with mod!=11 in the second byte is LES/LDS.
        if ((second & 0b11000000) != 0b11000000) {
            return { VexStatus::NotVex, info };
        }
    }

    if (first == 0xC5) {
        info.vex_length = 2;
        info.map = 0x01; // 0F
        info.pp = second & 0x03;
        info.L = (second >> 2) & 0x01;
        info.vvvv = (second >> 3) & 0x0F;
        info.R = (second & 0x80) != 0;
        info.W = 0;
        info.opcode_offset = static_cast<uint8_t>(i + 2);
    } else {
        // C4 three-byte VEX.
        if (i + 2 >= buffer.size()) {
            return { VexStatus::NeedMore, info };
        }
        const uint8_t third = buffer[i + 2];
        info.vex_length = 3;
        info.map = second & 0x1F;
        if (info.map == 0) {
            return { VexStatus::Invalid, info };
        }
        info.R = (second & 0x80) != 0;
        info.X = (second & 0x40) != 0;
        info.B = (second & 0x20) != 0;
        info.W = (third >> 7) & 0x01;
        info.vvvv = (third >> 3) & 0x0F;
        info.L = (third >> 2) & 0x01;
        info.pp = third & 0x03;
        info.opcode_offset = static_cast<uint8_t>(i + 3);
    }

    return { VexStatus::Valid, info };
}

} // namespace xendiza::detail

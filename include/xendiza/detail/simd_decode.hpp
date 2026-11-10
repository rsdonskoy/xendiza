#ifndef XENDIZA_SIMD_DECODE_HPP
#define XENDIZA_SIMD_DECODE_HPP

#include "simd.hpp"

#include <gsl/span>

namespace xendiza::detail {

// Shared SIMD (legacy SSE/SSE2/SSSE3/SSE4.x) decode engine entry points, used
// by both the x64 and x86 Decode2ByteOpcode paths. The descriptor schema and
// tables live in simd.hpp; the engine definitions and their internal helpers
// live in src/simd_decode.cpp and are explicitly instantiated for PrefixInfo
// (x64) and PrefixInfo32 (x86).
//
// `rex_w` is false in 32-bit mode (no REX prefixes there); `addr16` is true
// for the 32-bit path under a 67h prefix (16-bit addressing: no SIB byte,
// disp16 where the 32-bit form has none).
template <typename PrefixInfoT>
auto DecodeSimd2Byte(const PrefixInfoT& prefix_info, const gsl::span<const uint8_t> buffer,
                     const uint8_t opcode2, const bool rex_w, const bool addr16 = false) noexcept
    -> DecodedInstruction;

template <typename PrefixInfoT>
auto Dispatch3ByteOpcode(const PrefixInfoT& prefix_info, const gsl::span<const uint8_t> buffer,
                         const uint8_t opcode2, const bool rex_w, const bool addr16 = false) noexcept
    -> DecodedInstruction;

} // namespace xendiza::detail

#endif // XENDIZA_SIMD_DECODE_HPP

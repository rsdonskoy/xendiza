#ifndef INSTRUCTION_HPP
#define INSTRUCTION_HPP

#include "opcode_id.hpp"

namespace xendiza {

constexpr size_t MAX_INSTRUCTION_LENGTH = 0x0F; // Maximum instruction length in x86/x64

enum class Operand : uint16_t {
    noopr = 0x0000, // No operand

    Eb_Gb = 1,    // Memory to 8-bit register
    Ev_Gv = 2,    // Memory to 32-bit register
    Gb_Eb = 3,    // 8-bit register to Memory
    Gv_Ev = 4,    // 32-bit register to Memory
    Gv_Ev_Iz = 5, // 32-bit register to Memory with immediate
    Ev_Sw = 6,    // Segment register to Memory/Register
    Sw_Ev = 7,    // Memory/Register to Segment register
    Gv_M = 8,     // Memory to register

    // SIB-dispatch markers (not real operands): a table entry whose ModR/M
    // selects a SIB byte (mod!=11, rm=100) carries one of these instead of a
    // memory operand. The decode dispatch reads the SIB byte and resolves it
    // to a plain m*/stack_m* via kSibStackForm_*. _b = byte form, _v = 16/32/64.
    Sib_Mb = 9,
    Sib_Mv = 10,
    Sib_Mw = 11,  // 16-bit (intrinsic, e.g. MOV Sreg sources)

    // specific 8-bit registers
    al,    // AL register
    cl,    // CL register
    dl,    // DL register
    bl,    // BL register
    ah,    // AH register
    ch,    // CH register
    dh,    // DH register
    bh,    // BH register
    spl,   // SPL register
    bpl,   // BPL register
    sil,   // SIL register
    dil,   // DIL register
    r8b,   // R8B register
    r9b,   // R9B register
    r10b,  // R10B register
    r11b,  // R11B register
    r12b,  // R12B register
    r13b,  // R13B register
    r14b,  // R14B register
    r15b,  // R15B register

    // specific 16-bit registers
    ax,    // AX register
    cx,    // CX register
    dx,    // DX register
    bx,    // BX register
    sp,    // SP register
    bp,    // BP register
    si,    // SI register
    di,    // DI register
    r8w,   // R8W register
    r9w,   // R9W register
    r10w,  // R10W register
    r11w,  // R11W register
    r12w,  // R12W register
    r13w,  // R13W register
    r14w,  // R14W register
    r15w,  // R15W register

    // specific 32-bit registers
    eax,   // EAX register
    ecx,   // ECX register
    edx,   // EDX register
    ebx,   // EBX register
    esp,   // ESP register
    ebp,   // EBP register
    esi,   // ESI register
    edi,   // EDI register
    r8d,   // R8D register
    r9d,   // R9D register
    r10d,  // R10D register
    r11d,  // R11D register
    r12d,  // R12D register
    r13d,  // R13D register
    r14d,  // R14D register
    r15d,  // R15D register

    // specific 64-bit registers
    rax,   // RAX register
    rcx,   // RCX register
    rdx,   // RDX register
    rbx,   // RBX register
    rsp,   // RSP register
    rbp,   // RBP register
    rsi,   // RSI register
    rdi,   // RDI register
    r8_reg,    // R8 register
    r9_reg,    // R9 register
    r10_reg,   // R10 register
    r11_reg,   // R11 register
    r12_reg,   // R12 register
    r13_reg,   // R13 register
    r14_reg,   // R14 register
    r15_reg,   // R15 register

    // generic operand types

    rel8,   // 8-bit relative offset
    rel16,  // 16-bit relative offset
    rel32,  // 32-bit relative offset

    ptr16_16, // 16:16 far pointer
    ptr16_32, // 16:32 far pointer

    r8,    // 8-bit register
    r16,   // 16-bit register
    r32,   // 32-bit register
    r64,   // 64-bit register
    xmm,   // XMM register (abstract, no concrete register number mapping)
    st0,   // x87 stack top register
    sti,   // x87 stack register ST(i), abstract index

    lit1,  // literal 1 (for instructions like ROL m8, 1)

    imm8,   // 8-bit immediate
    imm16,  // 16-bit immediate
    imm32,  // 32-bit immediate
    imm64,  // 64-bit immediate

    rm8,  // 8-bit register or memory
    rm16, // 16-bit register or memory
    rm32, // 32-bit register or memory
    rm64, // 64-bit register or memory

    m,     // A 16-, 32- or 64-bit operand in memory
    m8,    // 8-bit memory
    m16,   // 16-bit memory
    m32,   // 32-bit memory
    m64,   // 64-bit memory
    m128,  // 128-bit memory
    m32fp, // 32-bit floating-point memory
    m64fp, // 64-bit floating-point memory
    m80fp, // 80-bit floating-point/BCD memory

    stack_m8,   // 8-bit memory on stack (effective-address base = RSP/ESP)
    stack_m16,  // 16-bit memory on stack
    stack_m32,  // 32-bit memory on stack
    stack_m64,  // 64-bit memory on stack

    moffs8,   // 8-bit offset from DS
    moffs16,  // 16-bit offset from DS
    moffs32,  // 32-bit offset from DS
    moffs64,  // 64-bit offset from DS

    m16_32, // 16:32 memory
    m16_64, // 16:64 memory

    sreg,
    es,    // ES segment register
    cs,    // CS segment register
    ss,    // SS segment register
    ds,    // DS segment register
    fs,    // FS segment register
    gs,    // GS segment register

    // Composite segment-prefixed memory operands (segment override + memory kind).
    // Used in-place of the original memory operand when a segment prefix is present.
    // x64: only fs/gs variants are emitted.
    // x86: all six segment overrides are emitted.
    es_m8, cs_m8, ss_m8, ds_m8, fs_m8, gs_m8,
    es_m16, cs_m16, ss_m16, ds_m16, fs_m16, gs_m16,
    es_m32, cs_m32, ss_m32, ds_m32, fs_m32, gs_m32,
    es_m64, cs_m64, ss_m64, ds_m64, fs_m64, gs_m64,
    es_moffs8, cs_moffs8, ss_moffs8, ds_moffs8, fs_moffs8, gs_moffs8,
    es_moffs16, cs_moffs16, ss_moffs16, ds_moffs16, fs_moffs16, gs_moffs16,
    es_moffs32, cs_moffs32, ss_moffs32, ds_moffs32, fs_moffs32, gs_moffs32,
    es_moffs64, cs_moffs64, ss_moffs64, ds_moffs64, fs_moffs64, gs_moffs64,

    creg,  // Control register
    cr0,   // CR0 control register
    cr2,   // CR2 control register
    cr3,   // CR3 control register
    cr4,   // CR4 control register
    dr,    // Debug register
    dr0,   // DR0 debug register
    dr1,   // DR1 debug register
    dr2,   // DR2 debug register
    dr3,   // DR3 debug register
    dr6,   // DR6 debug register
    dr7,   // DR7 debug register

    // AVX/AVX2 abstract vector operands appended at the end to preserve the
    // numeric values of all pre-existing Operand identifiers.
    ymm,   // YMM register (abstract, no concrete register number mapping)
    m256,  // 256-bit memory operand
    m32_vsib,  // VSIB vector-indexed 32-bit memory (gather)
    m64_vsib,  // VSIB vector-indexed 64-bit memory (gather)
    m128_vsib, // VSIB vector-indexed 128-bit memory
    m256_vsib, // VSIB vector-indexed 256-bit memory

    invalid = 0xFFFF // Invalid operand
};

enum class ModRmForm : uint8_t {
    Eb_Gb = 0,    // Memory to 8-bit register
    Ev_Gv = 1,    // Memory to 32-bit register
    Gb_Eb = 2,    // 8-bit register to Memory
    Gv_Ev = 3,    // 32-bit register to Memory
    Gv_Ev_Iz = 4, // 32-bit register to Memory with immediate
    Ev_Sw = 5,    // Segment register to Memory/Register
    Sw_Ev = 6,    // Memory/Register to Segment register
    Gv_M = 7,     // Memory to register
    None  = 0xFF,    // No ModRM byte
};

enum class ImmForm : uint8_t {
    None = 0, // No immediate
    Ib = 1,
    Iw = 2,
    Iz = 4,
};

} // namespace xendiza

#endif // INSTRUCTION_HPP

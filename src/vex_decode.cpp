#include "xendiza/detail/vex_decode.hpp"

#include "xendiza/detail/xendiza_common.hpp"

#include <cstring>
#include <tuple>
#include <utility>

namespace xendiza::detail {

namespace {

constexpr auto kNoOperands = std::array<Operand, 4>{ Operand::noopr, Operand::noopr, Operand::noopr, Operand::noopr };

constexpr auto Oprs(Operand a, Operand b = Operand::noopr, Operand c = Operand::noopr,
                    Operand d = Operand::noopr) noexcept -> std::array<Operand, 4>
{
    return { a, b, c, d };
}

constexpr auto Form(OpcodeId op, uint8_t n, std::array<Operand, 4> ops,
                    VexModrmShape shape, uint8_t trailing = 0,
                    VexTrailingRole role = VexTrailingRole::None,
                    std::array<Operand, 4> mem_ops = kNoOperands,
                    uint8_t mem_n = 0) noexcept -> VexOpForm
{
    if (mem_n == 0) {
        mem_ops = ops;
        mem_n = n;
    }
    return { op, n, ops, mem_ops, mem_n, shape, trailing, role };
}

constexpr auto MakeDescriptor(const VexOpForm& form) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x01; // L=0 only by default
    d.allowed_W = 0x03; // WIG by default
    d.forms_by_L[0] = form;
    return d;
}

constexpr auto MakeDescriptorL0L1(const VexOpForm& l0, const VexOpForm& l1) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L=0 and L=1
    d.allowed_W = 0x03; // WIG
    d.forms_by_L[0] = l0;
    d.forms_by_L[1] = l1;
    return d;
}

constexpr auto MakeDescriptorL1(const VexOpForm& l1) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x02; // L=1 only
    d.allowed_W = 0x03; // WIG
    d.forms_by_L[1] = l1;
    return d;
}

constexpr auto MakeNdsDescriptor(OpcodeId op, Operand mem_l0, Operand mem_l1,
                                 bool packed) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L0/L1; scalar forms are LIG and reuse L0 operands.
    d.allowed_W = 0x03;
    d.vvvv_required = true;

    const auto reg_l0 = Oprs(Operand::xmm, Operand::xmm, Operand::xmm);
    const auto mem0 = Oprs(Operand::xmm, Operand::xmm, mem_l0);
    d.forms_by_L[0] = Form(op, 3, reg_l0, VexModrmShape::Both, 0, VexTrailingRole::None, mem0, 3);

    if (packed) {
        const auto reg_l1 = Oprs(Operand::ymm, Operand::ymm, Operand::ymm);
        const auto mem1 = Oprs(Operand::ymm, Operand::ymm, mem_l1);
        d.forms_by_L[1] = Form(op, 3, reg_l1, VexModrmShape::Both, 0, VexTrailingRole::None, mem1, 3);
    }
    return d;
}

constexpr auto MakeNdsImmDescriptor(OpcodeId op, Operand mem_l0, Operand mem_l1,
                                    bool packed) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L0/L1; scalar forms are LIG and reuse L0 operands.
    d.allowed_W = 0x03;
    d.vvvv_required = true;

    const auto reg_l0 = Oprs(Operand::xmm, Operand::xmm, Operand::xmm, Operand::imm8);
    const auto mem0 = Oprs(Operand::xmm, Operand::xmm, mem_l0, Operand::imm8);
    d.forms_by_L[0] = Form(op, 4, reg_l0, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem0, 4);

    if (packed) {
        const auto reg_l1 = Oprs(Operand::ymm, Operand::ymm, Operand::ymm, Operand::imm8);
        const auto mem1 = Oprs(Operand::ymm, Operand::ymm, mem_l1, Operand::imm8);
        d.forms_by_L[1] = Form(op, 4, reg_l1, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem1, 4);
    }
    return d;
}

constexpr auto MakeNoNdsStoreDescriptor(OpcodeId op, Operand mem_op_l0, Operand mem_op_l1) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L=0 and L=1
    d.allowed_W = 0x03; // WIG
    d.vvvv_reserved = true;

    const auto mem0 = Oprs(mem_op_l0, Operand::xmm);
    d.forms_by_L[0] = Form(op, 2, mem0, VexModrmShape::Mem);

    const auto mem1 = Oprs(mem_op_l1, Operand::ymm);
    d.forms_by_L[1] = Form(op, 2, mem1, VexModrmShape::Mem);
    return d;
}

constexpr auto MakeNoNdsMoveDescriptor(OpcodeId op, bool packed, bool is_load, Operand scalar_mem = Operand::m32) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L0/L1; scalar forms are LIG and reuse L0 operands.
    d.allowed_W = 0x03;

    if (packed) {
        if (is_load) {
            // VMOVUPS xmm, xmm/m128  (reg form is xmm,xmm; mem form is xmm,m128)
            const auto reg_l0 = Oprs(Operand::xmm, Operand::xmm);
            const auto mem_l0 = Oprs(Operand::xmm, Operand::m128);
            d.forms_by_L[0] = Form(op, 2, reg_l0, VexModrmShape::Both, 0, VexTrailingRole::None, mem_l0, 2);
            const auto reg_l1 = Oprs(Operand::ymm, Operand::ymm);
            const auto mem_l1 = Oprs(Operand::ymm, Operand::m256);
            d.forms_by_L[1] = Form(op, 2, reg_l1, VexModrmShape::Both, 0, VexTrailingRole::None, mem_l1, 2);
        } else {
            // VMOVUPS xmm/m128, xmm
            const auto reg_l0 = Oprs(Operand::xmm, Operand::xmm);
            const auto mem_l0 = Oprs(Operand::m128, Operand::xmm);
            d.forms_by_L[0] = Form(op, 2, reg_l0, VexModrmShape::Both, 0, VexTrailingRole::None, mem_l0, 2);
            const auto reg_l1 = Oprs(Operand::ymm, Operand::ymm);
            const auto mem_l1 = Oprs(Operand::m256, Operand::ymm);
            d.forms_by_L[1] = Form(op, 2, reg_l1, VexModrmShape::Both, 0, VexTrailingRole::None, mem_l1, 2);
        }
    } else {
        // Scalar moves: treat as simple load/store without the NDS merge form.
        if (is_load) {
            const auto reg = Oprs(Operand::xmm, Operand::xmm);
            const auto mem = Oprs(Operand::xmm, scalar_mem);
            d.forms_by_L[0] = Form(op, 2, reg, VexModrmShape::Both, 0, VexTrailingRole::None, mem, 2);
        } else {
            const auto reg = Oprs(Operand::xmm, Operand::xmm);
            const auto mem = Oprs(scalar_mem, Operand::xmm);
            d.forms_by_L[0] = Form(op, 2, reg, VexModrmShape::Both, 0, VexTrailingRole::None, mem, 2);
        }
    }
    return d;
}

// Scalar VMOVSS/VMOVSD descriptor.  Both opcodes support a register NDS merge
// form (xmm1, xmm2, xmm3).  Opcode 0x10 is a memory load (xmm1, m32/m64), while
// opcode 0x11 is a memory store (m32/m64, xmm1).  vvvv is required for register
// forms and reserved for memory forms.
constexpr auto MakeScalarMoveDescriptor(OpcodeId op, bool is_load, Operand scalar_mem) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // LIG
    d.allowed_W = 0x03;

    const auto reg = Oprs(Operand::xmm, Operand::xmm, Operand::xmm);
    const auto mem = is_load ? Oprs(Operand::xmm, scalar_mem) : Oprs(scalar_mem, Operand::xmm);
    d.forms_by_L[0] = Form(op, 3, reg, VexModrmShape::Both, 0, VexTrailingRole::None, mem, 2);
    d.reg_vvvv_required = true;
    d.mem_vvvv_reserved = true;
    return d;
}

constexpr auto MakeNoNdsCompareDescriptor(OpcodeId op, Operand mem_op, bool packed) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L0/L1; scalar forms are LIG and reuse L0 operands.
    d.allowed_W = 0x03;

    const auto reg_l0 = Oprs(Operand::xmm, Operand::xmm, Operand::imm8);
    const auto mem_l0 = Oprs(Operand::xmm, mem_op, Operand::imm8);
    d.forms_by_L[0] = Form(op, 3, reg_l0, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem_l0, 3);

    if (packed) {
        const auto reg_l1 = Oprs(Operand::ymm, Operand::ymm, Operand::imm8);
        const auto mem_l1 = Oprs(Operand::ymm, Operand::m256, Operand::imm8);
        d.forms_by_L[1] = Form(op, 3, reg_l1, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem_l1, 3);
    }
    return d;
}

constexpr auto MakeNoNdsPackedDescriptor(OpcodeId op,
    Operand dst_l0, Operand src_l0, Operand mem_l0,
    Operand dst_l1, Operand src_l1, Operand mem_l1,
    uint8_t allowed_W = 0x03) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03;
    d.allowed_W = allowed_W;

    const auto reg_l0 = Oprs(dst_l0, src_l0);
    const auto mem0   = Oprs(dst_l0, mem_l0);
    d.forms_by_L[0] = Form(op, 2, reg_l0, VexModrmShape::Both, 0, VexTrailingRole::None, mem0, 2);

    const auto reg_l1 = Oprs(dst_l1, src_l1);
    const auto mem1   = Oprs(dst_l1, mem_l1);
    d.forms_by_L[1] = Form(op, 2, reg_l1, VexModrmShape::Both, 0, VexTrailingRole::None, mem1, 2);
    return d;
}

constexpr auto MakeNdsDescriptorW(OpcodeId op, Operand mem_l0, Operand mem_l1,
                                  bool packed, uint8_t allowed_W) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L0/L1; scalar forms are LIG and reuse L0 operands.
    d.allowed_W = allowed_W;
    d.vvvv_required = true;

    const auto reg_l0 = Oprs(Operand::xmm, Operand::xmm, Operand::xmm);
    const auto mem0 = Oprs(Operand::xmm, Operand::xmm, mem_l0);
    d.forms_by_L[0] = Form(op, 3, reg_l0, VexModrmShape::Both, 0, VexTrailingRole::None, mem0, 3);

    if (packed) {
        const auto reg_l1 = Oprs(Operand::ymm, Operand::ymm, Operand::ymm);
        const auto mem1 = Oprs(Operand::ymm, Operand::ymm, mem_l1);
        d.forms_by_L[1] = Form(op, 3, reg_l1, VexModrmShape::Both, 0, VexTrailingRole::None, mem1, 3);
    }
    return d;
}

constexpr auto MakeNdsDescriptorL1W(OpcodeId op, Operand mem_l1,
                                    uint8_t allowed_W) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x02; // L=1 only
    d.allowed_W = allowed_W;
    d.vvvv_required = true;

    const auto reg_l1 = Oprs(Operand::ymm, Operand::ymm, Operand::ymm);
    const auto mem1 = Oprs(Operand::ymm, Operand::ymm, mem_l1);
    d.forms_by_L[1] = Form(op, 3, reg_l1, VexModrmShape::Both, 0, VexTrailingRole::None, mem1, 3);
    return d;
}

// NDS packed descriptor with a different mnemonic for W=0 and W=1.
constexpr auto MakeNdsDescriptorWPair(OpcodeId op_w0, OpcodeId op_w1,
                                      Operand mem_l0, Operand mem_l1) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L=0 and L=1
    d.allowed_W = 0x03; // W=0 and W=1
    d.vvvv_required = true;
    d.opcode_by_W[0] = op_w0;
    d.opcode_by_W[1] = op_w1;

    const auto reg_l0 = Oprs(Operand::xmm, Operand::xmm, Operand::xmm);
    const auto mem0 = Oprs(Operand::xmm, Operand::xmm, mem_l0);
    d.forms_by_L[0] = Form(op_w0, 3, reg_l0, VexModrmShape::Both, 0, VexTrailingRole::None, mem0, 3);

    const auto reg_l1 = Oprs(Operand::ymm, Operand::ymm, Operand::ymm);
    const auto mem1 = Oprs(Operand::ymm, Operand::ymm, mem_l1);
    d.forms_by_L[1] = Form(op_w0, 3, reg_l1, VexModrmShape::Both, 0, VexTrailingRole::None, mem1, 3);
    return d;
}

constexpr auto MakeNdsMemOnlyDescriptor(OpcodeId op, Operand mem_l0,
                                        Operand mem_l1 = Operand::noopr,
                                        uint8_t allowed_W = 0x03) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    const bool packed = mem_l1 != Operand::noopr;
    d.allowed_L = 0x03; // L0/L1; scalar forms are LIG and reuse L0 operands.
    d.allowed_W = allowed_W;
    d.vvvv_required = true;

    const auto mem0 = Oprs(Operand::xmm, Operand::xmm, mem_l0);
    d.forms_by_L[0] = Form(op, 3, mem0, VexModrmShape::Mem, 0, VexTrailingRole::None, mem0, 3);

    if (packed) {
        const auto mem1 = Oprs(Operand::ymm, Operand::ymm, mem_l1);
        d.forms_by_L[1] = Form(op, 3, mem1, VexModrmShape::Mem, 0, VexTrailingRole::None, mem1, 3);
    }
    return d;
}

// NDS memory-only descriptor whose mnemonic changes with the W bit (e.g.
// VPMASKMOVD/Q load and store forms).
constexpr auto MakeNdsMemOnlyDescriptorWPair(OpcodeId op_w0, OpcodeId op_w1,
                                             Operand mem_l0, Operand mem_l1,
                                             bool is_load) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L=0 and L=1
    d.allowed_W = 0x03; // W=0 and W=1
    d.vvvv_required = true;
    d.opcode_by_W[0] = op_w0;
    d.opcode_by_W[1] = op_w1;

    if (is_load) {
        const auto mem0 = Oprs(Operand::xmm, Operand::xmm, mem_l0);
        d.forms_by_L[0] = Form(op_w0, 3, mem0, VexModrmShape::Mem, 0, VexTrailingRole::None, mem0, 3);
        const auto mem1 = Oprs(Operand::ymm, Operand::ymm, mem_l1);
        d.forms_by_L[1] = Form(op_w1, 3, mem1, VexModrmShape::Mem, 0, VexTrailingRole::None, mem1, 3);
    } else {
        const auto mem0 = Oprs(mem_l0, Operand::xmm, Operand::xmm);
        d.forms_by_L[0] = Form(op_w0, 3, mem0, VexModrmShape::Mem, 0, VexTrailingRole::None, mem0, 3);
        const auto mem1 = Oprs(mem_l1, Operand::ymm, Operand::ymm);
        d.forms_by_L[1] = Form(op_w1, 3, mem1, VexModrmShape::Mem, 0, VexTrailingRole::None, mem1, 3);
    }
    return d;
}

constexpr auto MakeNdsIs4Descriptor(OpcodeId op, Operand mem_l0, Operand mem_l1,
                                    bool packed) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03; // L0/L1; scalar forms are LIG and reuse L0 operands.
    d.allowed_W = 0x03;
    d.vvvv_required = true;

    const auto reg_l0 = Oprs(Operand::xmm, Operand::xmm, Operand::xmm, Operand::xmm);
    const auto mem0 = Oprs(Operand::xmm, Operand::xmm, mem_l0, Operand::xmm);
    d.forms_by_L[0] = Form(op, 4, reg_l0, VexModrmShape::Both, 1, VexTrailingRole::Is4, mem0, 4);

    if (packed) {
        const auto reg_l1 = Oprs(Operand::ymm, Operand::ymm, Operand::ymm, Operand::ymm);
        const auto mem1 = Oprs(Operand::ymm, Operand::ymm, mem_l1, Operand::ymm);
        d.forms_by_L[1] = Form(op, 4, reg_l1, VexModrmShape::Both, 1, VexTrailingRole::Is4, mem1, 4);
    }
    return d;
}

// Gather descriptor.  Patterns are indexed by [W][L] and list the three
// architectural operands: destination, VSIB memory, mask.  The VSIB memory
// operand width is determined by the data element size (vsib_w0 vs vsib_w1).
constexpr auto MakeGatherDescriptor(OpcodeId op_w0, OpcodeId op_w1,
                                    Operand vsib_w0, Operand vsib_w1,
                                    Operand dst_w0_l0, Operand mask_w0_l0,
                                    Operand dst_w0_l1, Operand mask_w0_l1,
                                    Operand dst_w1_l0, Operand mask_w1_l0,
                                    Operand dst_w1_l1, Operand mask_w1_l1,
                                    uint8_t allowed_W = 0x03) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03;
    d.allowed_W = allowed_W;
    d.vvvv_required = true;
    d.uses_vsib = true;
    d.vsib_op[0] = vsib_w0;
    d.vsib_op[1] = vsib_w1;
    d.opcode_by_W[0] = op_w0;
    d.opcode_by_W[1] = op_w1;

    d.gather_operands[0][0] = { dst_w0_l0, vsib_w0, mask_w0_l0 };
    d.gather_operands[0][1] = { dst_w0_l1, vsib_w0, mask_w0_l1 };
    d.gather_operands[1][0] = { dst_w1_l0, vsib_w1, mask_w1_l0 };
    d.gather_operands[1][1] = { dst_w1_l1, vsib_w1, mask_w1_l1 };
    d.gather_operands_valid[0][0] = true;
    d.gather_operands_valid[0][1] = true;
    d.gather_operands_valid[1][0] = true;
    d.gather_operands_valid[1][1] = true;

    // Placeholder forms used only for shape/trailing metadata.
    const auto placeholder_l0 = Oprs(Operand::xmm, Operand::m, Operand::xmm);
    d.forms_by_L[0] = Form(op_w0, 3, placeholder_l0, VexModrmShape::Mem, 0, VexTrailingRole::None, placeholder_l0, 3);
    const auto placeholder_l1 = Oprs(Operand::ymm, Operand::m, Operand::ymm);
    d.forms_by_L[1] = Form(op_w1, 3, placeholder_l1, VexModrmShape::Mem, 0, VexTrailingRole::None, placeholder_l1, 3);
    return d;
}

constexpr auto MakeNoNdsImmDescriptor(OpcodeId op,
    Operand dst_l0, Operand src_l0, Operand mem_l0,
    Operand dst_l1, Operand src_l1, Operand mem_l1,
    uint8_t allowed_W = 0x03) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03;
    d.allowed_W = allowed_W;

    const auto reg_l0 = Oprs(dst_l0, src_l0, Operand::imm8);
    const auto mem0 = Oprs(dst_l0, mem_l0, Operand::imm8);
    d.forms_by_L[0] = Form(op, 3, reg_l0, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem0, 3);

    const auto reg_l1 = Oprs(dst_l1, src_l1, Operand::imm8);
    const auto mem1 = Oprs(dst_l1, mem_l1, Operand::imm8);
    d.forms_by_L[1] = Form(op, 3, reg_l1, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem1, 3);
    return d;
}

constexpr auto MakeNdsCountShiftDescriptor(OpcodeId op) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03;
    d.allowed_W = 0x03;
    d.vvvv_required = true;
    d.forms_by_L[0] = Form(op, 3, Oprs(Operand::xmm, Operand::xmm, Operand::xmm),
        VexModrmShape::Both, 0, VexTrailingRole::None,
        Oprs(Operand::xmm, Operand::xmm, Operand::m128), 3);
    d.forms_by_L[1] = Form(op, 3, Oprs(Operand::ymm, Operand::ymm, Operand::xmm),
        VexModrmShape::Both, 0, VexTrailingRole::None,
        Oprs(Operand::ymm, Operand::ymm, Operand::m128), 3);
    return d;
}

constexpr auto MakeShiftGroup(Operand vec, std::array<std::pair<uint8_t, OpcodeId>, 4> entries) noexcept
    -> VexGroupForms
{
    VexGroupForms group{};
    for (const auto& [reg, op] : entries) {
        if (op != OpcodeId::INVALID_OPCODE) {
            group[reg] = Form(op, 3, Oprs(vec, vec, Operand::imm8),
                VexModrmShape::Reg, 1, VexTrailingRole::Imm8);
        }
    }
    return group;
}

constexpr VexGroupForms kVexGroup71L0 = MakeShiftGroup(Operand::xmm, {{{ 2, OpcodeId::VPSRLW }, { 4, OpcodeId::VPSRAW }, { 6, OpcodeId::VPSLLW }, { 0, OpcodeId::INVALID_OPCODE }}});
constexpr VexGroupForms kVexGroup71L1 = MakeShiftGroup(Operand::ymm, {{{ 2, OpcodeId::VPSRLW }, { 4, OpcodeId::VPSRAW }, { 6, OpcodeId::VPSLLW }, { 0, OpcodeId::INVALID_OPCODE }}});
constexpr VexGroupForms kVexGroup72L0 = MakeShiftGroup(Operand::xmm, {{{ 2, OpcodeId::VPSRLD }, { 4, OpcodeId::VPSRAD }, { 6, OpcodeId::VPSLLD }, { 0, OpcodeId::INVALID_OPCODE }}});
constexpr VexGroupForms kVexGroup72L1 = MakeShiftGroup(Operand::ymm, {{{ 2, OpcodeId::VPSRLD }, { 4, OpcodeId::VPSRAD }, { 6, OpcodeId::VPSLLD }, { 0, OpcodeId::INVALID_OPCODE }}});
constexpr VexGroupForms kVexGroup73L0 = MakeShiftGroup(Operand::xmm, {{{ 2, OpcodeId::VPSRLQ }, { 3, OpcodeId::VPSRLDQ }, { 6, OpcodeId::VPSLLQ }, { 7, OpcodeId::VPSLLDQ }}});
constexpr VexGroupForms kVexGroup73L1 = MakeShiftGroup(Operand::ymm, {{{ 2, OpcodeId::VPSRLQ }, { 3, OpcodeId::VPSRLDQ }, { 6, OpcodeId::VPSLLQ }, { 7, OpcodeId::VPSLLDQ }}});

constexpr VexGroupForms kVexGroupAeL0 = [] {
    VexGroupForms group{};
    group[2] = Form(OpcodeId::VLDMXCSR, 1, Oprs(Operand::m32), VexModrmShape::Mem);
    group[3] = Form(OpcodeId::VSTMXCSR, 1, Oprs(Operand::m32), VexModrmShape::Mem);
    return group;
}();

constexpr auto MakeGroupDescriptor(const VexGroupForms& l0, const VexGroupForms& l1) noexcept -> VexDescriptor
{
    VexDescriptor d{};
    d.allowed_L = 0x03;
    d.allowed_W = 0x03;
    d.forms_by_reg = { &l0, &l1 };
    return d;
}

// 256 rows x 4 pp slots.  Each map is independent.
using VexMapTable = std::array<std::array<std::optional<VexDescriptor>, 4>, 256>;

constexpr auto kVexMap_0F = [] {
    VexMapTable table{};

    // VZEROUPPER / VZEROALL: 0F 77, no ModR/M.
    table[0x77][0] = MakeDescriptorL0L1(
        Form(OpcodeId::VZEROUPPER, 0, kNoOperands, VexModrmShape::None),
        Form(OpcodeId::VZEROALL,   0, kNoOperands, VexModrmShape::None));

    // VMOVUPS / VMOVUPD loads and stores.
    table[0x10][0] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVUPS, true, true);
    table[0x11][0] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVUPS, true, false);
    table[0x10][1] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVUPD, true, true);
    table[0x11][1] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVUPD, true, false);

    // VMOVNTPS / VMOVNTPD stores (non-NDS, memory-only, L=0/1).
    table[0x2B][0] = MakeNoNdsStoreDescriptor(OpcodeId::VMOVNTPS, Operand::m128, Operand::m256);
    table[0x2B][1] = MakeNoNdsStoreDescriptor(OpcodeId::VMOVNTPD, Operand::m128, Operand::m256);

    // VMOVAPS / VMOVAPD loads and stores.
    table[0x28][0] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVAPS, true, true);
    table[0x29][0] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVAPS, true, false);
    table[0x28][1] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVAPD, true, true);
    table[0x29][1] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVAPD, true, false);

    // VMOVSS / VMOVSD scalar loads and stores with proper NDS register merge form.
    table[0x10][2] = MakeScalarMoveDescriptor(OpcodeId::VMOVSS, true,  Operand::m32);
    table[0x11][2] = MakeScalarMoveDescriptor(OpcodeId::VMOVSS, false, Operand::m32);
    table[0x10][3] = MakeScalarMoveDescriptor(OpcodeId::VMOVSD, true,  Operand::m64);
    table[0x11][3] = MakeScalarMoveDescriptor(OpcodeId::VMOVSD, false, Operand::m64);

    // VUCOMISS/ISD and VCOMISS/ISD: scalar, no NDS.
    table[0x2E][0] = MakeDescriptor(Form(OpcodeId::VUCOMISS, 2,
        Oprs(Operand::xmm, Operand::xmm), VexModrmShape::Both, 0,
        VexTrailingRole::None, Oprs(Operand::xmm, Operand::m32), 2));
    table[0x2E][1] = MakeDescriptor(Form(OpcodeId::VUCOMISD, 2,
        Oprs(Operand::xmm, Operand::xmm), VexModrmShape::Both, 0,
        VexTrailingRole::None, Oprs(Operand::xmm, Operand::m64), 2));
    table[0x2F][0] = MakeDescriptor(Form(OpcodeId::VCOMISS, 2,
        Oprs(Operand::xmm, Operand::xmm), VexModrmShape::Both, 0,
        VexTrailingRole::None, Oprs(Operand::xmm, Operand::m32), 2));
    table[0x2F][1] = MakeDescriptor(Form(OpcodeId::VCOMISD, 2,
        Oprs(Operand::xmm, Operand::xmm), VexModrmShape::Both, 0,
        VexTrailingRole::None, Oprs(Operand::xmm, Operand::m64), 2));

    // VMOVMSKPS/PD: register-only, no NDS.
    table[0x50][0] = MakeDescriptor(Form(OpcodeId::VMOVMSKPS, 2,
        Oprs(Operand::r32, Operand::xmm), VexModrmShape::Reg));
    table[0x50][1] = MakeDescriptor(Form(OpcodeId::VMOVMSKPD, 2,
        Oprs(Operand::r32, Operand::xmm), VexModrmShape::Reg));

    // VRSQRTPS/SS and VRCPPS/SS.
    table[0x52][0] = MakeNoNdsPackedDescriptor(OpcodeId::VRSQRTPS,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x52][2] = MakeNdsDescriptor(OpcodeId::VRSQRTSS, Operand::m32, Operand::m32, false);
    table[0x53][0] = MakeNoNdsPackedDescriptor(OpcodeId::VRCPPS,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x53][2] = MakeNdsDescriptor(OpcodeId::VRCPSS,   Operand::m32, Operand::m32, false);

    // VANDPS/PD, VANDNPS/PD, VORPS/PD, VXORPS/PD.
    table[0x54][0] = MakeNdsDescriptor(OpcodeId::VANDPS,  Operand::m128, Operand::m256, true);
    table[0x54][1] = MakeNdsDescriptor(OpcodeId::VANDPD,  Operand::m128, Operand::m256, true);
    table[0x55][0] = MakeNdsDescriptor(OpcodeId::VANDNPS, Operand::m128, Operand::m256, true);
    table[0x55][1] = MakeNdsDescriptor(OpcodeId::VANDNPD, Operand::m128, Operand::m256, true);
    table[0x56][0] = MakeNdsDescriptor(OpcodeId::VORPS,   Operand::m128, Operand::m256, true);
    table[0x56][1] = MakeNdsDescriptor(OpcodeId::VORPD,   Operand::m128, Operand::m256, true);
    table[0x57][0] = MakeNdsDescriptor(OpcodeId::VXORPS,  Operand::m128, Operand::m256, true);
    table[0x57][1] = MakeNdsDescriptor(OpcodeId::VXORPD,  Operand::m128, Operand::m256, true);

    // VADD/SUB/MUL/DIV/MIN/MAX PS/PD/SS/SD.
    table[0x58][0] = MakeNdsDescriptor(OpcodeId::VADDPS, Operand::m128, Operand::m256, true);
    table[0x58][1] = MakeNdsDescriptor(OpcodeId::VADDPD, Operand::m128, Operand::m256, true);
    table[0x58][2] = MakeNdsDescriptor(OpcodeId::VADDSS, Operand::m32,  Operand::m32,  false);
    table[0x58][3] = MakeNdsDescriptor(OpcodeId::VADDSD, Operand::m64,  Operand::m64,  false);

    table[0x59][0] = MakeNdsDescriptor(OpcodeId::VMULPS, Operand::m128, Operand::m256, true);
    table[0x59][1] = MakeNdsDescriptor(OpcodeId::VMULPD, Operand::m128, Operand::m256, true);
    table[0x59][2] = MakeNdsDescriptor(OpcodeId::VMULSS, Operand::m32,  Operand::m32,  false);
    table[0x59][3] = MakeNdsDescriptor(OpcodeId::VMULSD, Operand::m64,  Operand::m64,  false);

    table[0x5C][0] = MakeNdsDescriptor(OpcodeId::VSUBPS, Operand::m128, Operand::m256, true);
    table[0x5C][1] = MakeNdsDescriptor(OpcodeId::VSUBPD, Operand::m128, Operand::m256, true);
    table[0x5C][2] = MakeNdsDescriptor(OpcodeId::VSUBSS, Operand::m32,  Operand::m32,  false);
    table[0x5C][3] = MakeNdsDescriptor(OpcodeId::VSUBSD, Operand::m64,  Operand::m64,  false);

    table[0x5D][0] = MakeNdsDescriptor(OpcodeId::VMINPS, Operand::m128, Operand::m256, true);
    table[0x5D][1] = MakeNdsDescriptor(OpcodeId::VMINPD, Operand::m128, Operand::m256, true);
    table[0x5D][2] = MakeNdsDescriptor(OpcodeId::VMINSS, Operand::m32,  Operand::m32,  false);
    table[0x5D][3] = MakeNdsDescriptor(OpcodeId::VMINSD, Operand::m64,  Operand::m64,  false);

    table[0x5E][0] = MakeNdsDescriptor(OpcodeId::VDIVPS, Operand::m128, Operand::m256, true);
    table[0x5E][1] = MakeNdsDescriptor(OpcodeId::VDIVPD, Operand::m128, Operand::m256, true);
    table[0x5E][2] = MakeNdsDescriptor(OpcodeId::VDIVSS, Operand::m32,  Operand::m32,  false);
    table[0x5E][3] = MakeNdsDescriptor(OpcodeId::VDIVSD, Operand::m64,  Operand::m64,  false);

    table[0x5F][0] = MakeNdsDescriptor(OpcodeId::VMAXPS, Operand::m128, Operand::m256, true);
    table[0x5F][1] = MakeNdsDescriptor(OpcodeId::VMAXPD, Operand::m128, Operand::m256, true);
    table[0x5F][2] = MakeNdsDescriptor(OpcodeId::VMAXSS, Operand::m32,  Operand::m32,  false);
    table[0x5F][3] = MakeNdsDescriptor(OpcodeId::VMAXSD, Operand::m64,  Operand::m64,  false);

    // Conversions.
    table[0x5A][0] = MakeNoNdsPackedDescriptor(OpcodeId::VCVTPS2PD,
        Operand::xmm, Operand::xmm, Operand::m64,
        Operand::ymm, Operand::xmm, Operand::m128);
    table[0x5A][1] = MakeNoNdsPackedDescriptor(OpcodeId::VCVTPD2PS,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::xmm, Operand::ymm, Operand::m256);
    table[0x5A][2] = MakeNdsDescriptor(OpcodeId::VCVTSS2SD, Operand::m32,  Operand::m32,  false);
    table[0x5A][3] = MakeNdsDescriptor(OpcodeId::VCVTSD2SS, Operand::m64,  Operand::m64,  false);

    table[0x5B][0] = MakeNoNdsPackedDescriptor(OpcodeId::VCVTDQ2PS,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x5B][1] = MakeNoNdsPackedDescriptor(OpcodeId::VCVTPS2DQ,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x5B][2] = MakeNoNdsPackedDescriptor(OpcodeId::VCVTTPS2DQ,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);

    // Square root and reciprocal square root.
    table[0x51][0] = MakeNoNdsPackedDescriptor(OpcodeId::VSQRTPS,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x51][1] = MakeNoNdsPackedDescriptor(OpcodeId::VSQRTPD,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x51][2] = MakeNdsDescriptor(OpcodeId::VSQRTSS, Operand::m32,  Operand::m32,  false);
    table[0x51][3] = MakeNdsDescriptor(OpcodeId::VSQRTSD, Operand::m64,  Operand::m64,  false);

    // VUNPCKLPS/PD and VUNPCKHPS/PD.
    table[0x14][0] = MakeNdsDescriptor(OpcodeId::VUNPCKLPS, Operand::m128, Operand::m256, true);
    table[0x14][1] = MakeNdsDescriptor(OpcodeId::VUNPCKLPD, Operand::m128, Operand::m256, true);
    table[0x15][0] = MakeNdsDescriptor(OpcodeId::VUNPCKHPS, Operand::m128, Operand::m256, true);
    table[0x15][1] = MakeNdsDescriptor(OpcodeId::VUNPCKHPD, Operand::m128, Operand::m256, true);

    // VHADDPS/PD and VHSUBPS/PD.
    // HADDPS/HSUBPS use the F2 implied prefix (VEX.pp = 3);
    // HADDPD/HSUBPD use the 66 implied prefix (VEX.pp = 1).
    table[0x7C][3] = MakeNdsDescriptor(OpcodeId::VHADDPS, Operand::m128, Operand::m256, true);
    table[0x7C][1] = MakeNdsDescriptor(OpcodeId::VHADDPD, Operand::m128, Operand::m256, true);
    table[0x7D][3] = MakeNdsDescriptor(OpcodeId::VHSUBPS, Operand::m128, Operand::m256, true);
    table[0x7D][1] = MakeNdsDescriptor(OpcodeId::VHSUBPD, Operand::m128, Operand::m256, true);

    // VCMPPS/PD/SS/SD.
    table[0xC2][0] = MakeNdsImmDescriptor(OpcodeId::VCMPPS, Operand::m128, Operand::m256, true);
    table[0xC2][1] = MakeNdsImmDescriptor(OpcodeId::VCMPPD, Operand::m128, Operand::m256, true);
    table[0xC2][2] = MakeNdsImmDescriptor(OpcodeId::VCMPSS, Operand::m32,  Operand::m32,  false);
    table[0xC2][3] = MakeNdsImmDescriptor(OpcodeId::VCMPSD, Operand::m64,  Operand::m64,  false);

    // VSHUFPS/PD.
    table[0xC6][0] = MakeNdsImmDescriptor(OpcodeId::VSHUFPS, Operand::m128, Operand::m256, true);
    table[0xC6][1] = MakeNdsImmDescriptor(OpcodeId::VSHUFPD, Operand::m128, Operand::m256, true);

    // 128-bit integer SIMD (pp=66), L=0 AVX, L=1 AVX2.
    table[0xFC][1] = MakeNdsDescriptor(OpcodeId::VPADDB, Operand::m128, Operand::m256, true);
    table[0xFD][1] = MakeNdsDescriptor(OpcodeId::VPADDW, Operand::m128, Operand::m256, true);
    table[0xFE][1] = MakeNdsDescriptor(OpcodeId::VPADDD, Operand::m128, Operand::m256, true);
    table[0xD4][1] = MakeNdsDescriptor(OpcodeId::VPADDQ, Operand::m128, Operand::m256, true);

    table[0xE8][1] = MakeNdsDescriptor(OpcodeId::VPSUBB, Operand::m128, Operand::m256, true);
    table[0xE9][1] = MakeNdsDescriptor(OpcodeId::VPSUBW, Operand::m128, Operand::m256, true);
    table[0xFA][1] = MakeNdsDescriptor(OpcodeId::VPSUBD, Operand::m128, Operand::m256, true);
    table[0xFB][1] = MakeNdsDescriptor(OpcodeId::VPSUBQ, Operand::m128, Operand::m256, true);

    table[0xDB][1] = MakeNdsDescriptor(OpcodeId::VPAND,  Operand::m128, Operand::m256, true);
    table[0xDF][1] = MakeNdsDescriptor(OpcodeId::VPANDN, Operand::m128, Operand::m256, true);
    table[0xEB][1] = MakeNdsDescriptor(OpcodeId::VPOR,   Operand::m128, Operand::m256, true);
    table[0xEF][1] = MakeNdsDescriptor(OpcodeId::VPXOR,  Operand::m128, Operand::m256, true);

    table[0x74][1] = MakeNdsDescriptor(OpcodeId::VPCMPEQB, Operand::m128, Operand::m256, true);
    table[0x75][1] = MakeNdsDescriptor(OpcodeId::VPCMPEQW, Operand::m128, Operand::m256, true);
    table[0x76][1] = MakeNdsDescriptor(OpcodeId::VPCMPEQD, Operand::m128, Operand::m256, true);
    table[0x64][1] = MakeNdsDescriptor(OpcodeId::VPCMPGTB, Operand::m128, Operand::m256, true);
    table[0x65][1] = MakeNdsDescriptor(OpcodeId::VPCMPGTW, Operand::m128, Operand::m256, true);
    table[0x66][1] = MakeNdsDescriptor(OpcodeId::VPCMPGTD, Operand::m128, Operand::m256, true);

    table[0xD5][1] = MakeNdsDescriptor(OpcodeId::VPMULLW,  Operand::m128, Operand::m256, true);
    table[0xE5][1] = MakeNdsDescriptor(OpcodeId::VPMULHW,  Operand::m128, Operand::m256, true);
    table[0xE4][1] = MakeNdsDescriptor(OpcodeId::VPMULHUW, Operand::m128, Operand::m256, true);
    table[0xF4][1] = MakeNdsDescriptor(OpcodeId::VPMULUDQ, Operand::m128, Operand::m256, true);

    // VPMOVMSKB: register-only.
    table[0xD7][1] = MakeDescriptor(Form(OpcodeId::VPMOVMSKB, 2,
        Oprs(Operand::r32, Operand::xmm), VexModrmShape::Reg));

    // VPSHUFD/PSHUFHW/PSHUFLW with imm8.
    table[0x70][1] = MakeNoNdsCompareDescriptor(OpcodeId::VPSHUFD, Operand::m128, true);
    table[0x70][2] = MakeNoNdsCompareDescriptor(OpcodeId::VPSHUFHW, Operand::m128, true);
    table[0x70][3] = MakeNoNdsCompareDescriptor(OpcodeId::VPSHUFLW, Operand::m128, true);

    // VPUNPCKLBW/LWD/LDQ/LQDQ and HBW/HWD/HDQ/HQDQ.
    table[0x60][1] = MakeNdsDescriptor(OpcodeId::VPUNPCKLBW,  Operand::m128, Operand::m256, true);
    table[0x61][1] = MakeNdsDescriptor(OpcodeId::VPUNPCKLWD,  Operand::m128, Operand::m256, true);
    table[0x62][1] = MakeNdsDescriptor(OpcodeId::VPUNPCKLDQ,  Operand::m128, Operand::m256, true);
    table[0x6C][1] = MakeNdsDescriptor(OpcodeId::VPUNPCKLQDQ, Operand::m128, Operand::m256, true);
    table[0x68][1] = MakeNdsDescriptor(OpcodeId::VPUNPCKHBW,  Operand::m128, Operand::m256, true);
    table[0x69][1] = MakeNdsDescriptor(OpcodeId::VPUNPCKHWD,  Operand::m128, Operand::m256, true);
    table[0x6A][1] = MakeNdsDescriptor(OpcodeId::VPUNPCKHDQ,  Operand::m128, Operand::m256, true);
    table[0x6D][1] = MakeNdsDescriptor(OpcodeId::VPUNPCKHQDQ, Operand::m128, Operand::m256, true);

    // VMOVD/VMOVQ to/from GPR or memory; W=1 selects the 64-bit-only Q form.
    for (const auto opcode : { 0x6E, 0x7E }) {
        VexDescriptor d{};
        d.allowed_L = 0x01;
        d.allowed_W = 0x03;
        const bool load = opcode == 0x6E;
        const auto reg0 = load ? Oprs(Operand::xmm, Operand::r32) : Oprs(Operand::r32, Operand::xmm);
        const auto mem0 = load ? Oprs(Operand::xmm, Operand::m32) : Oprs(Operand::m32, Operand::xmm);
        const auto reg1 = load ? Oprs(Operand::xmm, Operand::r64) : Oprs(Operand::r64, Operand::xmm);
        const auto mem1 = load ? Oprs(Operand::xmm, Operand::m64) : Oprs(Operand::m64, Operand::xmm);
        d.forms_by_W[0] = Form(OpcodeId::VMOVD, 2, reg0, VexModrmShape::Both, 0, VexTrailingRole::None, mem0, 2);
        auto q = Form(OpcodeId::VMOVQ, 2, reg1, VexModrmShape::Both, 0, VexTrailingRole::None, mem1, 2);
        q.allowed_modes = 0x02;
        d.forms_by_W[1] = q;
        table[opcode][1] = d;
    }

    // Additional move, broadcast-style duplication, and conversion forms.
    table[0x6F][1] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVDQA, true, true);
    table[0x7F][1] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVDQA, true, false);
    table[0x6F][2] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVDQU, true, true);
    table[0x7F][2] = MakeNoNdsMoveDescriptor(OpcodeId::VMOVDQU, true, false);
    table[0x12][2] = MakeNoNdsPackedDescriptor(OpcodeId::VMOVSLDUP,
        Operand::xmm, Operand::xmm, Operand::m128, Operand::ymm, Operand::ymm, Operand::m256);
    table[0x16][2] = MakeNoNdsPackedDescriptor(OpcodeId::VMOVSHDUP,
        Operand::xmm, Operand::xmm, Operand::m128, Operand::ymm, Operand::ymm, Operand::m256);
    table[0x12][3] = MakeNoNdsPackedDescriptor(OpcodeId::VMOVDDUP,
        Operand::xmm, Operand::xmm, Operand::m64, Operand::ymm, Operand::ymm, Operand::m256);
    {
        auto d = MakeNoNdsMoveDescriptor(OpcodeId::VMOVQ, false, true, Operand::m64);
        d.allowed_L = 0x01;
        table[0x7E][2] = d;
        d = MakeNoNdsMoveDescriptor(OpcodeId::VMOVQ, false, false, Operand::m64);
        d.allowed_L = 0x01;
        table[0xD6][1] = d;
    }
    table[0xE7][1] = MakeNoNdsStoreDescriptor(OpcodeId::VMOVNTDQ, Operand::m128, Operand::m256);
    {
        VexDescriptor d{};
        d.allowed_L = 0x03;
        d.allowed_W = 0x03;
        d.forms_by_L[0] = Form(OpcodeId::VLDDQU, 2, Oprs(Operand::xmm, Operand::m128), VexModrmShape::Mem);
        d.forms_by_L[1] = Form(OpcodeId::VLDDQU, 2, Oprs(Operand::ymm, Operand::m256), VexModrmShape::Mem);
        table[0xF0][3] = d;
    }

    // VMOVLPS/LPD and VMOVHPS/HPD have distinct register/memory forms.
    {
        auto f = Form(OpcodeId::VMOVHLPS, 3, Oprs(Operand::xmm, Operand::xmm, Operand::xmm),
            VexModrmShape::Both, 0, VexTrailingRole::None,
            Oprs(Operand::xmm, Operand::xmm, Operand::m64), 3);
        f.mem_opcode = OpcodeId::VMOVLPS;
        auto d = MakeDescriptor(f);
        d.vvvv_required = true;
        table[0x12][0] = d;
        f = Form(OpcodeId::VMOVLHPS, 3, Oprs(Operand::xmm, Operand::xmm, Operand::xmm),
            VexModrmShape::Both, 0, VexTrailingRole::None,
            Oprs(Operand::xmm, Operand::xmm, Operand::m64), 3);
        f.mem_opcode = OpcodeId::VMOVHPS;
        d = MakeDescriptor(f);
        d.vvvv_required = true;
        table[0x16][0] = d;
        d = MakeNdsMemOnlyDescriptor(OpcodeId::VMOVLPD, Operand::m64);
        d.allowed_L = 0x01;
        table[0x12][1] = d;
        d = MakeNdsMemOnlyDescriptor(OpcodeId::VMOVHPD, Operand::m64);
        d.allowed_L = 0x01;
        table[0x16][1] = d;
    }
    table[0x13][0] = MakeDescriptor(Form(OpcodeId::VMOVLPS, 2, Oprs(Operand::m64, Operand::xmm), VexModrmShape::Mem));
    table[0x13][1] = MakeDescriptor(Form(OpcodeId::VMOVLPD, 2, Oprs(Operand::m64, Operand::xmm), VexModrmShape::Mem));
    table[0x17][0] = MakeDescriptor(Form(OpcodeId::VMOVHPS, 2, Oprs(Operand::m64, Operand::xmm), VexModrmShape::Mem));
    table[0x17][1] = MakeDescriptor(Form(OpcodeId::VMOVHPD, 2, Oprs(Operand::m64, Operand::xmm), VexModrmShape::Mem));

    // Scalar compares and integer conversions are LIG.  W=1 integer forms are 64-bit-only.
    table[0x2E][0] = MakeNoNdsPackedDescriptor(OpcodeId::VUCOMISS,
        Operand::xmm, Operand::xmm, Operand::m32, Operand::xmm, Operand::xmm, Operand::m32);
    table[0x2E][1] = MakeNoNdsPackedDescriptor(OpcodeId::VUCOMISD,
        Operand::xmm, Operand::xmm, Operand::m64, Operand::xmm, Operand::xmm, Operand::m64);
    table[0x2F][0] = MakeNoNdsPackedDescriptor(OpcodeId::VCOMISS,
        Operand::xmm, Operand::xmm, Operand::m32, Operand::xmm, Operand::xmm, Operand::m32);
    table[0x2F][1] = MakeNoNdsPackedDescriptor(OpcodeId::VCOMISD,
        Operand::xmm, Operand::xmm, Operand::m64, Operand::xmm, Operand::xmm, Operand::m64);
    for (const auto& [opcode, name] : { std::pair(0x2A, OpcodeId::VCVTSI2SS), std::pair(0x2A, OpcodeId::VCVTSI2SD) }) {
        const uint8_t pp = name == OpcodeId::VCVTSI2SS ? 2 : 3;
        VexDescriptor d{};
        d.allowed_L = 0x03;
        d.allowed_W = 0x03;
        d.vvvv_required = true;
        d.forms_by_W[0] = Form(name, 3, Oprs(Operand::xmm, Operand::xmm, Operand::r32),
            VexModrmShape::Both, 0, VexTrailingRole::None, Oprs(Operand::xmm, Operand::xmm, Operand::m32), 3);
        auto q = Form(name, 3, Oprs(Operand::xmm, Operand::xmm, Operand::r64),
            VexModrmShape::Both, 0, VexTrailingRole::None, Oprs(Operand::xmm, Operand::xmm, Operand::m64), 3);
        q.allowed_modes = 0x02;
        d.forms_by_W[1] = q;
        table[opcode][pp] = d;
    }
    for (const auto& [opcode, name] : {
        std::pair(0x2C, OpcodeId::VCVTTSS2SI), std::pair(0x2C, OpcodeId::VCVTTSD2SI),
        std::pair(0x2D, OpcodeId::VCVTSS2SI),  std::pair(0x2D, OpcodeId::VCVTSD2SI) }) {
        const bool double_source = name == OpcodeId::VCVTTSD2SI || name == OpcodeId::VCVTSD2SI;
        const uint8_t pp = double_source ? 3 : 2;
        const auto src_mem = double_source ? Operand::m64 : Operand::m32;
        VexDescriptor d{};
        d.allowed_L = 0x03;
        d.allowed_W = 0x03;
        d.forms_by_W[0] = Form(name, 2, Oprs(Operand::r32, Operand::xmm),
            VexModrmShape::Both, 0, VexTrailingRole::None, Oprs(Operand::r32, src_mem), 2);
        auto q = Form(name, 2, Oprs(Operand::r64, Operand::xmm),
            VexModrmShape::Both, 0, VexTrailingRole::None, Oprs(Operand::r64, src_mem), 2);
        q.allowed_modes = 0x02;
        d.forms_by_W[1] = q;
        table[opcode][pp] = d;
    }

    // Mask extraction uses a 32-bit GPR destination in both decoding modes.
    for (const auto& [opcode, name] : { std::pair(0x50, OpcodeId::VMOVMSKPS), std::pair(0x50, OpcodeId::VMOVMSKPD), std::pair(0xD7, OpcodeId::VPMOVMSKB) }) {
        const uint8_t pp = opcode == 0xD7 ? 1 : (name == OpcodeId::VMOVMSKPD ? 1 : 0);
        VexDescriptor d{};
        d.allowed_L = 0x03;
        d.allowed_W = 0x03;
        d.forms_by_L[0] = Form(name, 2, Oprs(Operand::r32, Operand::xmm), VexModrmShape::Reg);
        d.forms_by_L[1] = Form(name, 2, Oprs(Operand::r32, Operand::ymm), VexModrmShape::Reg);
        table[opcode][pp] = d;
    }

    table[0xE6][1] = MakeNoNdsPackedDescriptor(OpcodeId::VCVTTPD2DQ,
        Operand::xmm, Operand::xmm, Operand::m128, Operand::xmm, Operand::ymm, Operand::m256);
    table[0xE6][2] = MakeNoNdsPackedDescriptor(OpcodeId::VCVTDQ2PD,
        Operand::xmm, Operand::xmm, Operand::m64, Operand::ymm, Operand::xmm, Operand::m128);
    table[0xE6][3] = MakeNoNdsPackedDescriptor(OpcodeId::VCVTPD2DQ,
        Operand::xmm, Operand::xmm, Operand::m128, Operand::xmm, Operand::ymm, Operand::m256);
    table[0xD0][1] = MakeNdsDescriptor(OpcodeId::VADDSUBPD, Operand::m128, Operand::m256, true);
    table[0xD0][3] = MakeNdsDescriptor(OpcodeId::VADDSUBPS, Operand::m128, Operand::m256, true);

    // Full 0F integer SIMD rows.  L=0 is AVX and L=1 is AVX2 for these slots.
    for (const auto& [opcode, name] : {
        std::pair(0x60, OpcodeId::VPUNPCKLBW), std::pair(0x61, OpcodeId::VPUNPCKLWD),
        std::pair(0x62, OpcodeId::VPUNPCKLDQ), std::pair(0x63, OpcodeId::VPACKSSWB),
        std::pair(0x64, OpcodeId::VPCMPGTB),   std::pair(0x65, OpcodeId::VPCMPGTW),
        std::pair(0x66, OpcodeId::VPCMPGTD),   std::pair(0x67, OpcodeId::VPACKUSWB),
        std::pair(0x68, OpcodeId::VPUNPCKHBW), std::pair(0x69, OpcodeId::VPUNPCKHWD),
        std::pair(0x6A, OpcodeId::VPUNPCKHDQ), std::pair(0x6B, OpcodeId::VPACKSSDW),
        std::pair(0x6C, OpcodeId::VPUNPCKLQDQ),std::pair(0x6D, OpcodeId::VPUNPCKHQDQ),
        std::pair(0x74, OpcodeId::VPCMPEQB),   std::pair(0x75, OpcodeId::VPCMPEQW),
        std::pair(0x76, OpcodeId::VPCMPEQD),   std::pair(0xD4, OpcodeId::VPADDQ),
        std::pair(0xD5, OpcodeId::VPMULLW),    std::pair(0xD8, OpcodeId::VPSUBUSB),
        std::pair(0xD9, OpcodeId::VPSUBUSW),   std::pair(0xDA, OpcodeId::VPMINUB),
        std::pair(0xDB, OpcodeId::VPAND),      std::pair(0xDC, OpcodeId::VPADDUSB),
        std::pair(0xDD, OpcodeId::VPADDUSW),   std::pair(0xDE, OpcodeId::VPMAXUB),
        std::pair(0xDF, OpcodeId::VPANDN),     std::pair(0xE0, OpcodeId::VPAVGB),
        std::pair(0xE3, OpcodeId::VPAVGW),     std::pair(0xE4, OpcodeId::VPMULHUW),
        std::pair(0xE5, OpcodeId::VPMULHW),    std::pair(0xE8, OpcodeId::VPSUBSB),
        std::pair(0xE9, OpcodeId::VPSUBSW),    std::pair(0xEA, OpcodeId::VPMINSW),
        std::pair(0xEB, OpcodeId::VPOR),       std::pair(0xEC, OpcodeId::VPADDSB),
        std::pair(0xED, OpcodeId::VPADDSW),    std::pair(0xEE, OpcodeId::VPMAXSW),
        std::pair(0xEF, OpcodeId::VPXOR),      std::pair(0xF4, OpcodeId::VPMULUDQ),
        std::pair(0xF5, OpcodeId::VPMADDWD),   std::pair(0xF6, OpcodeId::VPSADBW),
        std::pair(0xF8, OpcodeId::VPSUBB),     std::pair(0xF9, OpcodeId::VPSUBW),
        std::pair(0xFA, OpcodeId::VPSUBD),     std::pair(0xFB, OpcodeId::VPSUBQ),
        std::pair(0xFC, OpcodeId::VPADDB),     std::pair(0xFD, OpcodeId::VPADDW),
        std::pair(0xFE, OpcodeId::VPADDD),
    }) {
        table[opcode][1] = MakeNdsDescriptor(name, Operand::m128, Operand::m256, true);
    }
    for (const auto& [opcode, name] : {
        std::pair(0xD1, OpcodeId::VPSRLW), std::pair(0xD2, OpcodeId::VPSRLD), std::pair(0xD3, OpcodeId::VPSRLQ),
        std::pair(0xE1, OpcodeId::VPSRAW), std::pair(0xE2, OpcodeId::VPSRAD),
        std::pair(0xF1, OpcodeId::VPSLLW), std::pair(0xF2, OpcodeId::VPSLLD), std::pair(0xF3, OpcodeId::VPSLLQ),
    }) {
        table[opcode][1] = MakeNdsCountShiftDescriptor(name);
    }

    table[0x71][1] = MakeGroupDescriptor(kVexGroup71L0, kVexGroup71L1);
    table[0x72][1] = MakeGroupDescriptor(kVexGroup72L0, kVexGroup72L1);
    table[0x73][1] = MakeGroupDescriptor(kVexGroup73L0, kVexGroup73L1);
    {
        VexDescriptor d{};
        d.allowed_L = 0x01;
        d.allowed_W = 0x03;
        d.forms_by_reg[0] = &kVexGroupAeL0;
        table[0xAE][0] = d;
    }
    table[0xF7][1] = MakeDescriptor(Form(OpcodeId::VMASKMOVDQU, 2,
        Oprs(Operand::xmm, Operand::xmm), VexModrmShape::Reg));

    // Word insert/extract use a GPR register form and a 16-bit memory form.
    {
        auto d = MakeNdsImmDescriptor(OpcodeId::VPINSRW, Operand::m16, Operand::m16, false);
        d.allowed_L = 0x01;
        d.forms_by_L[0] = Form(OpcodeId::VPINSRW, 4, Oprs(Operand::xmm, Operand::xmm, Operand::r32, Operand::imm8),
            VexModrmShape::Both, 1, VexTrailingRole::Imm8,
            Oprs(Operand::xmm, Operand::xmm, Operand::m16, Operand::imm8), 4);
        table[0xC4][1] = d;
        table[0xC5][1] = MakeDescriptor(Form(OpcodeId::VPEXTRW, 3,
            Oprs(Operand::r32, Operand::xmm, Operand::imm8), VexModrmShape::Reg, 1, VexTrailingRole::Imm8));
    }

    return table;
}();

constexpr auto kVexMap_0F38 = [] {
    VexMapTable table{};

    // 0F38 integer SIMD (pp=66), mostly NDS 3-operand packed.
    for (const auto& [opcode, name] : {
        std::pair(0x00, OpcodeId::VPSHUFB),
        std::pair(0x01, OpcodeId::VPHADDW),
        std::pair(0x02, OpcodeId::VPHADDD),
        std::pair(0x03, OpcodeId::VPHADDSW),
        std::pair(0x04, OpcodeId::VPMADDUBSW),
        std::pair(0x05, OpcodeId::VPHSUBW),
        std::pair(0x06, OpcodeId::VPHSUBD),
        std::pair(0x07, OpcodeId::VPHSUBSW),
        std::pair(0x08, OpcodeId::VPSIGNB),
        std::pair(0x09, OpcodeId::VPSIGNW),
        std::pair(0x0A, OpcodeId::VPSIGND),
        std::pair(0x0B, OpcodeId::VPMULHRSW),
    }) {
        table[opcode][1] = MakeNdsDescriptor(name, Operand::m128, Operand::m256, true);
    }

    // VPERMILPS/PD (NDS packed, pp=66).
    table[0x0C][1] = MakeNdsDescriptor(OpcodeId::VPERMILPS, Operand::m128, Operand::m256, true);
    table[0x0D][1] = MakeNdsDescriptor(OpcodeId::VPERMILPD, Operand::m128, Operand::m256, true);

    // VTESTPS/PD (non-NDS packed, pp=66).
    table[0x0E][1] = MakeNoNdsPackedDescriptor(OpcodeId::VTESTPS,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x0F][1] = MakeNoNdsPackedDescriptor(OpcodeId::VTESTPD,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);

    // VPABSB/W/D (non-NDS packed, pp=66).
    table[0x1C][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPABSB,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x1D][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPABSW,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x1E][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPABSD,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);

    // VPMOVSX* / VPMOVZX* (non-NDS, custom src widths).
    // 0x20/0x30: BW
    table[0x20][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVSXBW,
        Operand::xmm, Operand::xmm, Operand::m64,
        Operand::ymm, Operand::xmm, Operand::m128);
    table[0x30][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVZXBW,
        Operand::xmm, Operand::xmm, Operand::m64,
        Operand::ymm, Operand::xmm, Operand::m128);
    // 0x21/0x31: BD
    table[0x21][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVSXBD,
        Operand::xmm, Operand::xmm, Operand::m32,
        Operand::ymm, Operand::xmm, Operand::m64);
    table[0x31][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVZXBD,
        Operand::xmm, Operand::xmm, Operand::m32,
        Operand::ymm, Operand::xmm, Operand::m64);
    // 0x22/0x32: BQ
    table[0x22][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVSXBQ,
        Operand::xmm, Operand::xmm, Operand::m16,
        Operand::ymm, Operand::xmm, Operand::m32);
    table[0x32][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVZXBQ,
        Operand::xmm, Operand::xmm, Operand::m16,
        Operand::ymm, Operand::xmm, Operand::m32);
    // 0x23/0x33: WD
    table[0x23][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVSXWD,
        Operand::xmm, Operand::xmm, Operand::m64,
        Operand::ymm, Operand::xmm, Operand::m128);
    table[0x33][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVZXWD,
        Operand::xmm, Operand::xmm, Operand::m64,
        Operand::ymm, Operand::xmm, Operand::m128);
    // 0x24/0x34: WQ
    table[0x24][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVSXWQ,
        Operand::xmm, Operand::xmm, Operand::m32,
        Operand::ymm, Operand::xmm, Operand::m64);
    table[0x34][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVZXWQ,
        Operand::xmm, Operand::xmm, Operand::m32,
        Operand::ymm, Operand::xmm, Operand::m64);
    // 0x25/0x35: DQ
    table[0x25][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVSXDQ,
        Operand::xmm, Operand::xmm, Operand::m64,
        Operand::ymm, Operand::xmm, Operand::m128);
    table[0x35][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPMOVZXDQ,
        Operand::xmm, Operand::xmm, Operand::m64,
        Operand::ymm, Operand::xmm, Operand::m128);

    // VPCMPGTQ and min/max (NDS packed, pp=66).
    table[0x37][1] = MakeNdsDescriptor(OpcodeId::VPCMPGTQ, Operand::m128, Operand::m256, true);
    table[0x38][1] = MakeNdsDescriptor(OpcodeId::VPMINSB,  Operand::m128, Operand::m256, true);
    table[0x39][1] = MakeNdsDescriptor(OpcodeId::VPMINSD,  Operand::m128, Operand::m256, true);
    table[0x3A][1] = MakeNdsDescriptor(OpcodeId::VPMINUB,  Operand::m128, Operand::m256, true);
    table[0x3B][1] = MakeNdsDescriptor(OpcodeId::VPMINUD,  Operand::m128, Operand::m256, true);
    table[0x3C][1] = MakeNdsDescriptor(OpcodeId::VPMAXSB,  Operand::m128, Operand::m256, true);
    table[0x3D][1] = MakeNdsDescriptor(OpcodeId::VPMAXSD,  Operand::m128, Operand::m256, true);
    table[0x3E][1] = MakeNdsDescriptor(OpcodeId::VPMAXUB,  Operand::m128, Operand::m256, true);
    table[0x3F][1] = MakeNdsDescriptor(OpcodeId::VPMAXUD,  Operand::m128, Operand::m256, true);

    table[0x40][1] = MakeNdsDescriptor(OpcodeId::VPMULLD, Operand::m128, Operand::m256, true);

    // VPHMINPOSUW: L=0 only, non-NDS.
    table[0x41][1] = MakeDescriptor(Form(OpcodeId::VPHMINPOSUW, 2,
        Oprs(Operand::xmm, Operand::xmm), VexModrmShape::Both, 0,
        VexTrailingRole::None, Oprs(Operand::xmm, Operand::m128), 2));

    // AVX2 broadcasts (pp=66, non-NDS, src width independent of L).
    table[0x18][1] = MakeNoNdsPackedDescriptor(OpcodeId::VBROADCASTSS,
        Operand::xmm, Operand::xmm, Operand::m32,
        Operand::ymm, Operand::xmm, Operand::m32);
    // VBROADCASTSD is AVX2-only and L=1 only.
    table[0x19][1] = MakeDescriptorL1(Form(OpcodeId::VBROADCASTSD, 2,
        Oprs(Operand::ymm, Operand::xmm), VexModrmShape::Both, 0,
        VexTrailingRole::None, Oprs(Operand::ymm, Operand::m64), 2));
    table[0x58][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPBROADCASTD,
        Operand::xmm, Operand::xmm, Operand::m32,
        Operand::ymm, Operand::xmm, Operand::m32);
    table[0x59][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPBROADCASTQ,
        Operand::xmm, Operand::xmm, Operand::m64,
        Operand::ymm, Operand::xmm, Operand::m64);
    table[0x78][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPBROADCASTB,
        Operand::xmm, Operand::xmm, Operand::m8,
        Operand::ymm, Operand::xmm, Operand::m8);
    table[0x79][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPBROADCASTW,
        Operand::xmm, Operand::xmm, Operand::m16,
        Operand::ymm, Operand::xmm, Operand::m16);

    // VBROADCASTI128: L=1, mem-only.
    table[0x5A][1] = MakeDescriptorL1(Form(OpcodeId::VBROADCASTI128, 2,
        Oprs(Operand::ymm, Operand::m128), VexModrmShape::Mem));

    // AVX2 permutes (L=1 only, pp=66, W=0).
    // Note: VPERMPD/VPERMQ are 0F3A immediate forms only in AVX2; the NDS
    // 0F38 forms are VPERMPS (0x16) and VPERMD (0x36).
    table[0x16][1] = MakeNdsDescriptorL1W(OpcodeId::VPERMPS, Operand::m256, 0x01);
    table[0x36][1] = MakeNdsDescriptorL1W(OpcodeId::VPERMD,  Operand::m256, 0x01);

    // VPMASKMOVD/Q load (0x8C) and store (0x8E): NDS memory-only, W selects D/Q.
    table[0x8C][1] = MakeNdsMemOnlyDescriptorWPair(
        OpcodeId::VPMASKMOVD, OpcodeId::VPMASKMOVQ,
        Operand::m128, Operand::m256, true);
    table[0x8E][1] = MakeNdsMemOnlyDescriptorWPair(
        OpcodeId::VPMASKMOVD, OpcodeId::VPMASKMOVQ,
        Operand::m128, Operand::m256, false);

    // AVX2 variable shifts (0F38, pp=66, NDS packed).  The W bit selects the
    // element width: W=0 -> *D, W=1 -> *Q.  Note: VPSRAVQ is not an AVX2
    // instruction (introduced in AVX-512), so 0x46 only supports W=0.
    table[0x45][1] = MakeNdsDescriptorWPair(OpcodeId::VPSRLVD, OpcodeId::VPSRLVQ,
                                            Operand::m128, Operand::m256);
    table[0x46][1] = MakeNdsDescriptorW(OpcodeId::VPSRAVD, Operand::m128, Operand::m256, true, 0x01);
    table[0x47][1] = MakeNdsDescriptorWPair(OpcodeId::VPSLLVD, OpcodeId::VPSLLVQ,
                                            Operand::m128, Operand::m256);

    // AVX2 gather (pp=66, VSIB, NDS).  Each opcode encodes two mnemonics
    // distinguished by the W bit; the VSIB operand width tracks the data
    // element size.  VPGATHERQD/VGATHERQPS use XMM destination/mask even in
    // the L=1 case because the index vector is YMM-wide.
    table[0x90][1] = MakeGatherDescriptor(
        OpcodeId::VPGATHERDD, OpcodeId::VPGATHERDQ,
        Operand::m32_vsib, Operand::m64_vsib,
        Operand::xmm, Operand::xmm, Operand::ymm, Operand::ymm,
        Operand::xmm, Operand::xmm, Operand::ymm, Operand::ymm);
    table[0x91][1] = MakeGatherDescriptor(
        OpcodeId::VPGATHERQD, OpcodeId::VPGATHERQQ,
        Operand::m32_vsib, Operand::m64_vsib,
        Operand::xmm, Operand::xmm, Operand::xmm, Operand::xmm,
        Operand::xmm, Operand::xmm, Operand::ymm, Operand::ymm);
    table[0x92][1] = MakeGatherDescriptor(
        OpcodeId::VGATHERDPS, OpcodeId::VGATHERDPD,
        Operand::m32_vsib, Operand::m64_vsib,
        Operand::xmm, Operand::xmm, Operand::ymm, Operand::ymm,
        Operand::xmm, Operand::xmm, Operand::ymm, Operand::ymm);
    table[0x93][1] = MakeGatherDescriptor(
        OpcodeId::VGATHERQPS, OpcodeId::VGATHERQPD,
        Operand::m32_vsib, Operand::m64_vsib,
        Operand::xmm, Operand::xmm, Operand::xmm, Operand::xmm,
        Operand::xmm, Operand::xmm, Operand::ymm, Operand::ymm);

    table[0x17][1] = MakeNoNdsPackedDescriptor(OpcodeId::VPTEST,
        Operand::xmm, Operand::xmm, Operand::m128, Operand::ymm, Operand::ymm, Operand::m256);
    table[0x28][1] = MakeNdsDescriptor(OpcodeId::VPMULDQ, Operand::m128, Operand::m256, true);
    table[0x29][1] = MakeNdsDescriptor(OpcodeId::VPCMPEQQ, Operand::m128, Operand::m256, true);
    table[0x2B][1] = MakeNdsDescriptor(OpcodeId::VPACKUSDW, Operand::m128, Operand::m256, true);
    table[0x3A][1] = MakeNdsDescriptor(OpcodeId::VPMINUW, Operand::m128, Operand::m256, true);
    table[0x3E][1] = MakeNdsDescriptor(OpcodeId::VPMAXUW, Operand::m128, Operand::m256, true);
    {
        VexDescriptor d{};
        d.allowed_L = 0x03;
        d.allowed_W = 0x03;
        d.forms_by_L[0] = Form(OpcodeId::VMOVNTDQA, 2, Oprs(Operand::xmm, Operand::m128), VexModrmShape::Mem);
        d.forms_by_L[1] = Form(OpcodeId::VMOVNTDQA, 2, Oprs(Operand::ymm, Operand::m256), VexModrmShape::Mem);
        table[0x2A][1] = d;
        d = MakeDescriptorL1(Form(OpcodeId::VBROADCASTF128, 2, Oprs(Operand::ymm, Operand::m128), VexModrmShape::Mem));
        d.allowed_W = 0x01;
        table[0x1A][1] = d;
    }
    table[0x2C][1] = MakeNdsMemOnlyDescriptor(OpcodeId::VMASKMOVPS, Operand::m128, Operand::m256, 0x01);
    table[0x2D][1] = MakeNdsMemOnlyDescriptor(OpcodeId::VMASKMOVPD, Operand::m128, Operand::m256, 0x01);
    {
        auto d = MakeNdsMemOnlyDescriptor(OpcodeId::VMASKMOVPS, Operand::m128, Operand::m256, 0x01);
        d.forms_by_L[0] = Form(OpcodeId::VMASKMOVPS, 3, Oprs(Operand::m128, Operand::xmm, Operand::xmm), VexModrmShape::Mem);
        d.forms_by_L[1] = Form(OpcodeId::VMASKMOVPS, 3, Oprs(Operand::m256, Operand::ymm, Operand::ymm), VexModrmShape::Mem);
        table[0x2E][1] = d;
        d.forms_by_L[0] = Form(OpcodeId::VMASKMOVPD, 3, Oprs(Operand::m128, Operand::xmm, Operand::xmm), VexModrmShape::Mem);
        d.forms_by_L[1] = Form(OpcodeId::VMASKMOVPD, 3, Oprs(Operand::m256, Operand::ymm, Operand::ymm), VexModrmShape::Mem);
        table[0x2F][1] = d;
    }

    // These AVX/AVX2 forms require W=0 rather than WIG.
    for (const auto opcode : { 0x0C, 0x0D, 0x0E, 0x0F, 0x18, 0x19, 0x58, 0x59, 0x5A, 0x78, 0x79 }) {
        table[opcode][1]->allowed_W = 0x01;
    }

    return table;
}();

constexpr auto kVexMap_0F3A = [] {
    VexMapTable table{};

    // VPERM2F128: L=1 only, NDS imm8.
    {
        VexDescriptor d{};
        d.allowed_L = 0x02;
        d.allowed_W = 0x03;
        d.vvvv_required = true;
        const auto reg = Oprs(Operand::ymm, Operand::ymm, Operand::ymm, Operand::imm8);
        const auto mem = Oprs(Operand::ymm, Operand::ymm, Operand::m256, Operand::imm8);
        d.forms_by_L[1] = Form(OpcodeId::VPERM2F128, 4, reg, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem, 4);
        table[0x06][1] = d;
    }

    // VROUNDPS/PD (non-NDS packed imm8, pp=66).
    table[0x08][1] = MakeNoNdsImmDescriptor(OpcodeId::VROUNDPS,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);
    table[0x09][1] = MakeNoNdsImmDescriptor(OpcodeId::VROUNDPD,
        Operand::xmm, Operand::xmm, Operand::m128,
        Operand::ymm, Operand::ymm, Operand::m256);

    // VROUNDSS/SD (NDS scalar imm8, pp=66).
    table[0x0A][1] = MakeNdsImmDescriptor(OpcodeId::VROUNDSS, Operand::m32, Operand::m32, false);
    table[0x0B][1] = MakeNdsImmDescriptor(OpcodeId::VROUNDSD, Operand::m64, Operand::m64, false);

    // VBLENDPS/PD (NDS packed imm8).
    table[0x0C][1] = MakeNdsImmDescriptor(OpcodeId::VBLENDPS, Operand::m128, Operand::m256, true);
    table[0x0D][1] = MakeNdsImmDescriptor(OpcodeId::VBLENDPD, Operand::m128, Operand::m256, true);

    // VPBLENDW (NDS packed imm8).
    table[0x0E][1] = MakeNdsImmDescriptor(OpcodeId::VPBLENDW, Operand::m128, Operand::m256, true);

    // VPALIGNR (NDS packed imm8).
    table[0x0F][1] = MakeNdsImmDescriptor(OpcodeId::VPALIGNR, Operand::m128, Operand::m256, true);

    // VEXTRACTF128: L=1 only, non-NDS imm8.
    table[0x19][1] = MakeDescriptorL1(Form(OpcodeId::VEXTRACTF128, 3,
        Oprs(Operand::xmm, Operand::ymm, Operand::imm8),
        VexModrmShape::Both, 1, VexTrailingRole::Imm8,
        Oprs(Operand::m128, Operand::ymm, Operand::imm8), 3));

    // VINSERTF128: L=1 only, NDS imm8.
    {
        VexDescriptor d{};
        d.allowed_L = 0x02;
        d.allowed_W = 0x03;
        d.vvvv_required = true;
        const auto reg = Oprs(Operand::ymm, Operand::ymm, Operand::xmm, Operand::imm8);
        const auto mem = Oprs(Operand::ymm, Operand::ymm, Operand::m128, Operand::imm8);
        d.forms_by_L[1] = Form(OpcodeId::VINSERTF128, 4, reg, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem, 4);
        table[0x18][1] = d;
    }

    // VDPPS (NDS packed imm8).
    table[0x40][1] = MakeNdsImmDescriptor(OpcodeId::VDPPS, Operand::m128, Operand::m256, true);

    // VDPPD (NDS packed imm8, L=0 only).
    table[0x41][1] = MakeNdsImmDescriptor(OpcodeId::VDPPD, Operand::m128, Operand::m128, false);

    // VMPSADBW (NDS packed imm8).
    table[0x42][1] = MakeNdsImmDescriptor(OpcodeId::VMPSADBW, Operand::m128, Operand::m256, true);

    // /is4 blend forms (NDS, pp=66).
    table[0x4A][1] = MakeNdsIs4Descriptor(OpcodeId::VBLENDVPS, Operand::m128, Operand::m256, true);
    table[0x4B][1] = MakeNdsIs4Descriptor(OpcodeId::VBLENDVPD, Operand::m128, Operand::m256, true);
    table[0x4C][1] = MakeNdsIs4Descriptor(OpcodeId::VPBLENDVB, Operand::m128, Operand::m256, true);

    // VPERMQ / VPERMPD immediate (AVX2, L=1 only, W=1).
    {
        VexDescriptor d{};
        d.allowed_L = 0x02;
        d.allowed_W = 0x02; // W=1 only
        const auto reg = Oprs(Operand::ymm, Operand::ymm, Operand::imm8);
        const auto mem = Oprs(Operand::ymm, Operand::m256, Operand::imm8);
        d.forms_by_L[1] = Form(OpcodeId::VPERMQ, 3, reg, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem, 3);
        table[0x00][1] = d;
    }
    {
        VexDescriptor d{};
        d.allowed_L = 0x02;
        d.allowed_W = 0x02; // W=1 only
        const auto reg = Oprs(Operand::ymm, Operand::ymm, Operand::imm8);
        const auto mem = Oprs(Operand::ymm, Operand::m256, Operand::imm8);
        d.forms_by_L[1] = Form(OpcodeId::VPERMPD, 3, reg, VexModrmShape::Both, 1, VexTrailingRole::Imm8, mem, 3);
        table[0x01][1] = d;
    }

    table[0x02][1] = MakeNdsDescriptorW(OpcodeId::VPBLENDD, Operand::m128, Operand::m256, true, 0x01);
    table[0x02][1]->forms_by_L[0] = Form(OpcodeId::VPBLENDD, 4,
        Oprs(Operand::xmm, Operand::xmm, Operand::xmm, Operand::imm8), VexModrmShape::Both,
        1, VexTrailingRole::Imm8, Oprs(Operand::xmm, Operand::xmm, Operand::m128, Operand::imm8), 4);
    table[0x02][1]->forms_by_L[1] = Form(OpcodeId::VPBLENDD, 4,
        Oprs(Operand::ymm, Operand::ymm, Operand::ymm, Operand::imm8), VexModrmShape::Both,
        1, VexTrailingRole::Imm8, Oprs(Operand::ymm, Operand::ymm, Operand::m256, Operand::imm8), 4);
    table[0x04][1] = MakeNoNdsImmDescriptor(OpcodeId::VPERMILPS,
        Operand::xmm, Operand::xmm, Operand::m128, Operand::ymm, Operand::ymm, Operand::m256, 0x01);
    table[0x05][1] = MakeNoNdsImmDescriptor(OpcodeId::VPERMILPD,
        Operand::xmm, Operand::xmm, Operand::m128, Operand::ymm, Operand::ymm, Operand::m256, 0x01);

    // Extract forms have independent register and memory operand shapes.
    for (const auto& [opcode, name, reg_op, mem_op] : {
        std::tuple(0x14, OpcodeId::VPEXTRB, Operand::r32, Operand::m8),
        std::tuple(0x15, OpcodeId::VPEXTRW, Operand::r32, Operand::m16),
        std::tuple(0x17, OpcodeId::VEXTRACTPS, Operand::r32, Operand::m32) }) {
        table[opcode][1] = MakeDescriptor(Form(name, 3, Oprs(reg_op, Operand::xmm, Operand::imm8),
            VexModrmShape::Both, 1, VexTrailingRole::Imm8, Oprs(mem_op, Operand::xmm, Operand::imm8), 3));
    }
    {
        VexDescriptor d{};
        d.allowed_L = 0x01;
        d.allowed_W = 0x03;
        d.forms_by_W[0] = Form(OpcodeId::VPEXTRD, 3, Oprs(Operand::r32, Operand::xmm, Operand::imm8),
            VexModrmShape::Both, 1, VexTrailingRole::Imm8, Oprs(Operand::m32, Operand::xmm, Operand::imm8), 3);
        auto q = Form(OpcodeId::VPEXTRQ, 3, Oprs(Operand::r64, Operand::xmm, Operand::imm8),
            VexModrmShape::Both, 1, VexTrailingRole::Imm8, Oprs(Operand::m64, Operand::xmm, Operand::imm8), 3);
        q.allowed_modes = 0x02;
        d.forms_by_W[1] = q;
        table[0x16][1] = d;
    }

    // Insert forms are NDS and retain the merge source before the inserted value.
    table[0x20][1] = MakeDescriptor(Form(OpcodeId::VPINSRB, 4,
        Oprs(Operand::xmm, Operand::xmm, Operand::r32, Operand::imm8), VexModrmShape::Both,
        1, VexTrailingRole::Imm8, Oprs(Operand::xmm, Operand::xmm, Operand::m8, Operand::imm8), 4));
    table[0x20][1]->vvvv_required = true;
    table[0x21][1] = MakeDescriptor(Form(OpcodeId::VINSERTPS, 4,
        Oprs(Operand::xmm, Operand::xmm, Operand::xmm, Operand::imm8), VexModrmShape::Both,
        1, VexTrailingRole::Imm8, Oprs(Operand::xmm, Operand::xmm, Operand::m32, Operand::imm8), 4));
    table[0x21][1]->vvvv_required = true;
    {
        VexDescriptor d{};
        d.allowed_L = 0x01;
        d.allowed_W = 0x03;
        d.vvvv_required = true;
        d.forms_by_W[0] = Form(OpcodeId::VPINSRD, 4, Oprs(Operand::xmm, Operand::xmm, Operand::r32, Operand::imm8),
            VexModrmShape::Both, 1, VexTrailingRole::Imm8,
            Oprs(Operand::xmm, Operand::xmm, Operand::m32, Operand::imm8), 4);
        auto q = Form(OpcodeId::VPINSRQ, 4, Oprs(Operand::xmm, Operand::xmm, Operand::r64, Operand::imm8),
            VexModrmShape::Both, 1, VexTrailingRole::Imm8,
            Oprs(Operand::xmm, Operand::xmm, Operand::m64, Operand::imm8), 4);
        q.allowed_modes = 0x02;
        d.forms_by_W[1] = q;
        table[0x22][1] = d;
    }

    // AVX2 128-bit lane insertion/extraction and permutation.
    {
        auto d = MakeNdsImmDescriptor(OpcodeId::VINSERTI128, Operand::m128, Operand::m128, false);
        d.allowed_L = 0x02;
        d.allowed_W = 0x01;
        d.forms_by_L[1] = Form(OpcodeId::VINSERTI128, 4,
            Oprs(Operand::ymm, Operand::ymm, Operand::xmm, Operand::imm8), VexModrmShape::Both,
            1, VexTrailingRole::Imm8, Oprs(Operand::ymm, Operand::ymm, Operand::m128, Operand::imm8), 4);
        table[0x38][1] = d;
        table[0x39][1] = MakeDescriptorL1(Form(OpcodeId::VEXTRACTI128, 3,
            Oprs(Operand::xmm, Operand::ymm, Operand::imm8), VexModrmShape::Both,
            1, VexTrailingRole::Imm8, Oprs(Operand::m128, Operand::ymm, Operand::imm8), 3));
        table[0x39][1]->allowed_W = 0x01;
        d = MakeNdsImmDescriptor(OpcodeId::VPERM2I128, Operand::m256, Operand::m256, true);
        d.allowed_L = 0x02;
        d.allowed_W = 0x01;
        table[0x46][1] = d;
    }

    // AVX string comparison forms.
    for (const auto& [opcode, name] : {
        std::pair(0x60, OpcodeId::VPCMPESTRM), std::pair(0x61, OpcodeId::VPCMPESTRI),
        std::pair(0x62, OpcodeId::VPCMPISTRM), std::pair(0x63, OpcodeId::VPCMPISTRI) }) {
        auto d = MakeNoNdsCompareDescriptor(name, Operand::m128, false);
        d.allowed_L = 0x01;
        table[opcode][1] = d;
    }

    // W=0 forms (including /is4 blends and 128-bit lane operations).
    for (const auto opcode : { 0x06, 0x18, 0x19, 0x4A, 0x4B, 0x4C }) {
        table[opcode][1]->allowed_W = 0x01;
    }

    return table;
}();

constexpr auto GetDescriptor(const uint8_t map, const uint8_t opcode, const uint8_t pp) noexcept
    -> const std::optional<VexDescriptor>*
{
    if (pp > 3) return nullptr;
    const VexMapTable* table = nullptr;
    if (map == 0x01) table = &kVexMap_0F;
    else if (map == 0x02) table = &kVexMap_0F38;
    else if (map == 0x03) table = &kVexMap_0F3A;
    else return nullptr;
    return &(*table)[opcode][pp];
}

constexpr auto ModrmNeedsSib(const uint8_t modrm) noexcept -> bool
{
    return (modrm & 0b11'000'000) != 0b11'000'000 && (modrm & 0b00'000'111) == 0b00'000'100;
}

// Returns the ModR/M + SIB + displacement length for the given effective address size.
constexpr auto ModrmMemoryLength(const uint8_t modrm, const uint8_t addr_size) noexcept -> uint8_t
{
    if (addr_size == 16) {
        // 16-bit addressing: mod=00 rm=110 -> disp16; mod=01 -> disp8; mod=10 -> disp16.
        const auto mod = modrm & 0b11'000'000;
        const auto rm  = modrm & 0b00'000'111;
        if (mod == 0b00'000'000 && rm == 0b000'000'110) return 3; // disp16
        if (mod == 0b01'000'000) return 2; // disp8
        if (mod == 0b10'000'000) return 3; // disp16
        return 1;
    }
    // 32/64-bit addressing: reuse the shared kLengthTable_ModRM, which includes
    // the opcode byte; subtract it because callers already account for opcode.
    return static_cast<uint8_t>(kLengthTable_ModRM[modrm] - 1);
}

constexpr auto ResolveSibForLength(const uint8_t modrm, const uint8_t sib, const uint8_t addr_size) noexcept -> uint8_t
{
    if (addr_size == 16) return 0;
    // In 32/64-bit mode, SIB.base=101 with mod=00 adds a mandatory 4-byte displacement.
    if ((modrm & 0b11'000'000) == 0b00'000'000 && (sib & 0b000'000'111) == 0b000'000'101) {
        return 4;
    }
    return 0;
}

constexpr auto ResolveMemoryOperand(const Operand base, const uint8_t modrm, const uint8_t sib, const uint8_t addr_size) noexcept -> Operand
{
    (void)modrm;
    (void)sib;
    (void)addr_size;
    if (base == Operand::m128 || base == Operand::m256 || base == Operand::m32 || base == Operand::m64 ||
        base == Operand::m32_vsib || base == Operand::m64_vsib || base == Operand::m128_vsib || base == Operand::m256_vsib) {
        return base;
    }
    return base;
}

} // namespace

auto VexDecoder::Decode(gsl::span<const uint8_t> buffer, const VexInfo& info) noexcept -> DecodedInstruction
{
    if (info.opcode_offset >= buffer.size()) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    const uint8_t opcode = buffer[info.opcode_offset];
    const auto desc_ptr = GetDescriptor(info.map, opcode, info.pp);
    if (desc_ptr == nullptr || !desc_ptr->has_value()) {
        return ERR_UNIMPLEMENTED_DISASM;
    }
    const auto& desc = desc_ptr->value();

    // Validate L.
    const uint8_t L_bit = static_cast<uint8_t>(1u << info.L);
    if ((desc.allowed_L & L_bit) == 0) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    // Validate W.
    const uint8_t W_bit = static_cast<uint8_t>(1u << info.W);
    if ((desc.allowed_W & W_bit) == 0) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    const VexOpForm* form_ptr = nullptr;
    if (desc.forms_by_W[info.W].has_value()) {
        form_ptr = &desc.forms_by_W[info.W].value();
    } else if (desc.forms_by_L[info.L].has_value()) {
        form_ptr = &desc.forms_by_L[info.L].value();
    } else if (info.L == 1 && desc.forms_by_L[0].has_value() && desc.forms_by_reg[1] == nullptr) {
        // LIG: L=1 reuses the L=0 form when the descriptor explicitly allows it.
        form_ptr = &desc.forms_by_L[0].value();
    }

    // No-ModR/M forms still need the descriptor-wide vvvv policy.
    if (form_ptr != nullptr && form_ptr->shape == VexModrmShape::None) {
        if ((form_ptr->allowed_modes & (info.is_64bit ? 0x02u : 0x01u)) == 0) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        if (desc.vvvv_required && info.vvvv == 0x0F) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        if (!desc.vvvv_required && desc.vvvv_reserved && info.vvvv != 0x0F) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        const uint8_t len = static_cast<uint8_t>(info.prefix_length + info.vex_length + 1);
        if (len > MAX_INSTRUCTION_LENGTH) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        return { len, { form_ptr->opcode, form_ptr->operand_count, form_ptr->operands } };
    }

    // Read ModR/M before selecting optional ModR/M.reg group forms.
    const uint8_t modrm_offset = static_cast<uint8_t>(info.opcode_offset + 1);
    if (modrm_offset >= buffer.size()) {
        return ERR_INSUFFICIENT_BUFFER;
    }
    const uint8_t modrm = buffer[modrm_offset];
    const bool is_reg = (modrm & 0b11'000'000) == 0b11'000'000;

    if (desc.forms_by_reg[info.L] != nullptr) {
        const auto& group = (*desc.forms_by_reg[info.L])[(modrm >> 3) & 7];
        if (!group.has_value()) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        form_ptr = &group.value();
    }
    if (form_ptr == nullptr || (form_ptr->allowed_modes & (info.is_64bit ? 0x02u : 0x01u)) == 0) {
        return ERR_UNDEFINED_INSTRUCTION;
    }
    const auto& form = *form_ptr;

    if (form.shape == VexModrmShape::Reg && !is_reg) {
        return ERR_UNDEFINED_INSTRUCTION;
    }
    if (form.shape == VexModrmShape::Mem && is_reg) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    // Validate vvvv now that the register/memory form is known.  NDS forms require
    // a valid inverted register (vvvv != 1111); non-NDS forms normally require the
    // reserved value (vvvv == 1111).  Scalar moves are form-aware: register merge
    // uses an NDS source while memory load/store requires the reserved value.
    {
        bool require_nonreserved = desc.vvvv_required;
        bool require_reserved = !desc.vvvv_required && desc.vvvv_reserved;
        if (is_reg && desc.reg_vvvv_required) {
            require_nonreserved = true;
            require_reserved = false;
        }
        if (!is_reg && desc.mem_vvvv_reserved) {
            require_nonreserved = false;
            require_reserved = true;
        }
        if (require_nonreserved && info.vvvv == 0x0F) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        if (require_reserved && info.vvvv != 0x0F) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
    }

    uint8_t modrm_len = 0;
    uint8_t sib_extra = 0;

    if (is_reg) {
        modrm_len = 1;
    } else if (desc.uses_vsib) {
        // VSIB forms require 32/64-bit addressing with SIB/VSIB present.
        if (info.addr_size == 16) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        if ((modrm & 0b00'000'111) != 0b00'000'100) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        const uint8_t vsib_offset = static_cast<uint8_t>(modrm_offset + 1);
        if (vsib_offset >= buffer.size()) {
            return ERR_INSUFFICIENT_BUFFER;
        }
        const uint8_t vsib = buffer[vsib_offset];
        // VSIB.index=100 encodes no vector index only when VEX.X=1.  With X=0
        // the same low bits select the architecturally valid XMM12/YMM12 index.
        if (info.X && ((vsib >> 3) & 0b000'001'11) == 0b000'001'00) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
        modrm_len = ModrmMemoryLength(modrm, info.addr_size);
        sib_extra = ResolveSibForLength(modrm, vsib, info.addr_size);

        // Gather register-overlap check: destination, mask, and vector-index must differ.
        // info.vvvv holds the raw inverted VEX.vvvv field; the mask register index is
        // its 1's complement.  Destination and index use the extension bits directly.
        const uint8_t dest_reg = static_cast<uint8_t>(((modrm >> 3) & 7) | ((info.R ? 0u : 1u) << 3));
        const uint8_t mask_reg = static_cast<uint8_t>((~info.vvvv) & 0x0F);
        const uint8_t index_reg = static_cast<uint8_t>(((vsib >> 3) & 7) | ((info.X ? 0u : 1u) << 3));
        if (dest_reg == mask_reg || dest_reg == index_reg || mask_reg == index_reg) {
            return ERR_UNDEFINED_INSTRUCTION;
        }
    } else {
        modrm_len = ModrmMemoryLength(modrm, info.addr_size);
        if (ModrmNeedsSib(modrm)) {
            const uint8_t sib_offset = static_cast<uint8_t>(modrm_offset + 1);
            if (sib_offset >= buffer.size()) {
                return ERR_INSUFFICIENT_BUFFER;
            }
            const uint8_t sib = buffer[sib_offset];
            sib_extra = ResolveSibForLength(modrm, sib, info.addr_size);
        }
    }

    const uint8_t trailing_offset = static_cast<uint8_t>(modrm_offset + modrm_len + sib_extra);
    if (trailing_offset > buffer.size()) {
        return ERR_INSUFFICIENT_BUFFER;
    }

    uint8_t total_len = trailing_offset;
    if (form.trailing_size > 0) {
        total_len = static_cast<uint8_t>(total_len + form.trailing_size);
        if (total_len > buffer.size()) {
            return ERR_INSUFFICIENT_BUFFER;
        }
    }

    if (total_len > MAX_INSTRUCTION_LENGTH) {
        return ERR_UNDEFINED_INSTRUCTION;
    }

    // Select the operand pattern.
    const bool use_mem = !is_reg && (form.shape == VexModrmShape::Mem || form.shape == VexModrmShape::Both);
    const uint8_t active_count = use_mem ? form.mem_operand_count : form.operand_count;
    auto operands = use_mem ? form.mem_operands : form.operands;

    // Convert the memory pattern to the abstract memory operand.
    if (use_mem) {
        for (uint8_t i = 0; i < active_count; ++i) {
            const auto op = operands[i];
            if (op == Operand::m128 || op == Operand::m256 || op == Operand::m32 || op == Operand::m64 ||
                op == Operand::m32_vsib || op == Operand::m64_vsib || op == Operand::m128_vsib || op == Operand::m256_vsib) {
                operands[i] = ResolveMemoryOperand(op, modrm, 0, info.addr_size);
            } else if (op == Operand::m && desc.uses_vsib) {
                operands[i] = desc.vsib_op[info.W];
            }
        }
    }

    OpcodeId final_opcode = (use_mem && form.mem_opcode != OpcodeId::INVALID_OPCODE)
        ? form.mem_opcode
        : form.opcode;
    if (desc.opcode_by_W[info.W] != OpcodeId::INVALID_OPCODE) {
        final_opcode = desc.opcode_by_W[info.W];
    }

    // Gather forms use their own per-(W,L) operand pattern in architectural order:
    // destination, VSIB memory, mask.
    if (desc.uses_vsib && desc.gather_operands_valid[info.W][info.L]) {
        const auto& gops = desc.gather_operands[info.W][info.L];
        operands[0] = gops[0];
        operands[1] = gops[1];
        operands[2] = gops[2];
    }

    return { total_len, { final_opcode, active_count, operands } };
}

} // namespace xendiza::detail

// Differential test harness for xendiza (stream protocol).
// Input (stdin):  mode TAB hexbytes TAB srcid TAB expected_count
// Decodes expected_count instructions sequentially (linear sweep), advancing
// by each decoded length. Stops early on error (length >= 0xE0 convention).
// Output(stdout): srcid TAB index TAB length TAB mnemonic TAB op1,op2,...

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <xendiza/xendiza_x64.hpp>
#include <xendiza/xendiza_x86.hpp>

namespace {

const char* MnemonicName(xendiza::OpcodeId id)
{
    switch (id) {
#define MN_CASE(name) case xendiza::OpcodeId::name: return #name;
        MN_CASE(INVALID_OPCODE)
        MN_CASE(AAA) MN_CASE(AAD) MN_CASE(AAM) MN_CASE(AAS) MN_CASE(ADC) MN_CASE(ADD)
        MN_CASE(ADDPD) MN_CASE(ADDPS) MN_CASE(ADDSD) MN_CASE(ADDSS)
        MN_CASE(AND) MN_CASE(ANDPD) MN_CASE(ANDPS)
        MN_CASE(BSF) MN_CASE(BSR) MN_CASE(BSWAP) MN_CASE(BT) MN_CASE(BTC) MN_CASE(BTR) MN_CASE(BTS)
        MN_CASE(CALL) MN_CASE(CBW) MN_CASE(CDQ) MN_CASE(CDQE) MN_CASE(CLC) MN_CASE(CLD)
        MN_CASE(CLDEMOTE) MN_CASE(CLFLUSH) MN_CASE(CLI) MN_CASE(CLTS) MN_CASE(CMC)
        MN_CASE(CMOVO) MN_CASE(CMOVNO) MN_CASE(CMOVB) MN_CASE(CMOVAE) MN_CASE(CMOVZ) MN_CASE(CMOVNZ)
        MN_CASE(CMOVBE) MN_CASE(CMOVA) MN_CASE(CMOVS) MN_CASE(CMOVNS) MN_CASE(CMOVP) MN_CASE(CMOVNP)
        MN_CASE(CMOVL) MN_CASE(CMOVGE) MN_CASE(CMOVLE) MN_CASE(CMOVG)
        MN_CASE(CMP) MN_CASE(CMPSB) MN_CASE(CMPSD) MN_CASE(CMPSQ) MN_CASE(CMPSW)
        MN_CASE(CMPXCHG) MN_CASE(CMPXCHG16B) MN_CASE(CMPXCHG8B) MN_CASE(COMISD) MN_CASE(COMISS)
        MN_CASE(MOVSS) MN_CASE(WBINVD) MN_CASE(WRMSR) MN_CASE(OUTSB) MN_CASE(OUTSW) MN_CASE(OUTSD)
        MN_CASE(INSB) MN_CASE(INSW) MN_CASE(INSD)
        MN_CASE(CPUID) MN_CASE(CQO) MN_CASE(CWD) MN_CASE(CWDE)
        MN_CASE(DAA) MN_CASE(DAS) MN_CASE(DEC) MN_CASE(DIV) MN_CASE(ENTER)
        MN_CASE(F2XM1) MN_CASE(FABS) MN_CASE(FADD) MN_CASE(FADDP) MN_CASE(FBLD) MN_CASE(FBSTP)
        MN_CASE(FCHS) MN_CASE(FCLEX) MN_CASE(FCOM) MN_CASE(FCOMP) MN_CASE(FCOMPP) MN_CASE(FCOS)
        MN_CASE(FDECSTP) MN_CASE(FDIV) MN_CASE(FDIVP) MN_CASE(FDIVR) MN_CASE(FDIVRP)
        MN_CASE(FFREE) MN_CASE(FIADD) MN_CASE(FICOM) MN_CASE(FICOMP) MN_CASE(FIDIV) MN_CASE(FIDIVR)
        MN_CASE(FILD) MN_CASE(FIMUL) MN_CASE(FINCSTP) MN_CASE(FINIT) MN_CASE(FIST) MN_CASE(FISTP)
        MN_CASE(FISUB) MN_CASE(FISUBR) MN_CASE(FLD) MN_CASE(FLD1) MN_CASE(FLDCW) MN_CASE(FLDENV)
        MN_CASE(FLDL2E) MN_CASE(FLDL2T) MN_CASE(FLDLG2) MN_CASE(FLDLN2) MN_CASE(FLDPI) MN_CASE(FLDZ)
        MN_CASE(FMUL) MN_CASE(FMULP) MN_CASE(FNCLEX) MN_CASE(FNINIT) MN_CASE(FNOP) MN_CASE(FNSAVE)
        MN_CASE(FNSTCW) MN_CASE(FNSTENV) MN_CASE(FNSTSW) MN_CASE(FPATAN) MN_CASE(FPREM) MN_CASE(FPREM1)
        MN_CASE(FPTAN) MN_CASE(FRNDINT) MN_CASE(FRSTOR) MN_CASE(FSAVE) MN_CASE(FSCALE) MN_CASE(FSIN)
        MN_CASE(FSINCOS) MN_CASE(FSQRT) MN_CASE(FST) MN_CASE(FSTCW) MN_CASE(FSTENV) MN_CASE(FSTP)
        MN_CASE(FSTSW) MN_CASE(FSUB) MN_CASE(FSUBP) MN_CASE(FSUBR) MN_CASE(FSUBRP) MN_CASE(FTST)
        MN_CASE(FUCOM) MN_CASE(FUCOMP) MN_CASE(FUCOMPP) MN_CASE(FWAIT) MN_CASE(FXAM) MN_CASE(FXCH)
        MN_CASE(FXRSTOR) MN_CASE(FXSAVE) MN_CASE(FXTRACT) MN_CASE(FYL2X) MN_CASE(FYL2XP1)
        MN_CASE(HLT)
        MN_CASE(IDIV) MN_CASE(IMUL) MN_CASE(IN) MN_CASE(INC) MN_CASE(INT) MN_CASE(INT3) MN_CASE(INTO)
        MN_CASE(INVD) MN_CASE(INVLPG) MN_CASE(IRET) MN_CASE(IRETD) MN_CASE(IRETQ)
        MN_CASE(INT1)
        MN_CASE(Jcc) MN_CASE(JO) MN_CASE(JNO) MN_CASE(JB) MN_CASE(JAE) MN_CASE(JZ) MN_CASE(JNZ)
        MN_CASE(JBE) MN_CASE(JA) MN_CASE(JS) MN_CASE(JNS) MN_CASE(JP) MN_CASE(JNP)
        MN_CASE(JL) MN_CASE(JGE) MN_CASE(JLE) MN_CASE(JG)
        MN_CASE(JMP) MN_CASE(JRCXZ)
        MN_CASE(LAHF) MN_CASE(LAR) MN_CASE(LDS) MN_CASE(LEA) MN_CASE(LEAVE) MN_CASE(LES) MN_CASE(LFS)
        MN_CASE(LGDT) MN_CASE(LGS) MN_CASE(LIDT) MN_CASE(LLDT) MN_CASE(LMSW)
        MN_CASE(LODSB) MN_CASE(LODSW) MN_CASE(LODSD) MN_CASE(LODSQ)
        MN_CASE(LOOP) MN_CASE(LOOPE) MN_CASE(LOOPNE)
        MN_CASE(LSL) MN_CASE(LSS) MN_CASE(LTR)
        MN_CASE(LDMXCSR) MN_CASE(LFENCE) MN_CASE(MOVNTI) MN_CASE(SERIALIZE)
        MN_CASE(LZCNT) MN_CASE(TZCNT)
        MN_CASE(VERR) MN_CASE(VERW) MN_CASE(WRPKRU) MN_CASE(ENDBR32) MN_CASE(ENDBR64)
        MN_CASE(MFENCE) MN_CASE(MONITOR) MN_CASE(MOV) MN_CASE(MOVAPS) MN_CASE(MOVUPS)
        MN_CASE(MOVAPD) MN_CASE(MOVUPD) MN_CASE(MOVD) MN_CASE(MOVQ)
        MN_CASE(MOVSB) MN_CASE(MOVSW) MN_CASE(MOVSD) MN_CASE(MOVSQ)
        MN_CASE(MOVHLPS) MN_CASE(MOVLPS) MN_CASE(MOVLHPS) MN_CASE(MOVHPS)
        MN_CASE(MOVLPD) MN_CASE(MOVHPD) MN_CASE(MOVMSKPS) MN_CASE(MOVMSKPD)
        MN_CASE(MOVSLDUP) MN_CASE(MOVSHDUP) MN_CASE(MOVNTDQ) MN_CASE(MASKMOVDQU)
        MN_CASE(PMOVMSKB) MN_CASE(LDDQU)
        MN_CASE(MOVSX) MN_CASE(MOVSXD) MN_CASE(MOVZX) MN_CASE(MUL) MN_CASE(MWAIT)
        MN_CASE(NEG) MN_CASE(NOP) MN_CASE(NOT)
        MN_CASE(OR) MN_CASE(ORPD) MN_CASE(ORPS) MN_CASE(OUT) MN_CASE(OUTS)
        MN_CASE(PAUSE)
        MN_CASE(POP) MN_CASE(POPA) MN_CASE(POPAD) MN_CASE(POPF) MN_CASE(POPFD) MN_CASE(POPFQ)
        MN_CASE(PREFETCHNTA) MN_CASE(PREFETCHT0) MN_CASE(PREFETCHT1) MN_CASE(PREFETCHT2)
        MN_CASE(PUSH) MN_CASE(PUSHA) MN_CASE(PUSHAD) MN_CASE(PUSHF) MN_CASE(PUSHFD) MN_CASE(PUSHFQ)
        MN_CASE(RCL) MN_CASE(RCR) MN_CASE(RDMSR) MN_CASE(RDPID) MN_CASE(RDPKRU) MN_CASE(RDPMC)
        MN_CASE(RDRAND) MN_CASE(RDSEED) MN_CASE(RDTSC) MN_CASE(RDTSCP) MN_CASE(RET) MN_CASE(RETF)
        MN_CASE(ROL) MN_CASE(ROR) MN_CASE(RSM)
        MN_CASE(SAHF) MN_CASE(SAL) MN_CASE(SAR) MN_CASE(SBB) MN_CASE(SCASB) MN_CASE(SCASD)
        MN_CASE(SCASQ) MN_CASE(SCASW)
        MN_CASE(SETO) MN_CASE(SETNO) MN_CASE(SETB) MN_CASE(SETAE) MN_CASE(SETZ) MN_CASE(SETNZ)
        MN_CASE(SETBE) MN_CASE(SETA) MN_CASE(SETS) MN_CASE(SETNS) MN_CASE(SETP) MN_CASE(SETNP)
        MN_CASE(SETL) MN_CASE(SETGE) MN_CASE(SETLE) MN_CASE(SETG)
        MN_CASE(SFENCE) MN_CASE(SGDT) MN_CASE(SHLD) MN_CASE(SHRD) MN_CASE(SIDT)
        MN_CASE(SLDT) MN_CASE(SMSW) MN_CASE(STAC) MN_CASE(STC) MN_CASE(STD) MN_CASE(STI)
        MN_CASE(STMXCSR) MN_CASE(STOSB) MN_CASE(STOSW) MN_CASE(STOSD) MN_CASE(STOSQ) MN_CASE(STR)
        MN_CASE(SUB) MN_CASE(SUBPD) MN_CASE(SUBPS) MN_CASE(SUBSD) MN_CASE(SUBSS) MN_CASE(SWAPGS)
        MN_CASE(SYSCALL) MN_CASE(SYSENTER) MN_CASE(SYSEXIT) MN_CASE(SYSRET)
        MN_CASE(TEST)
        MN_CASE(UCOMISD) MN_CASE(UCOMISS) MN_CASE(UD) MN_CASE(XADD) MN_CASE(XCHG) MN_CASE(XGETBV)
        MN_CASE(MULSS) MN_CASE(MULSD)
        MN_CASE(DIVSS) MN_CASE(DIVSD) MN_CASE(SQRTPS) MN_CASE(SQRTPD) MN_CASE(SQRTSS) MN_CASE(SQRTSD)
        MN_CASE(RSQRTPS) MN_CASE(RCPPS) MN_CASE(ANDNPS) MN_CASE(ANDNPD) MN_CASE(MINPS) MN_CASE(MINPD)
        MN_CASE(MINSS) MN_CASE(MINSD) MN_CASE(MAXPS) MN_CASE(MAXPD) MN_CASE(MAXSS) MN_CASE(MAXSD)
        MN_CASE(CMPPS) MN_CASE(CMPPD) MN_CASE(CMPSS)
        MN_CASE(SHUFPS) MN_CASE(SHUFPD) MN_CASE(PSHUFD) MN_CASE(PSHUFHW) MN_CASE(PSHUFLW)
        MN_CASE(PINSRW) MN_CASE(PEXTRW) MN_CASE(CVTPS2PD) MN_CASE(CVTPD2PS) MN_CASE(CVTSS2SD)
        MN_CASE(CVTSD2SS) MN_CASE(CVTDQ2PS) MN_CASE(CVTPS2DQ) MN_CASE(CVTTPS2DQ)
        MN_CASE(CVTPD2DQ) MN_CASE(CVTTPD2DQ) MN_CASE(CVTDQ2PD) MN_CASE(CVTSI2SS) MN_CASE(CVTSI2SD)
        MN_CASE(CVTTSS2SI) MN_CASE(CVTTSD2SI) MN_CASE(CVTSS2SI) MN_CASE(CVTSD2SI)
        MN_CASE(ADDSUBPS) MN_CASE(ADDSUBPD) MN_CASE(HADDPS) MN_CASE(HADDPD) MN_CASE(HSUBPS) MN_CASE(HSUBPD)
        MN_CASE(MOVDQA) MN_CASE(MOVDQU) MN_CASE(PUNPCKLBW) MN_CASE(PUNPCKLWD) MN_CASE(PUNPCKLDQ)
        MN_CASE(PACKSSWB) MN_CASE(PCMPGTB) MN_CASE(PCMPGTW) MN_CASE(PCMPGTD) MN_CASE(PACKUSWB)
        MN_CASE(PUNPCKHBW) MN_CASE(PUNPCKHWD) MN_CASE(PUNPCKHDQ) MN_CASE(PACKSSDW)
        MN_CASE(PUNPCKLQDQ) MN_CASE(PUNPCKHQDQ) MN_CASE(PCMPEQB) MN_CASE(PCMPEQW) MN_CASE(PCMPEQD)
        MN_CASE(PSRLW) MN_CASE(PSRLD) MN_CASE(PSRLQ) MN_CASE(PSRLDQ) MN_CASE(PADDQ) MN_CASE(PMULLW)
        MN_CASE(PSUBUSB) MN_CASE(PSUBUSW) MN_CASE(PMINUB) MN_CASE(PAND) MN_CASE(PADDUSB) MN_CASE(PADDUSW)
        MN_CASE(PMAXUB) MN_CASE(PANDN) MN_CASE(PAVGB) MN_CASE(PAVGW) MN_CASE(PSRAW) MN_CASE(PSRAD)
        MN_CASE(PMULHUW) MN_CASE(PMULHW) MN_CASE(PSUBSB) MN_CASE(PSUBSW) MN_CASE(PMINSW) MN_CASE(POR)
        MN_CASE(PADDSB) MN_CASE(PADDSW) MN_CASE(PMAXSW) MN_CASE(PXOR) MN_CASE(PSLLW) MN_CASE(PSLLD)
        MN_CASE(PSLLQ) MN_CASE(PSLLDQ) MN_CASE(PMULUDQ) MN_CASE(PMADDWD) MN_CASE(PSADBW)
        MN_CASE(PSUBB) MN_CASE(PSUBW) MN_CASE(PSUBD) MN_CASE(PSUBQ) MN_CASE(PADDB) MN_CASE(PADDW)
        MN_CASE(PADDD)
        MN_CASE(XLAT) MN_CASE(XLATB) MN_CASE(XOR) MN_CASE(XORPD) MN_CASE(XORPS)
        MN_CASE(XSAVE) MN_CASE(XSAVEC) MN_CASE(XSAVEOPT) MN_CASE(XSAVES)
        MN_CASE(XRSTOR) MN_CASE(XRSTORS) MN_CASE(XSETBV) MN_CASE(XTEST)
#undef MN_CASE
    default: {
        static thread_local char buf[16];
        std::snprintf(buf, sizeof buf, "ID_%u", unsigned(id));
        return buf;
    }
    }
}

const char* OperandName(xendiza::Operand op)
{
    switch (op) {
#define OP_CASE(name) case xendiza::Operand::name: return #name;
        OP_CASE(noopr)
        OP_CASE(al) OP_CASE(cl) OP_CASE(dl) OP_CASE(bl) OP_CASE(ah) OP_CASE(ch) OP_CASE(dh) OP_CASE(bh)
        OP_CASE(ax) OP_CASE(cx) OP_CASE(dx) OP_CASE(bx) OP_CASE(sp) OP_CASE(bp) OP_CASE(si) OP_CASE(di)
        OP_CASE(eax) OP_CASE(ecx) OP_CASE(edx) OP_CASE(ebx) OP_CASE(esp) OP_CASE(ebp) OP_CASE(esi) OP_CASE(edi)
        OP_CASE(rax) OP_CASE(rcx) OP_CASE(rdx) OP_CASE(rbx) OP_CASE(rsp) OP_CASE(rbp) OP_CASE(rsi) OP_CASE(rdi)
        OP_CASE(rel8) OP_CASE(rel16) OP_CASE(rel32) OP_CASE(ptr16_16) OP_CASE(ptr16_32)
        OP_CASE(r8) OP_CASE(r16) OP_CASE(r32) OP_CASE(r64)
        OP_CASE(xmm) OP_CASE(st0) OP_CASE(sti) OP_CASE(lit1)
        OP_CASE(imm8) OP_CASE(imm16) OP_CASE(imm32) OP_CASE(imm64)
        OP_CASE(rm8) OP_CASE(rm16) OP_CASE(rm32) OP_CASE(rm64)
        OP_CASE(m) OP_CASE(m8) OP_CASE(m16) OP_CASE(m32) OP_CASE(m64) OP_CASE(m128)
        OP_CASE(m32fp) OP_CASE(m64fp) OP_CASE(m80fp)
        OP_CASE(stack_m8) OP_CASE(stack_m16) OP_CASE(stack_m32) OP_CASE(stack_m64)
        OP_CASE(moffs8) OP_CASE(moffs16) OP_CASE(moffs32) OP_CASE(moffs64)
        OP_CASE(m16_32) OP_CASE(m16_64)
        OP_CASE(sreg) OP_CASE(es) OP_CASE(cs) OP_CASE(ss) OP_CASE(ds) OP_CASE(fs) OP_CASE(gs)
        OP_CASE(creg) OP_CASE(cr0) OP_CASE(cr2) OP_CASE(cr3) OP_CASE(cr4)
        OP_CASE(dr) OP_CASE(dr0) OP_CASE(dr1) OP_CASE(dr2) OP_CASE(dr3) OP_CASE(dr6) OP_CASE(dr7)
        OP_CASE(es_m8) OP_CASE(cs_m8) OP_CASE(ss_m8) OP_CASE(ds_m8) OP_CASE(fs_m8) OP_CASE(gs_m8)
        OP_CASE(es_m16) OP_CASE(cs_m16) OP_CASE(ss_m16) OP_CASE(ds_m16) OP_CASE(fs_m16) OP_CASE(gs_m16)
        OP_CASE(es_m32) OP_CASE(cs_m32) OP_CASE(ss_m32) OP_CASE(ds_m32) OP_CASE(fs_m32) OP_CASE(gs_m32)
        OP_CASE(es_m64) OP_CASE(cs_m64) OP_CASE(ss_m64) OP_CASE(ds_m64) OP_CASE(fs_m64) OP_CASE(gs_m64)
        OP_CASE(es_moffs8) OP_CASE(cs_moffs8) OP_CASE(ss_moffs8) OP_CASE(ds_moffs8) OP_CASE(fs_moffs8) OP_CASE(gs_moffs8)
        OP_CASE(es_moffs16) OP_CASE(cs_moffs16) OP_CASE(ss_moffs16) OP_CASE(ds_moffs16) OP_CASE(fs_moffs16) OP_CASE(gs_moffs16)
        OP_CASE(es_moffs32) OP_CASE(cs_moffs32) OP_CASE(ss_moffs32) OP_CASE(ds_moffs32) OP_CASE(fs_moffs32) OP_CASE(gs_moffs32)
        OP_CASE(es_moffs64) OP_CASE(cs_moffs64) OP_CASE(ss_moffs64) OP_CASE(ds_moffs64) OP_CASE(fs_moffs64) OP_CASE(gs_moffs64)
#undef OP_CASE
    default: {
        static thread_local char buf[16];
        std::snprintf(buf, sizeof buf, "OP_%u", unsigned(op));
        return buf;
    }
    }
}

unsigned HexVal(char c)
{
    if (c >= '0' && c <= '9') return unsigned(c - '0');
    if (c >= 'a' && c <= 'f') return unsigned(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return unsigned(c - 'A' + 10);
    return 0;
}

} // namespace

int main()
{
    char buf[16384];
    while (std::fgets(buf, sizeof buf, stdin)) {
        std::string line(buf);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        if (line.empty()) continue;

        // mode TAB hex TAB srcid TAB count
        std::string fields[4];
        size_t start = 0;
        for (int i = 0; i < 4; ++i) {
            auto t = line.find('\t', start);
            fields[i] = (t == std::string::npos) ? line.substr(start) : line.substr(start, t - start);
            if (t == std::string::npos) { fields[3] = fields[i]; break; }
            start = t + 1;
        }
        int mode = std::atoi(fields[0].c_str());
        const std::string& hex = fields[1];
        const std::string& srcid = fields[2];
        int count = std::atoi(fields[3].c_str());

        uint8_t bytes[256];
        size_t n = 0;
        for (size_t i = 0; i + 1 < hex.size() && n < 256; i += 2)
            bytes[n++] = uint8_t((HexVal(hex[i]) << 4) | HexVal(hex[i + 1]));

        size_t off = 0;
        for (int i = 0; i < count; ++i) {
            if (off >= n) {
                std::printf("%s\t%d\t0\t<EOF>\t\n", srcid.c_str(), i);
                break;
            }
            auto r = (mode == 64)
                ? xendiza::detail::X64Traits::Disasm(gsl::span<const uint8_t>(bytes + off, n - off))
                : xendiza::detail::X86Traits::Disasm(gsl::span<const uint8_t>(bytes + off, n - off));
            const char* mname = MnemonicName(r.instrId.opcode);
            std::string ops;
            for (uint8_t k = 0; k < r.instrId.operand_count && k < 4; ++k) {
                if (k) ops += ",";
                ops += OperandName(r.instrId.operands.operand[k]);
            }
            std::printf("%s\t%d\t%u\t%s\t%s\n", srcid.c_str(), i,
                        unsigned(r.length), mname ? mname : "UNMAPPED_ID", ops.c_str());
            if (r.length >= 0xE0) break;  // error code: stop the stream
            off += r.length;
        }
        std::fflush(stdout);
    }
    return 0;
}

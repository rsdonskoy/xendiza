// Differential test harness for xendiza (stream protocol).
// Input (stdin):  mode TAB hexbytes TAB srcid TAB expected_count
// Decodes expected_count instructions sequentially (linear sweep), advancing
// by each decoded length. Stops early on error (length >= 0xE0 convention).
// Output(stdout): srcid TAB index TAB length TAB mnemonic TAB op1,op2,...
//
// This harness uses only the public C and C++ entry points.  Every vector is
// decoded through both APIs and the results are compared; a mismatch is
// reported as a synthetic API_MISMATCH result so the strict inventory checker
// fails the vector.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <gsl/span>

#include <xendiza/xendiza.hpp>
#include <xendiza/xendiza_c.h>

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
        MN_CASE(VERR) MN_CASE(VERW)
        MN_CASE(VADDPD) MN_CASE(VADDPS) MN_CASE(VADDSD) MN_CASE(VADDSS)
        MN_CASE(VANDNPD) MN_CASE(VANDNPS) MN_CASE(VANDPD) MN_CASE(VANDPS)
        MN_CASE(VCMPPD) MN_CASE(VCMPPS) MN_CASE(VCMPSD) MN_CASE(VCMPSS)
        MN_CASE(VCOMISD) MN_CASE(VCOMISS)
        MN_CASE(VCVTDQ2PS) MN_CASE(VCVTPS2DQ) MN_CASE(VCVTTPS2DQ)
        MN_CASE(VCVTPD2PS) MN_CASE(VCVTPS2PD)
        MN_CASE(VCVTSD2SS) MN_CASE(VCVTSS2SD)
        MN_CASE(VDIVPD) MN_CASE(VDIVPS) MN_CASE(VDIVSD) MN_CASE(VDIVSS)
        MN_CASE(VHADDPD) MN_CASE(VHADDPS) MN_CASE(VHSUBPD) MN_CASE(VHSUBPS)
        MN_CASE(VMAXPD) MN_CASE(VMAXPS) MN_CASE(VMAXSD) MN_CASE(VMAXSS)
        MN_CASE(VMINPD) MN_CASE(VMINPS) MN_CASE(VMINSD) MN_CASE(VMINSS)
        MN_CASE(VMOVAPD) MN_CASE(VMOVAPS)
        MN_CASE(VMOVD) MN_CASE(VMOVQ)
        MN_CASE(VMOVHPD) MN_CASE(VMOVHPS) MN_CASE(VMOVLHPS) MN_CASE(VMOVLPD) MN_CASE(VMOVLPS) MN_CASE(VMOVHLPS)
        MN_CASE(VMOVMSKPD) MN_CASE(VMOVMSKPS)
        MN_CASE(VMOVNTPS) MN_CASE(VMOVNTPD)
        MN_CASE(VMOVSD) MN_CASE(VMOVSS)
        MN_CASE(VMOVUPD) MN_CASE(VMOVUPS)
        MN_CASE(VMULPD) MN_CASE(VMULPS) MN_CASE(VMULSD) MN_CASE(VMULSS)
        MN_CASE(VORPD) MN_CASE(VORPS)
        MN_CASE(VPABSB) MN_CASE(VPABSD) MN_CASE(VPABSW)
        MN_CASE(VPADDB) MN_CASE(VPADDD) MN_CASE(VPADDQ) MN_CASE(VPADDW)
        MN_CASE(VPAND) MN_CASE(VPANDN)
        MN_CASE(VPCMPEQB) MN_CASE(VPCMPEQD) MN_CASE(VPCMPEQQ) MN_CASE(VPCMPEQW)
        MN_CASE(VPCMPGTB) MN_CASE(VPCMPGTD) MN_CASE(VPCMPGTQ) MN_CASE(VPCMPGTW)
        MN_CASE(VPMOVMSKB)
        MN_CASE(VPMULHUW) MN_CASE(VPMULHW) MN_CASE(VPMULLD) MN_CASE(VPMULLW) MN_CASE(VPMULUDQ)
        MN_CASE(VPOR)
        MN_CASE(VPSHUFB) MN_CASE(VPSHUFD) MN_CASE(VPSHUFHW) MN_CASE(VPSHUFLW)
        MN_CASE(VPSLLD) MN_CASE(VPSLLDQ) MN_CASE(VPSLLQ) MN_CASE(VPSLLW)
        MN_CASE(VPSRAD) MN_CASE(VPSRAW) MN_CASE(VPSRLD) MN_CASE(VPSRLDQ) MN_CASE(VPSRLQ) MN_CASE(VPSRLW)
        MN_CASE(VPSUBB) MN_CASE(VPSUBD) MN_CASE(VPSUBQ) MN_CASE(VPSUBW)
        MN_CASE(VPUNPCKHBW) MN_CASE(VPUNPCKHDQ) MN_CASE(VPUNPCKHQDQ) MN_CASE(VPUNPCKHWD)
        MN_CASE(VPUNPCKLBW) MN_CASE(VPUNPCKLDQ) MN_CASE(VPUNPCKLQDQ) MN_CASE(VPUNPCKLWD)
        MN_CASE(VPXOR)
        MN_CASE(VROUNDPD) MN_CASE(VROUNDPS) MN_CASE(VROUNDSD) MN_CASE(VROUNDSS)
        MN_CASE(VRCPPS) MN_CASE(VRCPSS)
        MN_CASE(VRSQRTPS) MN_CASE(VRSQRTSS)
        MN_CASE(VSQRTPD) MN_CASE(VSQRTPS) MN_CASE(VSQRTSD) MN_CASE(VSQRTSS)
        MN_CASE(VSHUFPD) MN_CASE(VSHUFPS)
        MN_CASE(VSUBPD) MN_CASE(VSUBPS) MN_CASE(VSUBSD) MN_CASE(VSUBSS)
        MN_CASE(VUCOMISD) MN_CASE(VUCOMISS)
        MN_CASE(VUNPCKHPD) MN_CASE(VUNPCKHPS) MN_CASE(VUNPCKLPD) MN_CASE(VUNPCKLPS)
        MN_CASE(VXORPD) MN_CASE(VXORPS)
        MN_CASE(VBROADCASTI128)
        MN_CASE(VBLENDPD) MN_CASE(VBLENDPS) MN_CASE(VBLENDVPD) MN_CASE(VBLENDVPS)
        MN_CASE(VPBLENDD) MN_CASE(VPBLENDVB) MN_CASE(VPBLENDW)
        MN_CASE(VPBROADCASTB) MN_CASE(VPBROADCASTD) MN_CASE(VPBROADCASTQ)
        MN_CASE(VPBROADCASTSD) MN_CASE(VPBROADCASTSS) MN_CASE(VPBROADCASTW)
        MN_CASE(VDPPS) MN_CASE(VDPPD)
        MN_CASE(VGATHERDPD) MN_CASE(VGATHERDPS) MN_CASE(VGATHERQPD) MN_CASE(VGATHERQPS)
        MN_CASE(VPGATHERDD) MN_CASE(VPGATHERDQ) MN_CASE(VPGATHERQD) MN_CASE(VPGATHERQQ)
        MN_CASE(VEXTRACTF128) MN_CASE(VEXTRACTI128) MN_CASE(VINSERTF128) MN_CASE(VINSERTI128)
        MN_CASE(VMPSADBW)
        MN_CASE(VPALIGNR)
        MN_CASE(VPERM2F128) MN_CASE(VPERM2I128)
        MN_CASE(VPERMD) MN_CASE(VPERMILPD) MN_CASE(VPERMILPS)
        MN_CASE(VPSLLVD) MN_CASE(VPSLLVQ)
        MN_CASE(VPSRAVD) MN_CASE(VPSRAVQ)
        MN_CASE(VPSRLVD) MN_CASE(VPSRLVQ)
        MN_CASE(VPERMPD) MN_CASE(VPERMPS) MN_CASE(VPERMQ)
        MN_CASE(VPHADDD) MN_CASE(VPHADDSW) MN_CASE(VPHADDW) MN_CASE(VPHMINPOSUW)
        MN_CASE(VPHSUBD) MN_CASE(VPHSUBSW) MN_CASE(VPHSUBW)
        MN_CASE(VPMASKMOVD) MN_CASE(VPMASKMOVQ) MN_CASE(VPMADDUBSW)
        MN_CASE(VPMAXSB) MN_CASE(VPMAXSD) MN_CASE(VPMAXUB) MN_CASE(VPMAXUD)
        MN_CASE(VPMINSB) MN_CASE(VPMINSD) MN_CASE(VPMINUB) MN_CASE(VPMINUD)
        MN_CASE(VPMOVSXBD) MN_CASE(VPMOVSXBQ) MN_CASE(VPMOVSXBW)
        MN_CASE(VPMOVSXDQ) MN_CASE(VPMOVSXWD) MN_CASE(VPMOVSXWQ)
        MN_CASE(VPMOVZXBD) MN_CASE(VPMOVZXBQ) MN_CASE(VPMOVZXBW)
        MN_CASE(VPMOVZXDQ) MN_CASE(VPMOVZXWD) MN_CASE(VPMOVZXWQ)
        MN_CASE(VPMULHRSW)
        MN_CASE(VPSIGNB) MN_CASE(VPSIGND) MN_CASE(VPSIGNW)
        MN_CASE(VTESTPD) MN_CASE(VTESTPS)
        MN_CASE(VZEROALL) MN_CASE(VZEROUPPER)
        MN_CASE(VADDSUBPD) MN_CASE(VADDSUBPS)
        MN_CASE(VBROADCASTF128) MN_CASE(VBROADCASTSD) MN_CASE(VBROADCASTSS)
        MN_CASE(VCVTDQ2PD) MN_CASE(VCVTPD2DQ) MN_CASE(VCVTSD2SI)
        MN_CASE(VCVTSI2SD) MN_CASE(VCVTSI2SS) MN_CASE(VCVTSS2SI)
        MN_CASE(VCVTTPD2DQ) MN_CASE(VCVTTSD2SI) MN_CASE(VCVTTSS2SI)
        MN_CASE(VEXTRACTPS) MN_CASE(VINSERTPS) MN_CASE(VLDDQU)
        MN_CASE(VLDMXCSR) MN_CASE(VSTMXCSR)
        MN_CASE(VMASKMOVDQU) MN_CASE(VMASKMOVPD) MN_CASE(VMASKMOVPS)
        MN_CASE(VMOVDDUP) MN_CASE(VMOVDQA) MN_CASE(VMOVDQU)
        MN_CASE(VMOVNTDQ) MN_CASE(VMOVNTDQA) MN_CASE(VMOVSHDUP) MN_CASE(VMOVSLDUP)
        MN_CASE(VPACKSSDW) MN_CASE(VPACKSSWB) MN_CASE(VPACKUSDW) MN_CASE(VPACKUSWB)
        MN_CASE(VPADDSB) MN_CASE(VPADDSW) MN_CASE(VPADDUSB) MN_CASE(VPADDUSW)
        MN_CASE(VPAVGB) MN_CASE(VPAVGW)
        MN_CASE(VPCMPESTRI) MN_CASE(VPCMPESTRM) MN_CASE(VPCMPISTRI) MN_CASE(VPCMPISTRM)
        MN_CASE(VPEXTRB) MN_CASE(VPEXTRD) MN_CASE(VPEXTRQ) MN_CASE(VPEXTRW)
        MN_CASE(VPINSRB) MN_CASE(VPINSRD) MN_CASE(VPINSRQ) MN_CASE(VPINSRW)
        MN_CASE(VPMADDWD) MN_CASE(VPMAXSW) MN_CASE(VPMAXUW)
        MN_CASE(VPMINSW) MN_CASE(VPMINUW) MN_CASE(VPMULDQ) MN_CASE(VPSADBW)
        MN_CASE(VPSUBSB) MN_CASE(VPSUBSW) MN_CASE(VPSUBUSB) MN_CASE(VPSUBUSW)
        MN_CASE(VPTEST)
        MN_CASE(WRPKRU) MN_CASE(ENDBR32) MN_CASE(ENDBR64)
        MN_CASE(MFENCE) MN_CASE(MONITOR) MN_CASE(MOV) MN_CASE(MOVAPS) MN_CASE(MOVUPS)
        MN_CASE(MOVAPD) MN_CASE(MOVUPD) MN_CASE(MOVD) MN_CASE(MOVQ)
        MN_CASE(MOVSB) MN_CASE(MOVSW) MN_CASE(MOVSD) MN_CASE(MOVSQ)
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
        OP_CASE(xmm) OP_CASE(ymm) OP_CASE(st0) OP_CASE(sti) OP_CASE(lit1)
        OP_CASE(imm8) OP_CASE(imm16) OP_CASE(imm32) OP_CASE(imm64)
        OP_CASE(rm8) OP_CASE(rm16) OP_CASE(rm32) OP_CASE(rm64)
        OP_CASE(m) OP_CASE(m8) OP_CASE(m16) OP_CASE(m32) OP_CASE(m64) OP_CASE(m128) OP_CASE(m256)
        OP_CASE(m32_vsib) OP_CASE(m64_vsib) OP_CASE(m128_vsib) OP_CASE(m256_vsib)
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

// Decode through both public C++ and C entry points and compare.
// On success returns the shared length and fills `mnemonic`/`ops`.
// On error returns the error code (>= 0xE0); `mnemonic` and `ops` are cleared.
// If the two APIs disagree, returns the synthetic mismatch code 0xED.
unsigned DecodeBoth(int mode, const uint8_t* bytes, size_t size,
                    const char*& mnemonic, std::string& ops)
{
    mnemonic = "";
    ops.clear();

    const auto cpp = (mode == 64)
        ? xendiza::Disasm<64>(gsl::span<const uint8_t>(bytes, size))
        : xendiza::Disasm<32>(gsl::span<const uint8_t>(bytes, size));

    const auto c = (mode == 64)
        ? xendiza_disasm64(bytes, size)
        : xendiza_disasm32(bytes, size);

    // Compare length (which also encodes error codes).
    if (cpp.length != c.length) {
        return 0xED;
    }

    // Error codes are returned as length values >= 0xE0.
    if (cpp.length >= 0xE0) {
        return cpp.length;
    }

    // Compare opcode, operand count, and ordered operands.
    if (static_cast<uint16_t>(cpp.instrId.opcode) != c.opcode) {
        return 0xED;
    }
    if (cpp.instrId.operand_count != c.operand_count) {
        return 0xED;
    }
    for (uint8_t k = 0; k < cpp.instrId.operand_count && k < 4; ++k) {
        if (static_cast<uint16_t>(cpp.instrId.operands.operand[k]) != c.operands[k]) {
            return 0xED;
        }
    }

    mnemonic = MnemonicName(cpp.instrId.opcode);
    for (uint8_t k = 0; k < cpp.instrId.operand_count && k < 4; ++k) {
        if (k) ops += ",";
        ops += OperandName(cpp.instrId.operands.operand[k]);
    }
    return cpp.length;
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
            const char* mnemonic = "";
            std::string ops;
            const unsigned len = DecodeBoth(mode, bytes + off, n - off, mnemonic, ops);
            std::printf("%s\t%d\t%u\t%s\t%s\n", srcid.c_str(), i,
                        len, mnemonic ? mnemonic : "UNMAPPED_ID", ops.c_str());
            if (len >= 0xE0) break;  // error code: stop the stream
            off += len;
        }
        std::fflush(stdout);
    }
    return 0;
}

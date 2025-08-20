//===- ArmPrettyPrinter.cpp -------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//

#include "ArmPrettyPrinter.hpp"
#include "AuxDataSchema.hpp"
#include "AuxDataUtils.hpp"
#include "StringUtils.hpp"
#include "driver/Logger.h"
#include <iostream>

namespace gtirb_pprint {

// Replace special characters rejected by assembler with '.' character.
// NOTE: It was observed that the IAR compiler produces such symbols with these
// special characters.
static std::string replaceSpecialChars(const std::string& S) {
  std::string Name(S);
  for (size_t I = 0; I < Name.size(); I++) {
    switch (Name[I]) {
    case '?':
    case '(':
    case ')':
    case '{':
    case '}':
    case ' ':
    case ':':
      Name[I] = '.';
      continue;
    default:
      continue;
    }
  }
  return Name;
}

std::string ArmSyntax::formatSectionName(const std::string& S) const {
  return replaceSpecialChars(S);
}

std::string ArmSyntax::formatFunctionName(const std::string& S) const {
  return replaceSpecialChars(S);
}

std::string ArmSyntax::formatSymbolName(const std::string& S) const {
  return replaceSpecialChars(S);
}

ArmPrettyPrinter::ArmPrettyPrinter(gtirb::Context& context_,
                                   const gtirb::Module& module_,
                                   const ArmSyntax& syntax_,

                                   const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_),
      armSyntax(syntax_) {
  // Setup Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM), &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
  cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

void ArmPrettyPrinter::printHeader(std::ostream& os) {
  os << "# ARM " << std::endl;
  os << ".syntax unified" << std::endl;
  os << ".arch_extension sec" << std::endl;
}

void ArmPrettyPrinter::setDecodeMode(std::ostream& Os,
                                     const gtirb::CodeBlock& x) {
  if (x.getDecodeMode() == gtirb::DecodeMode::Thumb) {
    Os << ".thumb" << std::endl;
  } else {
    Os << ".arm" << std::endl;
  }
}

const std::vector<size_t> ArmCsModes = {
    CS_MODE_ARM | CS_MODE_V8,
    CS_MODE_ARM,
};
const std::vector<size_t> ThumbCsModes = {
    CS_MODE_THUMB | CS_MODE_V8,
    CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_MCLASS,
    CS_MODE_THUMB,
    CS_MODE_THUMB | CS_MODE_MCLASS,
};

void ArmPrettyPrinter::printBlockContents(std::ostream& Os,
                                          const gtirb::CodeBlock& X,
                                          uint64_t Offset) {
  if (Offset > X.getSize()) {
    return;
  }

  gtirb::Addr Addr = *X.getAddress();
  Os << '\n';

  const std::vector<size_t>& CsModes =
      X.getDecodeMode() != gtirb::DecodeMode::Thumb ? ArmCsModes : ThumbCsModes;

  std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> InsnPtr;
  size_t InsnCount = 0;

  // NOTE: If the ARM CPU profile is not known, we may have to switch modes
  // to successfully decode all instructions.
  // Thumb2 MRS and MSR instructions support a larger set of `<spec_reg>` on
  // M-profile devices, so they do not decode without CS_MODE_MCLASS.
  // The Thumb 'blx label' instruction does not decode with CS_MODE_MCLASS,
  // because it is not a supported instruction on M-profile devices.
  //
  // This loop is to try out multiple CS modes to see if decoding succeeds.
  // Currently, this is done only when the arch type info is not available.
  bool Success = false;
  for (size_t CsMode : CsModes) {
    cs_insn* Insn = nullptr;

    cs_option(this->csHandle, CS_OPT_MODE, CsMode);
    InsnCount = cs_disasm(this->csHandle, X.rawBytes<uint8_t>() + Offset,
                          X.getSize() - Offset,
                          static_cast<uint64_t>(Addr) + Offset, 0, &Insn);

    // Exception-safe cleanup of instructions
    std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> TmpInsnPtr(
        Insn, [InsnCount](cs_insn* Instr) { cs_free(Instr, InsnCount); });

    size_t TotalSize = 0;
    for (size_t J = 0; J < InsnCount; J++) {
      TotalSize += Insn[J].size;
    }
    // If the sum of the instruction sizes equals to the block size, that
    // indicates the decoding succeeded.
    Success = (TotalSize == X.getSize() - Offset);
    // Keep the decoding attempt.
    if (Success) {
      // Assign the ownership of TmpInsnPtr to InsnPtr. This passes along the
      // deleter as well.
      // https://en.cppreference.com/w/cpp/memory/unique_ptr/operator%3D
      InsnPtr = std::move(TmpInsnPtr);
      break;
    }
  }

  if (!Success) {
    LOG_ERROR << "Failed to decode block at " << std::hex
              << static_cast<uint64_t>(Addr) + Offset << std::dec;
    std::exit(EXIT_FAILURE);
  }

  gtirb::Offset BlockOffset(X.getUUID(), Offset);
  for (size_t I = 0; I < InsnCount; I++) {
    fixupInstruction((&(*InsnPtr))[I]);
    printInstruction(Os, X, (&(*InsnPtr))[I], BlockOffset);
    BlockOffset.Displacement += (&(*InsnPtr))[I].size;
  }

  // print any CFI directives located at the end of the block
  // e.g. '.cfi_endproc' is usually attached to the end of the block
  printCFIDirectives(Os, BlockOffset);
}

static std::string armCc2String(arm_cc CC, bool Upper = false) {
  std::string Ans = "";
  switch (CC) {
  case ARM_CC_EQ:
    Ans = "eq";
    break;
  case ARM_CC_NE:
    Ans = "ne";
    break;
  case ARM_CC_HS:
    Ans = "hs";
    break;
  case ARM_CC_LO:
    Ans = "lo";
    break;
  case ARM_CC_MI:
    Ans = "mi";
    break;
  case ARM_CC_PL:
    Ans = "pl";
    break;
  case ARM_CC_VS:
    Ans = "vs";
    break;
  case ARM_CC_VC:
    Ans = "vc";
    break;
  case ARM_CC_HI:
    Ans = "hi";
    break;
  case ARM_CC_LS:
    Ans = "ls";
    break;
  case ARM_CC_GE:
    Ans = "ge";
    break;
  case ARM_CC_LT:
    Ans = "lt";
    break;
  case ARM_CC_GT:
    Ans = "gt";
    break;
  case ARM_CC_LE:
    Ans = "le";
    break;
  case ARM_CC_AL:
    Ans = "al";
    break;
  default:
    assert(!"Invalid arm_cc");
    Ans = "Invalid arm_cc";
    break;
  }
  if (Upper) {
    std::transform(Ans.begin(), Ans.end(), Ans.begin(), ::toupper);
  }
  return Ans;
}

static void rewriteMnemonic(cs_insn& inst, const char* str) {
  cs_arm& Detail = inst.detail->arm;
  std::stringstream SS;
  SS << str;
  if (Detail.cc != ARM_CC_AL) {
    std::string CC = armCc2String(Detail.cc, true);
    SS << CC;
  }
  std::string newMnemonic = SS.str();
  size_t newMnemonicLen = newMnemonic.size() + 1;
  if (newMnemonicLen > CS_MNEMONIC_SIZE) {
    LOG_ERROR << "Fixed up mnemonic \"" << newMnemonic << "\" does not fit in "
              << CS_MNEMONIC_SIZE << "\n";
    std::exit(EXIT_FAILURE);
  }
  memcpy(inst.mnemonic, newMnemonic.c_str(), newMnemonicLen);
}

void ArmPrettyPrinter::fixupInstruction(cs_insn& inst) {
  ElfPrettyPrinter::fixupInstruction(inst);

  cs_arm& Detail = inst.detail->arm;

  // Convert "add r, pc, offset" to "adr r, label".
  // Assume that pprinter is given the corresponding SymAddrConst for the
  // label.
  switch (inst.id) {
  case ARM_INS_ADD:
  case ARM_INS_ADDW:
  case ARM_INS_SUB:
  case ARM_INS_SUBW:
    if (Detail.op_count == 3) {
      cs_arm_op& Op1 = Detail.operands[1];
      cs_arm_op& Op2 = Detail.operands[2];
      if (Op1.type == ARM_OP_REG && Op1.reg == ARM_REG_PC &&
          Op2.type == ARM_OP_IMM) {
        inst.id = ARM_INS_ADR;
        rewriteMnemonic(inst, "ADR");
        Op1.type = ARM_OP_IMM;
        // The second operand will be rendered as symbolic.
        // In case when no symbolic operand is provided,
        // keep the offset as the second operand of the adr instruction.
        Op1.imm = Op2.imm;
        Detail.op_count = 2;
      }
    }
    break;
  case ARM_INS_TRAP:
    // gcc doesn't recognize "trap" as a valid instruction
    // "udf 0xfe" is equivalent.
    inst.id = ARM_INS_UDF;
    rewriteMnemonic(inst, "UDF");
    Detail.op_count = 1;
    cs_arm_op& Op1 = Detail.operands[0];
    Op1.imm = 0xfe;
    Op1.type = ARM_OP_IMM;
    break;
  }
}

void ArmPrettyPrinter::printInstruction(std::ostream& os,
                                        const gtirb::CodeBlock& block,
                                        const cs_insn& inst,
                                        const gtirb::Offset& offset) {
  gtirb::Addr ea(inst.address);
  std::stringstream InstructLine;
  printComments(InstructLine, offset, inst.size);
  printCFIDirectives(InstructLine, offset);
  printEA(InstructLine, ea);
  std::string opcode = ascii_str_tolower(inst.mnemonic);
  if (auto index = opcode.rfind(".w"); index != std::string::npos)
    opcode = opcode.substr(0, index);

  auto isItInstr = [](const std::string& i) {
    static const std::vector<std::string> it_instrs{
        "it",    "itt",   "ite",   "ittt",  "itte",  "itet",  "itee", "itttt",
        "ittte", "ittet", "ittee", "itett", "itete", "iteet", "iteee"};
    return (std::find(std::begin(it_instrs), std::end(it_instrs), i) !=
            std::end(it_instrs));
  };

  InstructLine << "  " << opcode;
  if (isItInstr(opcode)) {
    std::string cc = armCc2String(inst.detail->arm.cc);
    InstructLine << " " << cc;
  }
  InstructLine << ' ';
  // Make sure the initial m_accum_comment is empty.
  m_accum_comment.clear();
  printOperandList(InstructLine, block, inst);

  if (inst.detail->arm.cps_flag != ARM_CPSFLAG_NONE &&
      inst.detail->arm.cps_flag != ARM_CPSFLAG_INVALID) {
    if (inst.detail->arm.cps_flag & ARM_CPSFLAG_I)
      InstructLine << "i";
    if (inst.detail->arm.cps_flag & ARM_CPSFLAG_F)
      InstructLine << "f";
    if (inst.detail->arm.cps_flag & ARM_CPSFLAG_A)
      InstructLine << "a";
  }

  if (!m_accum_comment.empty()) {
    printCommentableLine(InstructLine, os, ea);
    InstructLine.str(std::string()); // Clear
    os << '\n';
    InstructLine << syntax.comment() << " ";
    printEA(InstructLine, ea);
    InstructLine << ": " << m_accum_comment;
    m_accum_comment.clear();
  }
  printCommentableLine(InstructLine, os, ea);
  os << '\n';
}

void ArmPrettyPrinter::printOperandList(std::ostream& os,
                                        const gtirb::CodeBlock& block,
                                        const cs_insn& inst) {
  cs_arm& detail = inst.detail->arm;

  int opCount = detail.op_count;

  static const std::set<arm_insn> LdmStm = {
      ARM_INS_LDM,     ARM_INS_LDMDA,   ARM_INS_LDMDB,  ARM_INS_LDMIB,
      ARM_INS_FLDMDBX, ARM_INS_FLDMIAX, ARM_INS_VLDMDB, ARM_INS_VLDMIA,
      ARM_INS_STM,     ARM_INS_STMDA,   ARM_INS_STMDB,  ARM_INS_STMIB,
      ARM_INS_FSTMDBX, ARM_INS_FSTMIAX, ARM_INS_VSTMDB, ARM_INS_VSTMIA};

  static const std::set<arm_insn> PushPop = {ARM_INS_POP, ARM_INS_PUSH,
                                             ARM_INS_VPOP, ARM_INS_VPUSH};

  static const std::set<arm_insn> VldVst = {
      ARM_INS_VLD1, ARM_INS_VLD2, ARM_INS_VLD3, ARM_INS_VLD4,
      ARM_INS_VST1, ARM_INS_VST2, ARM_INS_VST3, ARM_INS_VST4};

  // VLDn/VSTn
  if (VldVst.find(static_cast<arm_insn>(inst.id)) != VldVst.end()) {
    os << "{ ";
    for (int i = 0; i < opCount; i++) {
      const cs_arm_op& op = detail.operands[i];
      // Print out closing parenthesis once a memory operand is encountered.
      if (op.type == ARM_OP_MEM) {
        os << " }, [";
        if (op.mem.base != ARM_REG_INVALID) {
          os << getRegisterName(op.mem.base);
        }
        // The disp is for alignment for VLDn and VSTn instructions.
        if (op.mem.disp != 0) {
          os << " :" << op.mem.disp;
        }
        os << "]";
        if (detail.writeback) {
          os << "!";
        }
      } else {
        if (i != 0) {
          os << ", ";
        }
        printOperand(os, block, inst, i);
      }
    }
    return;
  }

  int RegBitVectorIndex = -1;

  if (LdmStm.find(static_cast<arm_insn>(inst.id)) != LdmStm.end())
    RegBitVectorIndex = 1;
  if (PushPop.find(static_cast<arm_insn>(inst.id)) != PushPop.end())
    RegBitVectorIndex = 0;

  for (int i = 0; i < opCount; i++) {
    if (i != 0) {
      os << ", ";
    }
    if (i == RegBitVectorIndex)
      os << "{ ";
    printOperand(os, block, inst, i);
    if (LdmStm.find(static_cast<arm_insn>(inst.id)) != LdmStm.end() && i == 0 &&
        detail.writeback) {
      os << "!";
    }
  }
  if (RegBitVectorIndex != -1)
    os << " }";
}

void ArmPrettyPrinter::printOperand(std::ostream& os,
                                    const gtirb::CodeBlock& block,
                                    const cs_insn& inst, uint64_t index) {
  gtirb::Addr ea(inst.address);
  const cs_arm_op& op = inst.detail->arm.operands[index];

  const gtirb::SymbolicExpression* symbolic = nullptr;
  switch (op.type) {
  case ARM_OP_REG:
  case ARM_OP_SYSREG: {
    if (op.subtracted)
      os << "-";
    printOpRegdirect(os, inst, index);
    return;
  }
  case ARM_OP_IMM:
  case ARM_OP_PIMM:
  case ARM_OP_CIMM: {
    symbolic = block.getByteInterval()->getSymbolicExpression(
        ea - *block.getByteInterval()->getAddress());
    printOpImmediate(os, symbolic, inst, index);
    return;
  }
  case ARM_OP_FP: {
    os << "#" << std::scientific << std::setprecision(18) << op.fp;
    return;
  }
  case ARM_OP_MEM: {
    symbolic = block.getByteInterval()->getSymbolicExpression(
        ea - *block.getByteInterval()->getAddress());
    printOpIndirect(os, symbolic, inst, index);
    return;
  }
  case ARM_OP_SETEND: {
    switch (op.setend) {
    case ARM_SETEND_BE:
      os << "BE";
      break;
    case ARM_SETEND_LE:
      os << "LE";
      break;
    default:
      std::cerr << "invalid SETEND operand\n";
      exit(1);
    }
    return;
  }
  default:
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

void ArmPrettyPrinter::printSymExprSuffix(std::ostream& OS,
                                          const gtirb::SymAttributeSet& Attrs,
                                          bool /*IsNotBranch*/) {
  if (Attrs.count(gtirb::SymAttribute::GOT)) {
    OS << "(GOT)";
  }
}

void ArmPrettyPrinter::printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                        uint64_t index) {
  auto armShifter2String = [](arm_shifter sft) {
    switch (sft) {
    case ARM_SFT_INVALID:
      return "";
    case ARM_SFT_ASR:
      return "asr";
    case ARM_SFT_LSL:
      return "lsl";
    case ARM_SFT_LSR:
      return "lsr";
    case ARM_SFT_ROR:
      return "ror";
    case ARM_SFT_RRX:
      return "rrx";
    case ARM_SFT_ASR_REG:
      return "asr";
    case ARM_SFT_LSL_REG:
      return "lsl";
    case ARM_SFT_LSR_REG:
      return "lsr";
    case ARM_SFT_ROR_REG:
      return "ror";
    case ARM_SFT_RRX_REG:
      return "rrx";
    default:
      return "";
    }
  };

  auto armSysReg2String = [](int sysreg) {
    if (sysreg == ARM_SYSREG_INVALID) {
      return std::string("INVALID");
    } else if (sysreg < 16) {
      std::string ret = "spsr_";
      if (sysreg & ARM_SYSREG_SPSR_C)
        ret += "c";
      if (sysreg & ARM_SYSREG_SPSR_X)
        ret += "x";
      if (sysreg & ARM_SYSREG_SPSR_S)
        ret += "s";
      if (sysreg & ARM_SYSREG_SPSR_F)
        ret += "f";
      return ret;
    } else if (sysreg < 256) {
      std::string ret = "cpsr_";
      if (sysreg & ARM_SYSREG_CPSR_C)
        ret += "c";
      if (sysreg & ARM_SYSREG_CPSR_X)
        ret += "x";
      if (sysreg & ARM_SYSREG_CPSR_S)
        ret += "s";
      if (sysreg & ARM_SYSREG_CPSR_F)
        ret += "f";
      return ret;
    } else {
      std::string ret;
      switch (sysreg) {
      case ARM_SYSREG_APSR:
        ret = "apsr";
        break;
      case ARM_SYSREG_APSR_G:
        ret = "apsr_g";
        break;
      case ARM_SYSREG_APSR_NZCVQ:
        ret = "apsr_nzcvq";
        break;
      case ARM_SYSREG_APSR_NZCVQG:
        ret = "apsr_nzcvqg";
        break;
      case ARM_SYSREG_IAPSR:
        ret = "iapsr";
        break;
      case ARM_SYSREG_IAPSR_G:
        ret = "iapsr_g";
        break;
      case ARM_SYSREG_IAPSR_NZCVQG:
        ret = "iapsr_nzcvqg";
        break;
      case ARM_SYSREG_IAPSR_NZCVQ:
        ret = "iapsr_nzcvq";
        break;
      case ARM_SYSREG_EAPSR:
        ret = "eapsr";
        break;
      case ARM_SYSREG_EAPSR_G:
        ret = "eapsr_g";
        break;
      case ARM_SYSREG_EAPSR_NZCVQG:
        ret = "eapsr_nzcvqg";
        break;
      case ARM_SYSREG_EAPSR_NZCVQ:
        ret = "eapsr_nzcvq";
        break;
      case ARM_SYSREG_XPSR:
        ret = "xpsr";
        break;
      case ARM_SYSREG_XPSR_G:
        ret = "xpsr_g";
        break;
      case ARM_SYSREG_XPSR_NZCVQG:
        ret = "xpsr_nzcvqg";
        break;
      case ARM_SYSREG_XPSR_NZCVQ:
        ret = "xpsr_nzcvq";
        break;
      case ARM_SYSREG_IPSR:
        ret = "ipsr";
        break;
      case ARM_SYSREG_EPSR:
        ret = "epsr";
        break;
      case ARM_SYSREG_IEPSR:
        ret = "iepsr";
        break;
      case ARM_SYSREG_MSP:
        ret = "msp";
        break;
      case ARM_SYSREG_PSP:
        ret = "psp";
        break;
      case ARM_SYSREG_PRIMASK:
        ret = "primask";
        break;
      case ARM_SYSREG_BASEPRI:
        ret = "basepri";
        break;
      case ARM_SYSREG_BASEPRI_MAX:
        ret = "basepri_max";
        break;
      case ARM_SYSREG_FAULTMASK:
        ret = "faultmask";
        break;
      case ARM_SYSREG_CONTROL:
        ret = "control";
        break;
      case ARM_SYSREG_MSPLIM:
        ret = "msplim";
        break;
      case ARM_SYSREG_PSPLIM:
        ret = "psplim";
        break;
      case ARM_SYSREG_MSP_NS:
        ret = "msp_ns";
        break;
      case ARM_SYSREG_PSP_NS:
        ret = "psp_ns";
        break;
      case ARM_SYSREG_MSPLIM_NS:
        ret = "msplim_ns";
        break;
      case ARM_SYSREG_PSPLIM_NS:
        ret = "psplim_ns";
        break;
      case ARM_SYSREG_PRIMASK_NS:
        ret = "primask_ns";
        break;
      case ARM_SYSREG_BASEPRI_NS:
        ret = "basepri_ns";
        break;
      case ARM_SYSREG_FAULTMASK_NS:
        ret = "faultmask_ns";
        break;
      case ARM_SYSREG_CONTROL_NS:
        ret = "control_ns";
        break;
      case ARM_SYSREG_SP_NS:
        ret = "sp_ns";
        break;
      default: {
        std::stringstream ss;
        ss << "<TODO:" << sysreg << ">";
        ret = ss.str();
        break;
      }
      }
      return ret;
    }
  };

  const cs_arm_op& op = inst.detail->arm.operands[index];
  if (op.type == ARM_OP_SYSREG) {
    os << armSysReg2String(op.reg);
  } else {
    os << getRegisterName(op.reg);
    std::string shift_type = armShifter2String(op.shift.type);
    std::string opcode = ascii_str_tolower(inst.mnemonic);
    opcode = opcode.substr(0, 3);
    if (op.shift.value != 0) {
      os << ", ";
      // In case where opcode is the same as one of arm_shifters (e.g., lsl),
      // do not print it again here.
      if (shift_type != "" && shift_type != opcode)
        os << shift_type << " ";
      if (op.shift.value > 32)
        os << getRegisterName(op.shift.value);
      else
        os << "#" << op.shift.value;
    }
  }

  if (op.vector_index != -1) {
    os << "[" << (int)op.vector_index << "]";
  }
}

std::string ArmPrettyPrinter::getRegisterName(unsigned int reg) const {
  return reg == ARM_REG_INVALID ? "" : cs_reg_name(this->csHandle, reg);
}

void ArmPrettyPrinter::printOpImmediate(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_arm_op& op = inst.detail->arm.operands[index];
  if (const auto* SAA = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
    printSymbolicExpression(os, SAA, false);
  } else if (const gtirb::SymAddrConst* s =
                 this->getSymbolicImmediate(symbolic)) {
    // The operand is symbolic.
    if (inst.id == ARM_INS_MOV)
      os << "#:lower16:";
    if (inst.id == ARM_INS_MOVT)
      os << "#:upper16:";
    this->printSymbolicExpression(os, s, true);
  } else {
    if (op.type == ARM_OP_IMM)
      os << '#';
    else if (op.type == ARM_OP_CIMM)
      os << "cr";
    // The operand is just a number.
    os << op.imm;
  }
}

void ArmPrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_arm& detail = inst.detail->arm;
  const cs_arm_op& op = detail.operands[index];
  assert(op.type == ARM_OP_MEM &&
         "printOpIndirect called without a memory operand");

  // pc-relative indirect operands like [pc, #100] with a symbolic expression
  // must replace the operand with the expression.
  // NOTE: For pc with register offset (including jump-table instructions)
  //       print the PC-relative operand as it is.
  if (op.mem.base == ARM_REG_PC && op.mem.index == ARM_REG_INVALID) {
    if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
      printSymbolicExpression(os, s, false);
      return;
    }
  }

  bool first = true;
  os << '[';

  if (op.mem.base != ARM_REG_INVALID) {
    first = false;
    os << getRegisterName(op.mem.base);
  }

  if (op.mem.index != ARM_REG_INVALID) {
    if (!first)
      os << ", ";
    first = false;
    if (op.mem.scale == -1)
      os << "-";
    os << getRegisterName(op.mem.index);
  }

  if (op.shift.value != 0 && op.shift.type != ARM_SFT_INVALID) {
    os << ", ";
    switch (op.shift.type) {
    case ARM_SFT_ASR_REG:
    case ARM_SFT_ASR:
      os << "ASR";
      break;
    case ARM_SFT_LSL_REG:
    case ARM_SFT_LSL:
      os << "LSL";
      break;
    case ARM_SFT_LSR_REG:
    case ARM_SFT_LSR:
      os << "LSR";
      break;
    case ARM_SFT_ROR_REG:
    case ARM_SFT_ROR:
      os << "ROR";
      break;
    case ARM_SFT_RRX_REG:
    case ARM_SFT_RRX:
      os << "RRX";
      break;
    case ARM_SFT_INVALID:
      std::cerr << "Invalid ARM shift operation.\n";
      exit(1);
    }
    os << " " << op.shift.value;
  }

  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    os << ", #";
    printSymbolicExpression(os, s, false);
  } else {
    if (op.mem.disp != 0)
      os << ", #" << op.mem.disp;
  }
  os << ']';
  if (detail.writeback) {
    // If this operand has 'writeback', and it's the last operand,
    // it can be assumed to be pre-indexed.
    // NOTE: Is there a way of finding the info about pre/post-index in
    // capstone??
    if ((uint64_t)(detail.op_count - 1) == index) {
      os << '!';
    }
  }
}

bool ArmPrettyPrinter::printSymbolReference(std::ostream& OS,
                                            const gtirb::Symbol* Symbol) {
  if (Symbol->getName() == "_GLOBAL_OFFSET_TABLE_") {
    OS << Symbol->getName();
    return false;
  }
  return PrettyPrinterBase::printSymbolReference(OS, Symbol);
}

std::unique_ptr<PrettyPrinterBase>
ArmPrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                const gtirb::Module& module,
                                const PrintingPolicy& policy) {
  static const ArmSyntax syntax{};
  return std::make_unique<ArmPrettyPrinter>(gtirb_context, module, syntax,
                                            policy);
}

ArmPrettyPrinterFactory::ArmPrettyPrinterFactory() {
  auto& DynamicPolicy = *findRegisteredNamedPolicy("dynamic");
  DynamicPolicy.skipSections.emplace(".ARM.exidx");
  DynamicPolicy.skipSections.emplace(".ARM.attributes");

  DynamicPolicy.skipSymbols.emplace("_fini");

  auto& StaticPolicy = *findRegisteredNamedPolicy("static");
  StaticPolicy.skipSections.emplace(".ARM.attributes");

  auto& CompletePolicy = *findRegisteredNamedPolicy("complete");
  CompletePolicy.skipSections.emplace(".ARM.attributes");
}
} // namespace gtirb_pprint

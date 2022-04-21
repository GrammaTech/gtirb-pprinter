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
#include "StringUtils.hpp"
#include <iostream>

namespace gtirb_pprint {

ArmPrettyPrinter::ArmPrettyPrinter(gtirb::Context& context_,
                                   gtirb::Module& module_,
                                   const ArmSyntax& syntax_,
                                   const Assembler& assembler_,
                                   const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, assembler_, policy_),
      armSyntax(syntax_) {
  // Setup Capstone.
  [[maybe_unused]] cs_err err = cs_open(
      CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM | CS_MODE_V8), &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");

  m_mclass = false;
  for (const auto& Section : module_.findSections(".ARM.attributes")) {
    for (const auto& ByteInterval : Section.byte_intervals()) {
      const char* RawChars = ByteInterval.rawBytes<const char>();
      // Remove zeros
      std::vector<char> Chars;
      for (size_t I = 0; I < ByteInterval.getInitializedSize(); ++I) {
        if (RawChars[I] != 0)
          Chars.push_back(RawChars[I]);
      }
      std::string SectStr(Chars.begin(), Chars.end());
      if (SectStr.find("Cortex-M7") != std::string::npos) {
        m_mclass = true;
        break;
      }
    }
  }
}

void ArmPrettyPrinter::printHeader(std::ostream& os) {
  ElfPrettyPrinter::printHeader(os);

  os << "# ARM " << std::endl;
  os << ".syntax unified" << std::endl;
  if (!m_mclass) {
    os << ".arch_extension idiv" << std::endl;
    os << ".arch_extension sec" << std::endl;
  }
}

void ArmPrettyPrinter::setDecodeMode(std::ostream& os,
                                     const gtirb::CodeBlock& x) {
  // 1 for THUMB 0 for regular ARM
  if (x.getDecodeMode()) {
    os << ".thumb" << std::endl;

    if (m_mclass) {
      cs_option(this->csHandle, CS_OPT_MODE,
                CS_MODE_THUMB | CS_MODE_V8 | CS_MODE_MCLASS);
    } else {
      cs_option(this->csHandle, CS_OPT_MODE, CS_MODE_THUMB | CS_MODE_V8);
    }
  } else {
    os << ".arm" << std::endl;
    cs_option(this->csHandle, CS_OPT_MODE, CS_MODE_ARM | CS_MODE_V8);
  }
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
    if (Detail.op_count == 3) {
      cs_arm_op& Op1 = Detail.operands[1];
      if (Op1.type == ARM_OP_REG && Op1.reg == ARM_REG_PC) {
        inst.id = ARM_INS_ADR;
        strncpy(inst.mnemonic, "ADR", 4);
        Op1.type = ARM_OP_IMM;
        // The second operand will be rendered as symbolic.
        // In case when no symbolic operand is provided,
        // keep the offset as the second operand of the adr instruction.
        cs_arm_op& Op2 = Detail.operands[2];
        assert(Op2.type == ARM_OP_IMM);
        Op1.imm = Op2.imm;
        Detail.op_count = 2;
      }
    }
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

  auto armCc2String = [](arm_cc cc) {
    switch (cc) {
    case ARM_CC_EQ:
      return "eq";
    case ARM_CC_NE:
      return "ne";
    case ARM_CC_HS:
      return "hs";
    case ARM_CC_LO:
      return "lo";
    case ARM_CC_MI:
      return "mi";
    case ARM_CC_PL:
      return "pl";
    case ARM_CC_VS:
      return "vs";
    case ARM_CC_VC:
      return "vc";
    case ARM_CC_HI:
      return "hi";
    case ARM_CC_LS:
      return "ls";
    case ARM_CC_GE:
      return "ge";
    case ARM_CC_LT:
      return "lt";
    case ARM_CC_GT:
      return "gt";
    case ARM_CC_LE:
      return "le";
    case ARM_CC_AL:
      return "al";
    default:
      assert(!"Invalid arm_cc");
      return "Invalid arm_cc";
    }
  };

  auto isItInstr = [](const std::string& i) {
    static std::vector<std::string> it_instrs{
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
  std::set<arm_insn> LdmSdm = {
      ARM_INS_LDM,     ARM_INS_LDMDA,   ARM_INS_LDMDB,  ARM_INS_LDMIB,
      ARM_INS_FLDMDBX, ARM_INS_FLDMIAX, ARM_INS_VLDMDB, ARM_INS_VLDMIA,
      ARM_INS_STM,     ARM_INS_STMDA,   ARM_INS_STMDB,  ARM_INS_STMIB,
      ARM_INS_FSTMDBX, ARM_INS_FSTMIAX, ARM_INS_VSTMDB, ARM_INS_VSTMIA,
      ARM_INS_VPOP,    ARM_INS_VPUSH};
  std::set<arm_insn> PushPop = {ARM_INS_POP, ARM_INS_PUSH, ARM_INS_VPOP,
                                ARM_INS_VPUSH};
  int RegBitVectorIndex = -1;

  if (LdmSdm.find(static_cast<arm_insn>(inst.id)) != LdmSdm.end())
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
    if (LdmSdm.find(static_cast<arm_insn>(inst.id)) != LdmSdm.end() && i == 0 &&
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
  if (Attrs.isFlagSet(gtirb::SymAttribute::GotRelPC)) {
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

  // PC-relative operand
  std::string opcode = ascii_str_tolower(inst.mnemonic);

  auto isJumpTableBranch = [&]() {
    // tbb [pc, rm] or tbh [pc, rm, lsl #N]
    if ((opcode == "tbb" || opcode == "tbh") && op.mem.base == ARM_REG_PC)
      return true;
    // ldr pc, [pc, rn, lsl #N]
    if (opcode.substr(0, 3) == "ldr" && op.mem.base == ARM_REG_PC) {
      const cs_arm_op& dst = detail.operands[0];
      if (dst.reg == ARM_REG_PC)
        return true;
    }
    return false;
  };

  // NOTE: For jump-table instructions,
  //       print the PC-relative operand as it is.
  if (op.mem.base == ARM_REG_PC && !isJumpTableBranch()) {
    if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
      printSymbolicExpression(os, s, false);
    } else {
      if (op.mem.disp != 0)
        os << "#" << op.mem.disp;
    }
    return;
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

std::string ArmPrettyPrinter::getFunctionName(gtirb::Addr x) const {
  if (isFunctionEntry(x)) {
    for (gtirb::Symbol& s : module.findSymbols(x)) {
      if (AmbiguousSymbols.count(&s) > 0)
        continue;
      // local symbol
      if (s.getName().find('.') == 0)
        continue;
      return s.getName();
    }
  }

  return PrettyPrinterBase::getFunctionName(x);
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
                                gtirb::Module& module,
                                const PrintingPolicy& policy) {
  static const ArmSyntax syntax{};
  static const Assembler assembler{};
  return std::make_unique<ArmPrettyPrinter>(gtirb_context, module, syntax,
                                            assembler, policy);
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

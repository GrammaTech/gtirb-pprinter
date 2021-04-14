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
#include "string_utils.hpp"
#include <iostream>

namespace gtirb_pprint {

ArmPrettyPrinter::ArmPrettyPrinter(gtirb::Context& context_,
                                   gtirb::Module& module_,
                                   const ArmSyntax& syntax_,
                                   const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_),
      armSyntax(syntax_) {
  // Setup Capstone.
  [[maybe_unused]] cs_err err = cs_open(
      CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM | CS_MODE_V8), &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
}

void ArmPrettyPrinter::printHeader(std::ostream& os) {
  os << "# ARM " << std::endl;
  os << ".syntax unified" << std::endl;
}

void ArmPrettyPrinter::setDecodeMode(std::ostream& os,
                                     const gtirb::CodeBlock& x) {
  // 1 for THUMB 0 for regular ARM
  if (x.getDecodeMode()) {
    os << ".thumb" << std::endl;
    cs_option(this->csHandle, CS_OPT_MODE, CS_MODE_THUMB | CS_MODE_V8);
  } else {
    os << ".arm" << std::endl;
    cs_option(this->csHandle, CS_OPT_MODE, CS_MODE_ARM | CS_MODE_V8);
  }
}

void ArmPrettyPrinter::printInstruction(std::ostream& os,
                                        const gtirb::CodeBlock& block,
                                        const cs_insn& inst,
                                        const gtirb::Offset& offset) {
  gtirb::Addr ea(inst.address);
  printComments(os, offset, inst.size);
  printCFIDirectives(os, offset);
  printEA(os, ea);
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
      return "";
    }
  };

  os << "  " << opcode;
  if (opcode == "ite" || opcode == "it" || opcode == "itt" ||
      opcode == "itte") {
    std::string cc = armCc2String(inst.detail->arm.cc);
    os << " " << cc;
  }
  os << ' ';
  // Make sure the initial m_accum_comment is empty.
  m_accum_comment.clear();
  printOperandList(os, block, inst);
  if (!m_accum_comment.empty()) {
    os << '\n' << syntax.comment() << " ";
    printEA(os, ea);
    os << ": " << m_accum_comment;
    m_accum_comment.clear();
  }
  os << '\n';
}

void ArmPrettyPrinter::printOperandList(std::ostream& os,
                                        const gtirb::CodeBlock& block,
                                        const cs_insn& inst) {
  cs_arm& detail = inst.detail->arm;
  int opCount = detail.op_count;
  std::set<arm_insn> LdmSdm = {ARM_INS_LDM,   ARM_INS_LDMDA, ARM_INS_LDMDB,
                               ARM_INS_LDMIB, ARM_INS_STM,   ARM_INS_STMDA,
                               ARM_INS_STMDB, ARM_INS_STMIB};
  std::set<arm_insn> PushPop = {ARM_INS_POP, ARM_INS_PUSH};
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
  case ARM_OP_SYSREG:
    printOpRegdirect(os, inst, index);
    return;
  case ARM_OP_IMM:
  case ARM_OP_PIMM:
  case ARM_OP_CIMM: {
    symbolic = block.getByteInterval()->getSymbolicExpression(
        ea - *block.getByteInterval()->getAddress());
    printOpImmediate(os, symbolic, inst, index);
    return;
  }
  case ARM_OP_MEM: {
    symbolic = block.getByteInterval()->getSymbolicExpression(
        ea - *block.getByteInterval()->getAddress());
    printOpIndirect(os, symbolic, inst, index);
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

  const cs_arm_op& op = inst.detail->arm.operands[index];
  if (op.type == ARM_OP_SYSREG)
    os << "msr";
  else {
    os << getRegisterName(op.reg);
    std::string shift_type = armShifter2String(op.shift.type);
    if (shift_type != "" && op.shift.value != 0)
      os << ", " << shift_type << " #" << op.shift.value;
  }
}

std::string ArmPrettyPrinter::getRegisterName(unsigned int reg) const {
  return reg == ARM_REG_INVALID ? "" : cs_reg_name(this->csHandle, reg);
}

void ArmPrettyPrinter::printOpImmediate(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_arm_op& op = inst.detail->arm.operands[index];
  if (const gtirb::SymAddrConst* s = this->getSymbolicImmediate(symbolic)) {
    // The operand is symbolic.
    if (inst.id == ARM_INS_MOV)
      os << "#:lower16:";
    if (inst.id == ARM_INS_MOVT)
      os << "#:upper16:";
    this->printSymbolicExpression(os, s, true);
  } else {
    if (op.type == ARM_OP_IMM)
      os << '#';
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
  // NOTE: For TBB and TBH (jump-table instructions),
  //       print the PC-relative operand as it is.
  if (op.mem.base == ARM_REG_PC && opcode != "tbb" && opcode != "tbh") {
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
      if (isAmbiguousSymbol(s.getName()))
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
  return std::make_unique<ArmPrettyPrinter>(gtirb_context, module, syntax,
                                            policy);
}

ArmPrettyPrinterFactory::ArmPrettyPrinterFactory() {
  auto& DynamicPolicy = *findRegisteredNamedPolicy("dynamic");
  DynamicPolicy.arraySections.clear();
  DynamicPolicy.skipSections.emplace(".init_array");
  DynamicPolicy.skipSections.emplace(".fini_array");
  DynamicPolicy.skipSections.emplace(".ARM.exidx");
}
} // namespace gtirb_pprint

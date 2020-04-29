//===- ArmPrettyPrinter.cpp -----------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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

  cs_close(&this->csHandle);
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_ARM, CS_MODE_ARM, &this->csHandle);
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
    cs_option(this->csHandle, CS_OPT_MODE, CS_MODE_THUMB);
  } else {
    os << ".arm" << std::endl;
    cs_option(this->csHandle, CS_OPT_MODE, CS_MODE_ARM);
  }
}

void ArmPrettyPrinter::fixupInstruction(cs_insn& /*inst*/) {}

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

  os << "  " << opcode << ' ';
  printOperandList(os, block, inst);
}

void ArmPrettyPrinter::printOperandList(std::ostream& os,
                                        const gtirb::CodeBlock& block,
                                        const cs_insn& inst) {
  cs_arm& detail = inst.detail->arm;
  uint8_t opCount = detail.op_count;
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
    if (i == RegBitVectorIndex)
      os << "{ ";
    if (i != 0) {
      os << ", ";
    }
    printOperand(os, block, inst, i);
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

void ArmPrettyPrinter::printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                        uint64_t index) {
  const cs_arm_op& op = inst.detail->arm.operands[index];
  if (op.type == ARM_OP_SYSREG)
    os << "msr";
  else
    os << getRegisterName(op.reg);
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
  if (op.mem.base == ARM_REG_PC) {
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

const PrintingPolicy& ArmPrettyPrinterFactory::defaultPrintingPolicy() const {
  static PrintingPolicy DefaultPolicy{

      /// Functions to avoid printing.
      {"_start", "call_weak_fn", "deregister_tm_clones", "register_tm_clones",
       "__do_global_dtors_aux", "frame_dummy", "__libc_csu_fini",
       "__libc_csu_init", "_dl_relocate_static_pie"},

      /// Symbols to avoid printing.
      {"_IO_stdin_used", "__data_start", "__dso_handle", "__TMC_END__",
       "_edata", "__bss_start", "program_invocation_name",
       "program_invocation_short_name"},

      /// Sections to avoid printing.
      {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt",
       ".plt.sec", ".eh_frame_hdr"},

      /// Sections with possible data object exclusion.
      {".init_array", ".fini_array"},
  };
  return DefaultPolicy;
}

std::unique_ptr<PrettyPrinterBase>
ArmPrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                gtirb::Module& module,
                                const PrintingPolicy& policy) {
  static const ArmSyntax syntax{};
  return std::make_unique<ArmPrettyPrinter>(gtirb_context, module, syntax,
                                            policy);
}

volatile bool ArmPrettyPrinter::registered =
    registerPrinter({"elf"}, {"arm"}, {"arm"},
                    std::make_shared<ArmPrettyPrinterFactory>(), true);

} // namespace gtirb_pprint

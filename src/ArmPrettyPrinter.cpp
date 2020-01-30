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
}

void ArmPrettyPrinter::printBlock(std::ostream& os, const gtirb::Block& x) {
  // 1 for THUMB 0 for regular ARM
  if (x.getDecodeMode())
    cs_option(this->csHandle, CS_OPT_MODE, CS_MODE_THUMB);
  else
    cs_option(this->csHandle, CS_OPT_MODE, CS_MODE_ARM);
  ElfPrettyPrinter::printBlock(os, x);
}

void ArmPrettyPrinter::fixupInstruction(cs_insn& /*inst*/) {}

void ArmPrettyPrinter::printInstruction(std::ostream& os, const cs_insn& inst,
                                        const gtirb::Offset& offset) {

  gtirb::Addr ea(inst.address);
  printSymbolDefinitionsAtAddress(os, ea);
  printComments(os, offset, inst.size);
  printCFIDirectives(os, offset);
  printEA(os, ea);
  std::string opcode = ascii_str_tolower(inst.mnemonic);
  os << "  " << opcode << ' ';
  printOperandList(os, inst);
}

void ArmPrettyPrinter::printOperandList(std::ostream& os, const cs_insn& inst) {
  cs_arm& detail = inst.detail->arm;
  uint8_t opCount = detail.op_count;

  for (int i = 0; i < opCount; i++) {
    if (i != 0) {
      os << ", ";
    }
    printOperand(os, inst, i);
  }
}

void ArmPrettyPrinter::printOperand(std::ostream& os, const cs_insn& inst,
                                    uint64_t index) {
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
    auto found = module.findSymbolicExpression(ea);
    if (found != module.symbolic_expr_end())
      symbolic = &*found;

    printOpImmediate(os, symbolic, inst, index);
    return;
  }
  case ARM_OP_MEM: {
    auto found = module.findSymbolicExpression(ea);
    if (found != module.symbolic_expr_end())
      symbolic = &*found;
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
    this->printSymbolicExpression(os, s, true);
  } else {
    // The operand is just a number.
    os << '#' << op.imm;
  }
}

void ArmPrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_arm& detail = inst.detail->arm;
  const cs_arm_op& op = detail.operands[index];
  assert(op.type == ARM_OP_MEM &&
         "printOpIndirect called without a memory operand");
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
    os << getRegisterName(op.mem.index) << '*' << std::to_string(op.mem.scale);
  }

  os << ", ";
  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    printSymbolicExpression(os, s, false);
  } else {
    os << '#' << op.mem.disp;
  }
  os << ']';
}

const PrintingPolicy& ArmPrettyPrinterFactory::defaultPrintingPolicy() const {
  return ElfPrettyPrinter::defaultPrintingPolicy();
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

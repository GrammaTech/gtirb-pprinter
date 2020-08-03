//===- IntelPrettyPrinter.cpp -----------------------------------*- C++ -*-===//
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

#include "IntelPrettyPrinter.hpp"

namespace gtirb_pprint {

IntelPrettyPrinter::IntelPrettyPrinter(gtirb::Context& context_,
                                       gtirb::Module& module_,
                                       const IntelSyntax& syntax_,
                                       const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_),
      intelSyntax(syntax_) {
  // Set up Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
}

void IntelPrettyPrinter::printHeader(std::ostream& os) {
  this->printBar(os);
  os << ".intel_syntax noprefix\n";
  this->printBar(os);
  os << '\n';

  for (int i = 0; i < 8; i++) {
    os << syntax.nop() << '\n';
  }
}

void IntelPrettyPrinter::printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                          uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  assert(op.type == X86_OP_REG &&
         "printOpRegdirect called without a register operand");
  os << getRegisterName(op.reg);
}

void IntelPrettyPrinter::printOpImmediate(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  assert(op.type == X86_OP_IMM &&
         "printOpImmediate called without an immediate operand");

  bool IsNotBranch =
      !cs_insn_group(this->csHandle, &inst, CS_GRP_CALL) &&
      !cs_insn_group(this->csHandle, &inst, CS_GRP_JUMP) &&
      !cs_insn_group(this->csHandle, &inst, CS_GRP_BRANCH_RELATIVE);

  if (const gtirb::SymAddrConst* s = this->getSymbolicImmediate(symbolic)) {
    // The operand is symbolic.
    if (IsNotBranch)
      os << intelSyntax.offset() << ' ';
    this->printSymbolicExpression(os, s, IsNotBranch);
  } else {
    // The operand is just a number.
    os << op.imm;
  }
}

void IntelPrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];
  assert(op.type == X86_OP_MEM &&
         "printOpIndirect called without a memory operand");
  bool first = true;

  if (std::optional<std::string> size = syntax.getSizeName(op.size * 8))
    os << *size << " PTR ";

  if (op.mem.segment != X86_REG_INVALID)
    os << getRegisterName(op.mem.segment) << ':';

  os << '[';

  if (op.mem.base != X86_REG_INVALID) {
    first = false;
    os << getRegisterName(op.mem.base);
  }

  if (op.mem.index != X86_REG_INVALID) {
    if (!first)
      os << '+';
    first = false;
    os << getRegisterName(op.mem.index) << '*' << std::to_string(op.mem.scale);
  }

  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    os << '+';
    printSymbolicExpression(os, s, false);
  } else {
    printAddend(os, op.mem.disp, first);
  }
  os << ']';
}

const PrintingPolicy& IntelPrettyPrinterFactory::defaultPrintingPolicy() const {
  return ElfPrettyPrinter::defaultPrintingPolicy();
}

std::unique_ptr<PrettyPrinterBase>
IntelPrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                  gtirb::Module& module,
                                  const PrintingPolicy& policy) {
  static const IntelSyntax syntax{};
  return std::make_unique<IntelPrettyPrinter>(gtirb_context, module, syntax,
                                              policy);
}
} // namespace gtirb_pprint

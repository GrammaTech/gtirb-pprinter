//===- Mips32PrettyPrinter.cpp ----------------------------------*- C++ -*-===//
//
//  Copyright (c) 2020 GrammaTech, Inc.
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

#include "Mips32PrettyPrinter.hpp"
#include "AuxDataSchema.hpp"

#include <capstone/capstone.h>

namespace gtirb_pprint {

const PrintingPolicy&
Mips32PrettyPrinterFactory::defaultPrintingPolicy() const {
  static PrintingPolicy DefaultPolicy{
      /// Functions to avoid printing.
      {},

      /// Symbols to avoid printing.
      {},

      /// Sections to avoid printing.
      {},

      /// Sections with possible data object exclusion.
      {},
  };
  return DefaultPolicy;
}

std::unique_ptr<PrettyPrinterBase>
Mips32PrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                   gtirb::Module& module,
                                   const PrintingPolicy& policy) {
  static const ElfSyntax syntax{};
  return std::make_unique<Mips32PrettyPrinter>(gtirb_context, module, syntax,
                                               policy);
}

Mips32PrettyPrinter::Mips32PrettyPrinter(gtirb::Context& context_,
                                         gtirb::Module& module_,
                                         const ElfSyntax& syntax_,
                                         const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_) {
  // Setup Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_MIPS, (cs_mode)(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN),
              &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
}

void Mips32PrettyPrinter::printHeader(std::ostream& /*os*/) {}

void Mips32PrettyPrinter::printOpRegdirect(std::ostream& os,
                                           const cs_insn& inst,
                                           uint64_t index) {
  const cs_mips_op& op = inst.detail->mips.operands[index];
  os << getRegisterName(op.reg);
}

void Mips32PrettyPrinter::printOpImmediate(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  if (symbolic) {
    if (auto* SAC = std::get_if<gtirb::SymAddrConst>(symbolic)) {
      printSymbolicExpression(os, SAC);
    } else if (auto* SAA = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
      printSymbolicExpression(os, SAA);
    } else {
      assert(!"Unknown sym expr type in printOpImmediate!");
    }
  } else {
    const cs_mips_op& op = inst.detail->mips.operands[index];
    os << op.imm;
  }
}

void Mips32PrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_mips_op& op = inst.detail->mips.operands[index];

  if (symbolic) {
    if (auto* SAC = std::get_if<gtirb::SymAddrConst>(symbolic)) {
      printSymbolicExpression(os, SAC);
    } else if (auto* SAA = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
      printSymbolicExpression(os, SAA);
    } else {
      assert(!"Unknown sym expr type in printOpImmediate!");
    }
  } else {
    os << op.mem.disp;
  }

  os << '(' << getRegisterName(op.mem.base) << ')';
}

std::string Mips32PrettyPrinter::getRegisterName(unsigned int reg) const {
  assert(reg != MIPS_REG_INVALID && "Register has no name!");
  return std::string{"$"} + cs_reg_name(this->csHandle, reg);
}

void Mips32PrettyPrinter::printOperand(std::ostream& os,
                                       const gtirb::CodeBlock& block,
                                       const cs_insn& inst, uint64_t index) {
  const cs_mips_op& op = inst.detail->mips.operands[index];
  const gtirb::SymbolicExpression* SymExpr = nullptr;

  switch (op.type) {
  case MIPS_OP_IMM:
    SymExpr = block.getByteInterval()->getSymbolicExpression(
        gtirb::Addr{inst.address} - *block.getByteInterval()->getAddress());
    printOpImmediate(os, SymExpr, inst, index);
    return;
  case MIPS_OP_REG:
    printOpRegdirect(os, inst, index);
    return;
  case MIPS_OP_MEM:
    SymExpr = block.getByteInterval()->getSymbolicExpression(
        gtirb::Addr{inst.address} - *block.getByteInterval()->getAddress());
    printOpIndirect(os, SymExpr, inst, index);
    return;
  default:
    assert(!"unknown mips op type!");
  }
}

void Mips32PrettyPrinter::printInstruction(std::ostream& os,
                                           const gtirb::CodeBlock& block,
                                           const cs_insn& inst,
                                           const gtirb::Offset& offset) {
  gtirb::Addr ea(inst.address);
  printComments(os, offset, inst.size);
  printCFIDirectives(os, offset);
  printEA(os, ea);

  os << "  " << inst.mnemonic << ' ';
  printOperandList(os, block, inst);
  os << '\n';
}

void Mips32PrettyPrinter::printOperandList(std::ostream& os,
                                           const gtirb::CodeBlock& block,
                                           const cs_insn& inst) {
  const cs_mips& detail = inst.detail->mips;

  for (int i = 0; i < detail.op_count; i++) {
    if (i != 0) {
      os << ',';
    }
    printOperand(os, block, inst, i);
  }
}

void Mips32PrettyPrinter::printSymbolicExpression(std::ostream& OS,
                                                  const gtirb::SymAddrConst* SE,
                                                  bool IsNotBranch) {
  printSymExprPrefix(OS, SE->Attributes);
  ElfPrettyPrinter::printSymbolicExpression(OS, SE, IsNotBranch);
  printSymExprSuffix(OS, SE->Attributes);
}

void Mips32PrettyPrinter::printSymbolicExpression(std::ostream& OS,
                                                  const gtirb::SymAddrAddr* SE,
                                                  bool IsNotBranch) {
  printSymExprPrefix(OS, SE->Attributes);
  ElfPrettyPrinter::printSymbolicExpression(OS, SE, IsNotBranch);
  printSymExprSuffix(OS, SE->Attributes);
}

void Mips32PrettyPrinter::printSymExprPrefix(
    std::ostream& OS, const gtirb::SymAttributeSet& Attrs) {
  for (const auto& Attr : Attrs) {
    switch (Attr) {
    case gtirb::SymAttribute::Part0: {
      OS << "%lo(";
    } break;
    case gtirb::SymAttribute::Part1: {
      OS << "%hi(";
    } break;
    case gtirb::SymAttribute::AddrRelGot: {
      OS << "%call16(";
    } break;
    default:
      assert(!"Unknown sym expr attribute encountered!");
    }
  }
}

void Mips32PrettyPrinter::printSymExprSuffix(
    std::ostream& OS, const gtirb::SymAttributeSet& Attrs) {
  for (const auto& Attr : Attrs) {
    switch (Attr) {
    case gtirb::SymAttribute::Part0:
    case gtirb::SymAttribute::Part1:
    case gtirb::SymAttribute::AddrRelGot: {
      OS << ")";
    } break;
    default:
      assert(!"Unknown sym expr attribute encountered!");
    }
  }
}

} // namespace gtirb_pprint

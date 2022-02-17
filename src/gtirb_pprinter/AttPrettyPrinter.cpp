//===- AttPrettyPrinter.cpp -------------------------------------*- C++ -*-===//
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
#include "AttPrettyPrinter.hpp"
#include "driver/Logger.h"
#include "StringUtils.hpp"
#include "version.h"

namespace gtirb_pprint {

AttPrettyPrinter::AttPrettyPrinter(gtirb::Context& context_,
                                   gtirb::Module& module_,
                                   const ElfSyntax& syntax_,
                                   const Assembler& assembler_,
                                   const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, assembler_, policy_) {
  // Setup Capstone.
  cs_mode Mode = CS_MODE_64;
  if (module.getISA() == gtirb::ISA::IA32) {
    Mode = CS_MODE_32;
  }
  [[maybe_unused]] cs_err err = cs_open(CS_ARCH_X86, Mode, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
  cs_option(this->csHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
}

void AttPrettyPrinter::fixupInstruction(cs_insn& inst) {
  x86FixupInstruction(inst);
}

std::string AttPrettyPrinter::getRegisterName(unsigned int reg) const {
  return std::string{"%"} +
         ascii_str_tolower(PrettyPrinterBase::getRegisterName(reg));
}

void AttPrettyPrinter::printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                        uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  assert(op.type == X86_OP_REG &&
         "printOpRegdirect called without a register operand");
  if (cs_insn_group(this->csHandle, &inst, CS_GRP_CALL) ||
      cs_insn_group(this->csHandle, &inst, CS_GRP_JUMP))
    os << '*';
  os << getRegisterName(op.reg);
}

void AttPrettyPrinter::printSymbolicExpression(
    std::ostream& Stream, const gtirb::SymAddrAddr* SymExpr, bool IsNotBranch) {

  // Print offset expression, e.g. _GLOBAL_OFFSET_TABLE_+(.Ltmp0-.L0$pb)
  if (SymExpr->Attributes.isFlagSet(gtirb::SymAttribute::GotOff)) {
    Stream << " $_GLOBAL_OFFSET_TABLE_+(";
    printSymbolReference(Stream, SymExpr->Sym1);
    Stream << '-';
    printSymbolReference(Stream, SymExpr->Sym2);
    Stream << ")";
    return;
  }

  PrettyPrinterBase::printSymbolicExpression(Stream, SymExpr, IsNotBranch);
}

void AttPrettyPrinter::printOpImmediate(
    std::ostream& Stream, const gtirb::SymbolicExpression* Symbolic,
    const cs_insn& Insn, uint64_t Index) {

  const cs_x86_op& Op = Insn.detail->x86.operands[Index];
  if (Op.type != X86_OP_IMM) {
    LOG_ERROR << "printOpImmediate called without an immediate operand";
    std::exit(EXIT_FAILURE);
  }

  bool ReferencesCode =
      cs_insn_group(this->csHandle, &Insn, CS_GRP_JUMP) ||
      cs_insn_group(this->csHandle, &Insn, CS_GRP_CALL) ||
      cs_insn_group(this->csHandle, &Insn, CS_GRP_BRANCH_RELATIVE);

  if (!ReferencesCode) {
    Stream << '$';
  }

  if (const gtirb::SymAddrAddr* SymAddrAddr =
          std::get_if<gtirb::SymAddrAddr>(Symbolic)) {
    // Print symbolic expression of the form "(Sym1 - Sym2) / Scale + Offset".
    printSymbolicExpression(Stream, SymAddrAddr, false);
  } else if (const gtirb::SymAddrConst* SymAddrConst =
                 getSymbolicImmediate(Symbolic)) {
    // Print symbolic expression of the form "Symbol + Offset".
    PrettyPrinterBase::printSymbolicExpression(Stream, SymAddrConst,
                                               !ReferencesCode);
  } else {
    // Print a hex-formatted integer.
    std::ios_base::fmtflags Flags = Stream.flags();
    if (ReferencesCode) {
      Stream << std::setbase(16) << std::showbase;
    }
    Stream << Op.imm;
    Stream.flags(Flags);
  }
}

void AttPrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];
  assert(op.type == X86_OP_MEM &&
         "printOpIndirect called without a memory operand");

  bool has_segment = op.mem.segment != X86_REG_INVALID;
  bool has_base = op.mem.base != X86_REG_INVALID;
  bool has_index = op.mem.index != X86_REG_INVALID;

  if (cs_insn_group(this->csHandle, &inst, CS_GRP_CALL) ||
      cs_insn_group(this->csHandle, &inst, CS_GRP_JUMP))
    os << '*';

  if (has_segment) {
    os << getRegisterName(op.mem.segment) << ':';
  }

  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    // Displacement is symbolic.
    PrettyPrinterBase::printSymbolicExpression(os, s, false);
  } else {
    // Displacement is numeric.
    if (!has_segment && !has_base && !has_index) {
      std::ios_base::fmtflags flags = os.flags();
      os << "0x" << std::hex << op.mem.disp;
      os.flags(flags);
    } else if (op.mem.disp != 0 || has_segment) {
      os << op.mem.disp;
    } else {
      // Print nothing. There is no segment register and the base or index
      // register will be printed, so the zero displacement is implicit.
    }
  }

  // Print base, index, and scale.
  if (has_base || has_index) {
    os << '(';
    if (has_base)
      os << getRegisterName(op.mem.base);
    if (has_index) {
      os << ',' << getRegisterName(op.mem.index);
      if (op.mem.scale != 1)
        os << ',' << op.mem.scale;
    }
    os << ')';
  }
}

std::unique_ptr<PrettyPrinterBase>
AttPrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                gtirb::Module& module,
                                const PrintingPolicy& policy) {
  static const ElfSyntax syntax{};
  static const Assembler assembler{};
  return std::make_unique<AttPrettyPrinter>(gtirb_context, module, syntax,
                                            assembler, policy);
}
} // namespace gtirb_pprint

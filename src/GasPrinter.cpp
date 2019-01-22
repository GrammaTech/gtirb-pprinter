//===- GasPrinter.cpp -------------------------------------------*- C++ -*-===//
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

#include "GasPrinter.h"
#include "string_utils.h"
#include <iomanip>

GasPP::GasPP(gtirb::Context& context, gtirb::IR& ir,
             const PrettyPrinter::string_range& skip_funcs, bool dbg)
    : AbstractPP(context, ir, skip_funcs, dbg) {
  cs_option(this->csHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
}

void GasPP::printHeader(std::ostream& /*os*/) {}

std::string GasPP::getRegisterName(unsigned int reg) const {
  return std::string{"%"} + str_tolower(AbstractPP::getRegisterName(reg));
}

int GasPP::getGtirbOpIndex(int index, int /*opCount*/) const { return index + 1; }

void GasPP::printOpRegdirect(std::ostream& os, const cs_insn& inst, const cs_x86_op& op) {
  assert(op.type == X86_OP_REG && "printOpRegdirect called without a register operand");
  if (cs_insn_group(this->csHandle, &inst, CS_GRP_CALL))
    os << '*';
  os << str_tolower(getRegisterName(op.reg));
}

void GasPP::printOpImmediate(std::ostream& os, const std::string& /*opcode*/,
                             const gtirb::SymbolicExpression* symbolic, const cs_insn& inst,
                             gtirb::Addr ea, uint64_t index) {
  const cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];
  assert(op.type == X86_OP_IMM && "printOpImmediate called without an immediate operand");

  bool is_call = cs_insn_group(this->csHandle, &inst, CS_GRP_CALL);
  bool is_jump = cs_insn_group(this->csHandle, &inst, CS_GRP_JUMP);

  if (!is_call && !is_jump)
    os << '$';

  // plt reference
  const std::optional<std::string>& plt_name = this->getPltCodeSymName(ea);
  if (plt_name) {
    os << plt_name.value();
    return;
  }

  if (symbolic) {
    const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic);
    assert(s != nullptr && "symbolic operands must be 'address[+offset]'");
    if (this->skipEA(s->Sym->getAddress().value()))
      // the symbol points to a skipped destination: treat as not symbolic
      symbolic = nullptr;
    else {
      os << this->getAdaptedSymbolNameDefault(s->Sym) << getAddendString(s->Offset);
    }
  }

  // skipped or not symbolic
  if (!symbolic) {
    std::ios_base::fmtflags flags = os.flags();
    if (is_call || is_jump)
      os << std::setbase(16) << std::showbase;
    os << op.imm;
    os.flags(flags);
  }
}

void GasPP::printOpIndirect(std::ostream& os, const gtirb::SymbolicExpression* symbolic,
                            const cs_insn& inst, uint64_t index) {
  const cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];
  assert(op.type == X86_OP_MEM && "printOpIndirect called without a memory operand");

  bool has_segment = op.mem.segment != X86_REG_INVALID;
  bool has_base = op.mem.base != X86_REG_INVALID;
  bool has_index = op.mem.index != X86_REG_INVALID;

  if (cs_insn_group(this->csHandle, &inst, CS_GRP_CALL))
    os << '*';
  if (has_segment)
    os << getRegisterName(op.mem.segment) << ':';

  const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic);
  if (s != nullptr &&
      (!s->Sym->getAddress() || !this->skipEA(s->Sym->getAddress().value()))) {
    // Symbolic displacement
    printSymbolicExpression(os, s);
  } else {
    // Numeric displacement
    if (!has_segment && !has_base && !has_index) {
      std::ios_base::fmtflags flags = os.flags();
      os << "0x" << std::hex << op.mem.disp;
      os.flags(flags);
    } else if (op.mem.disp != 0 || has_segment)
      // Optimization to only print a 0 displacement if there is a segment register prefix
      os << op.mem.disp;
  }

  // Base/Index/Scale
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

bool GasPP::registered = PrettyPrinter::registerPrinter(
    {"gas", "gnu"}, [](gtirb::Context& context, gtirb::IR& ir, const PrettyPrinter::string_range& skip_funcs, bool dbg) {
      return std::make_unique<GasPP>(context, ir, skip_funcs, dbg);
    });

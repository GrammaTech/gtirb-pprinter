//===- IntelPrinter.cpp ------------------------------------------*- C++
//-*-===//
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

#include "IntelPrinter.h"

IntelPP::IntelPP(gtirb::Context& context, gtirb::IR& ir,
                 const PrettyPrinter::string_range& skip_funcs,
                 PrettyPrinter::DebugStyle dbg)
    : AbstractPP(context, ir, skip_funcs, dbg) {}

int IntelPP::getGtirbOpIndex(int index, int opCount) const {
  // The datalog disassembler always treats operand indices as if using this
  // array:
  //   {opcode, src1, src2, ..., dst}
  // With CS_OP_SYNTAX_INTEL, Capstone operands are conceptually indexed as
  //   {dst, src1, src2, ...}
  // So to convert the Capstone index to an index into the gtirb, we need to
  // map 0 to opCount (since dst should be at the end) and leave the other
  // indices alone.
  if (index == 0)
    return opCount;
  return index;
}

void IntelPP::printHeader(std::ostream& os) {
  this->printBar(os);
  os << ".intel_syntax noprefix\n";
  this->printBar(os);
  os << '\n';

  for (int i = 0; i < 8; i++) {
    os << AbstractPP::StrNOP << '\n';
  }
}

void IntelPP::printOpRegdirect(std::ostream& os, const cs_insn& /*inst*/,
                               const cs_x86_op& op) {
  assert(op.type == X86_OP_REG &&
         "printOpRegdirect called without a register operand");
  os << getRegisterName(op.reg);
}

void IntelPP::printOpImmediate(std::ostream& os,
                               const gtirb::SymbolicExpression* symbolic,
                               const cs_insn& inst, gtirb::Addr ea,
                               uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  assert(op.type == X86_OP_IMM &&
         "printOpImmediate called without an immediate operand");

  bool is_call = cs_insn_group(this->csHandle, &inst, CS_GRP_CALL);
  bool is_jump = cs_insn_group(this->csHandle, &inst, CS_GRP_JUMP);

  const std::optional<std::string> plt_name = this->getPltCodeSymName(ea);
  if (plt_name) {
    // The operand is a plt reference.
    if (is_call || is_jump)
      os << *plt_name << "@PLT";
    else
      os << IntelPP::StrOffset << ' ' << *plt_name;
  } else if (const gtirb::SymAddrConst* s =
                 this->getSymbolicImmediate(symbolic)) {
    // The operand is symbolic.
    if (!is_call)
      os << IntelPP::StrOffset << ' ';
    os << this->getAdaptedSymbolNameDefault(s->Sym)
       << getAddendString(s->Offset);
  } else {
    // The operand is just a number.
    os << op.imm;
  }
}

void IntelPP::printOpIndirect(std::ostream& os,
                              const gtirb::SymbolicExpression* symbolic,
                              const cs_insn& inst, uint64_t index) {
  const cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];
  assert(op.type == X86_OP_MEM &&
         "printOpIndirect called without a memory operand");
  bool first = true;
  os << DisasmData::GetSizeName(op.size * 8) << ' ';

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
    if (s->Sym->getAddress() && this->skipEA(*s->Sym->getAddress())) {
      os << getAddendString(op.mem.disp, first);
    } else {
      os << '+';
      printSymbolicExpression(os, s);
    }
  } else {
    os << getAddendString(op.mem.disp, first);
  }
  os << ']';
}

volatile bool IntelPP::registered = PrettyPrinter::registerPrinter(
    {"intel"}, [](gtirb::Context& context, gtirb::IR& ir,
                  const PrettyPrinter::string_range& skip_funcs,
                  PrettyPrinter::DebugStyle dbg) {
      return std::make_unique<IntelPP>(context, ir, skip_funcs, dbg);
    });

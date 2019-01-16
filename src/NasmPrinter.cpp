//===- NasmPrinter.cpp ------------------------------------------*- C++ -*-===//
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

#include "NasmPrinter.h"

NasmPP::NasmPP(gtirb::Context& context, gtirb::IR& ir,
               const std::unordered_set<std::string>& skip_funcs, bool dbg)
    : AbstractPP(context, ir, skip_funcs, dbg) {}

int NasmPP::getGtirbOpIndex(int index, int opCount) const {
  // Note: disassembler currently puts the dest operand last and uses
  // 1-based operand indices. Capstone puts the dest first and uses
  // zero-based indices. Translate here.
  if (index == 0)
    return opCount;
  return index;
}

void NasmPP::printHeader(std::ostream& os) {
  this->printBar(os);
  os << ".intel_syntax noprefix" << std::endl;
  this->printBar(os);
  os << "" << std::endl;

  for (int i = 0; i < 8; i++) {
    os << AbstractPP::StrNOP << std::endl;
  }
}

void NasmPP::printOpRegdirect(std::ostream& os, const cs_insn& /*inst*/, const cs_x86_op& op) {
  assert(op.type == X86_OP_REG);
  os << getRegisterName(op.reg);
}

void NasmPP::printOpImmediate(std::ostream& os, const std::string& opcode,
                              const gtirb::SymbolicExpression* symbolic, const cs_insn& inst,
                              gtirb::Addr ea, uint64_t index) {
  const cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];
  assert(op.type == X86_OP_IMM);

  // plt reference
  const std::optional<std::string> plt_name = this->getPltCodeSymName(ea);
  if (plt_name) {
    if (cs_insn_group(this->csHandle, &inst, CS_GRP_CALL) ||
        cs_insn_group(this->csHandle, &inst, CS_GRP_JUMP))
      os << plt_name.value() << "@PLT";
    else
      os << NasmPP::StrOffset << " " << plt_name.value();
    return;
  }

  // not symbolic
  if (!symbolic) {
    os << op.imm;
    return;
  }

  // symbolic
  const gtirb::SymAddrConst* s = std::get_if<gtirb::SymAddrConst>(symbolic);
  assert(s != nullptr);

  // the symbol points to a skipped destination
  if (this->skipEA(s->Sym->getAddress().value())) {
    os << op.imm;
    return;
  }

  const char* offsetLabel = opcode == "call" ? "" : NasmPP::StrOffset;
  os << offsetLabel << " " << this->getAdaptedSymbolNameDefault(s->Sym)
     << getAddendString(s->Offset);
}

void NasmPP::printOpIndirect(std::ostream& os, const gtirb::SymbolicExpression* symbolic,
                             const cs_insn& inst, uint64_t index) {
  const cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];
  assert(op.type == X86_OP_MEM);
  bool first = true;
  const std::string sizeName = DisasmData::GetSizeName(op.size * 8);
  os << sizeName << " ";

  if (op.mem.segment != X86_REG_INVALID)
    os << getRegisterName(op.mem.segment) << ":";

  os << "[";

  if (op.mem.base != X86_REG_INVALID) {
    first = false;
    os << getRegisterName(op.mem.base);
  }

  if (op.mem.index != X86_REG_INVALID) {

    if (!first)
      os << "+";
    first = false;
    os << getRegisterName(op.mem.index) << "*" << std::to_string(op.mem.scale);
  }

  if (const gtirb::SymAddrConst* s = std::get_if<gtirb::SymAddrConst>(symbolic); s != nullptr) {
    if (s->Sym->getAddress().has_value() && this->skipEA(s->Sym->getAddress().value())) {
      os << getAddendString(op.mem.disp, first);
    } else {
      os << "+";
      printSymbolicExpression(os, s);
    }
  } else {
    os << getAddendString(op.mem.disp, first);
  }
  os << "]";
}

bool NasmPP::registered = PrettyPrinter::registerPrinter(
    {"intel", "nasm"}, [](gtirb::Context& context, gtirb::IR& ir, auto skip_funcs, bool dbg) {
      return std::make_unique<NasmPP>(context, ir, skip_funcs, dbg);
    });

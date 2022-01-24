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
#include "driver/Logger.h"

#include <capstone/capstone.h>

namespace gtirb_pprint {

const PrintingPolicy& Mips32PrettyPrinterFactory::defaultPrintingPolicy(
    gtirb::Module& /*Module*/) const {
  // Static binaries are not supported.
  return *findNamedPolicy("dynamic");
}

std::unique_ptr<PrettyPrinterBase>
Mips32PrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                   gtirb::Module& module,
                                   const PrintingPolicy& policy) {
  static const ElfSyntax syntax{};
  static const GasAssembler assembler{};
  return std::make_unique<Mips32PrettyPrinter>(gtirb_context, module, syntax,
                                               assembler, policy);
}

Mips32PrettyPrinterFactory::Mips32PrettyPrinterFactory() {
  auto& DynamicPolicy = *findRegisteredNamedPolicy("dynamic");
  DynamicPolicy.skipFunctions.erase("call_weak_fn");
  DynamicPolicy.skipSymbols.erase("_fp_hw");
  DynamicPolicy.skipSections.erase(".rela.dyn");
  DynamicPolicy.skipSections.erase(".rela.plt");

  DynamicPolicy.skipFunctions.insert(
      {"__do_global_ctors_aux", "__start",
       // Functions to avoid printing for sectionless binaries
       "_fini", "_init"});
  DynamicPolicy.skipSymbols.insert(
      {"_DYNAMIC", "data_start",
       // Include symbols in sections to avoid printing for sectionless binaries
       "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable",
       "_Jv_RegisterClasses", "__gmon_start__"});
  DynamicPolicy.skipSections.insert(
      {".MIPS.stubs", ".ctors", ".dtors", ".interp", ".rld_map", ".sdata"});

  deregisterNamedPolicy("static");
  deregisterNamedPolicy("complete");
}

Mips32PrettyPrinter::Mips32PrettyPrinter(gtirb::Context& context_,
                                         gtirb::Module& module_,
                                         const ElfSyntax& syntax_,
                                         const GasAssembler& assembler_,
                                         const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, assembler_, policy_) {

  unsigned int mode = CS_MODE_MIPS32;
  if (module_.getByteOrder() == gtirb::ByteOrder::Big) {
    mode |= CS_MODE_BIG_ENDIAN;
  } else if (module_.getByteOrder() == gtirb::ByteOrder::Little) {
    mode |= CS_MODE_LITTLE_ENDIAN;
  } else {
    LOG_ERROR << "WARNING: No BE/LE info: Use Big-Endian by default.";
    mode |= CS_MODE_BIG_ENDIAN;
  }

  // Setup Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_MIPS, (cs_mode)mode, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
}

void Mips32PrettyPrinter::printHeader(std::ostream& os) {
  ElfPrettyPrinter::printHeader(os);

  // we already account for delay slots; don't let the assembler insert them
  os << ".set noreorder" << std::endl;
}

void Mips32PrettyPrinter::printAlignment(std::ostream& OS, uint64_t Align) {
  // In MIPS Assembly Language, `.align N` aligns the next element to multiple
  // of 2^N. In other ISAs, `.align N` aligns the next element to N.
  int X = Align, Log2X = 0;
  while (X >>= 1) {
    ++Log2X;
  }

  ElfPrettyPrinter::printAlignment(OS, Log2X);
}

// Workaround for correct printing of the following instructions:
//
//      cfc1  $t0,$31       instead of      cfc1 $t0,$ra     (be: 4448f800)
//      ctc1  $at,$31       instead of      ctc1 $at,$ra     (be: 44c1f800)
//      rdhwr $v1,$29       instead of      rdhwr $v1,$sp    (be: 7c03e83b)
//      ldc2  $3,0($k0)     instead of      ldc2 $v1,0($k0)  (be: db430000)
//      lwc2  $3,0($k0)     instead of      lwc2 $v1,0($k0)  (be: cb430000)
//      sdc2  $3,0($k0)     instead of      sdc2 $v1,0($k0)  (be: fb430000)
//      swc2  $3,0($k0)     instead of      swc2 $v1,0($k0)  (be: eb430000)
//
// Note that capstone's Mips_printInst has the logic to produce the correct
// output (as can be seen by running `cstool -d mipsbe 4448f800`),
// but capstone's Mips_map_register folds away the distinction.
// To implement a proper capstone fix, start by looking at Mips_map_register.
//
// Note: cfc1 and ctc1 occur as part of trunc.w.d macro expansion (when
// compiling with -march=mips1); rdhwr is produced by gcc/libsanitizer (kernel
// illegal instruction trap optimized for v1).
static bool printOpRegdirectSpecial(std::ostream& os,
                                    unsigned int opcode, // cs_insn.id
                                    uint64_t opno, mips_reg reg) {
  // NOTE: this should ideally be an unordered_set, but it's not worth mucking
  // with a hash function at this point (until there is a std::hash_combine).
  static const std::set<std::pair<unsigned int, uint64_t>> specials = {
      {MIPS_INS_CTC1, 1}, {MIPS_INS_CFC1, 1}, {MIPS_INS_RDHWR, 1},
      {MIPS_INS_LDC2, 0}, {MIPS_INS_LWC2, 0}, {MIPS_INS_SDC2, 0},
      {MIPS_INS_SWC2, 0},
  };
  if (specials.find({opcode, opno}) == specials.end())
    return false;
  os << "$" << (reg - MIPS_REG_0);
  return true;
}

void Mips32PrettyPrinter::printOpRegdirect(std::ostream& os,
                                           const cs_insn& inst,
                                           uint64_t index) {
  const cs_mips_op& op = inst.detail->mips.operands[index];
  if (!printOpRegdirectSpecial(os, inst.id, index, op.reg))
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
  std::stringstream InstructLine;
  printComments(InstructLine, offset, inst.size);
  printCFIDirectives(InstructLine, offset);
  printEA(InstructLine, ea);

  InstructLine << "  " << inst.mnemonic << ' ';
  // Make sure the initial m_accum_comment is empty.
  m_accum_comment.clear();
  printOperandList(InstructLine, block, inst);
  if (!m_accum_comment.empty()) {
    InstructLine << " " << syntax.comment() << " " << m_accum_comment;
    m_accum_comment.clear();
  }
  printCommentableLine(InstructLine, os, ea);
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

void Mips32PrettyPrinter::printSymExprPrefix(
    std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
    bool /*IsNotBranch*/) {
  for (const auto& Attr : Attrs) {
    switch (Attr) {
    case gtirb::SymAttribute::Lo: {
      OS << "%lo(";
    } break;
    case gtirb::SymAttribute::Hi: {
      OS << "%hi(";
    } break;
    case gtirb::SymAttribute::AddrRelGot: {
      OS << "%got(";
    } break;
    default:
      assert(!"Unknown sym expr attribute encountered!");
    }
  }
}

void Mips32PrettyPrinter::printSymExprSuffix(
    std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
    bool /*IsNotBranch*/) {
  for (const auto& Attr : Attrs) {
    switch (Attr) {
    case gtirb::SymAttribute::Lo:
    case gtirb::SymAttribute::Hi:
    case gtirb::SymAttribute::AddrRelGot: {
      OS << ")";
    } break;
    default:
      assert(!"Unknown sym expr attribute encountered!");
    }
  }
}

void Mips32PrettyPrinter::printIntegralSymbol(std::ostream& os,
                                              const gtirb::Symbol& sym) {
  const gtirb::ProxyBlock* externalBlock = sym.getReferent<gtirb::ProxyBlock>();
  if (!externalBlock) {
    return;
  }
  ElfPrettyPrinter::printIntegralSymbol(os, sym);
}

void Mips32PrettyPrinter::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrAddr* sexpr, bool IsNotBranch) {
  if (sexpr->Sym1->getName() == "_gp" || sexpr->Sym1->getName() == "_gp_copy") {
    printSymExprPrefix(os, sexpr->Attributes, IsNotBranch);
    os << "_gp_disp";
    printSymExprSuffix(os, sexpr->Attributes, IsNotBranch);
    return;
  }

  ElfPrettyPrinter::printSymbolicExpression(os, sexpr, IsNotBranch);
}

void Mips32PrettyPrinter::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrConst* sexpr, bool IsNotBranch) {
  ElfPrettyPrinter::printSymbolicExpression(os, sexpr, IsNotBranch);
}

} // namespace gtirb_pprint

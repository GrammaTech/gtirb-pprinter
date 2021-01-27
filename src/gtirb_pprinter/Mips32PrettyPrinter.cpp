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
  static PrintingPolicy DefaultPolicy{
      /// Functions to avoid printing.
      {"_start", "__start", "deregister_tm_clones", "register_tm_clones",
       "__do_global_dtors_aux", "__do_global_ctors_aux", "frame_dummy",
       "__libc_csu_fini", "__libc_csu_init", "_dl_relocate_static_pie"},

      /// Symbols to avoid printing.
      {"_IO_stdin_used", "__data_start", "__dso_handle", "__TMC_END__",
       "_edata", "_fdata", "_DYNAMIC", "data_start", "__bss_start",
       "program_invocation_name", "program_invocation_short_name",
       // Include symbols in sections to avoid printing for sectionless binaries
       "__gmon_start__", "_ITM_deregisterTMCloneTable",
       "_ITM_registerTMCloneTable"},

      /// Sections to avoid printing.
      {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt",
       ".plt.sec", ".eh_frame_hdr", ".eh_frame", ".interp", ".MIPS.stubs",
       ".ctors", ".dtors", ".rld_map", ".sdata"},

      /// Sections with possible data object exclusion.
      {".init_array", ".fini_array"},
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
  auto a = module_.findSymbols("_gp_copy");
  if (!a.empty()) {
    GP = &a.front();
  } else {
    // If _gp is not found, leave GP as NULL.
    LOG_ERROR << "WARNING: Could not find _gp.";
  }

  // Setup Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_MIPS, (cs_mode)(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN),
              &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
}

void Mips32PrettyPrinter::printHeader(std::ostream& os) {
  // we already account for delay slots; don't let the assembler insert them
  os << ".set noreorder" << std::endl;
}

void Mips32PrettyPrinter::printAlignment(std::ostream& os,
                                         const gtirb::Addr addr) {
  // Enforce maximum alignment
  uint64_t x{addr};
  int n = 0;
  if (x % 16 == 0) {
    n = 4;
  } else if (x % 8 == 0) {
    n = 3;
  } else if (x % 4 == 0) {
    n = 2;
  } else if (x % 2 == 0) {
    n = 1;
  }

  if (n != 0) {
    // MIPS Assembly Language: .align n: aligns next element to multiple of 2^N
    // Other ISAs: .align n: aligns next element to n
    if (module.getISA() != gtirb::ISA::MIPS32)
      n = 1 << n;
    os << syntax.align() << " " << n << std::endl;
  }
}

void Mips32PrettyPrinter::printOpRegdirect(std::ostream& os,
                                           const cs_insn& inst,
                                           uint64_t index) {
  const cs_mips_op& op = inst.detail->mips.operands[index];
  os << getRegisterName(op.reg);
}

std::string
Mips32PrettyPrinter::printOpImmediate(std::ostream& os,
                                      const gtirb::SymbolicExpression* symbolic,
                                      const cs_insn& inst, uint64_t index) {
  std::string ret("");
  if (symbolic) {
    if (auto* SAC = std::get_if<gtirb::SymAddrConst>(symbolic)) {
      ret = printSymbolicExpression(os, SAC);
    } else if (auto* SAA = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
      ret = printSymbolicExpression(os, SAA);
    } else {
      assert(!"Unknown sym expr type in printOpImmediate!");
    }
  } else {
    const cs_mips_op& op = inst.detail->mips.operands[index];
    os << op.imm;
  }
  return ret;
}

std::string
Mips32PrettyPrinter::printOpIndirect(std::ostream& os,
                                     const gtirb::SymbolicExpression* symbolic,
                                     const cs_insn& inst, uint64_t index) {
  const cs_mips_op& op = inst.detail->mips.operands[index];

  std::string ret("");
  if (symbolic) {
    if (auto* SAC = std::get_if<gtirb::SymAddrConst>(symbolic)) {
      ret = printSymbolicExpression(os, SAC);
    } else if (auto* SAA = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
      ret = printSymbolicExpression(os, SAA);
    } else {
      assert(!"Unknown sym expr type in printOpImmediate!");
    }
  } else {
    os << op.mem.disp;
  }

  os << '(' << getRegisterName(op.mem.base) << ')';
  return ret;
}

std::string Mips32PrettyPrinter::getRegisterName(unsigned int reg) const {
  assert(reg != MIPS_REG_INVALID && "Register has no name!");
  return std::string{"$"} + cs_reg_name(this->csHandle, reg);
}

std::string Mips32PrettyPrinter::printOperand(std::ostream& os,
                                              const gtirb::CodeBlock& block,
                                              const cs_insn& inst,
                                              uint64_t index) {
  const cs_mips_op& op = inst.detail->mips.operands[index];
  const gtirb::SymbolicExpression* SymExpr = nullptr;

  switch (op.type) {
  case MIPS_OP_IMM:
    SymExpr = block.getByteInterval()->getSymbolicExpression(
        gtirb::Addr{inst.address} - *block.getByteInterval()->getAddress());
    return printOpImmediate(os, SymExpr, inst, index);
  case MIPS_OP_REG:
    printOpRegdirect(os, inst, index);
    return "";
  case MIPS_OP_MEM:
    SymExpr = block.getByteInterval()->getSymbolicExpression(
        gtirb::Addr{inst.address} - *block.getByteInterval()->getAddress());
    return printOpIndirect(os, SymExpr, inst, index);
  default:
    assert(!"unknown mips op type!");
  }
  return "";
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
  std::string comment_str = printOperandList(os, block, inst);
  if (!comment_str.empty()) {
    os << " " << syntax.comment() << " " << comment_str;
  }
  os << '\n';
}

std::string Mips32PrettyPrinter::printOperandList(std::ostream& os,
                                                  const gtirb::CodeBlock& block,
                                                  const cs_insn& inst) {
  const cs_mips& detail = inst.detail->mips;

  std::string ret("");
  for (int i = 0; i < detail.op_count; i++) {
    if (i != 0) {
      os << ',';
    }
    ret += printOperand(os, block, inst, i);
  }
  return ret;
}

void Mips32PrettyPrinter::printSymExprPrefix(
    std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
    bool /*IsNotBranch*/) {
  for (const auto& Attr : Attrs) {
    switch (Attr) {
    case gtirb::SymAttribute::Part0: {
      OS << "%lo(";
    } break;
    case gtirb::SymAttribute::Part1: {
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

void Mips32PrettyPrinter::printIntegralSymbol(std::ostream& os,
                                              const gtirb::Symbol& sym) {
  const gtirb::ProxyBlock* externalBlock = sym.getReferent<gtirb::ProxyBlock>();
  if (!externalBlock) {
    return;
  }
  ElfPrettyPrinter::printIntegralSymbol(os, sym);
}

std::string Mips32PrettyPrinter::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrAddr* sexpr, bool IsNotBranch) {
  if (sexpr->Sym1 == GP) {
    printSymExprPrefix(os, sexpr->Attributes, IsNotBranch);
    os << "_gp_disp";
    printSymExprSuffix(os, sexpr->Attributes, IsNotBranch);
    return "";
  }

  return ElfPrettyPrinter::printSymbolicExpression(os, sexpr, IsNotBranch);
}

std::string Mips32PrettyPrinter::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrConst* sexpr, bool IsNotBranch) {
  return ElfPrettyPrinter::printSymbolicExpression(os, sexpr, IsNotBranch);
}

} // namespace gtirb_pprint

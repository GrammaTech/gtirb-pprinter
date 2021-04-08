//===- MasmPrinter.cpp ------------------------------------------*- C++ -*-===//
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

#include "MasmPrettyPrinter.hpp"

#include "AuxDataSchema.hpp"
#include "regex"
#include "string_utils.hpp"
#include <boost/algorithm/string/replace.hpp>

namespace gtirb_pprint {

std::string MasmSyntax::formatSectionName(const std::string& x) const {
  std::string name(x);
  if (name[0] == '.')
    name[0] = '_';
  return ascii_str_toupper(name);
}

std::string MasmSyntax::formatFunctionName(const std::string& x) const {
  std::string name(x);
  if (name[0] == '.')
    name[0] = '$';
  return name;
}

std::string MasmSyntax::formatSymbolName(const std::string& x) const {
  std::string name = avoidRegNameConflicts(x);
  if (name[0] == '.')
    name[0] = '$';
  return name;
}

MasmPrettyPrinter::MasmPrettyPrinter(gtirb::Context& context_,
                                     gtirb::Module& module_,
                                     const MasmSyntax& syntax_,
                                     const PrintingPolicy& policy_)
    : PePrettyPrinter(context_, module_, syntax_, policy_),
      masmSyntax(syntax_) {
  // Setup Capstone.
  cs_mode Mode = CS_MODE_64;
  if (module.getISA() == gtirb::ISA::IA32) {
    Mode = CS_MODE_32;
  }
  [[maybe_unused]] cs_err err = cs_open(CS_ARCH_X86, Mode, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");

  // TODO: Evaluate this syntax option.
  // cs_option(this->csHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);

  BaseAddress = module.getPreferredAddr();
  if (auto It = module.findSymbols("__ImageBase"); !It.empty()) {
    ImageBase = &*It.begin();
    ImageBase->setReferent(module.addProxyBlock(context));
    if (module.getISA() == gtirb::ISA::IA32) {
      ImageBase->setName("___ImageBase");
    }
  }

  if (gtirb::CodeBlock* Block = module.getEntryPoint();
      Block && Block->getAddress()) {
    auto entry_syms = module.findSymbols(*Block->getAddress());
    if (entry_syms.empty()) {
      auto* EntryPoint = gtirb::Symbol::Create(context, *(Block->getAddress()),
                                               "__EntryPoint");
      EntryPoint->setReferent<gtirb::CodeBlock>(Block);
      module.addSymbol(EntryPoint);
      Exports.insert(EntryPoint->getUUID());
    } else {
      Exports.insert((&*entry_syms.begin())->getUUID());
    }
  }

  const auto* ImportedSymbols =
      module.getAuxData<gtirb::schema::PeImportedSymbols>();
  if (ImportedSymbols) {
    for (const auto& UUID : *ImportedSymbols) {
      Imports.insert(UUID);
    }
  }

  const auto* ExportedSymbols =
      module.getAuxData<gtirb::schema::PeExportedSymbols>();
  if (ExportedSymbols) {
    for (const auto& UUID : *ExportedSymbols) {
      Exports.insert(UUID);
    }
  }
}

void MasmPrettyPrinter::printIncludes(std::ostream& os) {
  const auto* libraries = module.getAuxData<gtirb::schema::Libraries>();
  if (libraries) {
    for (const auto& library : *libraries) {
      // Include import libs later generated using synthesized DEF files passed
      // through lib.exe
      os << "INCLUDELIB " << boost::ireplace_last_copy(library, ".dll", ".lib")
         << '\n';
    }
  }
  os << '\n';
}

void MasmPrettyPrinter::printExterns(std::ostream& os) {
  // Declare EXTERN symbols
  if (const auto* symbolForwarding =
          module.getAuxData<gtirb::schema::SymbolForwarding>()) {
    std::set<std::string> Externs;
    for (auto& forward : *symbolForwarding) {
      if (const auto* symbol = dyn_cast_or_null<gtirb::Symbol>(
              gtirb::Node::getByUUID(context, forward.second))) {
        std::string Name = getSymbolName(*symbol);
        // This is not completely understood why, but link.exe (msvc) mangles
        // differently.  We'll apply this heuristic until it's fully understood.
        Externs.insert(module.getISA() == gtirb::ISA::IA32 && Name[0] != '?'
                           ? "_" + Name
                           : Name);
      }
    }
    for (auto& Name : Externs) {
      // Since we don't know up front if the references to an export are direct,
      // indirect, or both, we will define both as extern conservatively.  This
      // should have no impact at runtime, and both with be defined in the
      // import library regardless.
      os << masmSyntax.extrn() << " "
         << "__imp_" << Name << ":PROC\n";
      os << masmSyntax.extrn() << " " << Name << ":PROC\n";
    }
  }

  os << '\n';

  os << masmSyntax.extrn() << " "
     << (module.getISA() == gtirb::ISA::IA32 ? "___ImageBase" : "__ImageBase")
     << ":BYTE\n";

  os << '\n';
}

void MasmPrettyPrinter::printHeader(std::ostream& os) {
  if (module.getISA() == gtirb::ISA::IA32) {
    os << ".686p\n"
       << ".XMM\n"
       << ".MODEL FLAT\n"
       << "ASSUME FS:NOTHING\n"
       << "\n";
  }
  printIncludes(os);
  printExterns(os);
}

void MasmPrettyPrinter::printSectionHeader(std::ostream& os,
                                           const gtirb::Section& section) {
  std::string sectionName = section.getName();
  os << '\n';
  printBar(os);

  printSectionHeaderDirective(os, section);
  printSectionProperties(os, section);
  os << '\n';

  printBar(os);
  os << '\n';
}

void MasmPrettyPrinter::printSectionHeaderDirective(
    std::ostream& os, const gtirb::Section& section) {
  std::string section_name = syntax.formatSectionName(section.getName());
  os << section_name << ' ' << syntax.section();
}

void MasmPrettyPrinter::printSectionProperties(std::ostream& os,
                                               const gtirb::Section& section) {
  const auto* peSectionProperties =
      module.getAuxData<gtirb::schema::PeSectionProperties>();
  if (!peSectionProperties)
    return;
  const auto sectionProperties = peSectionProperties->find(section.getUUID());
  if (sectionProperties == peSectionProperties->end())
    return;
  uint64_t flags = sectionProperties->second;

  if (flags & IMAGE_SCN_MEM_READ)
    os << " READ";
  if (flags & IMAGE_SCN_MEM_WRITE)
    os << " WRITE";
  if (flags & IMAGE_SCN_MEM_EXECUTE)
    os << " EXECUTE";
  if (flags & IMAGE_SCN_MEM_SHARED)
    os << " SHARED";
  if (flags & IMAGE_SCN_MEM_NOT_PAGED)
    os << " NOPAGE";
  if (flags & IMAGE_SCN_MEM_NOT_CACHED)
    os << " NOCACHE";
  if (flags & IMAGE_SCN_MEM_DISCARDABLE)
    os << " DISCARD";
  if (flags & IMAGE_SCN_CNT_CODE)
    os << " 'CODE'";
  if (flags & IMAGE_SCN_CNT_INITIALIZED_DATA)
    os << " 'DATA'";
};

void MasmPrettyPrinter::printSectionFooterDirective(
    std::ostream& os, const gtirb::Section& section) {
  std::string section_name = syntax.formatSectionName(section.getName());

  os << section_name << ' ' << masmSyntax.ends() << '\n';
}

void MasmPrettyPrinter::printFunctionHeader(std::ostream& /* os */,
                                            gtirb::Addr /* addr */) {
  // TODO
}

void MasmPrettyPrinter::printFunctionFooter(std::ostream& /* os */,
                                            gtirb::Addr /* addr */) {
  // TODO
}

void MasmPrettyPrinter::fixupInstruction(cs_insn& inst) {
  cs_x86& Detail = inst.detail->x86;

  // Change GAS-specific MOVABS opcode to equivalent MOV opcode.
  if (inst.id == X86_INS_MOVABS) {
    std::string_view mnemonic(inst.mnemonic);
    if (mnemonic.size() > 3) {
      inst.mnemonic[3] = '\0';
    }
  }

  // PBLENDVB/BLENDVPS have an implicit third argument (XMM0) required by MASM
  if (inst.id == X86_INS_PBLENDVB || inst.id == X86_INS_BLENDVPS) {
    if (Detail.op_count == 2) {
      Detail.op_count = 3;
      cs_x86_op& Op = Detail.operands[2];
      Op.type = X86_OP_REG;
      Op.reg = X86_REG_XMM0;
    }
  }

  // TODO: These next two fixups of one-operand floating-point instructions need
  // much more consideration.

  //  Floating point one-operand operations with an implicit FIRST operand.
  //   e.g  fmul st(1)  needs to be  fmul st(0),st(1)
  switch (inst.id) {
  case X86_INS_FDIV:
  case X86_INS_FSUB:
  case X86_INS_FMUL:
    if (Detail.op_count == 1) {
      cs_x86_op& Op = Detail.operands[0];
      if (Op.type == X86_OP_REG) {
        Detail.operands[1] = Detail.operands[0];
        Detail.operands[0].reg = X86_REG_ST0;
        Detail.op_count = 2;
      }
    }
  }

  // Floating point one-operand operations with an implicit SECOND operand.
  //   e.g  faddp st(2)  needs to be  faddp st(2),st(0)
  switch (inst.id) {
  case X86_INS_FSUBP:
  case X86_INS_FADD:
  case X86_INS_FMULP:
  case X86_INS_FDIVP:
  case X86_INS_FSUBRP:
  case X86_INS_FDIVRP:
    if (Detail.op_count == 1) {
      cs_x86_op& Op = Detail.operands[0];
      if (Op.type == X86_OP_REG) {
        Detail.operands[1] = Detail.operands[0];
        Detail.operands[1].reg = X86_REG_ST0;
        Detail.op_count = 2;
      }
    }
  }

  //  FUCOMPI has an implicit first operand and a different mnemonic.
  //   e.g. fucompi ST(1)  should be  fucomip ST(0),ST(1)
  if (inst.id == X86_INS_FUCOMPI)
    if (Detail.op_count == 1) {
      cs_x86_op& Op = Detail.operands[0];
      if (Op.type == X86_OP_REG && Op.reg == X86_REG_ST1) {
        Detail.operands[1] = Detail.operands[0];
        Detail.operands[0].reg = X86_REG_ST0;
        Detail.op_count = 2;
        inst.mnemonic[5] = 'i';
        inst.mnemonic[6] = 'p';
      }
    }

  // The first argument for SCASB is implied.
  if (inst.id == X86_INS_SCASB) {
    if (Detail.op_count == 2 && Detail.operands[0].type == X86_OP_REG &&
        Detail.operands[0].reg == X86_REG_AL) {
      Detail.operands[0] = Detail.operands[1];
      Detail.op_count = 1;
    }
  }

  // The k1 register from AVX512 instructions is frequently set to NULL.
  if (inst.id == X86_INS_KMOVB) {
    cs_x86_op& Op = Detail.operands[0];
    if (Op.type == X86_OP_REG && Op.reg == X86_REG_INVALID) {
      Op.reg = X86_REG_K1;
    }
  }

  if (inst.id == X86_INS_VCVTTPS2UQQ || inst.id == X86_INS_VCVTTPS2QQ) {
    if (Detail.op_count > 1) {
      cs_x86_op& Op = Detail.operands[1];
      if (Op.type == X86_OP_REG && Op.reg == X86_REG_INVALID) {
        Op.reg = X86_REG_K1;
      }
    }
  }

  x86FixupInstruction(inst);
}

std::optional<std::string>
MasmPrettyPrinter::getForwardedSymbolName(const gtirb::Symbol* symbol) const {
  if (std::optional<std::string> Name =
          PrettyPrinterBase::getForwardedSymbolName(symbol)) {
    return module.getISA() == gtirb::ISA::IA32 && (*Name)[0] != '?'
               ? "_" + *Name
               : Name;
  }
  return std::nullopt;
}

std::string MasmPrettyPrinter::getRegisterName(unsigned int Reg) const {
  // Uppercase `k1' causes a syntax error with MASM. Yes, really.
  if (Reg == X86_REG_K1) {
    return "k1";
  }
  return PrettyPrinterBase::getRegisterName(Reg);
}

void MasmPrettyPrinter::printSymbolDefinition(std::ostream& os,
                                              const gtirb::Symbol& symbol) {
  bool Exported = Exports.count(symbol.getUUID()) > 0;
  if (symbol.getReferent<gtirb::DataBlock>()) {
    if (Exported) {
      os << syntax.global() << ' ' << getSymbolName(symbol) << '\n';
    }
    os << getSymbolName(symbol) << ' ';
  } else {
    if (Exported) {
      os << symbol.getName() << ' ' << masmSyntax.proc() << " EXPORT\n"
         << symbol.getName() << ' ' << masmSyntax.endp() << '\n';
    } else {
      os << getSymbolName(symbol) << ":\n";
    }
  }
}

void MasmPrettyPrinter::printSymbolDefinitionRelativeToPC(
    std::ostream& os, const gtirb::Symbol& symbol, gtirb::Addr pc) {
  auto symAddr = *symbol.getAddress();

  os << getSymbolName(symbol) << " = " << syntax.programCounter();
  if (symAddr > pc) {
    os << " + " << (symAddr - pc);
  } else if (symAddr < pc) {
    os << " - " << (pc - symAddr);
  }
  os << "\n";
}

void MasmPrettyPrinter::printIntegralSymbol(std::ostream& os,
                                            const gtirb::Symbol& symbol) {
  if (*symbol.getAddress() == gtirb::Addr(0)) {
    return;
  }
  os << getSymbolName(symbol) << " = " << *symbol.getAddress() << '\n';
}

void MasmPrettyPrinter::printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                         uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  assert(op.type == X86_OP_REG &&
         "printOpRegdirect called without a register operand");
  os << getRegisterName(op.reg);
}

void MasmPrettyPrinter::printOpImmediate(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  assert(op.type == X86_OP_IMM &&
         "printOpImmediate called without an immediate operand");

  bool is_call = cs_insn_group(this->csHandle, &inst, CS_GRP_CALL);
  bool is_jump = cs_insn_group(this->csHandle, &inst, CS_GRP_JUMP);

  if (const gtirb::SymAddrConst* s = this->getSymbolicImmediate(symbolic)) {
    // The operand is symbolic.

    // Symbols for skipped addresses degrade to literals.
    if (!is_call && !is_jump && !shouldSkip(*s->Sym))
      os << masmSyntax.offset() << ' ';

    printSymbolicExpression(os, s, !is_call && !is_jump);
  } else {
    // The operand is just a number.
    os << op.imm;
  }
}

void MasmPrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];
  assert(op.type == X86_OP_MEM &&
         "printOpIndirect called without a memory operand");
  bool first = true;
  uint64_t size = op.size;

  // Indirect references to imported symbols should refer to the IAT entry,
  // i.e.
  // "__imp_foo"
  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    std::optional<std::string> forwardedName = getForwardedSymbolName(s->Sym);
    if (forwardedName) {
      // If this references code, then it is (and should continue to) reference
      // the jmp thunk of the import which will have the unprefixed "foo" symbol
      // on it. If this references data, then it is (and should continue to)
      // reference the relocation address (IAT entry) name "__imp_foo"
      if (s->Sym->getReferent<gtirb::CodeBlock>())
        os << *forwardedName;
      else {
        if (std::optional<std::string> Size = syntax.getSizeName(size * 8)) {
          os << *Size << " PTR ";
        }
        os << "__imp_" << *forwardedName;
      }

      return;
    }
  }

  //////////////////////////////////////////////////////////////////////////////
  // Capstone incorrectly gives memory operands XMMWORD size.
  if (inst.id == X86_INS_COMISD || inst.id == X86_INS_VCOMISD) {
    size = 8;
  }
  if (inst.id == X86_INS_COMISS) {
    size = 4;
  }
  //////////////////////////////////////////////////////////////////////////////

  if (std::optional<std::string> sizeName = syntax.getSizeName(size * 8))
    os << *sizeName << " PTR ";

  if (op.mem.segment != X86_REG_INVALID)
    os << getRegisterName(op.mem.segment) << ':';

  os << '[';

  if (op.mem.base != X86_REG_INVALID && op.mem.base != X86_REG_RIP) {
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
    if (!first)
      os << '+';

    printSymbolicExpression(os, s, false);
  } else if (const auto* rel = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
    if (std::optional<gtirb::Addr> Addr = rel->Sym1->getAddress(); Addr) {
      os << "+(" << masmSyntax.imagerel() << ' ' << getSymbolName(*rel->Sym1)
         << ")";
      printAddend(os, rel->Offset, false);
    }
  } else {
    printAddend(os, op.mem.disp, first);
  }
  os << ']';
}

void MasmPrettyPrinter::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrConst* sexpr, bool IsNotBranch) {
  PrettyPrinterBase::printSymbolicExpression(os, sexpr, IsNotBranch);
}

void MasmPrettyPrinter::printSymbolicExpression(std::ostream& os,
                                                const gtirb::SymAddrAddr* sexpr,
                                                bool IsNotBranch) {
  if (IsNotBranch && sexpr->Sym2 == ImageBase) {
    os << masmSyntax.imagerel() << ' ';
    printSymbolReference(os, sexpr->Sym1);
    return;
  }

  PrettyPrinterBase::printSymbolicExpression(os, sexpr, IsNotBranch);
}

void MasmPrettyPrinter::printByte(std::ostream& os, std::byte byte) {
  // Byte constants must start with a number for the MASM assembler.
  os << syntax.byteData() << " 0" << std::hex << std::setfill('0')
     << std::setw(2) << static_cast<uint32_t>(byte) << 'H' << std::dec << '\n';
}

void MasmPrettyPrinter::printZeroDataBlock(std::ostream& os,
                                           const gtirb::DataBlock& dataObject,
                                           uint64_t offset) {
  os << syntax.tab();
  os << "DB " << (dataObject.getSize() - offset) << " DUP(0)" << '\n';
}

void MasmPrettyPrinter::printString(std::ostream& os, const gtirb::DataBlock& x,
                                    uint64_t offset) {

  std::string Chunk{""};

  auto Range = x.bytes<uint8_t>();
  for (uint8_t b :
       boost::make_iterator_range(Range.begin() + offset, Range.end())) {
    // NOTE: MASM only supports strings smaller than 256 bytes.
    //  and  MASM only supports statements with 50 comma-separated items.
    if (Chunk.size() >= 64) {
      boost::replace_all(Chunk, "'", "''");
      os << syntax.tab() << syntax.string() << " '" << Chunk << "'\n";
      Chunk.clear();
    }

    // Aggegrate printable characters
    if (std::isprint(b)) {
      Chunk.append(1, b);
      continue;
    }

    // Found non-printable character, output previous chunk and print byte
    if (!Chunk.empty()) {
      boost::replace_all(Chunk, "'", "''");
      os << syntax.tab() << syntax.string() << " '" << Chunk << "'\n";
      Chunk.clear();
    }
    os << syntax.tab();
    printByte(os, static_cast<std::byte>(b));
  }
}

void MasmPrettyPrinter::printFooter(std::ostream& os) {
  os << '\n' << masmSyntax.end();
}

std::unique_ptr<PrettyPrinterBase>
MasmPrettyPrinterFactory::create(gtirb::Context& context, gtirb::Module& module,
                                 const PrintingPolicy& policy) {
  static const MasmSyntax syntax{};
  return std::make_unique<MasmPrettyPrinter>(context, module, syntax, policy);
}
} // namespace gtirb_pprint

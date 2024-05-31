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
#include "AuxDataUtils.hpp"
#include "FileUtils.hpp"
#include "StringUtils.hpp"
#include "regex"
#include <boost/algorithm/string/replace.hpp>

namespace gtirb_pprint {

std::string MasmSyntax::formatSectionName(const std::string& S) const {
  // Valid MASM identifiers are describe as ...
  // Max Length:                                            247
  //    Grammar:          id ::= alpha | id alpha | id decdigit
  //                    alpa ::= a-z | A-Z | @ _ $ ?
  //                decdigit ::= 0-9
  std::string Name(S);
  // Rewrite standard dot-prefixed names by convention,
  //   e.g.  '.text` to `_TEXT'
  if (Name[0] == '.') {
    Name[0] = '_';
    Name = ascii_str_toupper(Name);
  }
  // Truncate long section Names.
  if (Name.length() > 247) {
    Name.resize(247);
  }
  // Replace non-alpha characters with '?' characters.
  for (size_t I = 0; I < Name.size(); I++) {
    switch (Name[I]) {
    case '@':
    case '_':
    case '$':
    case '?':
      continue;
    default:
      if (!std::isalnum(Name[I])) {
        Name[I] = '?';
      }
      continue;
    }
  }
  return Name;
}

std::string MasmSyntax::formatFunctionName(const std::string& x) const {
  std::string name(x);
  if (name[0] == '.')
    name[0] = '$';
  return name;
}

std::string MasmSyntax::avoidRegNameConflicts(const std::string& x) const {
  // MASM has a long number of reserved words that ml.exe rejects
  // as symbol names; but most relevant for actual users,
  // "div" is an invalid symbol name for MASM but not intel.
  const std::vector<std::string> adapt{
      "FS", "MOD", "NOT", "Di", "DIV", "Si", "AND", "OR", "SHR",
      "fs", "mod", "not", "di", "div", "si", "and", "or", "shr"};

  if (const auto found = std::find(std::begin(adapt), std::end(adapt), x);
      found != std::end(adapt)) {
    return x + "_renamed";
  }
  return x;
}

std::string MasmSyntax::formatSymbolName(const std::string& x) const {
  std::string name = this->avoidRegNameConflicts(x);
  if (name[0] == '.')
    name[0] = '$';
  return name;
}

MasmPrettyPrinter::MasmPrettyPrinter(gtirb::Context& context_,
                                     const gtirb::Module& module_,
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
  auto ImageBaseName =
      module.getISA() == gtirb::ISA::IA32 ? "___ImageBase" : "__ImageBase";
  if (auto It = module.findSymbols(ImageBaseName); !It.empty()) {
    ImageBase = &*It.begin();
  }

  if (auto* Block = module.getEntryPoint(); Block && Block->getAddress()) {
    auto It = module.findSymbols(*Block->getAddress());
    EntryPoint = &*It.begin();
  }

  for (const auto& UUID : aux_data::getPeImportedSymbols(module)) {
    Imports.insert(UUID);
  }

  for (const auto& UUID : aux_data::getPeExportedSymbols(module)) {
    Exports.insert(UUID);
  }
}

void MasmPrettyPrinter::printIncludes(std::ostream& os) {
  for (const auto& Library : aux_data::getLibraries(module)) {
    // Include import libs later generated using synthesized DEF files passed
    // through lib.exe.  Have observed .dll and .drv files
    os << "INCLUDELIB " << gtirb_bprint::replaceExtension(Library, ".lib")
       << '\n';
  }
  os << '\n';
}

std::string
MasmPrettyPrinter::getSymbolName(const gtirb::Symbol& Symbol) const {

  std::string Name = PrettyPrinterBase::getSymbolName(Symbol);
  // In case of IA32, the MSVC compiler decorates symbols according to the
  // source language and calling convention. C++ names are mangled and begin
  // with `?`. MSVC generates C-language object files that contain decorated
  // symbols; we rename symbols in the assembly listing to emulate this
  // behavior.
  // To export symbols, we generate a `.def` file, generate an exports file
  // (.exp) from that file, and pass it to the linker. Empirically, using
  // undecorated names in the `.def` file results in an exports file with
  // names decorated with a prefixed underscore. If the symbols haven't been
  // decorated in the assembly, the linker fails to find the symbols with an
  // "unresolved external symbol" error.
  // We assume any symbol that does not begin with `?` is `__cdecl` and
  // prefix an underscore to ensure we can link correctly.
  // See https://learn.microsoft.com/en-us/cpp/build/reference/decorated-names
  // for more details.
  if (module.getISA() == gtirb::ISA::IA32 && Name[0] != '?') {
    bool Imported = Imports.count(Symbol.getUUID()) > 0;
    bool Exported = Exports.count(Symbol.getUUID()) > 0;
    if (Imported || Exported) {
      return "_" + Name;
    } else {
      return Name;
    }
  } else {
    return Name;
  }
}

void MasmPrettyPrinter::printExterns(std::ostream& os) {
  // Declare EXTERN symbols
  std::set<std::string> Externs;
  auto Forwarding = aux_data::getSymbolForwarding(module);
  if (Forwarding.empty()) {
    return;
  }

  for (auto& Forward : Forwarding) {
    if (const auto* Symbol = dyn_cast_or_null<gtirb::Symbol>(
            gtirb::Node::getByUUID(context, Forward.second))) {
      std::string Name = getSymbolName(*Symbol);
      Externs.insert(Name);
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

  os << '\n';

  if (const auto Handlers = aux_data::getPeSafeExceptionHandlers(module);
      Handlers.size() > 0) {

    // Print synthetic linker variables.
    os << masmSyntax.extrn() << " ___safe_se_handler_table:PTR\n";
    os << masmSyntax.extrn() << " ___safe_se_handler_count:BYTE\n";
    os << '\n';

    // Print macro definition of the load config data directory.
    os << "IMAGE_LOAD_CONFIG_DIRECTORY32 STRUCT \n"
       << "Size_                         DWORD ? \n"
       << "TimeDateStamp                 DWORD ? \n"
       << "MajorVersion                  WORD  ? \n"
       << "MinorVersion                  WORD  ? \n"
       << "GlobalFlagsClear              DWORD ? \n"
       << "GlobalFlagsSet                DWORD ? \n"
       << "CriticalSectionDefaultTimeout DWORD ? \n"
       << "DeCommitFreeBlockThreshold    DWORD ? \n"
       << "DeCommitTotalFreeThreshold    DWORD ? \n"
       << "LockPrefixTable               DWORD ? \n"
       << "MaximumAllocationSize         DWORD ? \n"
       << "VirtualMemoryThreshold        DWORD ? \n"
       << "ProcessHeapFlags              DWORD ? \n"
       << "ProcessAffinityMask           DWORD ? \n"
       << "CSDVersion                    WORD  ? \n"
       << "Reserved1                     WORD  ? \n"
       << "EditList                      DWORD ? \n"
       << "SecurityCookie                DWORD 0 \n"
       << "SEHandlerTable                DWORD ? \n"
       << "SEHandlerCount                DWORD ? \n"
       << "IMAGE_LOAD_CONFIG_DIRECTORY32 ENDS \n";

    os << '\n';

    // Print the synthetic `_load_config_used' declaration.
    os << "_RDATA SEGMENT READ 'DATA'\n\n"
       << "PUBLIC __load_config_used\n"
       << "__load_config_used IMAGE_LOAD_CONFIG_DIRECTORY32 {\\\n"
       << "    SIZEOF IMAGE_LOAD_CONFIG_DIRECTORY32,\n"
       << "    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n"
       << "    OFFSET ___safe_se_handler_table,\n"
       << "    OFFSET ___safe_se_handler_count\\\n"
       << "}\n\n"
       << "_RDATA ENDS\n";

    os << '\n';
  }

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
       << "ASSUME GS:NOTHING\n"
       << "\n";
  }
  printIncludes(os);
  printExterns(os);
  if (EntryPoint) {
    os << masmSyntax.global() << " " << (*EntryPoint)->getName() << "\n";
  }
}

void UasmPrettyPrinter::printHeader(std::ostream& os) {
  if (module.getISA() == gtirb::ISA::X64) {
    os << ".x64\n"
       << "ASSUME FS:NOTHING\n"
       << "\n";
  }
  MasmPrettyPrinter::printHeader(os);
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
    std::ostream& Stream, const gtirb::Section& Section) {
  std::string Name = syntax.formatSectionName(Section.getName());

  if (Name.empty()) {
    gtirb::UUID UUID = Section.getUUID();
    if (!RenamedSections.count(UUID)) {
      size_t N = RenamedSections.size() + 1;
      RenamedSections[UUID] = "unnamed_section_" + std::to_string(N);
    }
    Name = RenamedSections[UUID];
  }

  Stream << Name << ' ' << syntax.section();
}

void MasmPrettyPrinter::printSectionProperties(std::ostream& os,
                                               const gtirb::Section& section) {
  // Skip printing section properties for predefined segments.
  std::string Name = syntax.formatSectionName(section.getName());
  if (Name == "_TEXT" || Name == "_DATA") {
    return;
  }

  if (const auto SectionProperties = aux_data::getSectionProperties(section)) {
    uint64_t Flags = std::get<1>(*SectionProperties);

    if (Flags & IMAGE_SCN_MEM_READ)
      os << " READ";
    if (Flags & IMAGE_SCN_MEM_WRITE)
      os << " WRITE";
    if (Flags & IMAGE_SCN_MEM_EXECUTE)
      os << " EXECUTE";
    if (Flags & IMAGE_SCN_MEM_SHARED)
      os << " SHARED";
    if (Flags & IMAGE_SCN_MEM_NOT_PAGED)
      os << " NOPAGE";
    if (Flags & IMAGE_SCN_MEM_NOT_CACHED)
      os << " NOCACHE";
    if (Flags & IMAGE_SCN_MEM_DISCARDABLE)
      os << " DISCARD";
    if (Flags & IMAGE_SCN_CNT_CODE)
      os << " 'CODE'";
    if (Flags & IMAGE_SCN_CNT_INITIALIZED_DATA)
      os << " 'DATA'";
  }
};

void MasmPrettyPrinter::printSectionFooterDirective(
    std::ostream& Stream, const gtirb::Section& Section) {
  std::string Name = syntax.formatSectionName(Section.getName());
  if (RenamedSections.count(Section.getUUID())) {
    Name = RenamedSections[Section.getUUID()];
  }
  Stream << Name << ' ' << masmSyntax.ends() << '\n';
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

  // NOTE: Capstone does not have X86_INS_FADDP.
  // To distinguish FADDP from FADD, use the opcode byte.
  auto isFADDP = [](cs_insn& ins) -> bool {
    if (ins.id == X86_INS_FADD) {
      assert(ins.size > 1);
      return (ins.bytes[0] == 0xDE);
    }
    return false;
  };

  // TODO: These next two fixups of one-operand floating-point instructions need
  // much more consideration.

  //  Floating point one-operand operations with an implicit FIRST operand.
  //   e.g  fadd st(1)  needs to be  fadd st(0),st(1)
  switch (inst.id) {
  case X86_INS_FADD:
  case X86_INS_FDIV:
  case X86_INS_FDIVR:
  case X86_INS_FSUB:
  case X86_INS_FSUBR:
  case X86_INS_FMUL:
    if (Detail.op_count == 1) {
      if (isFADDP(inst))
        break;

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
  case X86_INS_FADD: // FADDP
  case X86_INS_FMULP:
  case X86_INS_FDIVP:
  case X86_INS_FSUBP:
  case X86_INS_FSUBRP:
  case X86_INS_FDIVRP:
    if (Detail.op_count == 1) {
      if (inst.id == X86_INS_FADD && !isFADDP(inst))
        break;

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
  if (inst.id == X86_INS_FUCOMPI || inst.id == X86_INS_FUCOMI)
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

  // Omit implicit operands for scan string instructions.
  switch (inst.id) {
  case X86_INS_SCASB:
  case X86_INS_SCASW:
  case X86_INS_SCASD:
    Detail.op_count = 0;
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

  // Change ATT-specific mnemonics PUSHAL/POPAL.
  if (inst.id == X86_INS_PUSHAL) {
    strcpy(inst.mnemonic, "pushad");
  }
  if (inst.id == X86_INS_POPAL) {
    strcpy(inst.mnemonic, "popad");
  }

  // Omit implicit LODS operands.
  switch (inst.id) {
  case X86_INS_LODSB:
  case X86_INS_LODSW:
  case X86_INS_LODSD:
  case X86_INS_LODSQ:
    Detail.op_count = 0;
  }

  // BOUND does not have a 64-bit mode.
  if (inst.id == X86_INS_BOUND && Detail.op_count == 2 &&
      Detail.operands[1].size == 8) {
    Detail.operands[1].size = 4;
  }

  // BNDSTX and BNDLDX do not have 128-bit registers.
  if (inst.id == X86_INS_BNDSTX || inst.id == X86_INS_BNDLDX) {
    for (int i = 0; i < Detail.op_count; i++) {
      if (Detail.operands[i].size == 16) {
        Detail.operands[i].size = 4;
      }
    }
  }

  // Remove REPZ from REPZ RET because Masm fails with
  // "error A2044:invalid character in file"
  if (inst.id == X86_INS_RET && Detail.prefix[0] == X86_PREFIX_REPE) {
    Detail.prefix[0] = 0;
    strcpy(inst.mnemonic, "ret");
  }

  x86FixupInstruction(inst);
}

std::optional<std::string>
MasmPrettyPrinter::getForwardedSymbolName(const gtirb::Symbol* symbol) const {
  if (std::optional<std::string> Name =
          PrettyPrinterBase::getForwardedSymbolName(symbol)) {
    return *Name;
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

void MasmPrettyPrinter::printSymbolDefinition(std::ostream& Stream,
                                              const gtirb::Symbol& Symbol) {
  std::string Name = getSymbolName(Symbol);
  // In MASM procedures can be exported by declaring "PROC EXPORT"
  // Non-procedures (data) need to be declared "PUBLIC" AND
  // be specified in the .def file.
  bool Exported = Exports.count(Symbol.getUUID()) > 0;
  if (Symbol.getReferent<gtirb::DataBlock>()) {
    if (Exported) {
      Stream << syntax.global() << ' ' << Name << '\n';
    }
    Stream << Name << (Symbol.getAtEnd() ? ":\n" : " ");
  } else {
    const gtirb::CodeBlock* Block = Symbol.getReferent<gtirb::CodeBlock>();
    bool SafeSeh = aux_data::getPeSafeExceptionHandlers(module).count(
                       Block->getUUID()) > 0;
    bool FunctionSymbol = FunctionSymbols.count(&Symbol) > 0;
    if (FunctionSymbol) {
      Stream << Name << ' ' << masmSyntax.proc();
      if (Exported) {
        Stream << " EXPORT";
      }
      Stream << "\n";
      if (SafeSeh) {
        Stream << ".SAFESEH " << Name << "\n";
      }
    } else {
      if (Exported) {
        Stream << syntax.global() << ' ' << Name << '\n';
      }
      // double colon makes labels available outside procedures
      Stream << Name << "::\n";
    }
  }
}

void MasmPrettyPrinter::printFunctionEnd(std::ostream& OS,
                                         const gtirb::Symbol& FunctionSymbol) {
  OS << getSymbolName(FunctionSymbol) << ' ' << masmSyntax.endp() << '\n';
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
  os << getSymbolName(symbol) << " = " << std::hex
     << static_cast<uint64_t>(*symbol.getAddress()) << "H\n";
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
  cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];

  assert(op.type == X86_OP_IMM &&
         "printOpImmediate called without an immediate operand");

  bool is_call = cs_insn_group(this->csHandle, &inst, CS_GRP_CALL);
  bool is_jump = cs_insn_group(this->csHandle, &inst, CS_GRP_JUMP);

  if (const gtirb::SymAddrConst* s = this->getSymbolicImmediate(symbolic)) {
    // The operand is symbolic.
    gtirb::Symbol& sym = *(s->Sym);

    if (!is_call && !is_jump && !shouldSkip(policy, sym)) {

      // MASM variables are given a 64-bit type for PE32+, which results in an
      // error when the symbol is written to a 32-bit register.
      bool omit = false;
      if (module.getISA() == gtirb::ISA::X64) {
        if (auto addr = sym.getAddress(); addr && !sym.hasReferent()) {
          // Integral symbol ...
          for (int i = 0; i < detail.op_count; i++) {
            if (detail.operands[i].size == 4 &&
                detail.operands[i].access == CS_AC_WRITE) {
              // written to a 32-bit operand.
              omit = true;
              break;
            }
          }
        }
      }

      if (!omit) {
        os << masmSyntax.offset() << ' ';
      }
    }

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

  // MASM (x86) requires explicit DS: segment prefix for absolute, integral
  // addresses, otherwise the operand will be assembled as an immediate value
  // regardless of indirect brackets.
  //
  // Note that this includes named symbols with assigned integral values,
  // e.g.  mov EAX,DWORD PTR DS:[KUSER_SHARED_DATA+620]
  //       ...
  //       KUSER_SHARED_DATA = 7ffe0000H
  if (module.getISA() == gtirb::ISA::IA32 &&
      op.mem.segment == X86_REG_INVALID && op.mem.base == X86_REG_INVALID &&
      op.mem.index == X86_REG_INVALID) {
    if (!symbolic) {
      os << "DS:";
    } else if (const auto* Expr = std::get_if<gtirb::SymAddrConst>(symbolic)) {
      gtirb::Symbol* Sym = Expr->Sym;
      if (Sym && Sym->getAddress() && !Sym->hasReferent()) {
        os << "DS:";
      }
    }
  }

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
     << std::setw(2) << static_cast<uint32_t>(byte) << 'H' << std::dec;
}

void MasmPrettyPrinter::printZeroDataBlock(std::ostream& os,
                                           const gtirb::DataBlock& dataObject,
                                           uint64_t offset) {
  os << syntax.tab();
  os << "DB " << (dataObject.getSize() - offset) << " DUP(0)" << '\n';
}

bool MasmPrettyPrinter::printSymbolReference(std::ostream& Stream,
                                             const gtirb::Symbol* Symbol) {
  if (Symbol && Symbol->getReferent<gtirb::DataBlock>()) {
    if (std::optional<std::string> Name = getForwardedSymbolName(Symbol)) {
      Stream << "__imp_" << *Name;
      return true;
    }
  }

  return PrettyPrinterBase::printSymbolReference(Stream, Symbol);
}

void MasmPrettyPrinter::printString(std::ostream& Stream,
                                    const gtirb::DataBlock& Block,
                                    uint64_t Offset, bool NullTerminated) {
  std::string Chunk{""};

  auto Bytes = Block.bytes<uint8_t>();
  auto It = boost::make_iterator_range(Bytes.begin() + Offset, Bytes.end());
  for (uint8_t Byte : It) {
    // NOTE: MASM only supports strings smaller than 256 bytes.
    //  and  MASM only supports statements with 50 comma-separated items.
    if (Chunk.size() >= 64) {
      boost::replace_all(Chunk, "'", "''");
      Stream << syntax.tab() << syntax.string() << " '" << Chunk << "'\n";
      Chunk.clear();
    }

    // Aggegrate printable characters
    if (std::isprint(Byte)) {
      Chunk.append(1, Byte);
      continue;
    }

    // Found non-printable character, output previous chunk and print byte
    if (!Chunk.empty()) {
      boost::replace_all(Chunk, "'", "''");
      Stream << syntax.tab() << syntax.string() << " '" << Chunk << "'\n";
      Chunk.clear();
    }
    Stream << syntax.tab();
    printByte(Stream, static_cast<std::byte>(Byte));
    Stream << "\n";
  }
  if (!NullTerminated && !Chunk.empty()) {
    boost::replace_all(Chunk, "'", "''");
    Stream << syntax.tab() << syntax.string() << " '" << Chunk << "'\n";
    Chunk.clear();
  }
}

void MasmPrettyPrinter::printFooter(std::ostream& os) {
  os << '\n' << masmSyntax.end();
}

std::unique_ptr<PrettyPrinterBase>
MasmPrettyPrinterFactory::create(gtirb::Context& context,
                                 const gtirb::Module& module,
                                 const PrintingPolicy& policy) {
  static const MasmSyntax syntax{};
  return std::make_unique<MasmPrettyPrinter>(context, module, syntax, policy);
}

std::unique_ptr<PrettyPrinterBase>
UasmPrettyPrinterFactory::create(gtirb::Context& context,
                                 const gtirb::Module& module,
                                 const PrintingPolicy& policy) {
  static const MasmSyntax syntax{};
  return std::make_unique<UasmPrettyPrinter>(context, module, syntax, policy);
}
} // namespace gtirb_pprint

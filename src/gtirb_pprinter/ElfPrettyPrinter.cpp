//===- ElfPrettyPrinter.cpp -------------------------------------*- C++ -*-===//
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
#include "ElfPrettyPrinter.hpp"

#include "AuxDataSchema.hpp"
#include <elf.h>

namespace gtirb_pprint {

struct ElfSymbolInfo {
  using AuxDataType =
      std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>;

  uint64_t Size;
  std::string Type;
  std::string Binding;
  std::string Visibility;
  uint64_t SectionIndex;

  ElfSymbolInfo(const AuxDataType& tuple)
      : Size(std::get<0>(tuple)), Type(std::get<1>(tuple)),
        Binding(std::get<2>(tuple)), Visibility(std::get<3>(tuple)),
        SectionIndex(std::get<4>(tuple)) {}
};

ElfPrettyPrinter::ElfPrettyPrinter(gtirb::Context& context_,
                                   gtirb::Module& module_,
                                   const ElfSyntax& syntax_,
                                   const PrintingPolicy& policy_)
    : PrettyPrinterBase(context_, module_, syntax_, policy_),
      elfSyntax(syntax_) {
  if (module.getAuxData<gtirb::schema::CfiDirectives>()) {
    policy.skipSections.insert(".eh_frame");
  }
}

const PrintingPolicy& ElfPrettyPrinter::defaultPrintingPolicy() {
  static PrintingPolicy DefaultPolicy{
      /// Functions to avoid printing.
      {"_start", "deregister_tm_clones", "register_tm_clones",
       "__do_global_dtors_aux", "frame_dummy", "__libc_csu_fini",
       "__libc_csu_init", "_dl_relocate_static_pie"},

      /// Symbols to avoid printing.
      {"_IO_stdin_used", "__data_start", "__dso_handle", "__TMC_END__", "_end",
       "_edata", "__bss_start"},

      /// Sections to avoid printing.
      {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt",
       ".plt.sec", ".eh_frame_hdr"},

      /// Sections with possible data object exclusion.
      {".init_array", ".fini_array"},
  };
  return DefaultPolicy;
}

void ElfPrettyPrinter::printSectionHeaderDirective(
    std::ostream& os, const gtirb::Section& section) {
  const std::string& sectionName = syntax.formatSectionName(section.getName());
  os << syntax.section() << ' ' << sectionName;
}

void ElfPrettyPrinter::printSectionProperties(std::ostream& os,
                                              const gtirb::Section& section) {
  const auto* elfSectionProperties =
      module.getAuxData<gtirb::schema::ElfSectionProperties>();
  if (!elfSectionProperties)
    return;
  auto sectionProperties = elfSectionProperties->find(section.getUUID());
  if (sectionProperties == elfSectionProperties->end())
    return;
  uint64_t type = std::get<0>(sectionProperties->second);
  uint64_t flags = std::get<1>(sectionProperties->second);
  os << " ,\"";
  if (flags & SHF_WRITE)
    os << "w";
  if (flags & SHF_ALLOC)
    os << "a";
  if (flags & SHF_EXECINSTR)
    os << "x";
  os << "\"";
  if (type == SHT_PROGBITS)
    os << ",@progbits";
  if (type == SHT_NOBITS)
    os << ",@nobits";
}

void ElfPrettyPrinter::printSectionFooterDirective(
    std::ostream& os, const gtirb::Section& section) {
  os << syntax.comment() << " end section " << section.getName() << '\n';
}

void ElfPrettyPrinter::printFunctionHeader(std::ostream& /* os */,
                                           gtirb::Addr /* addr */) {}

void ElfPrettyPrinter::printFunctionFooter(std::ostream& /* os */,
                                           gtirb::Addr /* addr */) {}

void ElfPrettyPrinter::printByte(std::ostream& os, std::byte byte) {
  std::ios_base::fmtflags flags = os.flags();
  os << syntax.byteData() << " 0x" << std::hex << static_cast<uint32_t>(byte)
     << '\n';
  os.flags(flags);
}

void ElfPrettyPrinter::printFooter(std::ostream& /* os */){};

void ElfPrettyPrinter::printSymbolHeader(std::ostream& os,
                                         const gtirb::Symbol& sym) {
  const auto* SymbolTypes = module.getAuxData<gtirb::schema::ElfSymbolInfo>();
  if (!SymbolTypes) {
    return;
  }

  auto SymTypeIt = SymbolTypes->find(sym.getUUID());
  if (SymTypeIt == SymbolTypes->end()) {
    return;
  }

  ElfSymbolInfo SymbolInfo{SymTypeIt->second};

  if (SymbolInfo.Binding == "LOCAL") {
    return;
  }

  auto ea = *sym.getAddress();
  auto name = getSymbolName(sym);

  printBar(os, false);
  printAlignment(os, ea);

  bool unique = false;
  if (SymbolInfo.Binding == "GLOBAL") {
    os << syntax.global() << ' ' << name << '\n';
  } else if (SymbolInfo.Binding == "WEAK") {
    os << elfSyntax.weak() << ' ' << name << '\n';
  } else if (SymbolInfo.Binding == "UNIQUE" ||
             SymbolInfo.Binding == "GNU_UNIQUE") {
    os << elfSyntax.global() << ' ' << name << '\n';
    unique = true;
  } else {
    assert(!"unknown binding in elfSymbolInfo!");
  }

  if (SymbolInfo.Visibility == "DEFAULT") {
    // do nothing
  } else if (SymbolInfo.Visibility == "HIDDEN") {
    os << elfSyntax.hidden() << ' ' << name << '\n';
  } else if (SymbolInfo.Visibility == "PROTECTED") {
    os << elfSyntax.protected_() << ' ' << name << '\n';
  } else {
    assert(!"unknown visibility in elfSymbolInfo!");
  }

  static const std::unordered_map<std::string, std::string> TypeNameConversion =
      {
          {"FUNC", "function"},  {"OBJECT", "object"},
          {"NOTYPE", "notype"},  {"NONE", "notype"},
          {"TLS", "tls_object"}, {"GNU_IFUNC", "gnu_indirect_function"},
      };
  auto TypeNameIt = TypeNameConversion.find(SymbolInfo.Type);
  if (TypeNameIt == TypeNameConversion.end()) {
    assert(!"unknown type in elfSymbolInfo!");
  }
  const auto& TypeName = unique ? "gnu_unique_object" : TypeNameIt->second;
  os << elfSyntax.type() << ' ' << name << ", @" << TypeName << "\n";

  printBar(os, false);
}

void ElfPrettyPrinter::printSymbolDefinition(std::ostream& os,
                                             const gtirb::Symbol& sym) {
  printSymbolHeader(os, sym);
  PrettyPrinterBase::printSymbolDefinition(os, sym);
}

void ElfPrettyPrinter::printSymbolDefinitionRelativeToPC(
    std::ostream& os, const gtirb::Symbol& sym, gtirb::Addr pc) {
  printSymbolHeader(os, sym);

  os << elfSyntax.set() << ' ' << getSymbolName(sym) << ", "
     << syntax.programCounter();
  auto symAddr = *sym.getAddress();
  if (symAddr > pc) {
    os << " + " << (symAddr - pc);
  } else if (symAddr < pc) {
    os << " - " << (pc - symAddr);
  }
  os << "\n";
}

void ElfPrettyPrinter::printIntegralSymbol(std::ostream& os,
                                           const gtirb::Symbol& sym) {
  printSymbolHeader(os, sym);

  os << elfSyntax.set() << ' ' << getSymbolName(sym) << ", "
     << *sym.getAddress() << '\n';
}

void ElfPrettyPrinter::printNonZeroDataBlock(std::ostream& os,
                                             const gtirb::DataBlock& dataObject,
                                             uint64_t offset) {
  auto* SymExpr = dataObject.getByteInterval()->getSymbolicExpression(
      dataObject.getOffset());
  if (!SymExpr) {
    PrettyPrinterBase::printNonZeroDataBlock(os, dataObject, offset);
    return;
  }

  if (const auto* types = module.getAuxData<gtirb::schema::Encodings>()) {
    if (auto foundType = types->find(dataObject.getUUID());
        foundType != types->end()) {
      // Is this a ULEB128?
      if (foundType->second == "uleb128") {
        assert(offset == 0 && "Can't print uleb128s that overlap!");

        os << syntax.tab() << elfSyntax.uleb128() << " ";
        if (std::holds_alternative<gtirb::SymAddrConst>(*SymExpr)) {
          printSymbolicExpression(os, &std::get<gtirb::SymAddrConst>(*SymExpr),
                                  true);
        } else if (std::holds_alternative<gtirb::SymAddrAddr>(*SymExpr)) {
          printSymbolicExpression(os, &std::get<gtirb::SymAddrAddr>(*SymExpr),
                                  true);
        } else {
          assert(!"Unknown sym expr type while printing uleb128!");
        }

        os << "\n";
        return;
      }

      // Is this a SLEB128?
      if (foundType->second == "sleb128") {
        assert(offset == 0 && "Can't print sleb128s that overlap!");

        os << syntax.tab() << elfSyntax.sleb128() << " ";
        if (std::holds_alternative<gtirb::SymAddrConst>(*SymExpr)) {
          printSymbolicExpression(os, &std::get<gtirb::SymAddrConst>(*SymExpr),
                                  true);
        } else if (std::holds_alternative<gtirb::SymAddrAddr>(*SymExpr)) {
          printSymbolicExpression(os, &std::get<gtirb::SymAddrAddr>(*SymExpr),
                                  true);
        } else {
          assert(!"Unknown sym expr type while printing sleb128!");
        }

        os << "\n";
        return;
      }
    }
  }

  // Else print normally.
  PrettyPrinterBase::printNonZeroDataBlock(os, dataObject, offset);
}

} // namespace gtirb_pprint

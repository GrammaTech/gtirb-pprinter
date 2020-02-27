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
      /// Sections to avoid printing.
      {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt",
       ".plt.sec", ".eh_frame_hdr"},

      /// Functions to avoid printing.
      {"_start", "deregister_tm_clones", "register_tm_clones",
       "__do_global_dtors_aux", "frame_dummy", "__libc_csu_fini",
       "__libc_csu_init", "_dl_relocate_static_pie", "_IO_stdin_used"},

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
    std::ostream& /* os */, const gtirb::Section& /* section */) {}

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

bool ElfPrettyPrinter::shouldExcludeDataElement(
    const gtirb::Section& section, const gtirb::DataBlock& dataObject) const {
  if (!policy.arraySections.count(section.getName()))
    return false;
  auto foundSymbolic =
      module.findSymbolicExpressionsAt(*dataObject.getAddress());
  if (!foundSymbolic.empty()) {
    if (const auto* s = std::get_if<gtirb::SymAddrConst>(
            &foundSymbolic.begin()->getSymbolicExpression())) {
      return skipEA(*s->Sym->getAddress());
    }
  }
  return false;
}

void ElfPrettyPrinter::printSymbolDefinitionsAtAddress(std::ostream& os,
                                                       gtirb::Addr ea,
                                                       bool inData) {
  const auto* SymbolTypes =
      module.getAuxData<std::map<gtirb::UUID, std::string>>("symbolType");

  if (SymbolTypes) {
    for (const auto& sym : module.findSymbols(ea)) {
      if (auto SymTypeIt = SymbolTypes->find(sym.getUUID());
          SymTypeIt != SymbolTypes->end()) {
        const auto& SymbolVisibility = SymTypeIt->second;

        std::string TypeName;
        if (sym.getReferent<gtirb::CodeBlock>()) {
          TypeName = "function";
        } else if (sym.getReferent<gtirb::DataBlock>()) {
          TypeName = "object";
        } else {
          TypeName = "notype";
        }

        if (SymbolVisibility == "GLOBAL") {
          printBar(os, false);
          printAlignment(os, ea);
          os << syntax.global() << ' ' << sym.getName() << '\n';
          os << elfSyntax.type() << ' ' << sym.getName() << ", @" << TypeName
             << "\n";
          printBar(os, false);
        } else if (SymbolVisibility == "WEAK") {
          printBar(os, false);
          printAlignment(os, ea);
          os << elfSyntax.weak() << ' ' << sym.getName() << '\n';
          os << elfSyntax.type() << ' ' << sym.getName() << ", @" << TypeName
             << "\n";
          printBar(os, false);
        } else if (SymbolVisibility == "LOCAL") {
          // Do nothing; just print the label.
        } else {
          assert(!"Unknown symbol type in symbolType aux data");
        }
      }
    }
  }

  PrettyPrinterBase::printSymbolDefinitionsAtAddress(os, ea, inData);
}

} // namespace gtirb_pprint

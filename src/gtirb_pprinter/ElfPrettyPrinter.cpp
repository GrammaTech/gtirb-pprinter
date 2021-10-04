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
#include "driver/Logger.h"

#include "AuxDataSchema.hpp"
#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_HASH 5
#define SHT_DYNAMIC 6
#define SHT_NOTE 7
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_SHLIB 10
#define SHT_DYNSYM 11
#define SHT_INIT_ARRAY 14
#define SHT_FINI_ARRAY 15
#define SHT_PREINIT_ARRAY 16
#define SHT_GROUP 17
#define SHT_SYMTAB_SHNDX 18
#define SHT_NUM 19
#define SHT_LOOS 0x60000000
#define SHT_GNU_ATTRIBUTES 0x6ffffff5
#define SHT_GNU_HASH 0x6ffffff6
#define SHT_GNU_LIBLIST 0x6ffffff7
#define SHT_CHECKSUM 0x6ffffff8
#define SHT_LOSUNW 0x6ffffffa
#define SHT_SUNW_move 0x6ffffffa
#define SHT_SUNW_COMDAT 0x6ffffffb
#define SHT_SUNW_syminfo 0x6ffffffc
#define SHT_GNU_verdef 0x6ffffffd
#define SHT_GNU_verneed 0x6ffffffe
#define SHT_GNU_versym 0x6fffffff
#define SHT_HISUNW 0x6fffffff
#define SHT_HIOS 0x6fffffff
#define SHT_LOPROC 0x70000000
#define SHT_HIPROC 0x7fffffff
#define SHT_LOUSER 0x80000000
#define SHT_HIUSER 0x8fffffff

#define SHF_WRITE (1 << 0)
#define SHF_ALLOC (1 << 1)
#define SHF_EXECINSTR (1 << 2)
#define SHF_MERGE (1 << 4)
#define SHF_STRINGS (1 << 5)
#define SHF_INFO_LINK (1 << 6)
#define SHF_LINK_ORDER (1 << 7)
#define SHF_OS_NONCONFORMING (1 << 8)

#define SHF_GROUP (1 << 9)
#define SHF_TLS (1 << 10)
#define SHF_COMPRESSED (1 << 11)
#define SHF_MASKOS 0x0ff00000
#define SHF_MASKPROC 0xf0000000
#define SHF_ORDERED (1 << 30)
#define SHF_EXCLUDE (1U << 31)

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

  AuxDataType asAuxData() {
    return AuxDataType{Size, Type, Binding, Visibility, SectionIndex};
  }
};

ElfPrettyPrinter::ElfPrettyPrinter(gtirb::Context& context_,
                                   gtirb::Module& module_,
                                   const ElfSyntax& syntax_,
                                   const Assembler& assembler_,
                                   const PrintingPolicy& policy_)
    : PrettyPrinterBase(context_, module_, syntax_, assembler_, policy_),
      elfSyntax(syntax_) {}

std::string ElfPrettyPrinter::getSymbolName(const gtirb::Symbol& Symbol) const {
  if (size_t I = Symbol.getName().find('@'); I != std::string::npos) {
    // Strip version string from symbol name.
    return Symbol.getName().substr(0, I);
  }
  return PrettyPrinterBase::getSymbolName(Symbol);
}

void ElfPrettyPrinter::printInstruction(std::ostream& os,
                                        const gtirb::CodeBlock& block,
                                        const cs_insn& inst,
                                        const gtirb::Offset& offset) {
  // Print explicit directives for instruction prefixes needed for @TLSGD
  // relocations, which require a fixed 16-byte instruction sequence.
  if (inst.id == X86_INS_LEA &&
      inst.detail->x86.prefix[2] == X86_PREFIX_OPSIZE) {

    gtirb::Addr ea(inst.address);

    uint8_t dispOffset = inst.detail->x86.encoding.disp_offset;
    const gtirb::SymbolicExpression* symbolic =
        block.getByteInterval()->getSymbolicExpression(
            ea + dispOffset - *block.getByteInterval()->getAddress());

    if (symbolic) {
      if (const auto* expr = std::get_if<gtirb::SymAddrConst>(symbolic)) {
        if (expr->Attributes.isFlagSet(gtirb::SymAttribute::TlsGd)) {
          TlsGdSequence = true;
          os << syntax.tab() << "  .byte 0x66\n";
        }
      }
    }
  } else if (TlsGdSequence && inst.id == X86_INS_CALL) {
    os << syntax.tab() << "  .value 0x6666\n";
    os << syntax.tab() << "  rex64\n";
    TlsGdSequence = false;
  } else if (TlsGdSequence) {
    LOG_ERROR << "Incorrect code sequence for @TLSGD relocation.\n";
    TlsGdSequence = false;
  }

  PrettyPrinterBase::printInstruction(os, block, inst, offset);
}

void ElfPrettyPrinter::printHeader(std::ostream& /*os*/) {
  if (policy.Shared) {
    fixupSharedObject();
  }
}

void ElfPrettyPrinter::fixupSharedObject() {
  // if this is a shared library or PIE executable, we need to
  // ensure all global symbols being referenced in code blocks either have a
  // hidden alias or are referenced via GOT/PLT
  if (auto* ElfSymInfo = module.getAuxData<gtirb::schema::ElfSymbolInfo>()) {
    // find the global symbols being referenced incorrectly
    std::unordered_set<gtirb::Symbol*> SymbolsToAlias;
    std::vector<gtirb::ByteInterval::SymbolicExpressionElement> SEEsToAlias,
        SEEsToPLT;
    for (auto& CB : module.code_blocks()) {
      if (shouldSkip(CB)) {
        continue;
      }

      for (auto SEE : CB.getByteInterval()->findSymbolicExpressionsAtOffset(
               CB.getOffset(), CB.getOffset() + CB.getSize())) {
        auto SymsToCheck = std::visit(
            [](const auto& SE) -> std::vector<gtirb::Symbol*> {
              using T = std::decay_t<decltype(SE)>;

              if (SE.Attributes.isFlagSet(gtirb::SymAttribute::PltRef) ||
                  SE.Attributes.isFlagSet(gtirb::SymAttribute::GotRelPC)) {
                return {}; // PLT/GOT references are allowed in shared objects
              }

              if constexpr (std::is_same_v<T, gtirb::SymAddrAddr>) {
                return {SE.Sym1, SE.Sym2};
              } else if constexpr (std::is_same_v<T, gtirb::SymAddrConst>) {
                return {SE.Sym};
              }
            },
            SEE.getSymbolicExpression());

        for (auto* Symbol : SymsToCheck) {
          if (!Symbol->hasReferent() && Symbol->getAddress()) {
            continue; // integral symbols don't need fixed up
          }

          if (auto It = ElfSymInfo->find(Symbol->getUUID());
              It != ElfSymInfo->end()) {
            if (ElfSymbolInfo Info{It->second};
                Info.Binding != "LOCAL" && Info.Visibility == "DEFAULT") {
              // direct references to global symbols are not allowed in
              // shared objects
              if (!Symbol->hasReferent() ||
                  Symbol->getReferent<gtirb::ProxyBlock>() ||
                  getForwardedSymbol(Symbol)) {
                // need to turn into a PLT reference
                SEEsToPLT.push_back(SEE);
              } else {
                // need to change to the hidden alias
                SymbolsToAlias.insert(Symbol);
                SEEsToAlias.push_back(SEE);
              }
            }
          }
        }
      }
    }

    // make a hidden alias for every global symbol that is called
    // directly by a code block
    using GlobalToHiddenSymsType =
        std::unordered_map<gtirb::Symbol*, gtirb::Symbol*>;
    GlobalToHiddenSymsType GlobalToHiddenSyms;

    for (auto* Symbol : SymbolsToAlias) {
      struct SetHiddenSymbolReferent {
        gtirb::Symbol* S;
        SetHiddenSymbolReferent(gtirb::Symbol* Sym) : S{Sym} {}
        void operator()(gtirb::Addr A) { S->setAddress(A); }
        void operator()(gtirb::CodeBlock* B) { S->setReferent(B); }
        void operator()(gtirb::DataBlock* B) { S->setReferent(B); }
        void operator()(gtirb::ProxyBlock* B) { S->setReferent(B); }
      };

      auto* HiddenSymbol = module.addSymbol(
          context, ".gtirb_pprinter.hidden_alias." + Symbol->getName());
      Symbol->visit(SetHiddenSymbolReferent(HiddenSymbol));
      ElfSymbolInfo NewSymInfo{(*ElfSymInfo)[Symbol->getUUID()]};
      NewSymInfo.Visibility = "HIDDEN";
      (*ElfSymInfo)[HiddenSymbol->getUUID()] = NewSymInfo.asAuxData();
      GlobalToHiddenSyms[Symbol] = HiddenSymbol;
    }

    // reassign bad code block references to hidden symbols
    for (auto SEE : SEEsToAlias) {
      auto SEToAdd = std::visit(
          [&GlobalToHiddenSyms](const auto& SE) -> gtirb::SymbolicExpression {
            using T = std::decay_t<decltype(SE)>;
            T NewSE{SE};

            if constexpr (std::is_same_v<T, gtirb::SymAddrAddr>) {
              if (auto It = GlobalToHiddenSyms.find(SE.Sym1);
                  It != GlobalToHiddenSyms.end()) {
                NewSE.Sym1 = It->second;
              }
              if (auto It = GlobalToHiddenSyms.find(SE.Sym2);
                  It != GlobalToHiddenSyms.end()) {
                NewSE.Sym2 = It->second;
              }
            } else if constexpr (std::is_same_v<T, gtirb::SymAddrConst>) {
              NewSE.Sym = GlobalToHiddenSyms.at(SE.Sym);
            }

            return {NewSE};
          },
          SEE.getSymbolicExpression());
      SEE.getByteInterval()->addSymbolicExpression(SEE.getOffset(), SEToAdd);
    }

    // make bad code block references to extern symbols go through the PLT
    for (auto SEE : SEEsToPLT) {
      auto SEToAdd = std::visit(
          [this](const auto& SE) -> gtirb::SymbolicExpression {
            using T = std::decay_t<decltype(SE)>;
            T NewSE{SE};
            NewSE.Attributes.addFlag(gtirb::SymAttribute::PltRef);

            if constexpr (std::is_same_v<T, gtirb::SymAddrAddr>) {
              if (auto Target = this->getForwardedSymbol(SE.Sym1)) {
                NewSE.Sym1 = Target;
              }
              if (auto Target = this->getForwardedSymbol(SE.Sym2)) {
                NewSE.Sym2 = Target;
              }
            } else if constexpr (std::is_same_v<T, gtirb::SymAddrConst>) {
              if (auto Target = this->getForwardedSymbol(SE.Sym)) {
                NewSE.Sym = Target;
              }
            }

            return {NewSE};
          },
          SEE.getSymbolicExpression());
      SEE.getByteInterval()->addSymbolicExpression(SEE.getOffset(), SEToAdd);
    }
  }
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
    os << "," << elfSyntax.attributePrefix() << "progbits";
  if (type == SHT_NOBITS)
    os << "," << elfSyntax.attributePrefix() << "nobits";
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

  auto name = getSymbolName(sym);

  printBar(os, false);
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
  } else if (SymbolInfo.Visibility == "INTERNAL") {
    os << elfSyntax.internal() << ' ' << name << '\n';
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
  } else {
    const auto& TypeName = unique ? "gnu_unique_object" : TypeNameIt->second;
    os << elfSyntax.type() << ' ' << name << ", " << elfSyntax.attributePrefix()
       << TypeName << "\n";
  }

  printBar(os, false);
}

void ElfPrettyPrinter::printSymExprSuffix(std::ostream& OS,
                                          const gtirb::SymAttributeSet& Attrs,
                                          bool IsNotBranch) {
  if (Attrs.isFlagSet(gtirb::SymAttribute::PltRef)) {
    if (!IsNotBranch) {
      OS << "@PLT";
    }
  } else if (Attrs.isFlagSet(gtirb::SymAttribute::GotOff)) {
    if (Attrs.isFlagSet(gtirb::SymAttribute::GotRef)) {
      OS << "@GOT";
    } else {
      OS << "@GOTOFF";
    }
  } else if (Attrs.isFlagSet(gtirb::SymAttribute::GotRelPC)) {
    OS << "@GOTPCREL";
  } else if (Attrs.isFlagSet(gtirb::SymAttribute::TpOff)) {
    OS << "@TPOFF";
  } else if (Attrs.isFlagSet(gtirb::SymAttribute::NtpOff)) {
    OS << "@NTPOFF";
  } else if (Attrs.isFlagSet(gtirb::SymAttribute::DtpOff)) {
    OS << "@DTPOFF";
  } else if (Attrs.isFlagSet(gtirb::SymAttribute::TlsGd)) {
    OS << "@TLSGD";
  } else if (Attrs.isFlagSet(gtirb::SymAttribute::TlsLd)) {
    OS << "@TLSLD";
  }
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

void ElfPrettyPrinter::printUndefinedSymbol(std::ostream& os,
                                            const gtirb::Symbol& sym) {
  printSymbolHeader(os, sym);
}

void ElfPrettyPrinter::printSymbolicDataType(
    std::ostream& os,
    const gtirb::ByteInterval::ConstSymbolicExpressionElement& SEE,
    uint64_t Size, std::optional<std::string> Type) {
  if (Type && *Type == "uleb128") {
    os << elfSyntax.uleb128();
  } else if (Type && *Type == "sleb128") {
    os << elfSyntax.sleb128();
  } else {
    PrettyPrinterBase::printSymbolicDataType(os, SEE, Size, Type);
  }
}

std::optional<uint64_t>
ElfPrettyPrinter::getAlignment(const gtirb::CodeBlock& Block) {
  // If the symbol is exported, ensure the block is aligned.
  // This is currently implemented only for code blocks because sometimes
  // data blocks occur inside other regions of data that must be contiguous,
  // and alignment in the middle may break up these data blocks.

  if (auto Align = PrettyPrinterBase::getAlignment(Block)) {
    return Align;
  }

  const auto* SymbolTypes = module.getAuxData<gtirb::schema::ElfSymbolInfo>();
  if (!SymbolTypes) {
    return std::nullopt;
  }

  for (const auto& Sym : module.findSymbols(Block)) {
    auto SymTypeIt = SymbolTypes->find(Sym.getUUID());
    if (SymTypeIt == SymbolTypes->end()) {
      continue;
    }

    ElfSymbolInfo SymbolInfo{SymTypeIt->second};
    if (SymbolInfo.Binding == "LOCAL" || SymbolInfo.Visibility != "DEFAULT") {
      continue;
    }

    // exported symbol detected; ensure alignment is preserved
    return PrettyPrinterBase::getAlignment(*Block.getAddress());
  }

  return std::nullopt;
}

bool ElfPrettyPrinterFactory::isStaticBinary(gtirb::Module& Module) const {
  return Module.findSections(".dynamic").empty();
}

const PrintingPolicy&
ElfPrettyPrinterFactory::defaultPrintingPolicy(gtirb::Module& Module) const {
  return isStaticBinary(Module) ? *findNamedPolicy("static")
                                : *findNamedPolicy("dynamic");
}

ElfPrettyPrinterFactory::ElfPrettyPrinterFactory() {
  registerNamedPolicy(
      "dynamic",
      PrintingPolicy{
          /// Functions to avoid printing.
          {"call_weak_fn", "deregister_tm_clones", "_dl_relocate_static_pie",
           "__do_global_dtors_aux", "frame_dummy", "_start",
           "register_tm_clones", "__libc_csu_fini", "__libc_csu_init"},

          /// Symbols to avoid printing.
          {"__bss_start", "__data_start", "__dso_handle", "_fp_hw",
           "_IO_stdin_used", "__TMC_END__"},

          /// Sections to avoid printing.
          {".comment", ".eh_frame_hdr", ".eh_frame", ".fini", ".got",
           ".got.plt", ".init", ".plt", ".plt.got", ".plt.sec", ".rela.dyn",
           ".rela.plt"},

          /// Sections with possible data object exclusion.
          {".fini_array", ".init_array"},
          /// Extra compiler arguments.
          {},
      });
  registerNamedPolicy("static",
                      PrintingPolicy{
                          /// Functions to avoid printing.
                          {},
                          /// Symbols to avoid printing.
                          {},
                          /// Sections to avoid printing.
                          {".eh_frame", ".rela.plt"},
                          /// Sections with possible data object exclusion.
                          {},
                          /// Extra compiler arguments.
                          {"-static"},
                      });
  registerNamedPolicy(
      "complete", PrintingPolicy{
                      /// Functions to avoid printing.
                      {},
                      /// Symbols to avoid printing.
                      {},
                      /// Sections to avoid printing.
                      {".eh_frame_hdr", ".eh_frame", ".got", ".got.plt", ".plt",
                       ".plt.got", ".plt.sec", ".rela.dyn", ".rela.plt"},
                      /// Sections with possible data object exclusion.
                      {},
                      /// Extra compiler arguments.
                      {"-nostartfiles"},
                  });
}

} // namespace gtirb_pprint

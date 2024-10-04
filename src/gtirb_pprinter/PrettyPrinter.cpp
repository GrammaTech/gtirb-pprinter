//===- PrettyPrinter.cpp ----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2018 GrammaTech, Inc.
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
#include "PrettyPrinter.hpp"
#include "AuxDataUtils.hpp"
#include "driver/Logger.h"

#include "AuxDataSchema.hpp"
#include "StringUtils.hpp"
#include <boost/lexical_cast.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <capstone/capstone.h>
#include <fstream>
#include <gtirb/gtirb.hpp>
#include <iomanip>
#include <iostream>
#include <utility>
#include <variant>

#ifdef __GNUC__
#define __BEGIN_DEPRECATED_DECL__()                                            \
  _Pragma("GCC diagnostic push")                                               \
      _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#define __END_DEPRECATED_DECL__() _Pragma("GCC diagnostic pop")
#elif defined(_MSC_VER)
#define __BEGIN_DEPRECATED_DECL__()                                            \
  _Pragma("warning(push)") _Pragma("warning(disable : 4996)") // deprecated
#define __END_DEPRECATED_DECL__() _Pragma("warning(pop)")
#endif

template <class T> T* nodeFromUUID(const gtirb::Context& C, gtirb::UUID id) {
  return gtirb::dyn_cast_or_null<T>(gtirb::Node::getByUUID(C, id));
}

static std::map<gtirb_pprint::TargetTy,
                std::shared_ptr<::gtirb_pprint::PrettyPrinterFactory>>&
getFactories() {
  static std::map<gtirb_pprint::TargetTy,
                  std::shared_ptr<::gtirb_pprint::PrettyPrinterFactory>>
      factories;
  return factories;
}

static std::map<std::tuple<std::string, std::string, gtirb_pprint::ListingMode>,
                std::string>&
getSyntaxes() {
  static std::map<
      std::tuple<std::string, std::string, gtirb_pprint::ListingMode>,
      std::string>
      defaults;
  return defaults;
}

namespace gtirb_pprint {

static std::optional<ListingMode> string_to_listing_mode(std::string ModeName) {
  if (ModeName == "debug") {
    return ListingDebug;
  } else if (ModeName == "ui") {
    return ListingUI;
  } else if (ModeName == "assembler" || ModeName == "") {
    return ListingAssembler;
  } else {
    return std::nullopt;
  }
}

bool registerPrinter(std::initializer_list<std::string> formats,
                     std::initializer_list<std::string> isas,
                     std::initializer_list<std::string> syntaxes,
                     std::shared_ptr<PrettyPrinterFactory> f) {
  assert(formats.size() > 0 && "No formats to register!");
  assert(isas.size() > 0 && "No ISAs to register!");
  assert(syntaxes.size() > 0 && "No syntaxes to register!");
  for (const std::string& format : formats) {
    for (const std::string& isa : isas) {
      for (const std::string& syntax : syntaxes) {
        getFactories()[std::make_tuple(format, isa, syntax)] = f;
      }
    }
  }
  return true;
}

std::set<TargetTy> getRegisteredTargets() {
  std::set<TargetTy> targets;
  for (const auto& entry : getFactories())
    targets.insert(entry.first);
  return targets;
}

std::string getModuleFileFormat(const gtirb::Module& module) {
  switch ((int)module.getFileFormat()) {
  case (int)gtirb::FileFormat::Undefined:
    return "undefined";
  case (int)gtirb::FileFormat::COFF:
    return "coff";
  case (int)gtirb::FileFormat::ELF:
    return "elf";
  case (int)gtirb::FileFormat::PE:
    return "pe";
  case (int)gtirb::FileFormat::IdaProDb32:
  case (int)gtirb::FileFormat::IdaProDb64:
    return "idb";
  case (int)gtirb::FileFormat::XCOFF:
    return "xcoff";
  case (int)gtirb::FileFormat::MACHO:
    return "macho";
  case (int)gtirb::FileFormat::RAW:
    return "raw";
  }
  return "undefined";
}

std::string getModuleISA(const gtirb::Module& module) {
  switch (module.getISA()) {
  case gtirb::ISA::ARM64:
    return "arm64";
  case gtirb::ISA::ARM:
    return "arm";
  case gtirb::ISA::X64:
    return "x64";
  case gtirb::ISA::IA32:
    return "x86";
  case gtirb::ISA::MIPS32:
    return "mips32";
  default:
    return "undefined";
  }
}

bool setDefaultSyntax(std::initializer_list<std::string> formats,
                      std::initializer_list<std::string> isas,
                      std::initializer_list<std::string> modes,
                      const std::string& syntax) {
  for (auto format : formats) {
    for (auto isa : isas) {
      for (auto mode : modes) {
        auto maybe_mode = string_to_listing_mode(mode);
        if (maybe_mode) {
          getSyntaxes()[std::tuple(format, isa, *maybe_mode)] = syntax;
        } else {
          return false;
        }
      }
    }
  }
  return false;
}

std::optional<std::string> getDefaultSyntax(const std::string& format,
                                            const std::string& isa,
                                            const std::string& mode) {
  auto maybe_mode = string_to_listing_mode(mode);
  if (maybe_mode) {
    return getDefaultSyntax(format, isa, *maybe_mode);
  }
  return std::nullopt;
}

DEBLOAT_PRETTYPRINTER_EXPORT_API std::optional<std::string>
getDefaultSyntax(const std::string& format, const std::string& isa,
                 ListingMode mode) {
  std::map<std::tuple<std::string, std::string, ListingMode>, std::string>
      defaults = getSyntaxes();
  auto it = defaults.find(std::tuple(format, isa, mode));
  return it != defaults.end() ? std::make_optional(it->second) : std::nullopt;
}

void PrettyPrinter::setTarget(const TargetTy& target) {
  assert(getFactories().find(target) != getFactories().end());
  const auto& [format, isa, syntax] = target;
  m_format = format;
  m_isa = isa;
  m_syntax = syntax;
}

const TargetTy PrettyPrinter::getTarget() const {
  return {m_format, m_isa, m_syntax};
}

void PrettyPrinter::setFormat(const std::string& format,
                              const std::string& isa) {
  const std::string& syntax =
      getDefaultSyntax(format, isa, LstMode).value_or("");
  setTarget(std::make_tuple(format, isa, syntax));
}

bool PrettyPrinter::setListingMode(const std::string& ModeName) {
  auto maybe_mode = string_to_listing_mode(ModeName);
  if (maybe_mode) {
    LstMode = *maybe_mode;
    return true;
  }
  return false;
}

std::set<std::string> PrettyPrinter::policyNames() const {
  auto It = getFactories().find(std::make_tuple(m_format, m_isa, m_syntax));
  if (It == getFactories().end()) {
    return std::set<std::string>();
  }

  std::set<std::string> result;
  for (const auto& Pair : It->second->namedPolicies()) {
    result.insert(Pair.first);
  }
  return result;
}

bool PrettyPrinter::namedPolicyExists(const std::string& Name) const {
  auto It = getFactories().find(std::make_tuple(m_format, m_isa, m_syntax));
  if (It == getFactories().end()) {
    return false;
  }
  return It->second->findNamedPolicy(Name) != nullptr;
}

PrettyPrinterFactory&
PrettyPrinter::getFactory(const gtirb::Module& Module) const {
  auto target = std::make_tuple(m_format, m_isa, m_syntax);
  if (m_format.empty()) {
    const std::string& format = gtirb_pprint::getModuleFileFormat(Module);
    const std::string& isa = gtirb_pprint::getModuleISA(Module);
    const std::string& syntax =
        getDefaultSyntax(format, isa, LstMode).value_or("");
    target = std::make_tuple(format, isa, syntax);
  }
  return *getFactories().at(target);
}

const PrintingPolicy&
PrettyPrinter::getPolicy(const gtirb::Module& Module) const {
  const PrettyPrinterFactory& Factory = getFactory(Module);
  return PolicyName == "default" ? Factory.defaultPrintingPolicy(Module)
                                 : *Factory.findNamedPolicy(PolicyName);
}

int PrettyPrinter::print(std::ostream& Stream, gtirb::Context& Context,
                         const gtirb::Module& Module) const {
  // Find pretty printer factory.
  PrettyPrinterFactory& Factory = getFactory(Module);

  // Configure printing policy.
  PrintingPolicy policy(getPolicy(Module));
  policy.LstMode = LstMode;
  policy.IgnoreSymbolVersions = IgnoreSymbolVersions;
  FunctionPolicy.apply(policy.skipFunctions);
  SymbolPolicy.apply(policy.skipSymbols);
  SectionPolicy.apply(policy.skipSections);
  ArraySectionPolicy.apply(policy.arraySections);

  // Create the pretty printer and print the IR.
  if (aux_data::validateAuxData(Module, m_format)) {
    if (Factory.create(Context, Module, policy)->print(Stream)) {
      return 0;
    }
  }
  return -1;
}

boost::iterator_range<NamedPolicyMap::const_iterator>
PrettyPrinterFactory::namedPolicies() const {
  return boost::make_iterator_range(NamedPolicies.begin(), NamedPolicies.end());
}

const PrintingPolicy*
PrettyPrinterFactory::findNamedPolicy(const std::string& Name) const {
  auto It = NamedPolicies.find(Name);
  if (It == NamedPolicies.end()) {
    return nullptr;
  } else {
    return &It->second;
  }
}

PrintingPolicy*
PrettyPrinterFactory::findRegisteredNamedPolicy(const std::string& Name) {
  auto It = NamedPolicies.find(Name);
  if (It == NamedPolicies.end()) {
    return nullptr;
  } else {
    return &It->second;
  }
}

void PrettyPrinterFactory::registerNamedPolicy(const std::string& Name,
                                               const PrintingPolicy Policy) {
  NamedPolicies.emplace(Name, std::move(Policy));
}

void PrettyPrinterFactory::deregisterNamedPolicy(const std::string& Name) {
  NamedPolicies.erase(Name);
}

__BEGIN_DEPRECATED_DECL__()

PrettyPrinterBase::PrettyPrinterBase(gtirb::Context& context_,
                                     const gtirb::Module& module_,
                                     const Syntax& syntax_,
                                     const PrintingPolicy& policy_)
    : syntax(syntax_), policy(policy_), LstMode(policy.LstMode),
      context(context_), module(module_),
      PreferredEOLCommentPos(64), type_printer{module_, context_} {
  computeFunctionInformation();
}

PrettyPrinterBase::~PrettyPrinterBase() { cs_close(&this->csHandle); }

__END_DEPRECATED_DECL__()

void PrettyPrinterBase::computeFunctionInformation() {
  auto FunctionNameMap = aux_data::getFunctionNames(module);
  // Compute function names
  for (const auto& Pair : FunctionNameMap) {
    const auto* Symbol = nodeFromUUID<gtirb::Symbol>(context, Pair.second);
    if (Symbol) {
      FunctionSymbols.insert(Symbol);
      FunctionToSymbols[Pair.first] = Symbol;
    } else {
      LOG_ERROR << "Value entry UUID " << boost::uuids::to_string(Pair.second)
                << " in the functionNames Auxdata is not a valid symbol\n";
    }
  }

  // Compute the begin and end address of a block
  auto getUUIDAddrRange = [&](gtirb::UUID Uuid) {
    std::optional<gtirb::Addr> Addr;
    uint64_t Size{0};
    const auto* CodeBlock = nodeFromUUID<gtirb::CodeBlock>(context, Uuid);
    if (CodeBlock) {
      Addr = CodeBlock->getAddress();
      Size = CodeBlock->getSize();
    } else {
      const auto* DataBlock = nodeFromUUID<gtirb::DataBlock>(context, Uuid);
      if (DataBlock) {
        Addr = DataBlock->getAddress();
        Size = DataBlock->getSize();
      }
    }
    std::optional<std::tuple<gtirb::Addr, gtirb::Addr>> AddrRange;
    if (Addr) {
      AddrRange = {*Addr, *Addr + Size};
    }
    return AddrRange;
  };
  // Compute function blocks, start, and ends
  for (auto const& Function : aux_data::getFunctionBlocks(module)) {
    if (Function.second.size() == 0) {
      continue;
    }
    gtirb::Addr FirstAddr{std::numeric_limits<uint64_t>::max()}, LastBlockAddr,
        LastAddr{0};
    gtirb::UUID FirstBlock, LastBlock;
    for (auto& BlockUuid : Function.second) {
      BlockToFunction[BlockUuid] = Function.first;
      auto BlockRange = getUUIDAddrRange(BlockUuid);
      if (!BlockRange) {
        LOG_WARNING << "UUID " << boost::uuids::to_string(BlockUuid)
                    << " in functionBlocks table references non-existent "
                    << "block or a block without address.\n";
        continue;
      }
      const auto& [Beg, End] = *BlockRange;
      if (Beg < FirstAddr) {
        FirstAddr = Beg;
        FirstBlock = BlockUuid;
      }
      if (End > LastAddr) {
        LastAddr = End;
        LastBlockAddr = Beg;
        LastBlock = BlockUuid;
      }
    }
    FunctionFirstBlocks.insert(FirstBlock);
    FunctionLastBlocks.insert(LastBlock);

    __BEGIN_DEPRECATED_DECL__()
    // These are deprecated
    functionEntry.insert(FirstAddr);
    functionLastBlock.insert(LastBlockAddr);

    __END_DEPRECATED_DECL__()
  }
}

void PrettyPrinterBase::computeAmbiguousSymbols() {
  // Collect all ambiguous symbols in the module and give them
  // unique names
  std::map<const std::string, std::multimap<gtirb::Addr, const gtirb::Symbol*>>
      SymbolsByNameAddr;
  for (auto& S : module.symbols()) {
    auto Addr = S.getAddress().value_or(gtirb::Addr(0));
    SymbolsByNameAddr[S.getName()].emplace(Addr, &S);
  }
  for (auto& [Name, Group] : SymbolsByNameAddr) {
    if (Group.size() > 1) {
      std::set<const gtirb::Symbol*, CmpSymPtr> Symbols;
      for (auto& [Addr, Sym] : Group) {
        Symbols.insert(Sym);
      }
      const gtirb::Symbol* SymbolToKeepOrigName = getBestSymbol(Symbols);
      int Index = 0;
      gtirb::Addr PrevAddress{0};
      for (auto& [Addr, Sym] : Group) {
        if (Sym == SymbolToKeepOrigName) {
          continue;
        }
        std::stringstream NewName;
        NewName << Name << "_disambig_" << Addr;
        if (Addr != PrevAddress) {
          Index = 0;
          PrevAddress = Addr;
        }
        std::stringstream Suffix;
        Suffix << "_" << Index++;
        while (!module.findSymbols(NewName.str() + Suffix.str()).empty()) {
          Suffix.seekp(0);
          Suffix << "_" << Index++;
        }
        NewName << Suffix.str();
        AmbiguousSymbols.insert({Sym, NewName.str()});
      }
    }
  }
}

bool PrettyPrinterBase::isFunctionEntry(gtirb::Addr Addr) const {
  for (auto& Block : module.findBlocksAt(Addr)) {
    if (FunctionFirstBlocks.count(Block.getUUID()) > 0) {
      return true;
    }
  }
  return false;
}

bool PrettyPrinterBase::isFunctionLastBlock(gtirb::Addr Addr) const {
  for (auto& Block : module.findBlocksAt(Addr)) {
    if (FunctionLastBlocks.count(Block.getUUID()) > 0) {
      return true;
    }
  }
  return false;
}

const gtirb::SymAddrConst* PrettyPrinterBase::getSymbolicImmediate(
    const gtirb::SymbolicExpression* symex) {
  if (symex) {
    const auto* s = std::get_if<gtirb::SymAddrConst>(symex);
    assert(s != nullptr && "symbolic operands must be 'address[+offset]'");
    return s;
  }
  return nullptr;
}

void PrettyPrinterBase::printIntegralSymbols(std::ostream& os) {
  // print integral symbols
  for (const auto& sym : module.symbols_by_name()) {
    if (auto addr = sym.getAddress();
        addr && !sym.hasReferent() && !shouldSkip(policy, sym)) {
      os << syntax.comment() << " WARNING: integral symbol " << sym.getName()
         << " may not have been correctly relocated\n";
      printIntegralSymbol(os, sym);
    }
    if (!sym.getAddress() &&
        (!sym.hasReferent() ||
         sym.getReferent<gtirb::ProxyBlock>() != nullptr) &&
        !shouldSkip(policy, sym)) {
      printUndefinedSymbol(os, sym);
    }
  }
}

std::ostream& PrettyPrinterBase::print(std::ostream& os) {
  computeAmbiguousSymbols();

  printHeader(os);

  // print every section
  for (const auto& section : module.sections()) {
    printSection(os, section);
  }

  printIntegralSymbols(os);

  // print footer
  printFooter(os);
  return os;
}

void PrettyPrinterBase::printOverlapWarning(std::ostream& os,
                                            const gtirb::Addr addr) {
  std::cerr << "WARNING: found overlapping element at address " << std::hex
            << static_cast<uint64_t>(addr) << std::endl
            << "The --layout option to gtirb-pprinter can fix "
               "overlapping elements."
            << std::endl;
  std::ios_base::fmtflags flags = os.flags();
  os << syntax.comment() << " WARNING: found overlapping blocks at address "
     << std::hex << static_cast<uint64_t>(addr) << '\n';
  os.flags(flags);
}

void PrettyPrinterBase::printBlockContents(std::ostream& os,
                                           const gtirb::CodeBlock& x,
                                           uint64_t offset) {
  if (offset > x.getSize()) {
    return;
  }

  gtirb::Addr addr = *x.getAddress();
  os << '\n';

  cs_insn* insn;
  cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);
  size_t count = cs_disasm(this->csHandle, x.rawBytes<uint8_t>() + offset,
                           x.getSize() - offset,
                           static_cast<uint64_t>(addr) + offset, 0, &insn);

  // Exception-safe cleanup of instructions
  std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> freeInsn(
      insn, [count](cs_insn* i) { cs_free(i, count); });

  gtirb::Offset blockOffset(x.getUUID(), offset);
  for (size_t i = 0; i < count; i++) {
    fixupInstruction(insn[i]);
    printInstruction(os, x, insn[i], blockOffset);
    blockOffset.Displacement += insn[i].size;
  }
  // print any CFI directives located at the end of the block
  // e.g. '.cfi_endproc' is usually attached to the end of the block
  printCFIDirectives(os, blockOffset);
}

void PrettyPrinterBase::setDecodeMode(std::ostream& /*os*/,
                                      const gtirb::CodeBlock& /*x*/) {}

void PrettyPrinterBase::printSectionHeader(std::ostream& os,
                                           const gtirb::Section& section) {
  std::string sectionName = section.getName();
  os << '\n';
  printBar(os);
  if (sectionName == syntax.textSection()) {
    os << syntax.text() << '\n';
  } else if (sectionName == syntax.dataSection()) {
    os << syntax.data() << '\n';
  } else if (sectionName == syntax.bssSection()) {
    os << syntax.bss() << '\n';
  } else {
    printSectionHeaderDirective(os, section);
    printSectionProperties(os, section);
    os << std::endl;
  }
  printBar(os);
  os << '\n';
}

void PrettyPrinterBase::printSectionFooter(std::ostream& os,
                                           const gtirb::Section& section) {
  printBar(os);
  printSectionFooterDirective(os, section);
  printBar(os);
}

void PrettyPrinterBase::printBar(std::ostream& os, bool heavy) {
  if (heavy) {
    os << syntax.comment() << "===================================\n";
  } else {
    os << syntax.comment() << "-----------------------------------\n";
  }
}

std::string PrettyPrinterBase::getFunctionName(gtirb::Addr Addr) const {

  for (auto& Block : module.findBlocksAt(Addr)) {
    if (FunctionFirstBlocks.count(Block.getUUID()) > 0) {
      if (auto FunctionSymbol = getContainerFunctionSymbol(Block.getUUID());
          FunctionSymbol) {
        return FunctionSymbol->getName();
      } else {
        std::stringstream Name;
        Name << "unknown_function_" << std::hex << static_cast<uint64_t>(Addr);
        return Name.str();
      }
    }
  }
  return std::string{};
}

bool PrettyPrinterBase::printSymbolReference(std::ostream& os,
                                             const gtirb::Symbol* symbol) {
  if (!symbol)
    return false;

  std::optional<std::string> forwardedName = getForwardedSymbolName(symbol);
  if (forwardedName) {
    if (LstMode == ListingDebug || LstMode == ListingUI) {
      os << forwardedName.value();
      return false;
    } else {
      if (policy.skipSymbols.count(forwardedName.value())) {
        // NOTE: It is OK not to print symbols in unexercised code (functions
        // that never execute, but were not skipped due to lack of information
        // : e.g., sectionless binaries). However, printing symbol addresses
        // can cause the assembler to fail if the address is too big for the
        // instruction. To avoid the problem, we print 0 here.
        os << "0";
        uint64_t symAddr = static_cast<uint64_t>(*symbol->getAddress());
        m_accum_comment += s_symaddr_0_warning(symAddr);
        return true;
      } else {
        os << forwardedName.value();
        return false;
      }
    }
  }
  if (shouldSkip(policy, *symbol)) {
    if (LstMode == ListingDebug || LstMode == ListingUI) {
      os << static_cast<uint64_t>(*symbol->getAddress());
    } else {
      // NOTE: See the comment above.
      os << "0";
      uint64_t symAddr = static_cast<uint64_t>(*symbol->getAddress());
      m_accum_comment += s_symaddr_0_warning(symAddr);
    }
    return true;
  }
  os << getSymbolName(*symbol);
  return false;
}

void PrettyPrinterBase::printSymbolDefinition(std::ostream& os,
                                              const gtirb::Symbol& symbol) {
  os << getSymbolName(symbol) << ":\n";
}

void PrettyPrinterBase::fixupInstruction(cs_insn&) {}

// Helper for x86-specific fixups, called from Att, Intel, and Masm pretty
// printers (Masm has additional fixups).
void PrettyPrinterBase::x86FixupInstruction(cs_insn& inst) {
  cs_x86& detail = inst.detail->x86;

  // Operands are implicit for various MOVS* instructions. But there is also
  // an SSE2 instruction named MOVSD which has explicit operands.
  if ((inst.id == X86_INS_MOVSB || inst.id == X86_INS_MOVSW ||
       inst.id == X86_INS_MOVSD || inst.id == X86_INS_MOVSQ) &&
      inst.detail->groups[0] != X86_GRP_SSE2) {
    detail.op_count = 0;
  }

  // Register operands are implicit for STOS* instructions.
  if (inst.id == X86_INS_STOSB || inst.id == X86_INS_STOSW ||
      inst.id == X86_INS_STOSD || inst.id == X86_INS_STOSQ) {
    detail.op_count = 1;
  }

  // IMUL: third operand is a signed number, but it is decoded as unsigned.
  if (inst.id == X86_INS_IMUL && detail.op_count == 3) {
    cs_x86_op& op = detail.operands[2];
    op.imm = static_cast<int32_t>(op.imm);
  }

  // The first operand of fxch  st(0) is implicit
  if (inst.id == X86_INS_FXCH && detail.op_count == 2) {
    detail.operands[0] = detail.operands[1];
    detail.op_count = 1;
  }

  // Comisd loads 64 bits from memory not 128
  if (inst.id == X86_INS_COMISD || inst.id == X86_INS_VCOMISD) {
    if (detail.op_count == 2 && detail.operands[1].type == X86_OP_MEM &&
        detail.operands[1].size == 16) {
      detail.operands[1].size = 8;
    }
  }

  // Comiss loads 32 bits from memory not 64
  if (inst.id == X86_INS_COMISS || inst.id == X86_INS_VCOMISS) {
    if (detail.op_count == 2 && detail.operands[1].type == X86_OP_MEM) {
      detail.operands[1].size = 4;
    }
  }

  // Operands that should not have a size annotation:
  // FXSAVE, XSAVE, XSAVEC, FXRSTOR, XRSTOR
  if (detail.op_count == 1 &&
      (inst.id == X86_INS_FXSAVE || inst.id == X86_INS_XSAVE ||
       inst.id == X86_INS_XSAVEC || inst.id == X86_INS_FXRSTOR ||
       inst.id == X86_INS_XRSTOR)) {
    detail.operands[0].size = 0;
  }

  // RDRAND and RDSEED should be printed with no suffix:
  // https://github.com/aquynh/capstone/issues/1603
  if (inst.id == X86_INS_RDRAND) {
    strcpy(inst.mnemonic, "rdrand");
  } else if (inst.id == X86_INS_RDSEED) {
    strcpy(inst.mnemonic, "rdseed");
  }

  // PUNPCKL* memory operands are 32 bits
  if (inst.id == X86_INS_PUNPCKLWD || inst.id == X86_INS_PUNPCKLBW ||
      inst.id == X86_INS_PUNPCKLDQ) {
    if (detail.op_count == 2 && detail.operands[1].type == X86_OP_MEM &&
        detail.operands[1].size == 8) {
      detail.operands[1].size = 4;
    }
  } else if (inst.id == X86_INS_INT1 || inst.id == X86_INS_INT3) {
    int N = (inst.id == X86_INS_INT1 ? 1 : 3);
    strcpy(inst.mnemonic, "int");
    detail.operands[0].type = X86_OP_IMM;
    detail.operands[0].imm = N;
    detail.op_count = 1;
  }
}

void PrettyPrinterBase::printPrototype(std::ostream& os,
                                       const gtirb::CodeBlock& block,
                                       const gtirb::Offset& offset) {
  if (this->LstMode != ListingDebug && this->LstMode != ListingUI) {
    return;
  }
  auto Addr = *block.getAddress() + offset.Displacement;
  if (FunctionFirstBlocks.count(block.getUUID()) > 0 &&
      offset.Displacement == 0) {
    type_printer.printPrototype(Addr, os, syntax.comment()) << std::endl;
  }
}

void PrettyPrinterBase::printInstruction(std::ostream& os,
                                         const gtirb::CodeBlock& block,
                                         const cs_insn& inst,
                                         const gtirb::Offset& offset) {
  gtirb::Addr ea(inst.address);
  printComments(os, offset, inst.size);
  printPrototype(os, block, offset);
  printCFIDirectives(os, offset);

  ////////////////////////////////////////////////////////////////////
  // special cases

  if (inst.id == X86_INS_NOP || inst.id == ARM64_INS_NOP) {
    uint64_t i = 0;
    do {
      std::stringstream InstructLine;
      printEA(InstructLine, ea);
      InstructLine << "  " << syntax.nop();
      printCommentableLine(InstructLine, os, ea);
      os << '\n';
      ea += 1;
    } while (++i < inst.size);
    return;
  }

  // end special cases
  ////////////////////////////////////////////////////////////////////

  std::stringstream InstructLine;
  std::string opcode = ascii_str_tolower(inst.mnemonic);
  printEA(InstructLine, ea);
  InstructLine << "  " << opcode << ' ';
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

void PrettyPrinterBase::printEA(std::ostream& os, gtirb::Addr ea) {
  os << syntax.tab();
  if (this->LstMode == ListingDebug) {
    os << std::hex << static_cast<uint64_t>(ea) << ": " << std::dec;
  }
}

void PrettyPrinterBase::printOperandList(std::ostream& os,
                                         const gtirb::CodeBlock& block,
                                         const cs_insn& inst) {
  const cs_x86& detail = inst.detail->x86;

  // some instructions don't put commas between their operands, but instead
  // put it in between {}s. These instructions are always AVX512 instructions
  // when you use the k registers. Not all AVX512 instructions use the k
  // registers in this manner, however.
  // TODO: find an exhaustive list of such instructions, or find a way for
  // Capstone to tell us this information directly.
  static const std::unordered_set<x86_insn> UnbracketedAVX512Instructions {
    X86_INS_KANDNB, X86_INS_KANDNW, X86_INS_KANDND, X86_INS_KANDNQ,
        X86_INS_KMOVB, X86_INS_KMOVW, X86_INS_KMOVD, X86_INS_KMOVQ,
        X86_INS_KUNPCKBW, X86_INS_KNOTB, X86_INS_KNOTW, X86_INS_KNOTD,
        X86_INS_KNOTQ, X86_INS_KORB, X86_INS_KORW, X86_INS_KORD, X86_INS_KORQ,
        X86_INS_KORTESTB, X86_INS_KORTESTW, X86_INS_KORTESTD, X86_INS_KORTESTQ,
        X86_INS_KSHIFTLB, X86_INS_KSHIFTLW, X86_INS_KSHIFTLD, X86_INS_KSHIFTLQ,
        X86_INS_KSHIFTRB, X86_INS_KSHIFTRW, X86_INS_KSHIFTRD, X86_INS_KSHIFTRQ,
        X86_INS_KXNORB, X86_INS_KXNORW, X86_INS_KXNORD, X86_INS_KXNORQ,
        X86_INS_KXORB, X86_INS_KXORW, X86_INS_KXORD, X86_INS_KXORQ,
#if CS_API_MAJOR >= 5
        X86_INS_KUNPCKDQ, X86_INS_KUNPCKWD, X86_INS_KADDB, X86_INS_KADDW,
        X86_INS_KADDD, X86_INS_KADDQ, X86_INS_KTESTB, X86_INS_KTESTW,
        X86_INS_KTESTD, X86_INS_KTESTQ, X86_INS_VPCMPESTRI
#endif
  };

  static const std::unordered_set<x86_insn> BracketedSecondKAVX512Instrs{
      X86_INS_VPCMPB,    X86_INS_VPCMPD,    X86_INS_VPCMPQ,
      X86_INS_VPCMPW,    X86_INS_VPCMPUB,   X86_INS_VPCMPUD,
      X86_INS_VPCMPUQ,   X86_INS_VPCMPUW,   X86_INS_VPCMPEQB,
      X86_INS_VPCMPEQD,  X86_INS_VPCMPEQQ,  X86_INS_VPCMPEQW,
      X86_INS_VPCMPGTB,  X86_INS_VPCMPGTD,  X86_INS_VPCMPGTQ,
      X86_INS_VPCMPGTW,  X86_INS_VPTEST,    X86_INS_VPTESTMB,
      X86_INS_VPTESTMD,  X86_INS_VPTESTMQ,  X86_INS_VPTESTMW,
      X86_INS_VPTESTNMB, X86_INS_VPTESTNMD, X86_INS_VPTESTNMQ,
      X86_INS_VPTESTNMW,
  };

  bool IsBracketedAVX512Instruction =
      UnbracketedAVX512Instructions.count(static_cast<x86_insn>(inst.id)) == 0;

  bool IsBracketedSecondKAVX512Instr =
      BracketedSecondKAVX512Instrs.count(static_cast<x86_insn>(inst.id)) != 0;

  // For some of the AVX512 instrutions
  // (listed in BracketedSecondKAVX512Instrs),
  // the first K register is not bracketed.
  // E.g., vpcmpnequb (%rdi),%ymm18,%k1{%k2}
  // For such instructions, have BracketedK initially set to false
  // so that the first K is not bracketed.
  bool BracketedK =
      IsBracketedAVX512Instruction && !IsBracketedSecondKAVX512Instr;

  for (int i = 0; i < detail.op_count; i++) {
    const cs_x86_op& Op = detail.operands[i];

    if (BracketedK && Op.type == X86_OP_REG &&
        (Op.reg >= X86_REG_K0 && Op.reg <= X86_REG_K7)) {
      // print AVX512 mask operand
      os << '{';
      printOperand(os, block, inst, i);
      os << '}';
      if (Op.avx_zero_opmask) {
        os << "{z}";
      }
    } else {
      // print normal operand
      if (i != 0) {
        os << ',';
      }
      printOperand(os, block, inst, i);

      if (IsBracketedSecondKAVX512Instr && Op.type == X86_OP_REG &&
          (Op.reg >= X86_REG_K0 && Op.reg <= X86_REG_K7)) {
        BracketedK = true;
      }
    }
  }
}

void PrettyPrinterBase::printOperand(std::ostream& os,
                                     const gtirb::CodeBlock& block,
                                     const cs_insn& inst, uint64_t index) {
  gtirb::Addr ea(inst.address);
  const cs_x86_op& op = inst.detail->x86.operands[index];

  const gtirb::SymbolicExpression* symbolic = nullptr;
  uint8_t immOffset = inst.detail->x86.encoding.imm_offset;
  uint8_t dispOffset = inst.detail->x86.encoding.disp_offset;

  switch (op.type) {
  case X86_OP_REG:
    printOpRegdirect(os, inst, index);
    return;
  case X86_OP_IMM:
    symbolic = block.getByteInterval()->getSymbolicExpression(
        ea + immOffset - *block.getByteInterval()->getAddress());
    printOpImmediate(os, symbolic, inst, index);
    return;
  case X86_OP_MEM:
    // FIXME: Capstone frequently populates instruction details incorrectly with
    // a displacement offset of 0. We use the same incorrect offset in ddisasm
    // to populate the symbolic expressions, so we find the corresponding
    // symbolic by coincidence, but the addresses are incorrect.
    // We should fix Capstone and check `dispOffset > 0` here.
    symbolic = block.getByteInterval()->getSymbolicExpression(
        ea + dispOffset - *block.getByteInterval()->getAddress());
    // We had a bug where Capstone gave us a displacement offset of 0 for
    // instructions using moffset operand encoding. For backwards
    // compatibility, look there for a symbolic expression.
    if (!symbolic && x86InstHasMoffsetEncoding(inst)) {
      symbolic = block.getByteInterval()->getSymbolicExpression(
          ea - *block.getByteInterval()->getAddress());
      if (symbolic) {
        static bool warned;
        if (!warned) {
          std::cerr << "WARNING: using symbolic expression at offset 0 for "
                       "compatibility; recreate your gtirb file with newer "
                       "tools that put expressions at the correct offset. "
                       "Starting in early 2022, newer versions of the pretty "
                       "printer will not use expressions at offset 0.\n";
          warned = true;
        }
      }
    }
    printOpIndirect(os, symbolic, inst, index);
    return;
  case X86_OP_INVALID:
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

template <typename BlockType>
void PrettyPrinterBase::printBlockImpl(std::ostream& os, BlockType& block) {
  if (shouldSkip(policy, block)) {
    return;
  }

  // Print symbols associated with block.
  gtirb::Addr addr = *block.getAddress();
  uint64_t offset;

  if (addr < programCounter) {
    // If the program counter is beyond the address already, then overlap is
    // occuring, so we need to print a symbol definition after the fact (rather
    // than place a label in the middle).

    offset = programCounter - addr;
    printOverlapWarning(os, addr);
    for (const auto& sym : module.findSymbols(block)) {
      if (!sym.getAtEnd() && !shouldSkip(policy, sym)) {
        printSymbolDefinitionRelativeToPC(os, sym, programCounter);
      }
    }
  } else {
    // Normal symbol; print labels before block.

    offset = 0;

    if (auto Align = getAlignment(block)) {
      printAlignment(os, *Align);
    }

    for (const auto& sym : module.findSymbols(block)) {
      if (!sym.getAtEnd() && !shouldSkip(policy, sym)) {
        printSymbolDefinition(os, sym);
      }
    }
  }

  // If this occurs in an array section, and the block points to something we
  // should skip: Skip contents, but do not skip label, so things can refer to
  // the array as a whole.
  if (policy.arraySections.count(
          block.getByteInterval()->getSection()->getName())) {
    if (auto SymExpr =
            block.getByteInterval()->getSymbolicExpression(block.getOffset())) {
      if (std::holds_alternative<gtirb::SymAddrConst>(*SymExpr)) {
        if (shouldSkip(policy, *std::get<gtirb::SymAddrConst>(*SymExpr).Sym)) {
          return;
        }
      } else {
        assert(!"Unexpected sym expr type in array section!");
      }
    }
  }

  // Print actual block contents.
  printBlockContents(os, block, offset);

  // Update the program counter.
  programCounter = std::max(programCounter, addr + block.getSize());

  // Print any symbols that should go at the end of this block.
  for (const auto& sym : module.findSymbols(block)) {
    if (sym.getAtEnd() && !shouldSkip(policy, sym)) {
      printSymbolDefinition(os, sym);
    }
  }
  // Print function ends if applicable
  if (FunctionLastBlocks.count(block.getUUID()) > 0) {
    const gtirb::Symbol* FunctionSymbol =
        getContainerFunctionSymbol(block.getUUID());
    // A function could have no name associated to it.
    if (FunctionSymbol) {
      printFunctionEnd(os, *FunctionSymbol);
      if (auto Aliases = FunctionAliases.find(FunctionSymbol);
          Aliases != FunctionAliases.end()) {
        for (const auto* Alias : Aliases->second) {
          printFunctionEnd(os, *Alias);
        }
      }
    }
  }
}

void PrettyPrinterBase::printBlock(std::ostream& os,
                                   const gtirb::DataBlock& block) {
  printBlockImpl(os, block);
}

void PrettyPrinterBase::printBlock(std::ostream& os,
                                   const gtirb::CodeBlock& block) {
  setDecodeMode(os, block);
  printBlockImpl(os, block);
}

void PrettyPrinterBase::printBlockContents(std::ostream& os,
                                           const gtirb::DataBlock& dataObject,
                                           uint64_t offset) {
  if (offset > dataObject.getSize()) {
    return;
  }

  const auto* foundSymbolic =
      dataObject.getByteInterval()->getSymbolicExpression(
          dataObject.getOffset() + offset);
  auto dataObjectBytes = dataObject.bytes<uint8_t>();
  if (std::all_of(dataObjectBytes.begin() + offset, dataObjectBytes.end(),
                  [](uint8_t x) { return x == 0; }) &&
      !foundSymbolic)
    printZeroDataBlock(os, dataObject, offset);
  else
    printNonZeroDataBlock(os, dataObject, offset);
}

void PrettyPrinterBase::printNonZeroDataBlock(
    std::ostream& os, const gtirb::DataBlock& dataObject, uint64_t offset) {
  if (dataObject.getSize() - offset == 0) {
    return;
  }
  gtirb::Offset CurrOffset = gtirb::Offset(dataObject.getUUID(), offset);

  // If this is a string, print it as one.
  std::optional<std::string> Type = aux_data::getEncodingType(dataObject);

  if (Type == "string" || Type == "ascii") {
    printComments(os, CurrOffset, dataObject.getSize() - offset);

    std::stringstream DataLine;
    printEA(DataLine, *dataObject.getAddress() + offset);
    printString(DataLine, dataObject, offset, Type == "string");
    printCommentableLine(DataLine, os, *dataObject.getAddress() + offset);
    os << '\n';
    return;
  }

  // Otherwise, print each byte and/or symbolic expression in order.
  auto ByteRange = dataObject.bytes<uint8_t>();
  uint64_t ByteI = dataObject.getOffset() + offset;

  // print comments at the right location efficiently (with a single iterator).
  bool HasComments = false;
  std::map<gtirb::Offset, std::string>::const_iterator CommentsIt;
  std::map<gtirb::Offset, std::string>::const_iterator CommentsEnd;
  if (this->LstMode == ListingDebug) {
    if (const auto* Comments = aux_data::getComments(module)) {
      HasComments = true;
      CommentsIt = Comments->lower_bound(CurrOffset);
      CommentsEnd = Comments->end();
    }
  }
  auto printCommentsBetween = [&](uint64_t Size) {
    gtirb::Offset EndOffset = CurrOffset;
    EndOffset.Displacement += Size;
    for (; CommentsIt != CommentsEnd && CommentsIt->first < EndOffset;
         ++CommentsIt) {
      os << syntax.comment();
      if (CommentsIt->first.Displacement > CurrOffset.Displacement)
        os << "+" << CommentsIt->first.Displacement - CurrOffset.Displacement
           << ":";
      os << " " << CommentsIt->second << '\n';
    }
  };

  for (auto ByteIt = ByteRange.begin() + offset; ByteIt != ByteRange.end();) {

    if (auto FoundSymExprRange =
            dataObject.getByteInterval()->findSymbolicExpressionsAtOffset(
                ByteI);
        !FoundSymExprRange.empty()) {
      const auto SEE = FoundSymExprRange.front();
      auto Size = getSymbolicExpressionSize(SEE);
      if (HasComments) {
        printCommentsBetween(Size);
      }
      gtirb::Addr EA = *dataObject.getAddress() + CurrOffset.Displacement;
      std::stringstream DataLine;
      printEA(DataLine, EA);
      printSymbolicData(DataLine, SEE, Size, Type);
      if (Size == 0) {
        LOG_ERROR
            << "ERROR: " << EA
            << ": Size 0 SymbolicExpression: break infinite loop of printing\n";
      }
      printCommentableLine(DataLine, os, *dataObject.getAddress() + offset);
      os << '\n';
      printSymbolicDataFollowingComments(os, EA);
      ByteI += Size;
      ByteIt += Size;
      CurrOffset.Displacement += Size;
    } else {
      if (HasComments) {
        printCommentsBetween(1);
      }

      std::stringstream DataLine;
      printEA(DataLine, *dataObject.getAddress() + CurrOffset.Displacement);
      printByte(DataLine,
                static_cast<std::byte>(static_cast<unsigned char>(*ByteIt)));
      printCommentableLine(DataLine, os,
                           *dataObject.getAddress() + CurrOffset.Displacement);
      os << '\n';
      ByteI++;
      ByteIt++;
      CurrOffset.Displacement++;
    }
  }
}

void PrettyPrinterBase::printZeroDataBlock(std::ostream& os,
                                           const gtirb::DataBlock& dataObject,
                                           uint64_t offset) {
  if (auto size = dataObject.getSize() - offset) {
    printComments(os, gtirb::Offset(dataObject.getUUID(), offset),
                  dataObject.getSize() - offset);

    std::stringstream DataLine;
    printEA(DataLine, *dataObject.getAddress() + offset);
    DataLine << ".zero " << size;
    printCommentableLine(DataLine, os, *dataObject.getAddress() + offset);
    os << '\n';
  }
}

void PrettyPrinterBase::printComments(std::ostream& os,
                                      const gtirb::Offset& offset,
                                      uint64_t range) {
  // We only print auxdata comments in debug mode. In UI mode, we _might_ want
  // some comments but there is no way to be selective of which ones.
  if (this->LstMode != ListingDebug)
    return;

  if (const auto* Comments = aux_data::getComments(module)) {
    gtirb::Offset endOffset(offset.ElementId, offset.Displacement + range);
    for (auto p = Comments->lower_bound(offset);
         p != Comments->end() && p->first < endOffset; ++p) {
      os << syntax.comment();
      if (p->first.Displacement > offset.Displacement)
        os << "+" << p->first.Displacement - offset.Displacement << ":";
      os << " " << p->second << '\n';
    }
  }
}

void PrettyPrinterBase::printCommentableLine(std::stringstream& LineContents,
                                             std::ostream& OutStream,
                                             gtirb::Addr EA) {
  std::copy(std::istreambuf_iterator<char>(LineContents),
            std::istreambuf_iterator<char>(),
            std::ostream_iterator<char>(OutStream));

  if (this->LstMode != ListingUI)
    return;

  // We could do this with std::setw() and <<, but I'm concerned about
  // performance since we would be iterating lineContents twice.
  const std::streampos Length = LineContents.tellp();
  assert(Length != -1);
  // If this _was_ -1, it will now be std::max<size_t> which gives us the
  // behavior we want (single space between end of instruction and comment)
  const size_t LengthUnsigned = static_cast<size_t>(Length);
  const size_t NumSpaces = PreferredEOLCommentPos > LengthUnsigned
                               ? (PreferredEOLCommentPos - LengthUnsigned - 1)
                               : 1;
  std::string Spaces(NumSpaces, ' ');

  OutStream << Spaces << syntax.comment();
  OutStream << " EA: " << std::hex << EA << std::dec;
}

void PrettyPrinterBase::printCFIDirectives(std::ostream& os,
                                           const gtirb::Offset& offset) {
  // CFI gets a little noisy for people trying to understand the code.
  if (this->LstMode == ListingUI)
    return;

  if (auto CfiDirectives = aux_data::getCFIDirectives(offset, module)) {
    for (auto& CfiDirective : *CfiDirectives) {
      std::string Directive = CfiDirective.Directive;

      if (Directive == ".cfi_startproc") {
        CFIStartProc = programCounter;
      } else if (!CFIStartProc) {
        std::cerr << "WARNING: Missing `.cfi_startproc', omitting `"
                  << Directive << "' directive.\n";
        continue;
      }

      os << Directive << " ";
      const std::vector<int64_t>& Operands = CfiDirective.Operands;
      for (auto It = Operands.begin(); It != Operands.end(); It++) {
        if (It != Operands.begin())
          os << ", ";
        os << *It;
      }

      gtirb::Symbol* Symbol =
          nodeFromUUID<gtirb::Symbol>(context, CfiDirective.Uuid);
      if (Symbol) {
        if (Operands.size() > 0)
          os << ", ";
        printSymbolReference(os, Symbol);
      }

      os << std::endl;

      if (Directive == ".cfi_endproc") {
        CFIStartProc = std::nullopt;
      }
    }
  }
}

void PrettyPrinterBase::printSymbolicDataType(
    std::ostream& os,
    const gtirb::ByteInterval::ConstSymbolicExpressionElement& /* SEE */,
    uint64_t Size, std::optional<std::string> /* Type */) {
  switch (Size) {
  case 1:
    os << syntax.byteData();
    break;
  case 2:
    os << syntax.wordData();
    break;
  case 4:
    os << syntax.longData();
    break;
  case 8:
    os << syntax.quadData();
    break;
  default:
    assert(!"Can't print symbolic expression of given size!");
    break;
  }
}

void PrettyPrinterBase::printSymbolicData(
    std::ostream& os,
    const gtirb::ByteInterval::ConstSymbolicExpressionElement& SEE,
    uint64_t Size, std::optional<std::string> Type) {
  printSymbolicDataType(os, SEE, Size, Type);

  os << " ";

  if (const auto* s =
          std::get_if<gtirb::SymAddrConst>(&SEE.getSymbolicExpression())) {
    // Make sure the initial m_accum_comment is empty.
    m_accum_comment.clear();
    printSymbolicExpression(os, s, true);
  } else if (const auto* sa = std::get_if<gtirb::SymAddrAddr>(
                 &SEE.getSymbolicExpression())) {
    // Make sure the initial m_accum_comment is empty.
    m_accum_comment.clear();
    printSymbolicExpression(os, sa, true);
  }
}

void PrettyPrinterBase::printSymbolicDataFollowingComments(
    std::ostream& OutStream, const gtirb::Addr& EA) {
  if (!m_accum_comment.empty()) {
    OutStream << syntax.comment() << " ";
    printEA(OutStream, EA);
    OutStream << ": " << m_accum_comment;
    m_accum_comment.clear();
    OutStream << '\n';
  }
}

void PrettyPrinterBase::printSymExprPrefix(
    std::ostream& /* OS */, const gtirb::SymAttributeSet& /* Attrs */,
    bool /* IsNotBranch */) {}

void PrettyPrinterBase::printSymExprSuffix(
    std::ostream& /* OS */, const gtirb::SymAttributeSet& /* Attrs */,
    bool /* IsNotBranch */) {}

std::string PrettyPrinterBase::s_symaddr_0_warning(uint64_t symAddr) {
  std::stringstream ss;
  ss << "WARNING:0: no symbol for address 0x" << std::hex << symAddr << " ";
  return ss.str();
}

void PrettyPrinterBase::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrConst* sexpr, bool IsNotBranch) {
  std::stringstream ss;
  bool skipped = printSymbolReference(ss, sexpr->Sym);

  if (skipped) {
    os << ss.str();
  } else {
    printSymExprPrefix(os, sexpr->Attributes, IsNotBranch);

    os << ss.str();
    printAddend(os, sexpr->Offset);

    printSymExprSuffix(os, sexpr->Attributes, IsNotBranch);
  }
}

void PrettyPrinterBase::printSymbolicExpression(std::ostream& os,
                                                const gtirb::SymAddrAddr* sexpr,
                                                bool IsNotBranch) {
  printSymExprPrefix(os, sexpr->Attributes, IsNotBranch);

  if (sexpr->Scale > 1) {
    os << "(";
  }

  printSymbolReference(os, sexpr->Sym1);
  os << '-';
  printSymbolReference(os, sexpr->Sym2);

  if (sexpr->Scale > 1) {
    os << ")/" << sexpr->Scale;
  }

  if (sexpr->Offset != 0) {
    if (sexpr->Offset > 0)
      os << "+";
    os << sexpr->Offset;
  }

  printSymExprSuffix(os, sexpr->Attributes, IsNotBranch);
}

std::optional<std::string>
PrettyPrinterBase::getContainerFunctionName(gtirb::Addr Addr) const {
  for (auto& Block : module.findBlocksOn(Addr)) {
    auto FunctionSymbol = getContainerFunctionSymbol(Block.getUUID());
    if (FunctionSymbol) {
      return FunctionSymbol->getName();
    }
  }
  return std::nullopt;
}

const gtirb::Symbol*
PrettyPrinterBase::getContainerFunctionSymbol(const gtirb::UUID& Uuid) const {
  if (auto FunctionEntry = BlockToFunction.find(Uuid);
      FunctionEntry != BlockToFunction.end()) {
    if (auto FunctionNameEntry = FunctionToSymbols.find(FunctionEntry->second);
        FunctionNameEntry != FunctionToSymbols.end()) {
      return FunctionNameEntry->second;
    }
  }
  return nullptr;
}

bool PrettyPrinterBase::isFunctionSkipped(
    const PrintingPolicy& Policy, const gtirb::Symbol& FunctionSymbol) const {
  if (Policy.skipFunctions.count(FunctionSymbol.getName())) {
    return true;
  }
  auto Aliases = FunctionAliases.find(&FunctionSymbol);
  if (Aliases == FunctionAliases.end()) {
    return false;
  }
  for (const auto* Alias : Aliases->second) {
    if (Policy.skipFunctions.count(Alias->getName())) {
      return true;
    }
  }
  return false;
}

bool PrettyPrinterBase::shouldSkip(const PrintingPolicy& Policy,
                                   const gtirb::Section& section) const {
  if (Policy.LstMode == ListingDebug) {
    return false;
  }

  // TODO: print bytes not covered by any block?
  if (section.blocks().empty()) {
    return true;
  }

  return Policy.skipSections.count(section.getName());
}

bool PrettyPrinterBase::shouldSkip(const PrintingPolicy& Policy,
                                   const gtirb::Symbol& Symbol) const {
  if (Policy.LstMode == ListingDebug) {
    return false;
  }

  if (Policy.skipSymbols.count(Symbol.getName())) {
    return true;
  }

  if (Symbol.hasReferent()) {
    const auto* Referent = Symbol.getReferent<gtirb::Node>();
    if (auto* CB = gtirb::dyn_cast<gtirb::CodeBlock>(Referent)) {
      return shouldSkip(Policy, *CB);
    } else if (auto* DB = gtirb::dyn_cast<gtirb::DataBlock>(Referent)) {
      return shouldSkip(Policy, *DB);
    } else if (gtirb::isa<gtirb::ProxyBlock>(Referent)) {
      return false;
    } else {
      assert(!"non block in symbol referent!");
      return false;
    }
  } else if (auto Addr = Symbol.getAddress()) {
    // If a symbol has no referent but has an address, we check for the first
    // block at that address.
    auto BlocksAtSymbolAddr = module.findBlocksAt(*Addr);
    if (BlocksAtSymbolAddr.begin() != BlocksAtSymbolAddr.end()) {
      auto FunctionSymbol =
          getContainerFunctionSymbol(BlocksAtSymbolAddr.begin()->getUUID());
      return FunctionSymbol && isFunctionSkipped(Policy, *FunctionSymbol);
    }
    return false;
  } else {
    return false;
  }
}

bool PrettyPrinterBase::shouldSkip(const PrintingPolicy& Policy,
                                   const gtirb::CodeBlock& block) const {
  if (Policy.LstMode == ListingDebug) {
    return false;
  }

  if (Policy.skipSections.count(
          block.getByteInterval()->getSection()->getName())) {
    return true;
  }

  auto FunctionSymbol = getContainerFunctionSymbol(block.getUUID());
  return FunctionSymbol && isFunctionSkipped(Policy, *FunctionSymbol);
}

bool PrettyPrinterBase::shouldSkip(const PrintingPolicy& Policy,
                                   const gtirb::DataBlock& block) const {
  if (Policy.LstMode == ListingDebug) {
    return false;
  }

  if (Policy.skipSections.count(
          block.getByteInterval()->getSection()->getName())) {
    return true;
  }

  auto FunctionSymbol = getContainerFunctionSymbol(block.getUUID());
  return FunctionSymbol && isFunctionSkipped(Policy, *FunctionSymbol);
}

const std::optional<const gtirb::Section*>
PrettyPrinterBase::getContainerSection(const gtirb::Addr addr) const {
  auto found_sections = module.findSectionsOn(addr);
  if (found_sections.begin() == found_sections.end())
    return std::nullopt;
  else
    return &*found_sections.begin();
}

std::string PrettyPrinterBase::getRegisterName(unsigned int reg) const {
  assert(reg != X86_REG_INVALID && "Register has no name!");
  return ascii_str_toupper(cs_reg_name(this->csHandle, reg));
}

void PrettyPrinterBase::printAddend(std::ostream& os, int64_t number,
                                    bool first) {
  if (number < 0 || first) {
    os << number;
    return;
  }
  if (number == 0)
    return;
  os << "+" << number;
}

template <typename BlockType>
std::optional<uint64_t>
PrettyPrinterBase::getAlignmentImpl(const BlockType& Block) {
  bool FirstInBI = (Block.getOffset() == 0),
       FirstInSection =
           (&Block.getByteInterval()->getSection()->byte_intervals().front() ==
            Block.getByteInterval());

  // print alignment if block specified in aux data table
  if (auto Alignment = aux_data::getAlignment(Block.getUUID(), module)) {
    return Alignment;
  }

  // print alignment if byte interval specified in aux data table
  if (FirstInBI) {
    if (auto Alignment = aux_data::getAlignment(
            Block.getByteInterval()->getUUID(), module)) {
      return Alignment;
    }

    // print alignment if section specified in aux data table
    if (FirstInSection) {
      if (auto Alignment = aux_data::getAlignment(
              Block.getByteInterval()->getSection()->getUUID(), module)) {
        return Alignment;
      }
    }
  }

  // if the section is an array section, print the ISA's array section width
  if (policy.arraySections.count(
          Block.getByteInterval()->getSection()->getName())) {
    switch (module.getISA()) {
    case gtirb::ISA::ARM:
    case gtirb::ISA::IA32:
    case gtirb::ISA::MIPS32:
    case gtirb::ISA::PPC32:
      return 4;
    case gtirb::ISA::ARM64:
    case gtirb::ISA::MIPS64:
    case gtirb::ISA::PPC64:
    case gtirb::ISA::X64:
      return 8;
    default:
      return std::nullopt;
    }
  }

  // if the block is first in the section, print alignment based on its address
  if (FirstInBI && FirstInSection) {
    return getAlignment(*Block.getAddress());
  }

  // else, no alignment needed
  return std::nullopt;
}

std::optional<uint64_t>
PrettyPrinterBase::getAlignment(const gtirb::CodeBlock& Block) {
  return getAlignmentImpl(Block);
}

std::optional<uint64_t>
PrettyPrinterBase::getAlignment(const gtirb::DataBlock& Block) {
  return getAlignmentImpl(Block);
}

void PrettyPrinterBase::printAlignment(std::ostream& OS, uint64_t Alignment) {
  // `.align N` specifies the number of low-order zero bits in the aligned
  // address (i.e., an alignment of 2^N).
  // In other styles, `.align N` aligns the next element to N bytes.
  if (syntax.alignmentStyle() == SyntaxAlignmentZeros) {

    uint64_t X = Alignment, Log2X = 0;
    while (X >>= 1) {
      ++Log2X;
    }
    Alignment = Log2X;
  }

  OS << syntax.align() << ' ' << Alignment << '\n';
}

std::string
PrettyPrinterBase::getSymbolName(const gtirb::Symbol& Symbol) const {
  if (auto Renaming = AmbiguousSymbols.find(&Symbol);
      Renaming != AmbiguousSymbols.end()) {
    auto newName = Renaming->second;
    assert(module.findSymbols(newName).empty());
    return syntax.formatSymbolName(newName);
  } else {
    return syntax.formatSymbolName(Symbol.getName());
  }
}

std::optional<std::string>
PrettyPrinterBase::getForwardedSymbolName(const gtirb::Symbol* Symbol) const {
  if (auto* Result = getForwardedSymbol(Symbol)) {
    return getSymbolName(*Result);
  } else {
    return std::nullopt;
  }
}

gtirb::Symbol*
PrettyPrinterBase::getForwardedSymbol(const gtirb::Symbol* Symbol) const {
  if (Symbol) {
    if (auto Found = aux_data::getForwardedSymbol(Symbol)) {
      return nodeFromUUID<gtirb::Symbol>(context, *Found);
    }
  }
  return nullptr;
}

const gtirb::Symbol* PrettyPrinterBase::getBestSymbol(
    const std::set<const gtirb::Symbol*, CmpSymPtr>& Symbols) const {
  // Given a set of gtirb::Symbol* that has the same name associated with
  // the same address, pick the best one.
  // Note that this function is used in computeAmbiguousSymbols where ambiguous
  // symbols are renamed except the best one.
  // By default, pick the first one in the set. Override it if needed.
  if (Symbols.size() > 0) {
    return *(Symbols.begin());
  }
  return nullptr;
}

void PrettyPrinterBase::printSection(std::ostream& os,
                                     const gtirb::Section& section) {
  if (shouldSkip(policy, section)) {
    return;
  }
  programCounter = gtirb::Addr{0};

  printSectionHeader(os, section);

  for (const auto& Block : section.blocks()) {
    if (auto* CB = gtirb::dyn_cast<gtirb::CodeBlock>(&Block)) {
      printBlock(os, *CB);
    } else if (auto* DB = gtirb::dyn_cast<gtirb::DataBlock>(&Block)) {
      printBlock(os, *DB);
    } else {
      assert(!"non block in block iterator!");
    }
  }

  printSectionFooter(os, section);
}

uint64_t PrettyPrinterBase::getSymbolicExpressionSize(
    const gtirb::ByteInterval::ConstSymbolicExpressionElement& SEE) const {
  // Check if it is present in aux data.
  gtirb::Offset Off{SEE.getByteInterval()->getUUID(), SEE.getOffset()};
  if (auto Size = aux_data::getSymbolicExpressionSize(Off, module)) {
    return *Size;
  }

  // If not, it's the size of that largest data block at this address that is:
  // (a) a power of 2
  // (b) a pointer-width or smaller
  const gtirb::DataBlock* LargestBlock = nullptr;
  for (auto& Block :
       SEE.getByteInterval()->findDataBlocksAtOffset(SEE.getOffset())) {
    auto BlockSize = Block.getSize();
    if (BlockSize != 1 && BlockSize != 2 && BlockSize != 4 && BlockSize != 8)
      continue;

    if (!LargestBlock || BlockSize > LargestBlock->getSize()) {
      LargestBlock = &Block;
    }
  }

  if (LargestBlock) {
    return LargestBlock->getSize();
  }

  // No size found, report an error.
  assert(!"Size of symbolic expression could not be determined!");
  return 0;
}

std::optional<uint64_t>
PrettyPrinterBase::getAlignment(gtirb::Addr Addr) const {
  auto A = uint64_t{Addr};

  if (A % 16 == 0) {
    return 16;
  } else if (A % 8 == 0) {
    return 8;
  } else if (A % 4 == 0) {
    return 4;
  } else if (A % 2 == 0) {
    return 2;
  }

  return std::nullopt;
}

bool PrettyPrinterBase::x86InstHasMoffsetEncoding(const cs_insn& inst) {
  // The moffset operand encoding is only used by a handful of mov
  // instructions.
  return (inst.detail->x86.opcode[0] == 0xA0 ||
          inst.detail->x86.opcode[0] == 0xA1 ||
          inst.detail->x86.opcode[0] == 0xA2 ||
          inst.detail->x86.opcode[0] == 0xA3) &&
         inst.detail->x86.opcode[1] == 0x00 &&
         inst.detail->x86.opcode[2] == 0x00 &&
         inst.detail->x86.opcode[3] == 0x00;
}

void PrettyPrinter::updateDynMode(gtirb::Module& Module,
                                  const std::string& SharedOption) {
  if (Module.getFileFormat() != gtirb::FileFormat::ELF)
    return;

  if (SharedOption == "yes") {
    std::vector<std::string> Vec;
    Vec.push_back("DYN");
    Vec.push_back("SHARED");
    aux_data::setBinaryType(Module, Vec);
  } else if (SharedOption == "no") {
    const auto& T = aux_data::getBinaryType(Module);
    if (std::find(T.begin(), T.end(), "DYN") != T.end()) {
      std::vector<std::string> Vec;
      Vec.push_back("DYN");
      Vec.push_back("PIE");
      aux_data::setBinaryType(Module, Vec);
    }
  }
}

DynMode PrettyPrinter::getDynMode(const gtirb::Module& Module) const {
  const auto& T = aux_data::getBinaryType(Module);
  if (std::find(T.begin(), T.end(), "SHARED") != T.end()) {
    return DYN_MODE_SHARED;
  } else if (std::find(T.begin(), T.end(), "PIE") != T.end()) {
    return DYN_MODE_PIE;
  } else if (std::find(T.begin(), T.end(), "DYN") != T.end()) {
    return DYN_MODE_PIE;
  } else {
    return DYN_MODE_NONE;
  }
}

// This is to have a deterministic order in a set of gtirb::Symbol*:
// std::set<const gtirb::Symbol*, CmpSymPtr>
bool CmpSymPtr::operator()(const gtirb::Symbol* A,
                           const gtirb::Symbol* B) const {
  auto A_addr = A->getAddress();
  auto B_addr = B->getAddress();
  auto A_name = A->getName();
  auto B_name = B->getName();
  auto A_kind = A->getKind();
  auto B_kind = B->getKind();
  auto A_module = A->getModule();
  auto B_module = B->getModule();
  return (std::tie(A_addr, A_name, A_kind, A_module, A) <
          std::tie(B_addr, B_name, B_kind, B_module, B));
}

} // namespace gtirb_pprint

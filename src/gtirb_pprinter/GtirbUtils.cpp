#include <boost/uuid/uuid_io.hpp>
#include <gtirb/Module.hpp>
#include <sstream>

#include "AuxDataUtils.hpp"
#include "GtirbUtils.hpp"
#include "PrettyPrinter.hpp"
#include "driver/Logger.h"

namespace gtirb_pprint {

ModuleInfo::ModuleInfo(gtirb::Context& Ctx, const gtirb::Module& Mod)
    : Module(Mod), functionEntry(), functionLastBlock() {
  for (auto const& Function : aux_data::getFunctionEntries(Module)) {
    for (auto& EntryBlockUuid : Function.second) {
      const auto* Block = nodeFromUUID<gtirb::CodeBlock>(Ctx, EntryBlockUuid);
      if (Block)
        functionEntry.insert(*Block->getAddress());
      else
        LOG_WARNING << "UUID " << boost::uuids::to_string(EntryBlockUuid)
                    << " in functionEntries table references non-existent "
                    << "block.\n";
    }
  }

  for (auto const& Function : aux_data::getFunctionBlocks(Module)) {
    assert(Function.second.size() > 0);
    gtirb::Addr LastAddr{0};
    for (auto& BlockUuid : Function.second) {
      const auto* Block = nodeFromUUID<gtirb::CodeBlock>(Ctx, BlockUuid);
      if (!Block)
        LOG_WARNING << "UUID " << boost::uuids::to_string(BlockUuid)
                    << " in functionBlocks table references non-existent "
                    << "block.\n";
      if (Block && Block->getAddress() > LastAddr)
        LastAddr = *Block->getAddress();
    }
    functionLastBlock.insert(LastAddr);
  }

  // Collect all ambiguous symbols in the module and give them
  // unique names
  std::map<const std::string, std::multimap<gtirb::Addr, const gtirb::Symbol*>>
      SymbolsByNameAddr;
  for (auto& S : Module.symbols()) {
    auto Addr = S.getAddress().value_or(gtirb::Addr(0));
    SymbolsByNameAddr[S.getName()].emplace(Addr, &S);
  }
  for (auto& [Name, Group] : SymbolsByNameAddr) {
    if (Group.size() > 1) {
      int Index = 0;
      gtirb::Addr PrevAddress{0};
      for (auto& [Addr, Sym] : Group) {
        std::stringstream NewName;
        NewName << Name << "_disambig_" << Addr;
        if (Addr != PrevAddress) {
          Index = 0;
          PrevAddress = Addr;
        }
        std::stringstream Suffix;
        Suffix << "_" << Index++;
        while (!Module.findSymbols(NewName.str() + Suffix.str()).empty()) {
          Suffix.seekp(0);
          Suffix << "_" << Index++;
        }
        NewName << Suffix.str();
        AmbiguousSymbols.insert({Sym, NewName.str()});
      }
    }
  }
}

bool ModuleInfo::isFunctionEntry(gtirb::Addr x) const {
  return functionEntry.count(x) > 0;
}

bool ModuleInfo::isFunctionLastBlock(gtirb::Addr x) const {
  return functionLastBlock.count(x) > 0;
}

std::string ModuleInfo::getFunctionName(gtirb::Addr x) const {
  // Is this address an entry point to a function with a symbol?
  if (isFunctionEntry(x)) {
    const auto symbols = Module.findSymbols(x);
    if (symbols.empty()) {
      // This is a function entry with no associated symbol?
      std::stringstream name;
      name << "unknown_function_" << std::hex << static_cast<uint64_t>(x);
      return name.str();
    } else {
      const gtirb::Symbol& s = symbols.front();
      return s.getName();
    }
  }
  // This doesn't seem to be a function.
  return std::string{};
}

std::string ModuleInfo::disambiguateName(const gtirb::Symbol* Symbol) const {
  if (auto NameIter = AmbiguousSymbols.find(Symbol);
      NameIter != AmbiguousSymbols.end()) {
    return NameIter->second;
  }
  return Symbol->getName();
}

std::optional<std::string>
ModuleInfo::getContainerFunctionName(gtirb::Addr x) const {
  auto it = functionEntry.upper_bound(x);
  if (it == functionEntry.begin())
    return std::nullopt;
  it--;
  return this->getFunctionName(*it);
}

bool ModuleInfo::shouldSkip(const PrintingPolicy& Policy,
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

bool ModuleInfo::shouldSkip(const PrintingPolicy& Policy,
                            const gtirb::Symbol& Symbol) const {
  if (Policy.LstMode == ListingDebug) {
    return false;
  }

  if (Policy.skipSymbols.count(Symbol.getName())) {
    return true;
  }

  if (Symbol.hasReferent()) {
    const auto* Referent = Symbol.getReferent<gtirb::Node>();
    if (auto* CB = dyn_cast<gtirb::CodeBlock>(Referent)) {
      return shouldSkip(Policy, *CB);
    } else if (auto* DB = dyn_cast<gtirb::DataBlock>(Referent)) {
      return shouldSkip(Policy, *DB);
    } else if (isa<gtirb::ProxyBlock>(Referent)) {
      return false;
    } else {
      assert(!"non block in symbol referent!");
      return false;
    }
  } else if (auto Addr = Symbol.getAddress()) {
    auto FunctionName = getContainerFunctionName(*Addr);
    return FunctionName && Policy.skipFunctions.count(*FunctionName);
  } else {
    return false;
  }
}

bool ModuleInfo::shouldSkip(const PrintingPolicy& Policy,
                            const gtirb::CodeBlock& block) const {
  if (Policy.LstMode == ListingDebug) {
    return false;
  }

  if (Policy.skipSections.count(
          block.getByteInterval()->getSection()->getName())) {
    return true;
  }

  auto FunctionName = getContainerFunctionName(*block.getAddress());
  return FunctionName && Policy.skipFunctions.count(*FunctionName);
}

bool ModuleInfo::shouldSkip(const PrintingPolicy& Policy,
                            const gtirb::DataBlock& block) const {
  if (Policy.LstMode == ListingDebug) {
    return false;
  }

  if (Policy.skipSections.count(
          block.getByteInterval()->getSection()->getName())) {
    return true;
  }

  auto FunctionName = getContainerFunctionName(*block.getAddress());
  return FunctionName && Policy.skipFunctions.count(*FunctionName);
}

} // namespace gtirb_pprint

#include "aux_data_util.hpp"
#include <iostream>

namespace aux_data {

bool validateAuxData(const gtirb::Module& Mod, std::string TargetFormat) {
  if (!Mod.getAuxData<gtirb::schema::FunctionEntries>()) {
    std::string Msg = "Missing FunctionEntries in module " + Mod.getName();
    std::cerr << Msg;
    // return gtirb::createStringError(
    //     gtirb_pprint::pprinter_error::MissingAuxData, Msg.str());
    return false;
  }
  auto Blocks = Mod.getAuxData<gtirb::schema::FunctionBlocks>();
  if (!Blocks) {
    std::string Msg = "Missing FunctionBlocks in module " + Mod.getName();
    std::cerr << Msg;
    // return gtirb::createStringError(
    //     gtirb_pprint::pprinter_error::MissingAuxData, Msg.str());
    return false;
  }
  for (auto& [UUID, BlockUUIDS] : *Blocks) {
    (void)UUID; // unused
    if (BlockUUIDS.empty()) {
      // return gtirb::createStringError(
      //     gtirb_pprint::pprinter_error::EmptyFunction,
      //     "Function with no blocks in module " + Mod.getName());
      return false;
    }
  }
  if (TargetFormat == "elf") {
    if (!Mod.getAuxData<gtirb::schema::ElfSymbolInfo>()) {
      std::string Msg = "Missing ElfSymbolInfo in module " + Mod.getName();
      std::cerr << Msg;
      // return gtirb::createStringError(
      //     gtirb_pprint::pprinter_error::MissingAuxData, Msg.str());
      return false;
    }
    if (!Mod.getAuxData<gtirb::schema::ElfSectionProperties>()) {
      std::string Msg{"Missing ElfSectionProperties in module "};
      Msg += Mod.getName();
      // return gtirb::createStringError(
      //     gtirb_pprint::pprinter_error::MissingAuxData, Msg.str());
      return false;
    }
  }
  return true; // gtirb::Error::success();
}

gtirb::schema::FunctionEntries::Type
getFunctionEntries(const gtirb::Module& Mod) {
  return util::getOrDefault<gtirb::schema::FunctionEntries>(Mod);
}

std::map<gtirb::UUID, std::set<gtirb::UUID>>
getFunctionBlocks(const gtirb::Module& Mod) {
  return util::getOrDefault<gtirb::schema::FunctionBlocks>(Mod);
}

// There's an extra vector allocated here
// that doesn't need to be, but getting c++
// to structure the output without allocating a new
// vector is a lot of work
std::optional<std::vector<CFIDirective>>
getCFIDirectives(const gtirb::Offset& Offset, const gtirb::Module& Mod) {
  if (auto Lst = util::getByOffset<gtirb::schema::CfiDirectives>(Offset, Mod)) {
    std::vector<CFIDirective> Dirs;
    for (const auto& Directive : *Lst) {
      Dirs.emplace_back(Directive);
    }
    return Dirs;
  }
  return std::nullopt;
}

std::optional<std::string> getEncodingType(const gtirb::DataBlock& DataBlock) {
  return util::getByNode<gtirb::schema::Encodings>(
      DataBlock, *(DataBlock.getByteInterval()->getSection()->getModule()));
}
std::optional<uint64_t> getSymbolicExpressionSize(const gtirb::Offset& Offset,
                                                  const gtirb::Module& Mod) {
  return util::getByOffset<gtirb::schema::SymbolicExpressionSizes>(Offset, Mod);
}

gtirb::schema::Alignment::Type getAlignments(const gtirb::Module& Mod) {
  return util::getOrDefault<gtirb::schema::Alignment>(Mod);
}

std::optional<uint64_t> getAlignment(const gtirb::UUID& Uuid,
                                     const gtirb::Module& Mod) {
  return util::getByKey<gtirb::schema::Alignment>(
      Uuid, Mod.getAuxData<gtirb::schema::Alignment>());
}

std::optional<gtirb::UUID> getForwardedSymbol(const gtirb::Symbol* Symbol) {
  if (Symbol && Symbol->getModule())
    return util::getByNode<gtirb::schema::SymbolForwarding>(
        *Symbol, *Symbol->getModule());
  return std::nullopt;
}

std::vector<std::string> getLibraries(const gtirb::Module& Module) {
  return util::getOrDefault<gtirb::schema::Libraries>(Module);
}

std::vector<std::string> getLibraryPaths(const gtirb::Module& Module) {
  return util::getOrDefault<gtirb::schema::LibraryPaths>(Module);
}

std::vector<std::string> getBinaryType(const gtirb::Module& Module) {
  return util::getOrDefault<gtirb::schema::BinaryType>(Module);
}

std::map<gtirb::UUID, gtirb::UUID>
getSymbolForwarding(const gtirb::Module& Module) {
  return util::getOrDefault<gtirb::schema::SymbolForwarding>(Module);
}

const gtirb::schema::Comments::Type* getComments(const gtirb::Module& Module) {
  return Module.getAuxData<gtirb::schema::Comments>();
}

std::optional<aux_data::ElfSymbolInfo>
getElfSymbolInfo(const gtirb::Symbol& Sym) {
  if (Sym.getModule())
    return util::getByNode<gtirb::schema::ElfSymbolInfo>(Sym,
                                                         *(Sym.getModule()));
  return std::nullopt;
}

void setElfSymbolInfo(gtirb::Symbol& Sym, aux_data::ElfSymbolInfo& Info) {
  auto* Table = Sym.getModule()->getAuxData<gtirb::schema::ElfSymbolInfo>();
  (*Table)[Sym.getUUID()] = Info.asAuxData();
}

std::optional<std::tuple<uint64_t, uint64_t>>
getElfSectionProperties(const gtirb::Section& Section) {
  if (Section.getModule())
    return util::getByNode<gtirb::schema::ElfSectionProperties>(
        Section, *Section.getModule());
  return std::nullopt;
};

std::optional<uint64_t> getPeSectionProperties(const gtirb::Section& Section) {
  return util::getByNode<gtirb::schema::PeSectionProperties>(
      Section, *Section.getModule());
}

gtirb::schema::ImportEntries::Type getImportEntries(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::ImportEntries>(M);
}

gtirb::schema::ExportEntries::Type getExportEntries(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::ExportEntries>(M);
}

gtirb::schema::PEResources::Type getPEResources(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::PEResources>(M);
};

gtirb::schema::PeImportedSymbols::Type
getPeImportedSymbols(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::PeImportedSymbols>(M);
}

gtirb::schema::PeExportedSymbols::Type
getPeExportedSymbols(const gtirb::Module& M) {
  return util::getOrDefault<gtirb::schema::PeExportedSymbols>(M);
}

} // namespace aux_data

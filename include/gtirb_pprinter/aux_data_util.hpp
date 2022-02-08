#ifndef AUXDATALOADER_HPP
#define AUXDATALOADER_HPP

#include <gtirb/gtirb.hpp>
#include <optional>
#include <type_traits>

#include "AuxDataSchema.hpp"

/*
 * What goes here?

 * 1. Validation
 * -- Check AuxData for all needed tables
 *    mandatory:
 *      all:
 *          FunctionEntries
 *          FunctionBlocks
 *      elf:
 *           elfSymbolInfo
 *          elfSectionProperties
 *      Pe:
 *          PeSectionProperties
 *    Optional:
 *      all:
 *          Encodings
 *          Comments
 *          CfiDirectives
 *          SymbolForwarding
 *          SymbolicExpressionSizes
 *          Libraries
 *          LibraryPaths
 *          BinaryType
 *      pe:
 *          PeImportedSymbols
 *          PeExportedSymbols
 *          ImportEntries
 *          ExportEntries
 *          PEResources
 *
 * - each block in FunctionBlocks must have positive size
 *
 * 2. structure
 * -- structure the auxdata if there's additional logic
 *    to it
 *
 */

namespace aux_data {

namespace util {
template <typename Schema>
typename Schema::Type getOrDefault(const typename Schema::Type* SchemaPtr) {
  if (SchemaPtr) {
    return *SchemaPtr;
  }
  return {};
}

template <typename Schema>
typename Schema::Type getOrDefault(const gtirb::Module& Module) {
  return getOrDefault<Schema>(Module.getAuxData<Schema>());
}

template <typename Schema, typename KeyType>
std::optional<typename Schema::Type::mapped_type>
getByKey(KeyType K, const typename Schema::Type* SchemaPtr) {
  if (SchemaPtr) {
    if (auto Val = SchemaPtr->find(K); Val != SchemaPtr->end()) {
      return Val->second;
    }
  }
  return std::nullopt;
}

template <typename Schema>
std::optional<typename Schema::Type::mapped_type>
getByOffset(const gtirb::Offset Offset, const gtirb::Module& Mod) {
  return getByKey<Schema, gtirb::Offset>(Offset, Mod.getAuxData<Schema>());
}

template <typename Schema>
std::optional<typename Schema::Type::mapped_type>
getByNode(const gtirb::Node& Node, const gtirb::Module& Mod) {
  return getByKey<Schema, gtirb::UUID>(Node.getUUID(),
                                       Mod.getAuxData<Schema>());
}

}; // namespace util

namespace elf {
static const std::unordered_map<std::string, std::string> TypeNameConversion = {
    {"FUNC", "function"},  {"OBJECT", "object"},
    {"NOTYPE", "notype"},  {"NONE", "notype"},
    {"TLS", "tls_object"}, {"GNU_IFUNC", "gnu_indirect_function"},
};

}; // namespace elf

struct ElfSymbolInfo {
  using AuxDataType =
      std::tuple<uint64_t, std::string, std::string, std::string, uint64_t>;

  uint64_t Size;
  std::string Type;
  std::string Binding;
  std::string Visibility;
  uint64_t SectionIndex;

  ElfSymbolInfo(const AuxDataType& Tuple)
      : Size(std::get<0>(Tuple)), Type(std::get<1>(Tuple)),
        Binding(std::get<2>(Tuple)), Visibility(std::get<3>(Tuple)),
        SectionIndex(std::get<4>(Tuple)) {}

  AuxDataType asAuxData() {
    return AuxDataType{Size, Type, Binding, Visibility, SectionIndex};
  }

  std::optional<std::string> convertType() {
    if (auto Converted = elf::TypeNameConversion.find(Type);
        Converted != elf::TypeNameConversion.end()) {
      return Converted->second;
    }
    return std::nullopt;
  }
};

struct CFIDirective {
  using AuxDataType =
      std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>;

  std::string Directive;
  std::vector<int64_t> Operands;
  gtirb::UUID Uuid;

  CFIDirective(const AuxDataType& Auxdata)
      : Directive(std::get<0>(Auxdata)), Operands(std::get<1>(Auxdata)),
        Uuid(std::get<2>(Auxdata)){};

  AuxDataType asAuxData() { return AuxDataType{Directive, Operands, Uuid}; }
};

std::optional<std::string> getEncodingType(const gtirb::DataBlock& DataBlock);

// There's an extra vector allocated here
// that doesn't need to be, but getting c++
// to structure the output without allocating a new
// vector is a lot of work
std::optional<std::vector<CFIDirective>>
getCFIDirectives(const gtirb::Offset& Offset, const gtirb::Module& Mod);

gtirb::schema::FunctionEntries::Type
getFunctionEntries(const gtirb::Module& Mod);

std::map<gtirb::UUID, std::set<gtirb::UUID>>
getFunctionBlocks(const gtirb::Module& Mod);

std::optional<uint64_t> getSymbolicExpressionSize(const gtirb::Offset& Offset,
                                                  const gtirb::Module& Mod);

gtirb::schema::Alignment::Type getAlignments(const gtirb::Module& Mod);

std::optional<uint64_t> getAlignment(const gtirb::UUID& Uuid,
                                     const gtirb::Module& Mod);

std::optional<gtirb::UUID> getForwardedSymbol(const gtirb::Symbol* Symbol);

std::vector<std::string> getLibraries(const gtirb::Module& Module);

std::vector<std::string> getLibraryPaths(const gtirb::Module& Module);

std::vector<std::string> getBinaryType(const gtirb::Module& Module);

std::map<gtirb::UUID, gtirb::UUID>
getSymbolForwarding(const gtirb::Module& Module);

const gtirb::schema::Comments::Type* getComments(const gtirb::Module& Module);

bool validateAuxData(const gtirb::Module& Mod, std::string TargetFormat);

std::optional<aux_data::ElfSymbolInfo>
getElfSymbolInfo(const gtirb::Symbol& Sym);

void setElfSymbolInfo(gtirb::Symbol& Sym, aux_data::ElfSymbolInfo& Info);

std::optional<std::tuple<uint64_t, uint64_t>>
getElfSectionProperties(const gtirb::Section& Section);

std::optional<uint64_t> getPeSectionProperties(const gtirb::Section& Section);

gtirb::schema::ImportEntries::Type getImportEntries(const gtirb::Module& M);

gtirb::schema::ExportEntries::Type getExportEntries(const gtirb::Module& M);

gtirb::schema::PEResources::Type getPEResources(const gtirb::Module& M);

gtirb::schema::PeImportedSymbols::Type
getPeImportedSymbols(const gtirb::Module& M);

gtirb::schema::PeExportedSymbols::Type
getPeExportedSymbols(const gtirb::Module& M);

} // namespace aux_data

#endif

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
    if (auto val = SchemaPtr->find(K); val != SchemaPtr->end()) {
      return val->second;
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

  ElfSymbolInfo(const AuxDataType& tuple)
      : Size(std::get<0>(tuple)), Type(std::get<1>(tuple)),
        Binding(std::get<2>(tuple)), Visibility(std::get<3>(tuple)),
        SectionIndex(std::get<4>(tuple)) {}

  ElfSymbolInfo(const ElfSymbolInfo& other)
      : Size(other.Size), Type(other.Type), Binding(other.Binding),
        Visibility(other.Visibility), SectionIndex(other.SectionIndex){};

  AuxDataType asAuxData() {
    return AuxDataType{Size, Type, Binding, Visibility, SectionIndex};
  }

  std::optional<std::string> convertType() {
    if (auto converted = elf::TypeNameConversion.find(Type);
        converted != elf::TypeNameConversion.end()) {
      return converted->second;
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

  CFIDirective(const AuxDataType& auxdata)
      : Directive(std::get<0>(auxdata)), Operands(std::get<1>(auxdata)),
        Uuid(std::get<2>(auxdata)){};

  AuxDataType asAuxData() { return AuxDataType{Directive, Operands, Uuid}; }
};

std::optional<std::string> getEncodingType(const gtirb::DataBlock& dataBlock);

// There's an extra vector allocated here
// that doesn't need to be, but getting c++
// to structure the output without allocating a new
// vector is a lot of work
std::optional<std::vector<CFIDirective>>
getCFIDirectives(const gtirb::Offset& offset, const gtirb::Module& mod);

gtirb::schema::FunctionEntries::Type
getFunctionEntries(const gtirb::Module& mod);

std::map<gtirb::UUID, std::set<gtirb::UUID>>
getFunctionBlocks(const gtirb::Module& mod);

std::optional<uint64_t> getSymbolicExpressionSize(const gtirb::Offset& offset,
                                                  const gtirb::Module& Mod);

gtirb::schema::Alignment::Type getAlignments(const gtirb::Module& Mod);

std::optional<uint64_t> getAlignment(const gtirb::UUID& uuid,
                                     const gtirb::Module& mod);

std::optional<gtirb::UUID> getForwardedSymbol(const gtirb::Symbol* Symbol);

std::vector<std::string> getLibraries(const gtirb::Module& Module);

std::vector<std::string> getLibraryPaths(const gtirb::Module& Module);

std::vector<std::string> getBinaryType(const gtirb::Module& Module);

std::map<gtirb::UUID, gtirb::UUID>
getSymbolForwarding(const gtirb::Module& Module);

const gtirb::schema::Comments::Type* getComments(const gtirb::Module& Module);

bool validateAuxData(const gtirb::Module& Mod, std::string TargetFormat);

std::optional<aux_data::ElfSymbolInfo>
getElfSymbolInfo(const gtirb::Symbol& sym);

void setElfSymbolInfo(gtirb::Symbol& sym, aux_data::ElfSymbolInfo& info);

std::optional<std::tuple<uint64_t, uint64_t>>
getElfSectionProperties(const gtirb::Section& section);

std::optional<uint64_t> getSectionProperties(const gtirb::Section& section);

gtirb::schema::ImportEntries::Type getImportEntries(const gtirb::Module& M_);

gtirb::schema::ExportEntries::Type getExportEntries(const gtirb::Module& M_);

gtirb::schema::PEResources::Type getPEResources(const gtirb::Module& M_);

gtirb::schema::PeImportedSymbols::Type
getPeImportedSymbols(const gtirb::Module& M_);

gtirb::schema::PeExportedSymbols::Type
getPeExportedSymbols(const gtirb::Module& M_);

} // namespace aux_data

#endif

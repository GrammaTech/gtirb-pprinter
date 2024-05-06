#ifndef AUXDATALOADER_HPP
#define AUXDATALOADER_HPP

#include <gtirb/gtirb.hpp>
#include <optional>
#include <type_traits>

#include "AuxDataSchema.hpp"
#include "Export.hpp"

/*
 * What goes here?

 * 1. Validation
 * -- Check AuxData for all needed tables
 *    mandatory:
 *      all:
 *          FunctionEntries
 *          FunctionBlocks
 *          sectionProperties
 *      elf:
 *          elfSymbolInfo
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

// Check that a Module's AuxData contains all tables required for printing.
bool validateAuxData(const gtirb::Module& Mod, std::string TargetFormat);

// Templated access patterns for AuxData tables
namespace util {

// Dereference an AuxData table or initialize a default value.
template <typename Schema>
typename Schema::Type getOrDefault(const typename Schema::Type* SchemaPtr) {
  if (SchemaPtr) {
    return *SchemaPtr;
  }
  return {};
}

// Load an AuxData table from a Module or a default value.
template <typename Schema>
typename Schema::Type getOrDefault(const gtirb::Module& Module) {
  return getOrDefault<Schema>(Module.getAuxData<Schema>());
}

// Access a map-typed AuxData schema by key value.
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

// Access a map-typed AuxData schema keyed by gtirb::Offset.
template <typename Schema>
std::optional<typename Schema::Type::mapped_type>
getByOffset(const gtirb::Offset Offset, const gtirb::Module& Mod) {
  return getByKey<Schema, gtirb::Offset>(Offset, Mod.getAuxData<Schema>());
}

// Access a map-typed AuxData schema keyed by gtirb::UUID.
template <typename Schema>
std::optional<typename Schema::Type::mapped_type>
getByNode(const gtirb::Node& Node, const gtirb::Module& Mod) {
  return getByKey<Schema, gtirb::UUID>(Node.getUUID(),
                                       Mod.getAuxData<Schema>());
}

}; // namespace util

namespace elf {

// Table mapping ELF flag labels to assembly keywords.
static const std::unordered_map<std::string, std::string> TypeNameConversion = {
    {"FUNC", "function"},  {"OBJECT", "object"},
    {"NOTYPE", "notype"},  {"NONE", "notype"},
    {"TLS", "tls_object"}, {"GNU_IFUNC", "gnu_indirect_function"},
};

}; // namespace elf

// Type wrapper for ELF symbol properties stored in the `elfSymbolInfo' table.
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

// Type wrapper for CFI directives stored in the `.cfiDirectives' table.
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

// Find the encoding for a DataBlock in the `Encodings` AuxData table.
std::optional<std::string> getEncodingType(const gtirb::DataBlock& DataBlock);

// Find CFI directives for some location in a byte interval in the
// `cfiDirectives' AuxData table.
// Retuns std::nullopt if either the `cfiDirectives` table is absent,
// or if there is no entry in the table for `Offset`.
std::optional<std::vector<CFIDirective>>
getCFIDirectives(const gtirb::Offset& Offset, const gtirb::Module& Mod);

// Load all function entry nodes from the `functionEntries' Auxdata table.
std::map<gtirb::UUID, std::set<gtirb::UUID>>
getFunctionEntries(const gtirb::Module& Mod);

// Load all function block UUIDs from the `functionBlocks' AuxData table.
std::map<gtirb::UUID, std::set<gtirb::UUID>>
getFunctionBlocks(const gtirb::Module& Mod);

// Load all function name UUIDs from the `functionNames' AuxData table.
std::map<gtirb::UUID, gtirb::UUID> getFunctionNames(const gtirb::Module& Mod);

// Find the size of a symbolic expression by offset (`symbolicExpressionSizes').
std::optional<uint64_t> getSymbolicExpressionSize(const gtirb::Offset& Offset,
                                                  const gtirb::Module& Mod);

// Load all alignment entries from the `alignment' AuxData table.
std::map<gtirb::UUID, uint64_t> getAlignments(const gtirb::Module& Mod);

// Get the alignment information for a specific node from the
// `alignment' AuxData table
std::optional<uint64_t> getAlignment(const gtirb::UUID& Uuid,
                                     const gtirb::Module& Mod);

// Find a mapping of one symbol to another in the `symbolForwarding' AuxData
// table.
std::optional<gtirb::UUID> getForwardedSymbol(const gtirb::Symbol* Symbol);

// Load all library names from the `libraries' AuxData table.
DEBLOAT_PRETTYPRINTER_EXPORT_API
std::vector<std::string> getLibraries(const gtirb::Module& Module);

// Load all library path names from the `libraryPaths' AuxData table.
DEBLOAT_PRETTYPRINTER_EXPORT_API
std::vector<std::string> getLibraryPaths(const gtirb::Module& Module);

// Load all binary type specifiers from the `binaryType' AuxData table.
DEBLOAT_PRETTYPRINTER_EXPORT_API std::vector<std::string>
getBinaryType(const gtirb::Module& Module);

void setBinaryType(gtirb::Module& Module, const std::vector<std::string>& Vec);

// Load symbol forwarding mapping from the `symbolForwarding' AuxData table.
std::map<gtirb::UUID, gtirb::UUID>
getSymbolForwarding(const gtirb::Module& Module);

// Load all comments for instructions from the `comments' AuxData table.
const std::map<gtirb::Offset, std::string>*
getComments(const gtirb::Module& Module);

// Check that a Module's AuxData contains all tables required for printing.
bool validateAuxData(const gtirb::Module& Mod, std::string TargetFormat);

// Load the properties of a symbol from the `elfSymbolInfo' AuxData table.
std::optional<aux_data::ElfSymbolInfo>
getElfSymbolInfo(const gtirb::Symbol& Sym);

// Store the properties of a symbol to the `elfSymbolInfo' AuxData table.
void setElfSymbolInfo(gtirb::Symbol& Sym, aux_data::ElfSymbolInfo& Info);

// In the given symbol range, find a symbol with the specified Binding in its
// elfSymbolInfo auxdata
gtirb::Symbol*
findSymWithBinding(gtirb::Module::symbol_ref_range CandidateSymbols,
                   const std::string& Binding);

// Determine if any version symbols are defined in a module
DEBLOAT_PRETTYPRINTER_EXPORT_API bool
hasVersionedSymDefs(const gtirb::Module& Module);

const gtirb::provisional_schema::ElfSymbolVersions::Type*
getSymbolVersions(const gtirb::Module& M);

bool isBaseVersion(uint64_t Flags);

bool hasBaseVersion(const gtirb::Symbol& Sym);

std::optional<std::string> getSymbolVersionString(const gtirb::Symbol& Sym);

/**
Returned by getSymbolVersionInfo if the GTIRB has no elfSymbolVersion auxdata
*/
struct NoSymbolVersionAuxData {};

/**
Returned by getSymbolVersionInfo if the Symbol is not versioned
*/
struct NoSymbolVersion {};

/**
Returned by getSymbolVersionInfo if the Symbol is versioned, but not found in
either SymVerDefs or SymVerNeeded (i.e., the auxdata is invalid)
*/
struct UndefinedSymbolVersion {};

/**
Returned by getSymbolVersionInfo for external symbols
*/
struct ExternalSymbolVersion {
  std::string VersionSuffix;
  std::string Library;
};

/**
Returned by getSymbolVersionInfo for internal symbols
*/
struct InternalSymbolVersion {
  std::string VersionSuffix;
  uint16_t Flags;
};

using SymbolVersionInfo =
    std::variant<NoSymbolVersionAuxData, NoSymbolVersion,
                 UndefinedSymbolVersion, ExternalSymbolVersion,
                 InternalSymbolVersion>;

/**
Get symbol version information for a given symbol.

Returns a gtirb::ErrorOr containing either a struct with symbol version
information or an empty structure representing a status.

See the SymbolVersionInfo variant members for possible returned structures.
*/
SymbolVersionInfo getSymbolVersionInfo(const gtirb::Symbol& Sym);

// Load the section properties of a binary section from the
// `sectionProperties' AuxData tables.
std::optional<std::tuple<uint64_t, uint64_t>>
getSectionProperties(const gtirb::Section& Section);

// Load all imported symbol properties for a PE binary from the
// `peImportEntries' AuxData table.
gtirb::schema::ImportEntries::Type getImportEntries(const gtirb::Module& M);

// Load all exported symbol properties for a PE binary from the
// `peExportEntries' AuxData table.
gtirb::schema::ExportEntries::Type getExportEntries(const gtirb::Module& M);

// Load all PE resources from the `peResources' AuxData table.
gtirb::schema::PEResources::Type getPEResources(const gtirb::Module& M);

// Load list of UUIDs for symbols imported by a PE binary from the
// `peImportedSymbols' AuxData table.
gtirb::schema::PeImportedSymbols::Type
getPeImportedSymbols(const gtirb::Module& M);

// Load list of UUIDs for symbols exported by a PE binary from the
// `peExportedSymbols' AuxData table.
gtirb::schema::PeExportedSymbols::Type
getPeExportedSymbols(const gtirb::Module& M);

// Load set of UUIDs for PE exception handlers.
// `peSafeExceptionHandlers' AuxData table.
gtirb::schema::PeSafeExceptionHandlers::Type
getPeSafeExceptionHandlers(const gtirb::Module& M);

gtirb::schema::ElfSymbolTabIdxInfo::Type
getElfSymbolTabIdxInfo(const gtirb::Module& M);

// Get the code block from an auxdata that contains a single CodeBlock UUID
template <typename Schema>
const gtirb::CodeBlock* getCodeBlock(const gtirb::Context& Ctx,
                                     const gtirb::Module& Mod) {
  auto UUID = Mod.getAuxData<Schema>();
  if (UUID) {
    auto Nd = gtirb::Node::getByUUID(Ctx, *UUID);
    if (const auto* CB = dyn_cast_or_null<gtirb::CodeBlock>(Nd)) {
      return CB;
    }
  }
  return nullptr;
}

template <typename Schema>
gtirb::CodeBlock* getCodeBlock(gtirb::Context& Ctx, gtirb::Module& Mod) {
  return const_cast<gtirb::CodeBlock*>(
      getCodeBlock<Schema>(const_cast<const gtirb::Context&>(Ctx),
                           const_cast<const gtirb::Module&>(Mod)));
}

// Load map from UUIDs to type descriptors
gtirb::provisional_schema::TypeTable::Type getTypeTable(const gtirb::Module& M);

// Load map from UUIDs for functions to UUIDs for their type signatures
gtirb::provisional_schema::PrototypeTable::Type
getPrototypeTable(const gtirb::Module& M);

} // namespace aux_data

// Utilities for dealing with TypeTable auxdata in particular
namespace gtirb_types {
namespace schema = gtirb::provisional_schema;
typedef schema::TypeTable::Type TypeMap;
typedef TypeMap::mapped_type TypeTableEntry;
typedef schema::PrototypeTable::Type PrototypeTable;

enum class Index : size_t {
  Unknown = 0,
  Bool,
  Int,
  Char,
  Float,
  Function,
  Pointer,
  Array,
  Struct,
  Void,
  Alias,
};

template <Index I>
using GtType_t = typename std::variant_alternative_t<static_cast<size_t>(I),
                                                     schema::GtirbType>;

template <Index I> GtType_t<I> getVariant(const schema::GtirbType& Var) {
  return std::get<static_cast<size_t>(I)>(Var);
};

struct TypePrinter {

public:
  TypePrinter(const gtirb::Module& Module, gtirb::Context& C);
  std::ostream& printPrototype(const gtirb::Addr& Addr, std::ostream& S,
                               const std::string Comment = "#");
  std::ostream& printPrototype(const gtirb::UUID& FnId, std::ostream& S,
                               const std::string Comment = "#");
  std::ostream& layoutStruct(const GtType_t<Index::Struct>& StructType,
                             std::ostream& Stream, const gtirb::UUID& Id);
  std::ostream& printType(const gtirb::UUID& TypeID, std::ostream& Stream);

protected:
  void makeName(const gtirb::UUID& StructId);
  // Simple types
  std::ostream& printUnknown(const GtType_t<Index::Unknown>& UnknownType,
                             std::ostream& Stream);
  std::ostream& printBool(std::ostream& Stream);
  std::ostream& printInt(const GtType_t<Index::Int>& IntType,
                         std::ostream& Stream);
  std::ostream& printChar(const GtType_t<Index::Char>& CharType,
                          std::ostream& Stream);
  std::ostream& printFloat(const GtType_t<Index::Float>& FloatType,
                           std::ostream& Stream);
  std::ostream& printVoid(std::ostream& Stream);

  // Compound types
  std::ostream& printFunction(const GtType_t<Index::Function>& FunType,
                              std::ostream& Stream);
  std::ostream& printArray(const GtType_t<Index::Array>& ArrayType,
                           std::ostream& Stream);
  // This one doesn't follow the same pattern, because structs are complicated
  // and we don't want to print them in place
  std::ostream& printStruct(const gtirb::UUID& Id, std::ostream& Stream);
  std::ostream& printPointer(const GtType_t<Index::Pointer>& PointerType,
                             std::ostream& Stream);
  std::ostream& printAlias(const GtType_t<Index::Alias>& AliasType,
                           std::ostream& Stream);
  std::set<gtirb::UUID> collectStructs(const gtirb::UUID& FnId);
  void collectStructs(const gtirb::UUID& Id, std::set<gtirb::UUID>& Out);
  std::map<gtirb::UUID, std::string> StructNames;
  TypeMap Types;
  PrototypeTable Prototypes;
  std::map<gtirb::Addr, gtirb::UUID> functionEntries;
  const gtirb::Module& Module;
  gtirb::Context& Context;
};
} // namespace gtirb_types

#endif

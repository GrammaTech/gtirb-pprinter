//===- AuxDataSchema.hpp ----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
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
#ifndef GTIRB_PPRINTER_AUXDATASCHEMA_HPP
#define GTIRB_PPRINTER_AUXDATASCHEMA_HPP

#include <gtirb/gtirb.hpp>
#include <map>
#include <string>
#include <tuple>
#include <vector>

/// \file AuxDataSchema.hpp
/// \ingroup AUXDATA_GROUP
/// \brief AuxData types used by gtirb_pprinter that are not sanctioned.
/// \see AUXDATA_GROUP

namespace auxdata {

/// Version identifiers are 16 bit unsigned integers.
using SymbolVersionId = uint16_t;
/// Map from version identifiers to version definitions. These correspond
/// to ELFxx_Verdef entries in the ELF section .gnu.version_d.
/// The values in the map are tuples containing the list of versions strings and
/// the verdef flags. The verdef flag may be VER_FLG_BASE (0x1), which indicates
/// that the given version definiton is the file itself, and must not be
/// used for matching a symbol. The first element of the list is the version
/// itself, the subsequent elements are predecessor versions.
using ElfSymVerDefs =
    std::map<SymbolVersionId, std::tuple<std::vector<std::string>, uint16_t>>;
/// Map from dynamic library names to the symbol versions that they need.
/// For each library, we have a map from version identifiers to version strings.
using ElfSymVerNeeded =
    std::map<std::string, std::map<SymbolVersionId, std::string>>;
//// Map from gtirb::Symbol UUIDs to a tuple of symbol version identifier and
/// hidden attribute.
using ElfSymbolVersionsEntries =
    std::map<gtirb::UUID, std::tuple<SymbolVersionId, bool>>;
} // namespace auxdata

namespace gtirb {
namespace schema {

/// \brief Auxiliary data covering data object encoding specifiers.
struct Encodings {
  static constexpr const char* Name = "encodings";
  typedef std::map<gtirb::UUID, std::string> Type;
};

/// \brief Auxiliary data covering section properties.
struct SectionProperties {
  static constexpr const char* Name = "sectionProperties";
  typedef std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> Type;
};

/// \brief Auxiliary data covering cfi directives.
struct CfiDirectives {
  static constexpr const char* Name = "cfiDirectives";
  typedef std::map<
      gtirb::Offset,
      std::vector<std::tuple<std::string, std::vector<int64_t>, gtirb::UUID>>>
      Type;
};

/// \brief Auxiliary data that includes names of necessary libraries.
struct Libraries {
  static constexpr const char* Name = "libraries";
  typedef std::vector<std::string> Type;
};

/// \brief Auxiliary data that includes names of necessary library paths.
struct LibraryPaths {
  static constexpr const char* Name = "libraryPaths";
  typedef std::vector<std::string> Type;
};

/// \brief Auxiliary data for Windows data directories.
struct DataDirectories {
  static constexpr const char* Name = "dataDirectories";
  typedef std::vector<std::tuple<std::string, uint64_t, uint64_t>> Type;
};

/// \brief Auxiliary data for the UUIDs of imported symbols in a PE file.
struct PeImportedSymbols {
  static constexpr const char* Name = "peImportedSymbols";
  typedef std::vector<gtirb::UUID> Type;
};

/// \brief Auxiliary data for the UUIDs of exported symbols in a PE file.
struct PeExportedSymbols {
  static constexpr const char* Name = "peExportedSymbols";
  typedef std::vector<gtirb::UUID> Type;
};

/// \brief Auxiliary data for the UUIDs of PE exception handlers.
struct PeSafeExceptionHandlers {
  static constexpr const char* Name = "peSafeExceptionHandlers";
  typedef std::set<gtirb::UUID> Type;
};

/// \brief Auxiliary data for extra symbol info.
struct ElfSymbolInfo {
  static constexpr const char* Name = "elfSymbolInfo";
  typedef std::map<gtirb::UUID, std::tuple<uint64_t, std::string, std::string,
                                           std::string, uint64_t>>
      Type;
};

/// \brief Auxiliary data for ELF symbol versions.
/// This includes the symbol version definitions, the symbol version
/// requirements, and the mapping from symbols to symbol versions.
struct ElfSymbolVersions {
  static constexpr const char* Name = "elfSymbolVersions";
  typedef std::tuple<auxdata::ElfSymVerDefs, auxdata::ElfSymVerNeeded,
                     auxdata::ElfSymbolVersionsEntries>
      Type;
};

/// \brief Auxiliary data that stores the size of symbolic expressions.
struct SymbolicExpressionSizes {
  static constexpr const char* Name = "symbolicExpressionSizes";
  typedef std::map<gtirb::Offset, uint64_t> Type;
};

/// \brief Auxiliary data describing a binary's type.
struct BinaryType {
  static constexpr const char* Name = "binaryType";
  typedef std::vector<std::string> Type;
};

/// \brief Auxiliary data describing architecture information
struct ArchInfo {
  static constexpr const char* Name = "archInfo";
  typedef std::vector<std::string> Type;
};

/// \brief Auxiliary data representing the export table of a PE file.
struct ExportEntries {
  static constexpr const char* Name = "peExportEntries";
  // Tuples of the form {Address, Ordinal, Name}.
  typedef std::vector<std::tuple<uint64_t, int64_t, std::string>> Type;
};

/// \brief Auxiliary data representing the import table of a PE file.
struct ImportEntries {
  static constexpr const char* Name = "peImportEntries";
  // Tuples of the form {Iat_address, Ordinal, Function, Library}.
  typedef std::vector<std::tuple<uint64_t, int64_t, std::string, std::string>>
      Type;
};

// \brief List on PE Resources in the form <header, data_offset, data_length
struct PEResources {
  static constexpr const char* Name = "peResources";
  typedef std::vector<std::tuple<std::vector<uint8_t>, gtirb::Offset, uint64_t>>
      Type;
};

} // namespace schema

namespace provisional_schema {

// Type descriptors used by gtirb-types
typedef std::variant<
    uint64_t,                                          // Unknown{Width}
    std::tuple<uint8_t>,                               // Bool
    std::tuple<int8_t, uint64_t>,                      // Int{Signed, Width}
    uint64_t,                                          // Char{Width}
    uint64_t,                                          // Float{Width}
    std::tuple<gtirb::UUID, std::vector<gtirb::UUID>>, // Function{ReturnType,
                                                       // ArgumentTypes}
    gtirb::UUID,                                       // Pointer{Type}
    std::tuple<gtirb::UUID, uint64_t>,                 // Array {Type, Size}
    std::tuple<uint64_t,
               std::vector<std::tuple<uint64_t, gtirb::UUID>>>, // Struct {Size,
                                                                // Fields}
    std::tuple<uint8_t>,                                        // Void
    gtirb::UUID>                                                // Alias {Type}
    GtirbType;

struct TypeTable {
  // Map assigning each type used a UUID
  static constexpr const char* Name = "typeTable";
  typedef std::map<gtirb::UUID, GtirbType> Type;
};

struct PrototypeTable {
  // Map from UUIDs of functions to UUIDs for their types in typeTable
  static constexpr const char* Name = "prototypeTable";
  typedef std::map<gtirb::UUID, gtirb::UUID> Type;
};

} // namespace provisional_schema

} // namespace gtirb

#endif // GTIRB_PPRINTER_AUXDATASCHEMA_HPP

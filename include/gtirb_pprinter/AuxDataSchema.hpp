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

namespace gtirb {
namespace schema {

/// \brief Auxiliary data covering data object encoding specifiers.
struct Encodings {
  static constexpr const char* Name = "encodings";
  typedef std::map<gtirb::UUID, std::string> Type;
};

/// \brief Auxiliary data covering ELF section properties.
struct ElfSectionProperties {
  static constexpr const char* Name = "elfSectionProperties";
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

/// \brief Auxiliary data for extra symbol info.
struct ElfSymbolInfo {
  static constexpr const char* Name = "elfSymbolInfo";
  typedef std::map<gtirb::UUID, std::tuple<uint64_t, std::string, std::string,
                                           std::string, uint64_t>>
      Type;
};

/// \brief Auxiliary data that stores the size of symbolic expressions.
struct SymbolicExpressionSizes {
  static constexpr const char* Name = "symbolicExpressionSizes";
  typedef std::map<gtirb::Offset, uint64_t> Type;
};

} // namespace schema
} // namespace gtirb

#endif // GTIRB_PPRINTER_AUXDATASCHEMA_HPP

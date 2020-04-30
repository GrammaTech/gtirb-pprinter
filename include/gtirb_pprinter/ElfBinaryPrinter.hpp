//===- ElfBinaryPrinter.hpp ----------------------------------------*- C++ ---//
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
#ifndef GTIRB_PP_ELF_BINARY_PRINTER_H
#define GTIRB_PP_ELF_BINARY_PRINTER_H

#include "BinaryPrinter.hpp"

#include <gtirb/gtirb.hpp>

#include <string>
#include <vector>

/// \brief ElfBinary-print GTIRB representations.
namespace gtirb_bprint {
class DEBLOAT_PRETTYPRINTER_EXPORT_API ElfBinaryPrinter : public BinaryPrinter {
private:
  std::string compiler = "gcc";
  bool debug = false;
  std::optional<std::string>
  getInfixLibraryName(const std::string& library) const;
  std::optional<std::string>
  findLibrary(const std::string& library,
              const std::vector<std::string>& paths) const;
  std::vector<std::string> buildCompilerArgs(
      std::string outputFilename, const std::vector<std::string>& asmPath,
      const std::vector<std::string>& extraCompilerArgs,
      const std::vector<std::string>& userlibraryPaths, gtirb::IR& ir) const;

public:
  /// Construct a ElfBinaryPrinter with the default configuration.
  ElfBinaryPrinter() {}
  ElfBinaryPrinter(bool debugFlag) : debug(debugFlag) {}

  ElfBinaryPrinter(const ElfBinaryPrinter&) = default;
  ElfBinaryPrinter(ElfBinaryPrinter&&) = default;
  ElfBinaryPrinter& operator=(const ElfBinaryPrinter&) = default;
  ElfBinaryPrinter& operator=(ElfBinaryPrinter&&) = default;

  int link(std::string outputFilename,
           const std::vector<std::string>& extraCompilerArgs,
           const std::vector<std::string>& userLibraryPaths,
           const gtirb_pprint::PrettyPrinter& pp, gtirb::Context& context,
           gtirb::IR& ir) const;
};

} // namespace gtirb_bprint

#endif /* GTIRB_PP_ELF_BINARY_PRINTER_H */

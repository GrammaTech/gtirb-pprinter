//===- PeBinaryPrinter.hpp -----------------------------------------*- C++ ---//
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
#ifndef GTIRB_PP_PE_BINARY_PRINTER_H
#define GTIRB_PP_PE_BINARY_PRINTER_H

#include "BinaryPrinter.hpp"

#include <gtirb/gtirb.hpp>

#include <string>
#include <vector>

/// \brief PeBinary-print GTIRB representations.
namespace gtirb_bprint {
class TempFile;

class DEBLOAT_PRETTYPRINTER_EXPORT_API PeBinaryPrinter : public BinaryPrinter {
  std::string compiler;

  void
  prepareAssemblerArguments(const std::vector<TempFile>& compilands,
                            gtirb::IR& ir, const std::string& outputFilename,
                            const std::vector<std::string>& extraCompilerArgs,
                            const std::vector<std::string>& libraryPaths,
                            std::vector<std::string>& args) const;

public:
  PeBinaryPrinter();
  int link(const std::string& outputFilename,
           const std::vector<std::string>& extraCompilerArgs,
           const std::vector<std::string>& userLibraryPaths,
           const gtirb_pprint::PrettyPrinter& pp, gtirb::Context& context,
           gtirb::IR& ir) const override;
};

} // namespace gtirb_bprint

#endif /* GTIRB_PP_PE_BINARY_PRINTER_H */

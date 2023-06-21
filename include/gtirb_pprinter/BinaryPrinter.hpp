//===- BinaryPrinter.h ------------------------------------------*- C++ -*-===//
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
#ifndef GTIRB_PP_BINARY_PRINTER_H
#define GTIRB_PP_BINARY_PRINTER_H

#include "PrettyPrinter.hpp"
#include <gtirb/gtirb.hpp>
#include <string>
#include <vector>

/// \brief Binary-print GTIRB representations.
namespace gtirb_bprint {
class TempFile;

class DEBLOAT_PRETTYPRINTER_EXPORT_API BinaryPrinter {
protected:
  std::vector<std::string> ExtraCompileArgs;
  std::vector<std::string> LibraryPaths;
  const gtirb_pprint::PrettyPrinter& Printer;

  bool prepareSource(gtirb::Context& ctx, gtirb::Module& mod,
                     TempFile& tempFile) const;

  bool prepareSources(gtirb::Context& ctx, gtirb::IR& ir,
                      std::vector<TempFile>& tempFiles) const;

public:
  BinaryPrinter(const gtirb_pprint::PrettyPrinter& prettyPrinter,
                const std::vector<std::string>& extraCompileArgs,
                const std::vector<std::string>& libraryPaths)
      : ExtraCompileArgs(extraCompileArgs), LibraryPaths(libraryPaths),
        Printer(prettyPrinter) {}

  virtual ~BinaryPrinter() = default;
  virtual int assemble(const std::string& outputFilename,
                       gtirb::Context& context, gtirb::Module& mod) const = 0;
  virtual int link(const std::string& outputFilename, gtirb::Context& context,
                   gtirb::Module& module) const = 0;
};
} // namespace gtirb_bprint

#endif /* GTIRB_PP_BINARY_PRINTER_H */

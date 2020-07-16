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
  bool prepareSources(gtirb::Context& ctx, gtirb::IR& ir,
                      const gtirb_pprint::PrettyPrinter& pp,
                      std::vector<TempFile>& tempFiles,
                      std::vector<std::string>& tempFileNames) const;

public:
  virtual ~BinaryPrinter() = default;
  virtual int link(const std::string& output_filename,
                   const std::vector<std::string>& extraCompilerArgs,
                   const std::vector<std::string>& library_paths,
                   const gtirb_pprint::PrettyPrinter& pp,
                   gtirb::Context& context, gtirb::IR& ir) const = 0;
};
} // namespace gtirb_bprint

#endif /* GTIRB_PP_BINARY_PRINTER_H */

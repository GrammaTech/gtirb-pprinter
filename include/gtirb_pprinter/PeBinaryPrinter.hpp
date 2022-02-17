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
#include "FileUtils.hpp"

#include <gtirb/gtirb.hpp>

#include <string>
#include <vector>

namespace gtirb_bprint {

class TempFile;

class DEBLOAT_PRETTYPRINTER_EXPORT_API PeBinaryPrinter : public BinaryPrinter {
public:
  PeBinaryPrinter(const gtirb_pprint::PrettyPrinter& Printer,
                  const std::vector<std::string>& ExtraCompileArgs,
                  const std::vector<std::string>& LibraryPaths);

  // Assemble a module but do not link the object.
  int assemble(const std::string& OutputFile, gtirb::Context& Context,
               gtirb::Module& Module) const override;

  // Assemble and link all modules.
  int link(const std::string& OutputFile, gtirb::Context& Context,
           gtirb::IR& IR) const override;

  // Generate LIB files for all imports.
  int libs(const gtirb::IR& IR) const;

  // Generate RES files for all resources.
  int resources(const gtirb::IR& IR, const gtirb::Context& Context) const;

protected:
  // Generate DEF files for imported libaries (temp files).
  bool prepareImportDefs(
      const gtirb::IR& IR,
      std::map<std::string, std::unique_ptr<TempFile>>& ImportDefs) const;

  // Generated a DEF file with all exports.
  bool prepareExportDef(gtirb::IR& IR, TempFile& Def) const;

  // Generate RES files for all embedded PE resources.
  bool prepareResources(const gtirb::IR& IR, const gtirb::Context& Context,
                        std::vector<std::string>& Resources) const;
};

} // namespace gtirb_bprint

#endif /* GTIRB_PP_PE_BINARY_PRINTER_H */

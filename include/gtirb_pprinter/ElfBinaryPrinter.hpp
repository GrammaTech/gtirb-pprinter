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
class TempFile;

class DEBLOAT_PRETTYPRINTER_EXPORT_API ElfBinaryPrinter : public BinaryPrinter {
private:
  std::string compiler = "gcc";
  bool debug = false;
  bool useDummySO = false;
  std::optional<std::string>
  getInfixLibraryName(const std::string& library) const;
  std::optional<std::string>
  findLibrary(const std::string& library,
              const std::vector<std::string>& paths) const;
  bool
  generateDummySO(const std::string& lib,
                  std::vector<const gtirb::Symbol*>::const_iterator begin,
                  std::vector<const gtirb::Symbol*>::const_iterator end) const;
  std::optional<std::vector<std::string>>
  prepareDummySOLibs(const gtirb::IR& ir) const;
  void addOrigLibraryArgs(const gtirb::IR& ir,
                          std::vector<std::string>& args) const;
  std::vector<std::string>
  buildCompilerArgs(std::string outputFilename,
                    const std::vector<TempFile>& asmPath, gtirb::IR& ir,
                    const std::vector<std::string>& dummySoArgs) const;

public:
  /// Construct a ElfBinaryPrinter with the default configuration.
  explicit ElfBinaryPrinter(const gtirb_pprint::PrettyPrinter& prettyPrinter,
                            const std::vector<std::string>& extraCompileArgs,
                            const std::vector<std::string>& libraryPaths,
                            bool debugFlag, bool dummySOFlag)
      : BinaryPrinter(prettyPrinter, extraCompileArgs, libraryPaths),
        debug(debugFlag), useDummySO(dummySOFlag) {}
  virtual ~ElfBinaryPrinter() = default;

  int assemble(const std::string& outputFilename, gtirb::Context& context,
               gtirb::Module& mod) const override;
  int link(const std::string& outputFilename, gtirb::Context& context,
           gtirb::IR& ir) const override;
};

} // namespace gtirb_bprint

#endif /* GTIRB_PP_ELF_BINARY_PRINTER_H */

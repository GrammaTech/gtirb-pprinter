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
#include "FileUtils.hpp"

#include <gtirb/gtirb.hpp>

#include <string>
#include <vector>

/// \brief ElfBinary-print GTIRB representations.
namespace gtirb_bprint {
class TempFile;

using SymbolGroup = std::vector<const gtirb::Symbol*>;

class DEBLOAT_PRETTYPRINTER_EXPORT_API ElfBinaryPrinter : public BinaryPrinter {
private:
  const std::string defaultCompiler = "gcc";
  std::string compiler;
  bool debug = false;
  bool useDummySO = false;
  bool isInfixLibraryName(const std::string& library) const;
  std::optional<std::string>
  findLibrary(const std::string& library,
              const std::vector<std::string>& paths) const;

  /**
  Generate a dummy stand-in library defining the symbols specified in syms.

  Symbols in a group together will be generated refer to the same location in
  the library.

  Creates a library with the filename lib in the directory libDir. Appends
  compiler arguments to libArgs required for linking with the generated
  library.

  Returns true on success, or false if:
  - libDir does not exist
  - elfSymbolInfo auxdata cannot be found for a symbol in syms
  - Symbols in the same SymbolGroup have inconsistent sizes
  - The compiler returned an error when building the dummy .so
  */
  bool generateDummySO(const gtirb::IR& ir, const std::string& libDir,
                       const std::string& lib,
                       const std::vector<SymbolGroup>& syms) const;

  /**
  Generate dummy stand-in libraries for .so files, so that original libraries
  are not needed to re-link the binary.

  Libraries are generated in the libDir directory. Appends compiler arguments
  to libArgs required for linking with the generated libraries.

  Returns true on success, or false if:
  - generateDummySO fails (see its docstring for failure reasons)
  - There are no dynamic libraries needed
  - Symbols in the same group have conflicting elfSymbolVersionInfo
  - There are not enough external symbols to generate all of the dynamically
    linked libraries
  */
  bool prepareDummySOLibs(const gtirb::Context& Context, const gtirb::IR& ir,
                          const std::string& libDir,
                          std::vector<std::string>& libArgs) const;
  void addOrigLibraryArgs(const gtirb::IR& ir,
                          std::vector<std::string>& args) const;
  std::vector<std::string>
  buildCompilerArgs(std::string outputFilename,
                    const std::vector<TempFile>& asmPath,
                    gtirb::Context& context, gtirb::IR& ir,
                    const std::vector<std::string>& libArgs) const;

public:
  /// Construct a ElfBinaryPrinter with the default configuration.
  explicit ElfBinaryPrinter(const gtirb_pprint::PrettyPrinter& prettyPrinter,
                            const std::string& gccExecutable,
                            const std::vector<std::string>& extraCompileArgs,
                            const std::vector<std::string>& libraryPaths,
                            bool debugFlag, bool dummySOFlag)
      : BinaryPrinter(prettyPrinter, extraCompileArgs, libraryPaths),
        compiler(gccExecutable.empty() ? defaultCompiler : gccExecutable),
        debug(debugFlag), useDummySO(dummySOFlag) {}
  virtual ~ElfBinaryPrinter() = default;

  int assemble(const std::string& outputFilename, gtirb::Context& context,
               gtirb::Module& mod) const override;
  int link(const std::string& outputFilename, gtirb::Context& context,
           gtirb::IR& ir) const override;
};

} // namespace gtirb_bprint

#endif /* GTIRB_PP_ELF_BINARY_PRINTER_H */

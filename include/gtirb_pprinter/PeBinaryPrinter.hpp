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
#include "file_utils.hpp"

#include <gtirb/gtirb.hpp>

#include <iostream>
#include <string>
#include <vector>

/// \brief PeBinary-print GTIRB representations.
namespace gtirb_bprint {
class TempFile;

class PeAssembler {
public:
  PeAssembler(const std::string& Name_,
              const std::vector<std::string>& ExtraArgs_)
      : Name(Name_), ExtraArgs(ExtraArgs_){};

  virtual ~PeAssembler() = default;

  virtual int assemble(const std::string& I, const std::string& O) = 0;

protected:
  int run(const std::vector<std::string>& Args) {
    // Invoke the assembler.
    if (std::optional<int> Rc = execute(Name, Args)) {
      if (*Rc) {
        std::cerr << "ERROR: assembler returned: " << *Rc << "\n";
      }
      return *Rc;
    }
    std::cerr << "ERROR: could not find the assembler '" << Name
              << "' on the PATH.\n";
    return -1;
  }

  const std::string Name;
  const std::vector<std::string> ExtraArgs;
};

class MsvcAssembler : public PeAssembler {
public:
  MsvcAssembler(const std::string Name_,
                const std::vector<std::string>& ExtraArgs_)
      : PeAssembler(Name_, ExtraArgs_) {}

  int assemble(const std::string& I, const std::string& O) override;
};

class Ml64Assembler : public MsvcAssembler {
public:
  Ml64Assembler(const std::vector<std::string>& ExtraArgs_)
      : MsvcAssembler("ml64.exe", ExtraArgs_) {}
};

class MlAssembler : public MsvcAssembler {
public:
  MlAssembler(const std::vector<std::string>& ExtraArgs_)
      : MsvcAssembler("ml.exe", ExtraArgs_) {}
};

// class PeLinker {
// public:
//   int link(const std::string File) = 0;
// };

class PeLibrary {
public:
  PeLibrary(const std::string& Name_,
            const std::vector<std::string>& LibraryPaths_)
      : Name(Name_), LibraryPaths(LibraryPaths_){};

  virtual ~PeLibrary() = default;

  virtual int lib(const std::string& I, const std::string& O) = 0;

protected:
  int run(const std::vector<std::string>& Args) {
    // Invoke the assembler.
    if (std::optional<int> Rc = execute(Name, Args)) {
      if (*Rc)
        std::cerr << "ERROR: LIB utility returned: " << *Rc << "\n";
      return *Rc;
    }
    std::cerr << "ERROR: could not find the LIB utility '" << Name
              << "' on the PATH.\n";
    return -1;
  }

  const std::string Name;
  const std::vector<std::string> LibraryPaths;
};

class MsvcLib : public PeLibrary {
public:
  MsvcLib(const std::vector<std::string>& LibraryPaths_)
      : PeLibrary("lib.exe", LibraryPaths_) {}

  int lib(const std::string& I, const std::string& O) override;
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API PeBinaryPrinter : public BinaryPrinter {
  std::string compiler;

public:
  PeBinaryPrinter(const gtirb_pprint::PrettyPrinter& prettyPrinter,
                  const std::vector<std::string>& extraCompileArgs,
                  const std::vector<std::string>& libraryPaths);

  int assemble(const std::string& outputFilename, gtirb::Context& context,
               gtirb::Module& mod) const override;
  int link(const std::string& outputFilename, gtirb::Context& context,
           gtirb::IR& ir) override;

protected:
  std::unique_ptr<PeAssembler> Assembler;
  // std::unique_ptr<PeLinker> Linker;
  std::unique_ptr<PeLibrary> Library;

  virtual bool prepareImportDefs(
      const gtirb::IR& IR,
      std::map<std::string, std::unique_ptr<TempFile>>& ImportDefs) const;
  virtual bool prepareImportLibs(const gtirb::IR& IR,
                                 std::vector<std::string>& ImportLibs) const;

  virtual bool prepareDefFile(gtirb::IR& ir, TempFile& defFile) const;
  virtual bool prepareResources(gtirb::IR& ir, gtirb::Context& ctx,
                                std::vector<std::string>& resourceFiles) const;
  virtual void prepareLinkerArguments(gtirb::IR& ir,
                                      std::vector<std::string>& resourceFiles,
                                      std::string defFile,
                                      std::vector<std::string>& args) const;
};

} // namespace gtirb_bprint

#endif /* GTIRB_PP_PE_BINARY_PRINTER_H */

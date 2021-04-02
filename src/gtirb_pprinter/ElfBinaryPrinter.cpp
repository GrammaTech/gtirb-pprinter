//===- ElfBinaryPrinter.cpp -------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2018 GrammaTech, Inc.
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
#include "ElfBinaryPrinter.hpp"

#include "AuxDataSchema.hpp"
#include "file_utils.hpp"
#include <iostream>
#include <regex>
#include <string>
#include <vector>

namespace gtirb_bprint {

std::optional<std::string>
ElfBinaryPrinter::getInfixLibraryName(const std::string& library) const {
  std::regex libsoRegex("^lib(.*)\\.so.*");
  std::smatch m;
  if (std::regex_match(library, m, libsoRegex)) {
    return m.str(1);
  }
  return std::nullopt;
}

std::optional<std::string>
ElfBinaryPrinter::findLibrary(const std::string& library,
                              const std::vector<std::string>& paths) const {
  for (const auto& path : paths) {
    if (std::optional<std::string> fp = resolveRegularFilePath(path, library))
      return fp;
  }
  return std::nullopt;
}

std::vector<std::string>
ElfBinaryPrinter::buildCompilerArgs(std::string outputFilename,
                                    const std::vector<TempFile>& asmPaths,
                                    gtirb::IR& ir) const {
  std::vector<std::string> args;
  // Start constructing the compile arguments, of the form
  // -o <output_filename> fileAXADA.s
  args.emplace_back("-o");
  args.emplace_back(outputFilename);
  std::transform(asmPaths.begin(), asmPaths.end(), std::back_inserter(args),
                 [](const TempFile& TF) { return TF.fileName(); });
  args.insert(args.end(), ExtraCompileArgs.begin(), ExtraCompileArgs.end());

  // collect all the library paths
  std::vector<std::string> allBinaryPaths = LibraryPaths;

  for (gtirb::Module& module : ir.modules()) {

    if (const auto* binaryLibraryPaths =
            module.getAuxData<gtirb::schema::LibraryPaths>())
      allBinaryPaths.insert(allBinaryPaths.end(), binaryLibraryPaths->begin(),
                            binaryLibraryPaths->end());
  }
  // add needed libraries
  for (gtirb::Module& module : ir.modules()) {
    if (const auto* libraries = module.getAuxData<gtirb::schema::Libraries>()) {
      for (const auto& library : *libraries) {
        // if they match the lib*.so pattern we let the compiler look for them
        std::optional<std::string> infixLibraryName =
            getInfixLibraryName(library);
        if (infixLibraryName) {
          args.push_back("-l" + *infixLibraryName);
        } else {
          // otherwise we try to find them here
          if (std::optional<std::string> libraryLocation =
                  findLibrary(library, allBinaryPaths)) {
            args.push_back(*libraryLocation);
          } else {
            std::cerr << "ERROR: Could not find library " << library
                      << std::endl;
          }
        }
      }
    }
  }
  // add user library paths
  for (const auto& libraryPath : LibraryPaths) {
    args.push_back("-L" + libraryPath);
  }
  // add binary library paths (add them to rpath as well)
  for (gtirb::Module& module : ir.modules()) {
    if (const auto* binaryLibraryPaths =
            module.getAuxData<gtirb::schema::LibraryPaths>()) {
      for (const auto& libraryPath : *binaryLibraryPaths) {
        args.push_back("-L" + libraryPath);
        args.push_back("-Wl,-rpath," + libraryPath);
      }
    }
  }
  // add pie or no pie depending on the binary type
  for (gtirb::Module& M : ir.modules()) {
    if (const auto* BinType = M.getAuxData<gtirb::schema::BinaryType>()) {
      // if DYN, pie. if EXEC, no-pie. if both, pie overrides no-pie. If none,
      // do not specify either argument.

      bool pie = false;
      bool noPie = false;

      for (const auto& BinTypeStr : *BinType) {
        if (BinTypeStr == "DYN") {
          pie = true;
          noPie = false;
        } else if (BinTypeStr == "EXEC") {
          if (!pie) {
            noPie = true;
            pie = false;
          }
        } else {
          assert(!"Unknown binary type!");
        }
      }

      if (pie) {
        args.push_back("-shared");
      }
      if (noPie) {
        args.push_back("-no-pie");
      }

      break;
    }
  }
  // add -m32 for x86 binaries
  for (gtirb::Module& module : ir.modules()) {
    if (module.getISA() == gtirb::ISA::IA32) {
      args.push_back("-m32");
    }
  }
  // add arguments given by the printing policy
  for (gtirb::Module& Module : ir.modules()) {
    const auto& Policy = Printer.getPolicy(Module);
    args.insert(args.end(), Policy.compilerArguments.begin(),
                Policy.compilerArguments.end());
  }

  if (debug) {
    std::cout << "Compiler arguments: ";
    for (auto i : args)
      std::cout << i << ' ';
    std::cout << std::endl;
  }
  return args;
}

int ElfBinaryPrinter::assemble(const std::string& outputFilename,
                               gtirb::Context& ctx, gtirb::Module& mod) const {
  TempFile tempFile;
  if (!prepareSource(ctx, mod, tempFile)) {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  std::vector<std::string> args{{"-o", outputFilename, "-c"}};
  args.insert(args.end(), ExtraCompileArgs.begin(), ExtraCompileArgs.end());
  args.push_back(tempFile.fileName());

  if (std::optional<int> ret = execute(compiler, args)) {
    if (*ret)
      std::cerr << "ERROR: assembler returned: " << *ret << "\n";
    return *ret;
  }

  std::cerr << "ERROR: could not find the assembler '" << compiler
            << "' on the PATH.\n";
  return -1;
}

int ElfBinaryPrinter::link(const std::string& outputFilename,
                           gtirb::Context& ctx, gtirb::IR& ir) {
  if (debug)
    std::cout << "Generating binary file" << std::endl;
  std::vector<TempFile> tempFiles;
  if (!prepareSources(ctx, ir, tempFiles)) {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  if (std::optional<int> ret =
          execute(compiler, buildCompilerArgs(outputFilename, tempFiles, ir))) {
    if (*ret)
      std::cerr << "ERROR: assembler returned: " << *ret << "\n";
    return *ret;
  }

  std::cerr << "ERROR: could not find the assembler '" << compiler
            << "' on the PATH.\n";
  return -1;
}

} // namespace gtirb_bprint

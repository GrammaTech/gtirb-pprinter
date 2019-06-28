//===- ElfBinaryPrinter.cpp ----------------------------------------*- C++
//-*-===//
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
#include "ElfBinaryPrinter.h"

#include <boost/process/search_path.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include <boost/process/system.hpp>
#pragma GCC diagnostic pop
#include <experimental/filesystem>
#include <regex>
#include <string>
#include <vector>

namespace bp = boost::process;
namespace fs = std::experimental::filesystem;

namespace gtirb_bprint {

std::optional<std::string>
ElfBinaryPrinter::getInfixLibraryName(const std::string& library) const {
  std::regex libsoRegex("^lib(.*)\\.so.*");
  std::smatch m;
  if (std::regex_match(library, m, libsoRegex)) {
    size_t suffixPosition = library.rfind(".so");
    return library.substr(3, suffixPosition - 3);
  }
  return std::nullopt;
}

std::optional<std::string>
ElfBinaryPrinter::findLibrary(const std::string& library,
                              const std::vector<std::string>& paths) const {
  for (const auto& path : paths) {
    fs::path filePath(path);
    filePath.append(library);
    if (fs::is_regular_file(filePath) || fs::is_symlink(filePath))
      return filePath.string();
  }
  return std::nullopt;
}

std::vector<std::string> ElfBinaryPrinter::buildCompilerArgs(
    std::string outputFilename, std::string asmPath,
    const std::vector<std::string>& userLibraryPaths, gtirb::IR& ir) const {
  std::vector<std::string> args;
  // Start constructing the compile arguments, of the form
  // -o <output_filename> fileAXADA.s
  args.insert(args.end(), {"-o", outputFilename, std::string(asmPath)});

  const auto* libraries =
      ir.modules().begin()->getAuxData<std::vector<std::string>>("libraries");
  const auto* binaryLibraryPaths =
      ir.modules().begin()->getAuxData<std::vector<std::string>>(
          "libraryPaths");

  // collect all the library paths
  std::vector<std::string> allBinaryPaths = userLibraryPaths;
  if (binaryLibraryPaths)
    allBinaryPaths.insert(allBinaryPaths.end(), binaryLibraryPaths->begin(),
                          binaryLibraryPaths->end());
  // add needed libraries
  if (libraries) {
    for (const auto& library : *libraries) {
      // if they match the lib*.so pattern we let the compiler look for them
      auto infixLibraryName = getInfixLibraryName(library);
      if (infixLibraryName) {
        args.push_back("-l" + *infixLibraryName);
      } else {
        // otherwise we try to find them here
        auto libraryLocation = findLibrary(library, allBinaryPaths);
        if (libraryLocation) {
          args.push_back(*libraryLocation);
        } else {
          std::cerr << "ERROR: Could not find library " << library << std::endl;
        }
      }
    }
  }
  // add user library paths
  for (const auto& libraryPath : userLibraryPaths) {
    args.push_back("-L" + libraryPath);
  }
  // add binary library paths (add them to rpath as well)
  if (binaryLibraryPaths) {
    for (const auto& libraryPath : *binaryLibraryPaths) {
      args.push_back("-L" + libraryPath);
      args.push_back("-Wl,-rpath," + libraryPath);
    }
  }
  std::cout << "Compiler arguments: ";
  for (auto i : args)
    std::cout << i << ' ';
  std::cout << std::endl;
  return args;
}

int ElfBinaryPrinter::link(std::string outputFilename,
                           const std::vector<std::string>& userLibraryPaths,
                           const gtirb_pprint::PrettyPrinter& pp,
                           gtirb::Context& ctx, gtirb::IR& ir) const {
  std::cout << "Generating binary file" << std::endl;
  // Write the assembly to a temp file
  char asmPath[] = "/tmp/fileXXXXXX.s";
  close(mkstemps(asmPath, 2)); // Create and open temp file
  std::ofstream ofs(asmPath);
  if (ofs) {
    std::cout << "Printing assembly to temporary file " << asmPath << std::endl;
    pp.print(ofs, ctx, ir);
    ofs.close();
  } else {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  auto compilerPath = bp::search_path(this->compiler);
  if (compilerPath.empty()) {
    std::cerr << "ERROR: Could not find compiler" << this->compiler;
    return -1;
  }
  std::cout << "Calling compiler" << std::endl;
  return bp::system(compilerPath, buildCompilerArgs(outputFilename, asmPath,
                                                    userLibraryPaths, ir));
}

} // namespace gtirb_bprint

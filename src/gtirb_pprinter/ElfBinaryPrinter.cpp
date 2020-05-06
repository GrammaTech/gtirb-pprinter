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
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wc++11-compat"
#pragma GCC diagnostic ignored "-Wpessimizing-move"
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4456) // variable shadowing warning
#endif                          // __GNUC__
#include <boost/filesystem.hpp>
#include <boost/process/search_path.hpp>
#include <boost/process/system.hpp>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif // __GNUC__
#include <iostream>
#include <regex>
#include <string>
#include <vector>

namespace fs = boost::filesystem;
namespace bp = boost::process;

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
    fs::path filePath(path);
    filePath.append(library);
    // check that if filePath is a symbolic link, it eventually leads to a
    // regular file.
    fs::path resolvedFilePath(filePath);
    while (fs::is_symlink(resolvedFilePath)) {
      resolvedFilePath = fs::read_symlink(resolvedFilePath);
    }
    if (fs::is_regular_file(resolvedFilePath)) {
      return filePath.string();
    }
  }
  return std::nullopt;
}

std::vector<std::string> ElfBinaryPrinter::buildCompilerArgs(
    std::string outputFilename, const std::vector<std::string>& asmPaths,
    const std::vector<std::string>& extraCompilerArgs,
    const std::vector<std::string>& userLibraryPaths, gtirb::IR& ir) const {
  std::vector<std::string> args;
  // Start constructing the compile arguments, of the form
  // -o <output_filename> fileAXADA.s
  args.emplace_back("-o");
  args.emplace_back(outputFilename);
  args.insert(args.end(), asmPaths.begin(), asmPaths.end());
  args.insert(args.end(), extraCompilerArgs.begin(), extraCompilerArgs.end());

  // collect all the library paths
  std::vector<std::string> allBinaryPaths = userLibraryPaths;

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
  for (const auto& libraryPath : userLibraryPaths) {
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

  if (debug) {
    std::cout << "Compiler arguments: ";
    for (auto i : args)
      std::cout << i << ' ';
    std::cout << std::endl;
  }
  return args;
}

/// Auxiliary class to make sure we delete the temporary assembly file at the
/// end
class TempFile {
public:
  std::string name;
  std::ofstream fileStream;
  TempFile() {
#ifdef _WIN32
    std::string tmpFileName;
    std::FILE* f = nullptr;
    while (!f) {
      tmpFileName = std::tmpnam(nullptr);
      tmpFileName += ".s";
      f = fopen(tmpFileName.c_str(), "wx");
    }
    fclose(f);
#else
    char tmpFileName[] = "/tmp/fileXXXXXX.s";
    close(mkstemps(tmpFileName, 2)); // Create tmp file
#endif // _WIN32
    name = tmpFileName;
    fileStream.open(name);
  };
  ~TempFile() {
    if (fs::exists(name))
      fs::remove(name);
  };
};

int ElfBinaryPrinter::link(std::string outputFilename,
                           const std::vector<std::string>& extraCompilerArgs,
                           const std::vector<std::string>& userLibraryPaths,
                           const gtirb_pprint::PrettyPrinter& pp,
                           gtirb::Context& ctx, gtirb::IR& ir) const {
  if (debug)
    std::cout << "Generating binary file" << std::endl;
  std::vector<TempFile> tempFiles(
      std::distance(ir.modules().begin(), ir.modules().end()));
  std::vector<std::string> tempFileNames;
  int i = 0;
  for (gtirb::Module& module : ir.modules()) {
    if (tempFiles[i].fileStream) {
      if (debug)
        std::cout << "Printing module" << module.getName()
                  << " to temporary file " << tempFiles[i].name << std::endl;
      pp.print(tempFiles[i].fileStream, ctx, module);
      tempFiles[i].fileStream.close();
      tempFileNames.push_back(tempFiles[i].name);
    } else {
      std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
      return -1;
    }
    ++i;
  }

  boost::filesystem::path compilerPath = bp::search_path(this->compiler);
  if (compilerPath.empty()) {
    std::cerr << "ERROR: Could not find compiler" << this->compiler;
    return -1;
  }
  if (debug)
    std::cout << "Calling compiler" << std::endl;
  return bp::system(compilerPath,
                    buildCompilerArgs(outputFilename, tempFileNames,
                                      extraCompilerArgs, userLibraryPaths, ir));
}

} // namespace gtirb_bprint

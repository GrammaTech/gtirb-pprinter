//===- file_utils.cpp -------------------------------------------*- C++ -*-===//
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
#include "file_utils.hpp"
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

namespace fs = boost::filesystem;
namespace bp = boost::process;

namespace gtirb_bprint {
TempFile::TempFile() {
  // FIXME: this has TOCTOU issues.
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
  ::close(mkstemps(tmpFileName, 2)); // Create tmp file
#endif // _WIN32
  name = tmpFileName;
  fileStream.open(name);
}

TempFile::~TempFile() { fs::remove(name); }

std::optional<std::string> resolve_regular_file_path(const std::string& path) {
  // Check that if path is a symbolic link, it eventually leads to a regular
  // file.
  fs::path resolvedFilePath(path);
  while (fs::is_symlink(resolvedFilePath)) {
    resolvedFilePath = fs::read_symlink(resolvedFilePath);
  }
  if (fs::is_regular_file(resolvedFilePath)) {
    return resolvedFilePath.string();
  }
  return std::nullopt;
}

std::optional<std::string>
resolve_regular_file_path(const std::string& path,
                          const std::string& fileName) {
  fs::path filePath(path);
  filePath.append(fileName);
  return resolve_regular_file_path(filePath.string());
}

std::optional<int> execute(const std::string& tool,
                           const std::vector<std::string>& args) {
  fs::path compilerPath = bp::search_path(tool);
  if (compilerPath.empty())
    return std::nullopt;
  return bp::system(compilerPath, args);
}
} // namespace gtirb_bprint

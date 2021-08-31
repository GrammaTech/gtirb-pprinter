//===- file_utils.hpp ----------------------------------------------*- C++ ---//
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
#ifndef GTIRB_FILE_UTILS_H
#define GTIRB_FILE_UTILS_H

#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace gtirb_bprint {
/// Auxiliary class to make sure we delete the temporary assembly file at the
/// end
class TempFile {
  std::string Name;
  std::ofstream FileStream;

public:
  TempFile(const std::string extension = std::string(".s"));
  ~TempFile();

  bool isOpen() const { return static_cast<bool>(FileStream); }
  void close() { FileStream.close(); }

  operator const std::ofstream&() const { return FileStream; }
  operator std::ofstream&() { return FileStream; }
  const std::string& fileName() const { return Name; }
};

/// Auxiliary class to manage creation and deletion of a temporary directory.
class TempDir {
  std::string Name;
  int Errno;

public:
  TempDir();
  ~TempDir();

  bool created() const { return Name.size() > 0; }
  int errno_code() const { return Errno; }

  const std::string& dirName() const { return Name; }
};

std::string replaceExtension(const std::string path, const std::string new_ext);

// Helper functions to resolve symlinks and get a real path to a file.
std::optional<std::string> resolveRegularFilePath(const std::string& path);
std::optional<std::string> resolveRegularFilePath(const std::string& path,
                                                  const std::string& fileName);

// Helper function to execute a process with arguments; will search for the
// given tool on PATH automatically. If the tool cannot be found, the function
// returns nullopt. Otherwise, the function returns the return code from
// executing the tool.
std::optional<int> execute(const std::string& tool,
                           const std::vector<std::string>& args);

} // namespace gtirb_bprint
#endif /* GTIRB_FILE_UTILS_H */

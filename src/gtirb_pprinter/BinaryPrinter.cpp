//===- BinaryPrinter.cpp ----------------------------------------*- C++ -*-===//
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
#include "BinaryPrinter.hpp"
#include "file_utils.hpp"

namespace gtirb_bprint {
bool BinaryPrinter::prepareSources(
    gtirb::Context& ctx, gtirb::IR& ir, const gtirb_pprint::PrettyPrinter& pp,
    std::vector<TempFile>& tempFiles,
    std::vector<std::string>& tempFileNames) const {
  tempFiles = std::vector<TempFile>(
      std::distance(ir.modules().begin(), ir.modules().end()));
  int i = 0;
  for (gtirb::Module& module : ir.modules()) {
    if (tempFiles[i].isOpen()) {
      pp.print(tempFiles[i], ctx, module);
      tempFiles[i].close();
      tempFileNames.push_back(tempFiles[i].fileName());
    } else {
      return false;
    }
    ++i;
  }
  return true;
}
} // namespace gtirb_bprint

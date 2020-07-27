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
bool BinaryPrinter::prepareSource(gtirb::Context& ctx, gtirb::Module& mod,
                                  TempFile& tempFile) const {
  if (tempFile.isOpen()) {
    Printer.print(tempFile, ctx, mod);
    tempFile.close();
    return true;
  }
  return false;
}

bool BinaryPrinter::prepareSources(gtirb::Context& ctx, gtirb::IR& ir,
                                   std::vector<TempFile>& tempFiles) const {
  tempFiles = std::vector<TempFile>(
      std::distance(ir.modules().begin(), ir.modules().end()));
  int i = 0;
  for (gtirb::Module& module : ir.modules()) {
    if (!prepareSource(ctx, module, tempFiles[i]))
      return false;
    ++i;
  }
  return true;
}
} // namespace gtirb_bprint

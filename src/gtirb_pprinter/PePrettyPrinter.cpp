//===- PePrinter.cpp --------------------------------------------*- C++ -*-===//
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
#include "PePrettyPrinter.hpp"

#include <iostream>

namespace gtirb_pprint {
PePrettyPrinter::PePrettyPrinter(gtirb::Context& context_,
                                 gtirb::Module& module_, const Syntax& syntax_,
                                 const PrintingPolicy& policy_)
    : PrettyPrinterBase(context_, module_, syntax_, policy_) {

  const auto* directories =
      module
          .getAuxData<std::vector<std::tuple<std::string, uint64_t, uint64_t>>>(
              "dataDirectories");
  for (auto const& entry : *directories) {
    dataDirectories.push_back(entry);
  }
}

const PrintingPolicy& PePrettyPrinter::defaultPrintingPolicy() {
  static PrintingPolicy DefaultPolicy{
      /// Sections to avoid printing.
      {".pdata", ".reloc"},

      /// Functions to avoid printing.
      {},

      /// Sections with possible data object exclusion.
      {},
  };
  return DefaultPolicy;
}

bool PePrettyPrinter::isInSkippedDataDirectory(const gtirb::Addr x) const {
  const uint64_t y = static_cast<uint64_t>(x);
  for (const auto& [name, address, size] : dataDirectories) {
    if (y >= address && y < (address + size)) {
      return keepDataDirectories.count(name) == 0;
    }
  }
  return false;
}

bool PePrettyPrinter::skipEA(const gtirb::Addr x) const {
  return isInSkippedDataDirectory(x) || PrettyPrinterBase::skipEA(x);
}

} // namespace gtirb_pprint

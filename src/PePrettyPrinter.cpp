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

namespace gtirb_pprint {
PePrettyPrinter::PePrettyPrinter(gtirb::Context& context_, gtirb::IR& ir_,
                                 const Syntax& syntax_,
                                 const PrintingPolicy& policy_)
    : PrettyPrinterBase(context_, ir_, syntax_, policy_) {}

const PrintingPolicy& PePrettyPrinter::defaultPrintingPolicy() {
  static PrintingPolicy DefaultPolicy{
      /// Sections to avoid printing.
      {".pdata"},

      /// Functions to avoid printing.
      {},

      /// Sections with possible data object exclusion.
      {},
  };
  return DefaultPolicy;
}
} // namespace gtirb_pprint

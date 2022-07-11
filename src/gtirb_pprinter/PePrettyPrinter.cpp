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

#include "AuxDataSchema.hpp"
#include <iostream>

namespace gtirb_pprint {
PePrettyPrinter::PePrettyPrinter(gtirb::Context& context_,
                                 const gtirb::Module& module_, const Syntax& syntax_,
                                 const PrintingPolicy& policy_)
    : PrettyPrinterBase(context_, module_, syntax_, policy_) {}

const PrintingPolicy&
PePrettyPrinterFactory::defaultPrintingPolicy(gtirb::Module& /*Module*/) const {
  static PrintingPolicy DefaultPolicy{
      /// Functions to avoid printing.
      {},

      // Symbols to avoid printing.
      {},

      /// Sections to avoid printing.
      {".pdata", ".reloc", ".rsrc"},

      /// Sections with possible data object exclusion.
      {},
  };
  return DefaultPolicy;
}

} // namespace gtirb_pprint

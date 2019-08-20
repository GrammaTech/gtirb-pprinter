//===- ElfPrinter.cpp -------------------------------------------*- C++ -*-===//
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
#include "ElfPrinter.h"

namespace gtirb_pprint {
ElfPrettyPrinter::ElfPrettyPrinter(gtirb::Context& context_, gtirb::IR& ir_,
                                   const string_range& skip_funcs,
                                   DebugStyle dbg_)
    : PrettyPrinterBase(context_, ir_, skip_funcs, dbg_) {
  if (this->ir.modules()
          .begin()
          ->getAuxData<
              std::map<gtirb::Offset,
                       std::vector<std::tuple<std::string, std::vector<int64_t>,
                                              gtirb::UUID>>>>(
              "cfiDirectives")) {
    AsmSkipSection.insert(".eh_frame");
  }
}
} // namespace gtirb_pprint

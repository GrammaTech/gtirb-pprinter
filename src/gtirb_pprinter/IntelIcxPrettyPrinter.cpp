//===- IntelIcxPrettyPrinter.cpp -------------------------------*- C++ -*-===//
//
//  Copyright (C) 2021 GrammaTech, Inc.
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
//===---------------------------------------------------------------------===//

#include "IntelIcxPrettyPrinter.hpp"

namespace gtirb_pprint {

IntelIcxPrettyPrinter::IntelIcxPrettyPrinter(gtirb::Context& context_,
                                             gtirb::Module& module_,
                                             const IntelSyntax& syntax_,
                                             const IcxAssembler& assembler_,
                                             const PrintingPolicy& policy_)
    : IntelPrettyPrinter(context_, module_, syntax_, assembler_, policy_) {}

std::unique_ptr<PrettyPrinterBase>
IntelIcxPrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                     gtirb::Module& module,
                                     const PrintingPolicy& policy) {
  static const IntelSyntax syntax{};
  static const IcxAssembler assembler{};
  return std::make_unique<IntelPrettyPrinter>(gtirb_context, module, syntax,
                                              assembler, policy);
}
} // namespace gtirb_pprint

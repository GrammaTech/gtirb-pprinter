//===- Mips32PrettyPrinter.cpp ----------------------------------*- C++ -*-===//
//
//  Copyright (c) 2020 GrammaTech, Inc.
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

#include "Mips32PrettyPrinter.hpp"
#include "AuxDataSchema.hpp"

#include <capstone/capstone.h>

namespace gtirb_pprint {

const PrintingPolicy&
Mips32PrettyPrinterFactory::defaultPrintingPolicy() const {
  static PrintingPolicy DefaultPolicy{
      /// Functions to avoid printing.
      {},

      /// Symbols to avoid printing.
      {},

      /// Sections to avoid printing.
      {},

      /// Sections with possible data object exclusion.
      {},
  };
  return DefaultPolicy;
}

std::unique_ptr<PrettyPrinterBase>
Mips32PrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                   gtirb::Module& module,
                                   const PrintingPolicy& policy) {
  static const ElfSyntax syntax{};
  return std::make_unique<Mips32PrettyPrinter>(gtirb_context, module, syntax,
                                               policy);
}

Mips32PrettyPrinter::Mips32PrettyPrinter(gtirb::Context& context_,
                                         gtirb::Module& module_,
                                         const ElfSyntax& syntax_,
                                         const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_) {
  // Setup Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
}

void Mips32PrettyPrinter::printHeader(std::ostream& /*os*/) {}
void Mips32PrettyPrinter::printOpRegdirect(std::ostream& /*os*/,
                                           const cs_insn& /*inst*/,
                                           uint64_t /*index*/) {}
void Mips32PrettyPrinter::printOpImmediate(
    std::ostream& /*os*/, const gtirb::SymbolicExpression* /*symbolic*/,
    const cs_insn& /*inst*/, uint64_t /*index*/) {}
void Mips32PrettyPrinter::printOpIndirect(
    std::ostream& /*os*/, const gtirb::SymbolicExpression* /*symbolic*/,
    const cs_insn& /*inst*/, uint64_t /*index*/) {}

} // namespace gtirb_pprint

//===- AttPrettyPrinter.hpp --------------------------------------- C++ -*-===//
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
#ifndef GTIRB_PP_GAS_PRINTER_H
#define GTIRB_PP_GAS_PRINTER_H

#include "ElfPrettyPrinter.hpp"

namespace gtirb_pprint {

class DEBLOAT_PRETTYPRINTER_EXPORT_API AttPrettyPrinter
    : public ElfPrettyPrinter {
public:
  AttPrettyPrinter(gtirb::Context& context, const gtirb::Module& module,
                   const ElfSyntax& syntax, const PrintingPolicy& policy);

protected:
  std::string getRegisterName(unsigned int reg) const override;

  void fixupInstruction(cs_insn& inst) override;
  void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                        uint64_t index) override;
  void printOpImmediate(std::ostream& os,
                        const gtirb::SymbolicExpression* symbolic,
                        const cs_insn& inst, uint64_t index) override;
  void printOpIndirect(std::ostream& os,
                       const gtirb::SymbolicExpression* symbolic,
                       const cs_insn& inst, uint64_t index) override;
  void printSymbolicExpression(std::ostream& Stream,
                               const gtirb::SymAddrAddr* SymExpr,
                               bool IsNotBranch = false) override;
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API AttPrettyPrinterFactory
    : public ElfPrettyPrinterFactory {
public:
  std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, const gtirb::Module& module,
         const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_GAS_PRINTER_H */

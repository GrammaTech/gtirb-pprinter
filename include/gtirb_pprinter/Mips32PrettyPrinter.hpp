//===- Mips32PrettyPrinter.hpp ----------------------------------*- C++ -*-===//
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

#ifndef GTIRB_PP_MIPS32_ASM_PRINTER_H
#define GTIRB_PP_MIPS32_ASM_PRINTER_H

#include "ElfPrettyPrinter.hpp"

namespace gtirb_pprint {

class DEBLOAT_PRETTYPRINTER_EXPORT_API Mips32PrettyPrinter
    : public ElfPrettyPrinter {
public:
  Mips32PrettyPrinter(gtirb::Context& context, gtirb::Module& module,
                      const ElfSyntax& syntax, const PrintingPolicy& policy);

protected:
  void printHeader(std::ostream& os) override;
  void printAlignment(std::ostream& os, const gtirb::Addr addr) override;
  void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                        uint64_t index) override;
  void printOpImmediate(std::ostream& os,
                        const gtirb::SymbolicExpression* symbolic,
                        const cs_insn& inst, uint64_t index) override;
  void printOpIndirect(std::ostream& os,
                       const gtirb::SymbolicExpression* symbolic,
                       const cs_insn& inst, uint64_t index) override;

  std::string getRegisterName(unsigned int reg) const override;
  void printOperand(std::ostream& os, const gtirb::CodeBlock& block,
                    const cs_insn& inst, uint64_t index) override;
  void printInstruction(std::ostream& os, const gtirb::CodeBlock& block,
                        const cs_insn& inst,
                        const gtirb::Offset& offset) override;
  void printOperandList(std::ostream& os, const gtirb::CodeBlock& block,
                        const cs_insn& inst) override;
  void printSymExprPrefix(std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
                          bool IsNotBranch = false) override;
  void printSymExprSuffix(std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
                          bool IsNotBranch = false) override;
  void printIntegralSymbol(std::ostream& os, const gtirb::Symbol& sym) override;
  void printSymbolicExpression(std::ostream& os,
                               const gtirb::SymAddrConst* sexpr,
                               bool IsNotBranch = false) override;
  void printSymbolicExpression(std::ostream& os,
                               const gtirb::SymAddrAddr* sexpr,
                               bool IsNotBranch = false) override;

private:
  const gtirb::Symbol& GP;
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API Mips32PrettyPrinterFactory
    : public PrettyPrinterFactory {
public:
  const PrintingPolicy& defaultPrintingPolicy() const override;

  std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, gtirb::Module& module,
         const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_MIPS32_ASM_PRINTER_H */

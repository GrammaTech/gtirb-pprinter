//===- IntelPrinter.h -------------------------------------------*- C++ -*-===//
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
#ifndef GTIRB_PP_NASM_PRINTER_H
#define GTIRB_PP_NASM_PRINTER_H

#include "ElfPrinter.h"

namespace gtirb_pprint {

class IntelSyntax : public ElfSyntax {
public:
  IntelSyntax();
  const std::string& Offset() const;

private:
  const std::string offsetDirective{"OFFSET"};
};

class IntelPrettyPrinter : public ElfPrettyPrinter {
public:
  IntelPrettyPrinter(gtirb::Context& context, gtirb::IR& ir,
                     const IntelSyntax& syntax, const PrintingPolicy& policy);

protected:
  void printHeader(std::ostream& os) override;
  void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                        const cs_x86_op& op) override;
  void printOpImmediate(std::ostream& os,
                        const gtirb::SymbolicExpression* symbolic,
                        const cs_insn& inst, uint64_t index) override;
  void printOpIndirect(std::ostream& os,
                       const gtirb::SymbolicExpression* symbolic,
                       const cs_insn& inst, uint64_t index) override;

private:
  IntelSyntax intelSyntax;
  static volatile bool registered;
};

class IntelPrettyPrinterFactory : public PrettyPrinterFactory {
public:
  const PrintingPolicy& DefaultPrintingPolicy() override;
  std::unique_ptr<PrettyPrinterBase>
  Create(gtirb::Context& context, gtirb::IR& ir,
         const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_NASM_PRINTER_H */

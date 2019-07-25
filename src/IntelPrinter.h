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

#include "PrettyPrinter.h"

namespace gtirb_pprint {

class IntelPrettyPrinter : public PrettyPrinterBase {
public:
  IntelPrettyPrinter(gtirb::Context& context, gtirb::IR& ir,
                     const string_range& skip_funcs, DebugStyle dbg);

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

  static constexpr char StrOffset[]{"OFFSET"};

private:
  static volatile bool registered;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_NASM_PRINTER_H */

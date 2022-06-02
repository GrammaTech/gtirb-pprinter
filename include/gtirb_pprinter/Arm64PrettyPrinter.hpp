//===- Arm64PrettyPrinter.hpp -----------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020-2022 GrammaTech, Inc.
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

#ifndef GTIRB_PP_A64ASM_PRINTER_H
#define GTIRB_PP_A64ASM_PRINTER_H

#include "ElfPrettyPrinter.hpp"

namespace gtirb_pprint {

class Arm64Syntax : public ElfSyntax {
public:
  SyntaxAlignmentStyle alignmentStyle() const override {
    return SyntaxAlignmentZeros;
  };

  const std::string& wordData() const override { return WordDirective; }

private:
  // ".word" on aarch64 is 4 bytes, so we must use .short instead.
  const std::string WordDirective{".short"};
};

class Arm64PrettyPrinter : public ElfPrettyPrinter {
public:
  Arm64PrettyPrinter(gtirb::Context& context, gtirb::Module& module,
                     const ElfSyntax& syntax, const Assembler& assembler,
                     const PrintingPolicy& policy);

protected:
  std::string getRegisterName(unsigned int reg) const override;

  void printInstruction(std::ostream& os, const gtirb::CodeBlock& block,
                        const cs_insn& inst,
                        const gtirb::Offset& offset) override;

  void printHeader(std::ostream& os) override;
  void printOperandList(std::ostream& os, const gtirb::CodeBlock& block,
                        const cs_insn& inst) override;
  void printOperand(std::ostream& os, const gtirb::CodeBlock& block,
                    const cs_insn& inst, uint64_t index) override;
  void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                        uint64_t index) override;
  void printOpImmediate(std::ostream& os,
                        const gtirb::SymbolicExpression* symbolic,
                        const cs_insn& inst, uint64_t index) override;
  void printOpIndirect(std::ostream& os,
                       const gtirb::SymbolicExpression* symbolic,
                       const cs_insn& inst, uint64_t index) override;

  void printOpRawValue(std::ostream& os, const cs_insn& inst, uint64_t index);
  void printOpPrefetch(std::ostream& os, const arm64_prefetch_op prefetch);
  void printOpBarrier(std::ostream& os, const arm64_barrier_op barrier);

  void printSymExprPrefix(std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
                          bool IsNotBranch) override;
  void printSymExprSuffix(std::ostream& OS, const gtirb::SymAttributeSet& Attrs,
                          bool IsNotBranch) override;

  void printShift(std::ostream& os, const arm64_shifter type,
                  unsigned int value);
  void printExtender(std::ostream& os, const arm64_extender& ext,
                     const arm64_shifter shiftType, uint64_t shiftValue);
  void printSymbolHeader(std::ostream& os, const gtirb::Symbol& sym) override;

private:
  void buildSymGotRefTable(void);

  bool IsPrintingGroupedOperands = false;

  /*
  UUIDs of symbols in the Module where at least one of the references to that
  symbol are via the GOT.
  */
  std::set<gtirb::UUID> LocalGotSyms = {};
};

class Arm64PrettyPrinterFactory : public ElfPrettyPrinterFactory {
public:
  Arm64PrettyPrinterFactory() {}

  std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, gtirb::Module& module,
         const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_A64ASM_PRINTER_H */

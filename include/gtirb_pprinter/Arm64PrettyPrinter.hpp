//===- Arm64PrettyPrinter.hpp -----------------------------------*- C++ -*-===//
//
//  Copyright (c) 2020, The Binrat Developers.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//===----------------------------------------------------------------------===//

#ifndef GTIRB_PP_A64ASM_PRINTER_H
#define GTIRB_PP_A64ASM_PRINTER_H

#include "ElfPrettyPrinter.hpp"

namespace gtirb_pprint {

class Arm64PrettyPrinter : public ElfPrettyPrinter {
public:
  Arm64PrettyPrinter(gtirb::Context& context, gtirb::Module& module,
                     const ElfSyntax& syntax, const PrintingPolicy& policy);

protected:
  std::string getRegisterName(unsigned int reg) const override;

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
  std::optional<std::string> getForwardedSymbolName(const gtirb::Symbol* symbol,
                                                    bool inData) const override;

  void printOpRawValue(std::ostream& os, const cs_insn& inst, uint64_t index);
  void printOpPrefetch(std::ostream& os, const arm64_prefetch_op prefetch);
  void printOpBarrier(std::ostream& os, const arm64_barrier_op barrier);

  void printPrefix(std::ostream& os, const cs_insn& inst, uint64_t index);
  void printShift(std::ostream& os, const arm64_shifter type,
                  unsigned int value);
  void printExtender(std::ostream& os, const arm64_extender& ext,
                     const arm64_shifter shiftType, uint64_t shiftValue);
};

class Arm64PrettyPrinterFactory : public PrettyPrinterFactory {
public:
  const PrintingPolicy& defaultPrintingPolicy() const override;

  std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, gtirb::Module& module,
         const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_A64ASM_PRINTER_H */

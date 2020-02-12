// TODO: copyright

#ifndef GTIRB_PP_A64ASM_PRINTER_H
#define GTIRB_PP_A64ASM_PRINTER_H

#include "ElfPrettyPrinter.hpp"

namespace gtirb_pprint {

class AArch64PrettyPrinter : public ElfPrettyPrinter {
public:
    AArch64PrettyPrinter(gtirb::Context& context, gtirb::Module& module,
            const ElfSyntax& syntax, const PrintingPolicy& policy);

protected:
    std::string getRegisterName(unsigned int reg) const override;

    // TODO: see what else needs to be covered
    void printHeader(std::ostream& os) override;
    void printOperandList(std::ostream& os, const cs_insn& inst) override;
    void printOperand(std::ostream& os, const cs_insn& inst,
                        uint64_t index) override;
    void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                          const cs_x86_op& op) override;
    void printOpImmediate(std::ostream& os,
                          const gtirb::SymbolicExpression* symbolic,
                          const cs_insn& inst, uint64_t index) override;
    void printOpIndirect(std::ostream& os,
                       const gtirb::SymbolicExpression* symbolic,
                       const cs_insn& inst, uint64_t index) override;

private:
    static volatile bool registered;
};

class AArch64PrettyPrinterFactory : public PrettyPrinterFactory {
public:
    const PrintingPolicy& defaultPrintingPolicy() const override;

    std::unique_ptr<PrettyPrinterBase>
    create(gtirb::Context& context, gtirb::Module& module,
            const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_A64ASM_PRINTER_H */

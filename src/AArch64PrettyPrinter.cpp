// TODO: copyright

#include "AArch64PrettyPrinter.hpp"

namespace gtirb_pprint {

AArch64PrettyPrinter::AArch64PrettyPrinter(gtirb::Context& context_,
    gtirb::Module& module_, const ElfSyntax& syntax_,
    const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_) {}

void AArch64PrettyPrinter::printHeader(std::ostream& os) {
    this->printBar(os);
    // TODO hmm?
    os << "[HEADER]" << '\n';
    this->printBar(os);
    os << '\n';

    for (int i = 0; i < 8; i++) {
        // TODO why is this here?
        os << syntax.nop() << '\n';
    }
}

std::string AArch64PrettyPrinter::getRegisterName(unsigned int reg) const {
    (void) reg;
    return "[REGNAME]";
}

void AArch64PrettyPrinter::printOpRegdirect(std::ostream& os,
        const cs_insn& inst, const cs_x86_op& op) {
    (void) inst;
    (void) op;
    os << "[REGDIRECT]";
}

void AArch64PrettyPrinter::printOpImmediate(std::ostream& os,
        const gtirb::SymbolicExpression* symbolic,
        const cs_insn& inst, uint64_t index) {
    (void) symbolic;
    (void) inst;
    (void) index;
    os << "[IMMEDIATE]";
}

void AArch64PrettyPrinter::printOpIndirect(std::ostream& os,
        const gtirb::SymbolicExpression* symbolic,
        const cs_insn& inst, uint64_t index) {
    (void) symbolic;
    (void) inst;
    (void) index;
    os << "[INDIRECT]";
}

const PrintingPolicy& AArch64PrettyPrinterFactory::defaultPrintingPolicy() const {
    return ElfPrettyPrinter::defaultPrintingPolicy();
}

std::unique_ptr<PrettyPrinterBase>
AArch64PrettyPrinterFactory::create(gtirb::Context& gtirb_context,
        gtirb::Module& module, const PrintingPolicy& policy) {
    static const ElfSyntax syntax{};
    return std::make_unique<AArch64PrettyPrinter>(gtirb_context,
            module, syntax, policy);
}

volatile bool AArch64PrettyPrinter::registered = registerPrinter(
        {"elf"}, {"aarch64"},
        std::make_shared<AArch64PrettyPrinterFactory>(), true);

}


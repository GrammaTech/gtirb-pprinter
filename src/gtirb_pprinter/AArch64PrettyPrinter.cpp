// TODO: copyright

#include "AArch64PrettyPrinter.hpp"

#include <capstone/capstone.h>

namespace gtirb_pprint {

AArch64PrettyPrinter::AArch64PrettyPrinter(gtirb::Context& context_,
    gtirb::Module& module_, const ElfSyntax& syntax_,
    const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_, CS_ARCH_ARM64, CS_MODE_ARM) {}

void AArch64PrettyPrinter::printHeader(std::ostream& os) {
    // TODO: check this part
    this->printBar(os);
    os << ".intel_syntax noprefix\n";
    this->printBar(os);
    os << '\n';

    for (int i = 0; i < 8; i++) {
        // TODO why is this here?
        os << syntax.nop() << '\n';
    }
}

std::string AArch64PrettyPrinter::getRegisterName(unsigned int reg) const {
    return reg == ARM64_REG_INVALID ? "" : cs_reg_name(this->csHandle, reg);
}

void AArch64PrettyPrinter::printOperandList(std::ostream& os,
        const cs_insn& inst) {
    cs_arm64& detail = inst.detail->arm64;
    uint8_t opCount = detail.op_count;

    for (int i = 0; i < opCount; i++) {
        if (i != 0) {
            os << ',';
        }
        printOperand(os, inst, i);
    }

    // TODO: correct placement?
    if (detail.writeback) {
        os << "!";
    }
}

void AArch64PrettyPrinter::printOperand(std::ostream& os,
        const cs_insn& inst, uint64_t index) {
    gtirb::Addr ea(inst.address);
    const cs_arm64_op& op = inst.detail->arm64.operands[index];
    const gtirb::SymbolicExpression* symbolic = nullptr;

    // TODO: symbolic stuff
    switch (op.type) {
    case ARM64_OP_REG:
        printOpRegdirect(os, inst, op.reg);
        return;
    case ARM64_OP_IMM:
        {
            auto pos = module.findSymbolicExpressionsAt(ea);
            if (!pos.empty()) {
                symbolic = &pos.begin()->getSymbolicExpression();
            }
        }
        printOpImmediate(os, symbolic, inst, index);
        return;
    case ARM64_OP_MEM:
        {
            auto pos = module.findSymbolicExpressionsAt(ea);
            if (!pos.empty()) {
                symbolic = &pos.begin()->getSymbolicExpression();
            }
        }
        printOpIndirect(os, symbolic, inst, index);
        return;
    case ARM64_OP_INVALID:
        std::cout << "BREWWW" << std::endl;
        std::cerr << "invalid operand\n";
        exit(1);
    default:
        os << "[?OPERAND]";
        return;
    }
}

void AArch64PrettyPrinter::printOpRegdirect(std::ostream& os,
        const cs_insn& /* inst */, unsigned int reg) {
    os << getRegisterName(reg);
}

void printShift(std::ostream& os, const arm64_shifter type, unsigned int value) {
    switch (type) {
        case ARM64_SFT_LSL:
            os << "lsl";
            break;
        case ARM64_SFT_MSL:
            os << "msl";
            break;
        case ARM64_SFT_LSR:
            os << "lsr";
            break;
        case ARM64_SFT_ASR:
            os << "asr";
            break;
        case ARM64_SFT_ROR:
            os << "ror";
            break;
        default:
            assert(false && "unexpected case");
    }
    os << " #" << value;
}

void AArch64PrettyPrinter::printOpImmediate(std::ostream& os,
        const gtirb::SymbolicExpression* symbolic,
        const cs_insn& inst, uint64_t index) {
    const cs_arm64_op& op = inst.detail->arm64.operands[index];
    assert(op.type == ARM64_OP_IMM &&
            "printOpImmediate called without an immediate operand");

    bool is_jump = cs_insn_group(this->csHandle, &inst, ARM64_GRP_JUMP);

    if (const gtirb::SymAddrConst* s = this->getSymbolicImmediate(symbolic)) {
        if (!is_jump) {
            os << ' ';
        }
        this->printSymbolicExpression(os, s, !is_jump);
    } else {
        os << "#" << op.imm;
        if (op.shift.type != ARM64_SFT_INVALID && op.shift.value != 0) {
            os << ",";
            printShift(os, op.shift.type, op.shift.value);
        }
    }
}

void AArch64PrettyPrinter::printOpIndirect(std::ostream& os,
        const gtirb::SymbolicExpression* symbolic,
        const cs_insn& inst, uint64_t index) {
    if (symbolic) os << "<indirect_symbol>";
    const cs_arm64& detail = inst.detail->arm64;
    const cs_arm64_op& op = detail.operands[index];
    assert(op.type == ARM64_OP_MEM &&
            "printOpIndirect called without a memory operand");

    // TODO: ptr stuff
    bool first = true;

    os << "[";

    // base register
    if (op.mem.base != ARM64_REG_INVALID) {
        first = false;
        os << getRegisterName(op.mem.base);
    }

    // displacement (constant)
    if (op.mem.disp != 0) {
        if (!first) {
            os << ",";
        }
        first = false;
        os << "#" << op.mem.disp;
    }

    // index register
    if (op.mem.index != ARM64_REG_INVALID) {
        if (!first) {
            os << ",";
        }
        first = false;
        os << getRegisterName(op.mem.index);
    }

    // add shift
    // TODO: extenders?
    if (op.shift.type != ARM64_SFT_INVALID && op.shift.value != 0) {
        os << ",";
        assert(!first && "unexpected shift operator");
        printShift(os, op.shift.type, op.shift.value);
    }

    os << "]";
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


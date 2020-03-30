//===- AArch64PrettyPrinter.cpp ---------------------------------*- C++ -*-===//
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

    // TODO: fix placement - should only be here for pre-indexed
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
        case ARM64_OP_FP:
            os << "#" << op.fp;
            return;
        case ARM64_OP_CIMM:
            printOpRawString(os, inst, index);
            return;
        case ARM64_OP_REG_MRS:
            printOpRawString(os, inst, index);
            return;
        case ARM64_OP_REG_MSR:
            printOpRawString(os, inst, index);
            return;
        case ARM64_OP_PSTATE:
            printOpRawString(os, inst, index);
            return;
        case ARM64_OP_SYS:
            printOpRawString(os, inst, index);
            return;
        case ARM64_OP_PREFETCH:
            printOpPrefetch(os, op.prefetch);
            return;
        case ARM64_OP_BARRIER:
            printOpBarrier(os, op.barrier);
            return;
        case ARM64_OP_INVALID:
        default:
            std::cerr << "invalid operand\n";
            exit(1);
    }
}

void AArch64PrettyPrinter::printOpRawString(std::ostream& os, const cs_insn& inst, uint64_t index) {
    const char* op_str = inst.op_str;

    // go to the correct one
    unsigned int curr_operand = 0;
    bool in_block = false;
    const char* op_start = nullptr;

    while (*op_str != '\0') {
        char c = *op_str;
        if (c == '[') in_block = true;
        else if (c == ']') in_block = false;
        else if (!in_block && c == ',') curr_operand++;
        else if (curr_operand == index) {
            op_start = op_str;
            break;
        }
        op_str++;
    }

    assert(op_start != nullptr && "expected correct amount of operands");
    // skip leading whitespace
    while (isspace(*op_start)) op_start++;

    // check for the end of the op
    const char* op_end = nullptr;
    while (*op_str != '\0') {
        char c = *op_str;
        if (c == '[') in_block = true;
        else if (c == ']') in_block = false;
        else if (!in_block && c == ',') {
            op_end = op_str;
            break;
        }
        op_str++;
    }
    op_end = op_end == nullptr ? op_str : op_end;

    for (const char* curr = op_start; curr < op_end; curr++) {
        os << *curr;
    }
}

void AArch64PrettyPrinter::printOpRegdirect(std::ostream& os,
        const cs_insn& /* inst */, unsigned int reg) {
    os << getRegisterName(reg);
}

void AArch64PrettyPrinter::printOpBarrier(std::ostream& os, const arm64_barrier_op barrier) {
    switch (barrier) {
        case ARM64_BARRIER_OSHLD:
            os << "oshld";
            return;
        case ARM64_BARRIER_OSHST:
            os << "oshst";
            return;
        case ARM64_BARRIER_OSH:
            os << "osh";
            return;
        case ARM64_BARRIER_NSHLD:
            os << "nshld";
            return;
        case ARM64_BARRIER_NSHST:
            os << "nshst";
            return;
        case ARM64_BARRIER_NSH:
            os << "nsh";
            return;
        case ARM64_BARRIER_ISHLD:
            os << "ishld";
            return;
        case ARM64_BARRIER_ISHST:
            os << "ishst";
            return;
        case ARM64_BARRIER_ISH:
            os << "ish";
            return;
        case ARM64_BARRIER_LD:
            os << "ld";
            return;
        case ARM64_BARRIER_ST:
            os << "st";
            return;
        case ARM64_BARRIER_SY:
            os << "sy";
            return;
        case ARM64_BARRIER_INVALID:
        default:
            std::cerr << "invalid operand\n";
            exit(1);
    }
}

void AArch64PrettyPrinter::printOpPrefetch(std::ostream& os, const arm64_prefetch_op prefetch) {
    switch (prefetch) {
        case ARM64_PRFM_PLDL1KEEP:
            os << "pldl1keep";
            return;
        case ARM64_PRFM_PLDL1STRM:
            os << "pldl1strm";
            return;
        case ARM64_PRFM_PLDL2KEEP:
            os << "pldl2keep";
            return;
        case ARM64_PRFM_PLDL2STRM:
            os << "pldl2strm";
            return;
        case ARM64_PRFM_PLDL3KEEP:
            os << "pldl3keep";
            return;
        case ARM64_PRFM_PLDL3STRM:
            os << "pldl3strm";
            return;
        case ARM64_PRFM_PLIL1KEEP:
            os << "plil1keep";
            return;
        case ARM64_PRFM_PLIL1STRM:
            os << "plil1strm";
            return;
        case ARM64_PRFM_PLIL2KEEP:
            os << "plil2keep";
            return;
        case ARM64_PRFM_PLIL2STRM:
            os << "plil2strm";
            return;
        case ARM64_PRFM_PLIL3KEEP:
            os << "plil3keep";
            return;
        case ARM64_PRFM_PLIL3STRM:
            os << "plil3strm";
            return;
        case ARM64_PRFM_PSTL1KEEP:
            os << "pstl1keep";
            return;
        case ARM64_PRFM_PSTL1STRM:
            os << "pstl1strm";
            return;
        case ARM64_PRFM_PSTL2KEEP:
            os << "pstl2keep";
            return;
        case ARM64_PRFM_PSTL2STRM:
            os << "pstl2strm";
            return;
        case ARM64_PRFM_PSTL3KEEP:
            os << "pstl3keep";
            return;
        case ARM64_PRFM_PSTL3STRM:
            os << "pstl3strm";
            return;
        case ARM64_PRFM_INVALID:
        default:
            std::cerr << "invalid operand\n";
            exit(1);
    }
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


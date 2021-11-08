//===- Arm64PrettyPrinter.cpp -----------------------------------*- C++ -*-===//
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

#include <iostream>

#include "Arm64PrettyPrinter.hpp"
#include "AuxDataSchema.hpp"
#include "string_utils.hpp"

#include <capstone/capstone.h>

namespace gtirb_pprint {

Arm64PrettyPrinter::Arm64PrettyPrinter(gtirb::Context& context_,
                                       gtirb::Module& module_,
                                       const ElfSyntax& syntax_,
                                       const Assembler& assembler_,
                                       const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, assembler_, policy_) {
  // Setup Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
}

void Arm64PrettyPrinter::printHeader(std::ostream& os) {
  ElfPrettyPrinter::printHeader(os);

  this->printBar(os);
  os << ".arch armv8-a\n";
  this->printBar(os);
  os << '\n';
}

std::string Arm64PrettyPrinter::getRegisterName(unsigned int reg) const {
  return reg == ARM64_REG_INVALID ? "" : cs_reg_name(this->csHandle, reg);
}

void Arm64PrettyPrinter::printInstruction(std::ostream& os,
                                          const gtirb::CodeBlock& block,
                                          const cs_insn& inst,
                                          const gtirb::Offset& offset) {
  gtirb::Addr ea(inst.address);
  printComments(os, offset, inst.size);
  printCFIDirectives(os, offset);
  printEA(os, ea);

  ////////////////////////////////////////////////////////////////////
  // special cases

  if (inst.id == ARM64_INS_NOP) {
    os << "  " << syntax.nop();
    for (uint64_t i = 1; i < inst.size; ++i) {
      ea += 1;
      os << '\n';
      printEA(os, ea);
      os << "  " << syntax.nop();
    }
    os << '\n';
    return;
  }

  // end special cases
  ////////////////////////////////////////////////////////////////////

  std::string opcode = ascii_str_tolower(inst.mnemonic);
  os << "  " << opcode << ' ';

  // Make sure the initial m_accum_comment is empty.
  m_accum_comment.clear();
  printOperandList(os, block, inst);
  if (!m_accum_comment.empty()) {
    os << '\n' << syntax.comment() << " ";
    printEA(os, ea);
    os << ": " << m_accum_comment;
    m_accum_comment.clear();
  }
  os << '\n';
}

void Arm64PrettyPrinter::printOperandList(std::ostream& os,
                                          const gtirb::CodeBlock& block,
                                          const cs_insn& inst) {
  cs_arm64& detail = inst.detail->arm64;
  int opCount = detail.op_count;

  for (int i = 0; i < opCount; i++) {
    if (i != 0) {
      os << ',';
    }
    printOperand(os, block, inst, i);
  }

  auto arm64Cc2String = [](arm64_cc cc) {
    switch (cc) {
    case ARM64_CC_EQ:
      return "eq";
    case ARM64_CC_NE:
      return "ne";
    case ARM64_CC_HS:
      return "hs";
    case ARM64_CC_LO:
      return "lo";
    case ARM64_CC_MI:
      return "mi";
    case ARM64_CC_PL:
      return "pl";
    case ARM64_CC_VS:
      return "vs";
    case ARM64_CC_VC:
      return "vc";
    case ARM64_CC_HI:
      return "hi";
    case ARM64_CC_LS:
      return "ls";
    case ARM64_CC_GE:
      return "ge";
    case ARM64_CC_LT:
      return "lt";
    case ARM64_CC_GT:
      return "gt";
    case ARM64_CC_LE:
      return "le";
    case ARM64_CC_AL:
      return "al";
    default:
      assert(!"Invalid arm64_cc");
      return "Invalid arm64_cc";
    }
  };

  auto isCondInstr = [](const std::string& opcode) {
    static std::vector<std::string> cond_instrs{
        "ccmn", "ccmp",  "cinc",  "cinv",  "cneg", "csel",
        "cset", "csetm", "csinc", "csinv", "csneg"};
    return (std::find(std::begin(cond_instrs), std::end(cond_instrs), opcode) !=
            std::end(cond_instrs));
  };

  std::string opcode = ascii_str_tolower(inst.mnemonic);
  if (isCondInstr(opcode) && inst.detail->arm64.cc != ARM64_CC_INVALID) {
    std::string cc = arm64Cc2String(inst.detail->arm64.cc);
    os << ',' << cc;
  }
}

void Arm64PrettyPrinter::printOperand(std::ostream& os,
                                      const gtirb::CodeBlock& block,
                                      const cs_insn& inst, uint64_t index) {
  gtirb::Addr ea(inst.address);
  const cs_arm64_op& op = inst.detail->arm64.operands[index];
  const gtirb::SymbolicExpression* symbolic = nullptr;
  bool finalOp = (index + 1 == inst.detail->arm64.op_count);

  switch (op.type) {
  case ARM64_OP_REG:
    printOpRegdirect(os, inst, index);
    return;
  case ARM64_OP_IMM:
    if (finalOp) {
      uint64_t Offset = ea - *block.getByteInterval()->getAddress();
      symbolic = block.getByteInterval()->getSymbolicExpression(Offset);
    }
    printOpImmediate(os, symbolic, inst, index);
    return;
  case ARM64_OP_MEM:
    if (finalOp) {
      uint64_t Offset = ea - *block.getByteInterval()->getAddress();
      symbolic = block.getByteInterval()->getSymbolicExpression(Offset);
    }
    printOpIndirect(os, symbolic, inst, index);
    return;
  case ARM64_OP_FP:
    os << "#" << std::scientific << std::setprecision(18) << op.fp;
    return;
  case ARM64_OP_CIMM:
  case ARM64_OP_REG_MRS:
  case ARM64_OP_REG_MSR:
  case ARM64_OP_PSTATE:
  case ARM64_OP_SYS:
    // Print the operand directly.
    printOpRawValue(os, inst, index);
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

void Arm64PrettyPrinter::printSymExprPrefix(std::ostream& OS,
                                            const gtirb::SymAttributeSet& Attrs,
                                            bool /* IsNotBranch */) {
  if (Attrs.isFlagSet(gtirb::SymAttribute::GotRef)) {
    if (Attrs.isFlagSet(gtirb::SymAttribute::Lo12)) {
      OS << ":got_lo12:";
    } else {
      OS << ":got:";
    }
  } else if (Attrs.isFlagSet(gtirb::SymAttribute::Lo12)) {
    OS << ":lo12:";
  }
}

void Arm64PrettyPrinter::printSymExprSuffix(
    std::ostream& /* OS */, const gtirb::SymAttributeSet& /* Attrs */,
    bool /* IsNotBranch */) {}

void Arm64PrettyPrinter::printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                          uint64_t index) {
  assert(index < inst.detail->arm64.op_count &&
         "printOpRegdirect called with invalid register index");
  const cs_arm64_op& op = inst.detail->arm64.operands[index];
  assert(op.type == ARM64_OP_REG &&
         "printOpRegdirect called without a register operand");
  os << getRegisterName(op.reg);

  auto arm64Shifter2String = [](arm64_shifter sft) {
    switch (sft) {
    case ARM64_SFT_INVALID:
      return "";
    case ARM64_SFT_ASR:
      return "asr";
    case ARM64_SFT_LSL:
      return "lsl";
    case ARM64_SFT_LSR:
      return "lsr";
    case ARM64_SFT_MSL:
      return "msl";
    case ARM64_SFT_ROR:
      return "ror";
    default:
      return "";
    }
  };

  // Add extender if needed.
  if (op.ext != ARM64_EXT_INVALID) {
    os << ", ";
    printExtender(os, op.ext, op.shift.type, op.shift.value);
  } else {
    std::string opcode = ascii_str_tolower(inst.mnemonic);
    opcode = opcode.substr(0, 3);
    if (op.shift.type != ARM64_SFT_INVALID && op.shift.value != 0) {
      os << ", ";
      // In case where opcode is the same as one of arm64_shifters (e.g., lsl),
      // do not print it again here.
      std::string shift_type = arm64Shifter2String(op.shift.type);
      if (shift_type != opcode)
        os << shift_type << " ";
      if (op.shift.value >= 64)
        os << getRegisterName(op.shift.value);
      else
        os << "#" << op.shift.value;
    }
  }
}

void Arm64PrettyPrinter::printOpImmediate(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_arm64_op& op = inst.detail->arm64.operands[index];
  assert(op.type == ARM64_OP_IMM &&
         "printOpImmediate called without an immediate operand");

  if (const gtirb::SymAddrConst* s = this->getSymbolicImmediate(symbolic)) {
    bool is_jump = cs_insn_group(this->csHandle, &inst, ARM64_GRP_JUMP);
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

void Arm64PrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_arm64& detail = inst.detail->arm64;
  const cs_arm64_op& op = detail.operands[index];
  assert(op.type == ARM64_OP_MEM &&
         "printOpIndirect called without a memory operand");

  bool first = true;

  os << "[";

  // Base register
  if (op.mem.base != ARM64_REG_INVALID) {
    first = false;
    os << getRegisterName(op.mem.base);
  }

  // Displacement (constant)
  if (op.mem.disp != 0) {
    if (!first) {
      os << ",";
    }
    if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
      printSymbolicExpression(os, s, false);
    } else {
      os << "#" << op.mem.disp;
    }
    first = false;
  }

  // Index register
  if (op.mem.index != ARM64_REG_INVALID) {
    if (!first) {
      os << ",";
    }
    first = false;
    os << getRegisterName(op.mem.index);
  }

  // Add shift
  if (op.shift.type != ARM64_SFT_INVALID && op.shift.value != 0) {
    os << ",";
    assert(!first && "unexpected shift operator");
    if (op.shift.type == ARM64_SFT_LSL && op.ext != ARM64_EXT_INVALID) {
      printExtender(os, op.ext, op.shift.type, op.shift.value);
    } else {
      printShift(os, op.shift.type, op.shift.value);
    }
  }

  os << "]";

  if (detail.writeback && index + 1 == detail.op_count) {
    os << "!";
  }
}

void Arm64PrettyPrinter::printOpRawValue(std::ostream& os, const cs_insn& inst,
                                         uint64_t index) {
  // Grab the full operand string.
  const char* opStr = inst.op_str;

  // Flick through to the start of the operand.
  unsigned int currOperand = 0;
  bool inBlock = false;
  const char* pos;
  for (pos = opStr; *pos != '\0' && currOperand != index; pos++) {
    char cur = *pos;
    if (cur == '[') {
      // Entering an indirect memory access.
      assert(!inBlock && "nested blocks should not be possible");
      inBlock = true;
    } else if (cur == ']') {
      // Exiting an indirect memory access.
      assert(inBlock && "Closing unopened memory access");
      inBlock = false;
    } else if (!inBlock && cur == ',') {
      // Hit a new operand.
      currOperand++;
    }
  }
  assert(currOperand == index && "unexpected end of operands");
  const char* operandStart = pos;

  // Find the end of the operand.
  while (*pos != '\0') {
    char cur = *pos;
    if (cur == '[') {
      inBlock = true;
    } else if (cur == ']') {
      inBlock = false;
    } else if (!inBlock && cur == ',') {
      // Found end of operand.
      break;
    }
    pos++;
  }
  const char* operandEnd = pos;

  // Skip leading whitespace.
  while (isspace(*operandStart))
    operandStart++;

  // Print every character in the operand.
  for (const char* cur = operandStart; cur < operandEnd; cur++) {
    os << *cur;
  }
}

void Arm64PrettyPrinter::printOpBarrier(std::ostream& os,
                                        const arm64_barrier_op barrier) {
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

void Arm64PrettyPrinter::printOpPrefetch(std::ostream& os,
                                         const arm64_prefetch_op prefetch) {
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

void Arm64PrettyPrinter::printShift(std::ostream& os, const arm64_shifter type,
                                    unsigned int value) {
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

void Arm64PrettyPrinter::printExtender(std::ostream& os,
                                       const arm64_extender& ext,
                                       const arm64_shifter shiftType,
                                       uint64_t shiftValue) {
  switch (ext) {
  case ARM64_EXT_UXTB:
    os << "uxtb";
    break;
  case ARM64_EXT_UXTH:
    os << "uxth";
    break;
  case ARM64_EXT_UXTW:
    os << "uxtw";
    break;
  case ARM64_EXT_UXTX:
    os << "uxtx";
    break;
  case ARM64_EXT_SXTB:
    os << "sxtb";
    break;
  case ARM64_EXT_SXTH:
    os << "sxth";
    break;
  case ARM64_EXT_SXTW:
    os << "sxtw";
    break;
  case ARM64_EXT_SXTX:
    os << "sxtx";
    break;
  default:
    assert(false && "unexpected case");
  }
  if (shiftType != ARM64_SFT_INVALID) {
    assert(shiftType == ARM64_SFT_LSL && "unexpected shift type in extender");
    os << " #" << shiftValue;
  }
}

std::unique_ptr<PrettyPrinterBase>
Arm64PrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                  gtirb::Module& module,
                                  const PrintingPolicy& policy) {
  static const ElfSyntax syntax{};
  static const Assembler assembler{};
  return std::make_unique<Arm64PrettyPrinter>(gtirb_context, module, syntax,
                                              assembler, policy);
}

Arm64PrettyPrinterFactory::Arm64PrettyPrinterFactory() {
  auto& DynamicPolicy = *findRegisteredNamedPolicy("dynamic");
  DynamicPolicy.arraySections.clear();
  DynamicPolicy.skipSections.emplace(".init_array");
  DynamicPolicy.skipSections.emplace(".fini_array");
}

} // namespace gtirb_pprint

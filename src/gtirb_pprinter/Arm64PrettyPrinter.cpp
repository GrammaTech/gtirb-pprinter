//===- Arm64PrettyPrinter.cpp -----------------------------------*- C++ -*-===//
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

#include <iostream>

#include "Arm64PrettyPrinter.hpp"
#include "AuxDataSchema.hpp"
#include "AuxDataUtils.hpp"
#include "StringUtils.hpp"

#include <capstone/capstone.h>

namespace gtirb_pprint {

Arm64PrettyPrinter::Arm64PrettyPrinter(gtirb::Context& context_,
                                       const gtirb::Module& module_,
                                       const ElfSyntax& syntax_,

                                       const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_) {
  // Setup Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");

  buildSymGotRefTable();
}

void Arm64PrettyPrinter::buildSymGotRefTable(void) {
  for (auto It : module.symbolic_expressions()) {
    auto SymExpr = It.getSymbolicExpression();
    if (const auto* SymAddr = std::get_if<gtirb::SymAddrConst>(&SymExpr)) {
      if (SymAddr->Attributes.count(gtirb::SymAttribute::GOT)) {
        if (auto Found = aux_data::getForwardedSymbol(SymAddr->Sym)) {
          // the SymExpr will reference the got entry itself, so we need to
          // look up the forwarded symbol.
          auto ForwardedSymbol = gtirb::dyn_cast_or_null<gtirb::Symbol>(
              gtirb::Node::getByUUID(context, *Found));
          if (ForwardedSymbol) {
            LocalGotSyms.insert(ForwardedSymbol->getUUID());
          }
        }
      }
    }
  }
}

void Arm64PrettyPrinter::printHeader(std::ostream& os) {
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
  std::stringstream InstructLine;
  printComments(InstructLine, offset, inst.size);
  printCFIDirectives(InstructLine, offset);
  printEA(InstructLine, ea);

  ////////////////////////////////////////////////////////////////////
  // special cases
  std::string opcode = std::string();

  if (inst.id == ARM64_INS_NOP) {
    InstructLine << "  " << syntax.nop();
    for (uint64_t i = 1; i < inst.size; ++i) {
      printCommentableLine(InstructLine, os, ea);
      InstructLine.str(std::string()); // Clear
      ea += 1;
      os << '\n';
      printEA(InstructLine, ea);
      InstructLine << "  " << syntax.nop();
    }
    printCommentableLine(InstructLine, os, ea);
    os << '\n';
    return;
  } else if (inst.id == ARM64_INS_ADR) {
    // The assembler does not allow :got: on adr instructions, but sometimes
    // it substitutes an adrp x0, :got:symbol for an adr instruction. In order
    // to print something that can be reassembled, reverse this substitution
    // and print an adrp.

    const gtirb::SymbolicExpression* Symex =
        block.getByteInterval()->getSymbolicExpression(
            ea - *block.getByteInterval()->getAddress());
    if (Symex != nullptr) {
      const gtirb::SymAddrConst* Symaddr = this->getSymbolicImmediate(Symex);
      if (Symaddr != nullptr &&
          Symaddr->Attributes.count(gtirb::SymAttribute::GOT)) {
        opcode = "adrp";

        // Print a comment indicating the substitution

        os << syntax.comment()
           << " Instruction substituted from adr to adrp to support :got: "
              "reference.\n";
      }
    }
  }

  // end special cases
  ////////////////////////////////////////////////////////////////////

  if (opcode.empty()) {
    opcode = ascii_str_tolower(inst.mnemonic);
  }

  InstructLine << "  " << opcode << ' ';

  // Make sure the initial m_accum_comment is empty.
  m_accum_comment.clear();
  printOperandList(InstructLine, block, inst);
  if (!m_accum_comment.empty()) {
    printCommentableLine(InstructLine, os, ea);
    InstructLine.str(std::string()); // Clear
    os << '\n';
    InstructLine << syntax.comment() << " ";
    printEA(InstructLine, ea);
    InstructLine << ": " << m_accum_comment;
    m_accum_comment.clear();
  }
  printCommentableLine(InstructLine, os, ea);
  os << '\n';
}

void Arm64PrettyPrinter::printOperandList(std::ostream& os,
                                          const gtirb::CodeBlock& block,
                                          const cs_insn& inst) {
  cs_arm64& detail = inst.detail->arm64;
  int opCount = detail.op_count;

  const static std::map<arm64_insn, uint8_t> Groupings = {
      {ARM64_INS_LD1, 0},     {ARM64_INS_LD1B, 0},    {ARM64_INS_LD1D, 0},
      {ARM64_INS_LD1H, 0},    {ARM64_INS_LD1R, 0},    {ARM64_INS_LD1RB, 0},
      {ARM64_INS_LD1RD, 0},   {ARM64_INS_LD1RH, 0},   {ARM64_INS_LD1RQB, 0},
      {ARM64_INS_LD1RQD, 0},  {ARM64_INS_LD1RQH, 0},  {ARM64_INS_LD1RQW, 0},
      {ARM64_INS_LD1RSB, 0},  {ARM64_INS_LD1RSH, 0},  {ARM64_INS_LD1RSW, 0},
      {ARM64_INS_LD1RW, 0},   {ARM64_INS_LD1SB, 0},   {ARM64_INS_LD1SH, 0},
      {ARM64_INS_LD1SW, 0},   {ARM64_INS_LD1W, 0},    {ARM64_INS_LD2, 0},
      {ARM64_INS_LD2B, 0},    {ARM64_INS_LD2D, 0},    {ARM64_INS_LD2H, 0},
      {ARM64_INS_LD2R, 0},    {ARM64_INS_LD2W, 0},    {ARM64_INS_LD3, 0},
      {ARM64_INS_LD3B, 0},    {ARM64_INS_LD3D, 0},    {ARM64_INS_LD3H, 0},
      {ARM64_INS_LD3R, 0},    {ARM64_INS_LD3W, 0},    {ARM64_INS_LD4, 0},
      {ARM64_INS_LD4B, 0},    {ARM64_INS_LD4D, 0},    {ARM64_INS_LD4H, 0},
      {ARM64_INS_LD4R, 0},    {ARM64_INS_LD4W, 0},    {ARM64_INS_LDFF1B, 0},
      {ARM64_INS_LDFF1D, 0},  {ARM64_INS_LDFF1H, 0},  {ARM64_INS_LDFF1SB, 0},
      {ARM64_INS_LDFF1SH, 0}, {ARM64_INS_LDFF1SW, 0}, {ARM64_INS_LDFF1W, 0},
      {ARM64_INS_LDNF1B, 0},  {ARM64_INS_LDNF1D, 0},  {ARM64_INS_LDNF1H, 0},
      {ARM64_INS_LDNF1SB, 0}, {ARM64_INS_LDNF1SH, 0}, {ARM64_INS_LDNF1SW, 0},
      {ARM64_INS_LDNF1W, 0},  {ARM64_INS_LDNT1B, 0},  {ARM64_INS_LDNT1D, 0},
      {ARM64_INS_LDNT1H, 0},  {ARM64_INS_LDNT1W, 0},  {ARM64_INS_ST1, 0},
      {ARM64_INS_ST1, 0},     {ARM64_INS_ST1, 0},     {ARM64_INS_ST1, 0},
      {ARM64_INS_ST1B, 0},    {ARM64_INS_ST1D, 0},    {ARM64_INS_ST1H, 0},
      {ARM64_INS_ST1W, 0},    {ARM64_INS_ST2B, 0},    {ARM64_INS_ST2D, 0},
      {ARM64_INS_ST2H, 0},    {ARM64_INS_ST2W, 0},    {ARM64_INS_ST3B, 0},
      {ARM64_INS_ST3D, 0},    {ARM64_INS_ST3H, 0},    {ARM64_INS_ST3W, 0},
      {ARM64_INS_ST4B, 0},    {ARM64_INS_ST4D, 0},    {ARM64_INS_ST4H, 0},
      {ARM64_INS_ST4W, 0},    {ARM64_INS_STNT1B, 0},  {ARM64_INS_STNT1D, 0},
      {ARM64_INS_STNT1H, 0},  {ARM64_INS_STNT1W, 0},  {ARM64_INS_TBL, 1}};

  std::optional<uint8_t> GroupingStart;
  if (auto It = Groupings.find(static_cast<arm64_insn>(inst.id));
      It != Groupings.end()) {
    GroupingStart = It->second;
  }

  for (uint8_t i = 0; i < opCount; i++) {
    if (i != 0) {
      os << ',';
    }

    if (GroupingStart && *GroupingStart == i) {
      os << "{";
      IsPrintingGroupedOperands = true;
    }

    printOperand(os, block, inst, i);

    if (IsPrintingGroupedOperands) {
      uint8_t offset = 0;

      if (static_cast<arm64_insn>(inst.id) == ARM64_INS_TBL) {
        // Special case: TBL instructions have a trailing ungrouped operand.
        offset = 1;
      }

      // Expect grouped operands to all be registers with a VAS specifier.
      // Close the grouping when we find an operand that does not match this,
      // or if there are no more operands.
      if (i + 1 + offset < opCount) {
        cs_arm64_op& nextOp = inst.detail->arm64.operands[i + 1];
        if (nextOp.type != ARM64_OP_REG || nextOp.vas == ARM64_VAS_INVALID) {
          IsPrintingGroupedOperands = false;
        }
      } else {
        IsPrintingGroupedOperands = false;
      }

      if (!IsPrintingGroupedOperands) {
        os << "}";
        cs_arm64_op& op = inst.detail->arm64.operands[i];
        if (op.vector_index != -1) {
          os << "[" << op.vector_index << "]";
        }
      }
    }
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

  // This set of special cases is required to handle conditional operands,
  // which capstone does not represent as an explicit operand. See the capstone
  // issue: https://github.com/capstone-engine/capstone/issues/1889
  auto isCondInstr = [](const arm64_insn opcode) {
    static std::vector<arm64_insn> cond_instrs{
        ARM64_INS_CCMN,   ARM64_INS_CCMP,  ARM64_INS_CINC,  ARM64_INS_CINV,
        ARM64_INS_CNEG,   ARM64_INS_CSEL,  ARM64_INS_CSET,  ARM64_INS_CSETM,
        ARM64_INS_CSINC,  ARM64_INS_CSINV, ARM64_INS_CSNEG, ARM64_INS_FCCMP,
        ARM64_INS_FCCMPE, ARM64_INS_FCSEL,
    };

    return (std::find(std::begin(cond_instrs), std::end(cond_instrs), opcode) !=
            std::end(cond_instrs));
  };

  if (inst.detail->arm64.cc != ARM64_CC_INVALID &&
      isCondInstr(static_cast<arm64_insn>(inst.id))) {
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
  if (Attrs.count(gtirb::SymAttribute::GOT)) {
    if (Attrs.count(gtirb::SymAttribute::LO12)) {
      OS << ":got_lo12:";
    } else {
      OS << ":got:";
    }
  } else if (Attrs.count(gtirb::SymAttribute::LO12)) {
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

  if (op.vas != ARM64_VAS_INVALID) {
    auto arm64Vas2String = [](arm64_vas vas) {
      switch (vas) {
      case ARM64_VAS_16B:
        return "16b";
      case ARM64_VAS_8B:
        return "8b";
      case ARM64_VAS_4B:
        return "4b";
      case ARM64_VAS_1B:
        return "b";
      case ARM64_VAS_8H:
        return "8h";
      case ARM64_VAS_4H:
        return "4h";
      case ARM64_VAS_2H:
        return "2h";
      case ARM64_VAS_1H:
        return "h";
      case ARM64_VAS_4S:
        return "4s";
      case ARM64_VAS_2S:
        return "2s";
      case ARM64_VAS_1S:
        return "s";
      case ARM64_VAS_2D:
        return "2d";
      case ARM64_VAS_1D:
        return "d";
      case ARM64_VAS_1Q:
        return "q";
      default:
        return "";
      }
    };

    os << "." << arm64Vas2String(op.vas);
    if (!IsPrintingGroupedOperands) {
      // Grouped operands print the index following the group.
      if (op.vector_index != -1) {
        os << "[" << op.vector_index << "]";
      }
    }
  }

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
    // Handle MOVZ/MOVK with absolute address group attributes (G0-G3).
    // The #:abs_gN: prefix tells the assembler which 16-bit group of the
    // symbol address to extract.  MOVK uses _nc (no-check) variants.
    bool hasAbsGroup = s->Attributes.count(gtirb::SymAttribute::G0)
                    || s->Attributes.count(gtirb::SymAttribute::G1)
                    || s->Attributes.count(gtirb::SymAttribute::G2)
                    || s->Attributes.count(gtirb::SymAttribute::G3);

    if (hasAbsGroup) {
      bool isMovk = (inst.id == ARM64_INS_MOVK);
      if (s->Attributes.count(gtirb::SymAttribute::G0))
        os << (isMovk ? "#:abs_g0_nc:" : "#:abs_g0:");
      else if (s->Attributes.count(gtirb::SymAttribute::G1))
        os << (isMovk ? "#:abs_g1_nc:" : "#:abs_g1:");
      else if (s->Attributes.count(gtirb::SymAttribute::G2))
        os << (isMovk ? "#:abs_g2_nc:" : "#:abs_g2:");
      else // G3 is always the highest group, no _nc needed.
        os << "#:abs_g3:";
      this->printSymbolicExpression(os, s, true);
    } else {
      bool is_jump = cs_insn_group(this->csHandle, &inst, ARM64_GRP_JUMP);
      if (!is_jump) {
        os << ' ';
      }
      this->printSymbolicExpression(os, s, !is_jump);
    }
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
  // Must always be printed if symbolic, even if disp is zero.
  const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic);
  if (op.mem.disp != 0 || s) {
    if (!first) {
      os << ",";
    }
    if (s) {
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

  // Add extend / shift
  if (op.ext != ARM64_EXT_INVALID) {
    os << ",";
    printExtender(os, op.ext, op.shift.type, op.shift.value);
  } else if (op.shift.type != ARM64_SFT_INVALID && op.shift.value != 0) {
    os << ",";
    assert(!first && "unexpected shift operator");
    printShift(os, op.shift.type, op.shift.value);
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

void Arm64PrettyPrinter::printSymbolHeader(std::ostream& os,
                                           const gtirb::Symbol& sym) {
  if (LocalGotSyms.find(sym.getUUID()) != LocalGotSyms.end()) {
    if (auto SymbolInfo = aux_data::getElfSymbolInfo(sym)) {
      if (SymbolInfo->Binding == "LOCAL" &&
          SymbolInfo->Visibility == "DEFAULT") {
        // If there is a :got: reference to this symbol, we need it to be a
        // global symbol. Otherwise, the linker fails to generate .got entries
        // properly. Using ld from binutils 2.34, I observed where it would
        // generate a single entry in the .got for *all* symbols defined in the
        // binary referenced via :got:, so they all resolved to the same
        // (usually incorrect) symbol. We also apply hidden, so when linked into
        // a shared object or executable, the symbol is converted back to a
        // local symbol. These attributes match how the symbol would have
        // originally appeared in the assembly in an individual object file; to
        // be referenced via the got, the reference would be across compilation
        // units, so it would have to be global in the original object.
        auto Name = getSymbolName(sym);
        printBar(os, false);
        os << syntax.global() << ' ' << Name << '\n';
        os << elfSyntax.hidden() << ' ' << Name << '\n';

        printSymbolType(os, Name, *SymbolInfo);
        printBar(os, false);
        return;
      }
    }
  }

  // With no got references, print it normally.
  ElfPrettyPrinter::printSymbolHeader(os, sym);
}

std::unique_ptr<PrettyPrinterBase>
Arm64PrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                  const gtirb::Module& module,
                                  const PrintingPolicy& policy) {
  static const Arm64Syntax syntax{};
  return std::make_unique<Arm64PrettyPrinter>(gtirb_context, module, syntax,
                                              policy);
}

} // namespace gtirb_pprint

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

#include <capstone/capstone.h>

namespace gtirb_pprint {

Arm64PrettyPrinter::Arm64PrettyPrinter(gtirb::Context& context_,
                                       gtirb::Module& module_,
                                       const ElfSyntax& syntax_,
                                       const PrintingPolicy& policy_)
    : ElfPrettyPrinter(context_, module_, syntax_, policy_) {
  // Setup Capstone.
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
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

    // Add extender if needed.
    if (op.ext != ARM64_EXT_INVALID) {
      os << ", ";
      printExtender(os, op.ext, op.shift.type, op.shift.value);
    }
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
    os << "#" << op.fp;
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

void Arm64PrettyPrinter::printPrefix(std::ostream& os, const cs_insn& inst,
                                     uint64_t index) {
  if (auto* symbolicOperandInfo =
          module.getAuxData<gtirb::schema::SymbolicOperandInfoAD>()) {
    for (const auto& pair : *symbolicOperandInfo) {
      const auto& symbolInfo = pair.second;
      if (pair.first == gtirb::Addr(inst.address) &&
          index == std::get<0>(symbolInfo)) {
        os << std::get<1>(symbolInfo);
      }
    }
  }
}

void Arm64PrettyPrinter::printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                          uint64_t index) {
  assert(index < inst.detail->arm64.op_count &&
         "printOpRegdirect called with invalid register index");
  const cs_arm64_op& op = inst.detail->arm64.operands[index];
  assert(op.type == ARM64_OP_REG &&
         "printOpRegdirect called without a register operand");
  os << getRegisterName(op.reg);
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
    printPrefix(os, inst, index);
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
      printPrefix(os, inst, index);
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

std::optional<std::string>
Arm64PrettyPrinter::getForwardedSymbolName(const gtirb::Symbol* symbol,
                                           bool /* IsNotBranch */) const {
  if (const auto* symbolForwarding =
          module.getAuxData<gtirb::schema::SymbolForwarding>()) {
    auto found = symbolForwarding->find(symbol->getUUID());
    if (found != symbolForwarding->end()) {
      // Find the destination symbol.
      if (gtirb::Node* N = gtirb::Node::getByUUID(context, found->second)) {
        return cast<gtirb::Symbol>(N)->getName();
      }
    }
  }
  return {};
}

const PrintingPolicy& Arm64PrettyPrinterFactory::defaultPrintingPolicy() const {
  static PrintingPolicy DefaultPolicy{
      /// Functions to avoid printing.
      {"_start", "deregister_tm_clones", "register_tm_clones",
       "__do_global_dtors_aux", "frame_dummy", "__libc_csu_fini",
       "__libc_csu_init", "_dl_relocate_static_pie", "call_weak_fn"},

      /// Symbols to avoid printing.
      {"_IO_stdin_used", "__data_start", "__dso_handle", "__TMC_END__",
       "_edata", "__bss_start", "program_invocation_name",
       "program_invocation_short_name"},

      /// Sections to avoid printing.
      {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt",
       ".plt.sec", ".eh_frame_hdr", ".init_array", ".fini_array"},

      /// Sections with possible data object exclusion.
      {},
  };
  return DefaultPolicy;
}

std::unique_ptr<PrettyPrinterBase>
Arm64PrettyPrinterFactory::create(gtirb::Context& gtirb_context,
                                  gtirb::Module& module,
                                  const PrintingPolicy& policy) {
  static const ElfSyntax syntax{};
  return std::make_unique<Arm64PrettyPrinter>(gtirb_context, module, syntax,
                                              policy);
}
} // namespace gtirb_pprint

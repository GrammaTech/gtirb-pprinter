#include "PrettyPrinter.h"
#include <capstone/capstone.h>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>
#include <gsl/gsl>
#include <gtirb/gtirb.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>
#include <variant>
#include "DisasmData.h"

using namespace std::rel_ops;

///
/// Pring a comment that automatically scopes.
///
class BlockAreaComment {
public:
  BlockAreaComment(std::stringstream& ss, std::string m = std::string{},
                   std::function<void()> f = []() {})
      : ofs{ss}, message{std::move(m)}, func{std::move(f)} {
    ofs << std::endl;

    if (message.empty() == false) {
      ofs << "# BEGIN - " << this->message << std::endl;
    }

    func();
  }

  ~BlockAreaComment() {
    func();

    if (message.empty() == false) {
      ofs << "# END   - " << this->message << std::endl;
    }

    ofs << std::endl;
  }

  std::stringstream& ofs;
  const std::string message;
  std::function<void()> func;
};

std::string str_tolower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return std::tolower(c); } // correct
  );
  return s;
}

std::string str_toupper(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return std::toupper(c); } // correct
  );
  return s;
}

PrettyPrinter::PrettyPrinter() {
  assert(cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle) == CS_ERR_OK);
}

PrettyPrinter::~PrettyPrinter() { cs_close(&this->csHandle); }

void PrettyPrinter::setDebug(bool x) { this->debug = x; }

bool PrettyPrinter::getDebug() const { return this->debug; }

std::string PrettyPrinter::prettyPrint(gtirb::Context& context, gtirb::IR* ir) {
  this->disasm = std::make_unique<DisasmData>(context, ir);
  this->ofs.clear();

  this->printHeader();

  for (const auto& b : gtirb::blocks(this->disasm->ir.modules()[0].getCFG())) {
    this->printBlock(b);
  }

  this->printDataGroups();

  this->printBSS();

  this->disasm.release();

  return this->ofs.str();
}

void PrettyPrinter::printHeader() {
  this->printBar();
  this->ofs << ".intel_syntax noprefix" << std::endl;
  this->printBar();
  this->ofs << "" << std::endl;

  for (int i = 0; i < 8; i++) {
    this->ofs << PrettyPrinter::StrNOP << std::endl;
  }
}

void PrettyPrinter::printBlock(const gtirb::Block& x) {
  if (this->skipEA(x.getAddress())) {
    return;
  }

  this->condPrintSectionHeader(x);
  this->printFunctionHeader(x.getAddress());
  this->printLabel(x.getAddress());
  this->ofs << std::endl;

  cs_insn* insn;
  cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);

  auto bytes2 = getBytes(this->disasm->ir.modules()[0].getImageByteMap(), x);
  size_t count = cs_disasm(this->csHandle, reinterpret_cast<const uint8_t*>(&bytes2[0]),
                           bytes2.size(), uint64_t(x.getAddress()), 0, &insn);

  // Exception-safe cleanup of instructions
  std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> freeInsn(
      insn, [count](cs_insn* i) { cs_free(i, count); });

  for (size_t i = 0; i < count; i++) {
    this->printInstruction(insn[i]);
  }
}

void PrettyPrinter::condPrintSectionHeader(const gtirb::Block& x) {
  const auto name = this->disasm->getSectionName(x.getAddress());

  if (!name.empty()) {
    this->printSectionHeader(name);
    return;
  }
}

void PrettyPrinter::printSectionHeader(const std::string& x, uint64_t alignment) {
  ofs << std::endl;
  this->printBar();

  if (x == PrettyPrinter::StrSectionText) {
    ofs << PrettyPrinter::StrSectionText << std::endl;
  } else if (x == PrettyPrinter::StrSectionBSS) {
    ofs << PrettyPrinter::StrSectionBSS << std::endl;
    this->ofs << ".align " << alignment << std::endl;
  } else {
    this->ofs << PrettyPrinter::StrSection << " " << x << std::endl;

    if (alignment != 0) {
      this->ofs << ".align " << alignment << std::endl;
    }
  }

  this->printBar();
  ofs << std::endl;
}

void PrettyPrinter::printBar(bool heavy) {
  if (heavy == true) {
    this->ofs << "#===================================" << std::endl;
  } else {
    this->ofs << "#-----------------------------------" << std::endl;
  }
}

void PrettyPrinter::printFunctionHeader(gtirb::Addr ea) {
  const auto name = this->disasm->getFunctionName(ea);

  if (name.empty() == false) {
    const auto bac =
        BlockAreaComment(this->ofs, "Function Header", [this]() { this->printBar(false); });

    // enforce maximum alignment
    auto x = uint64_t(ea);
    if (x % 8 == 0) {
      this->ofs << ".align 8" << std::endl;
    } else if (x % 2 == 0) {
      this->ofs << ".align 2" << std::endl;
    }

    this->ofs << PrettyPrinter::StrSectionGlobal << " " << name << std::endl;
    this->ofs << PrettyPrinter::StrSectionType << " " << name << ", @function" << std::endl;
    this->ofs << name << ":" << std::endl;
  }
}

void PrettyPrinter::printLabel(gtirb::Addr ea) {
  this->condPrintGlobalSymbol(ea);
  this->ofs << ".L_" << std::hex << uint64_t(ea) << ":" << std::dec;
}

void PrettyPrinter::condPrintGlobalSymbol(gtirb::Addr ea) {
  auto name = this->disasm->getGlobalSymbolName(ea);

  if (name.empty() == false) {
    this->ofs << name << ":" << std::endl;
  }
}

void PrettyPrinter::printInstruction(const cs_insn& inst) {
  gtirb::Addr ea(inst.address);
  this->printEA(ea);
  auto opcode = str_tolower(inst.mnemonic);

  ////////////////////////////////////////////////////////////////////
  // special cases

  if (opcode == std::string{"nop"}) {
    for (uint64_t i = 0; i < inst.size; ++i)
      this->ofs << " " << opcode << std::endl;
    return;
  }

  // // MOVS and CMPS have the operand implicit but size suffix
  // if ((boost::algorithm::ends_with(opcode, std::string{"movs"}) ||
  //      boost::algorithm::ends_with(opcode, std::string{"cmps"})) &&
  //     operands[1] == 0 && operands[2] == 0) {
  //   auto opInd = this->disasm->getOpIndirect(operands[0]);

  //   if (opInd != nullptr) {
  //     // do not print the first operand
  //     operands[0] = 0;
  //     opcode = opcode + disasm->GetSizeSuffix(*opInd);
  //   }
  // }

  // // FDIV_TO, FMUL_TO, FSUBR_TO, etc.
  // if (boost::algorithm::ends_with(opcode, std::string{"_to"})) {
  //   opcode = boost::replace_all_copy(opcode, "_to", "");
  //   operands[1] = operands[0];
  //   operands[0] = disasm->getOpRegdirectCode("ST");
  //   assert(false);
  // }
  // if (boost::algorithm::starts_with(opcode, std::string{"fcmov"})) {
  //   operands[1] = operands[0];
  //   operands[0] = disasm->getOpRegdirectCode("ST");
  //   assert(false);
  // }
  // // for 'loop' with rcx, the operand is implicit
  // if (boost::algorithm::starts_with(opcode, std::string{"loop"})) {
  //   auto reg = disasm->getOpRegdirect(operands[0]);
  //   if (reg != nullptr && reg->Register == std::string{"RCX"}) {
  //     operands[0] = 0;
  //     assert(false);
  //   }
  // }

  //////////////////////////////////////////////////////////////////////
  opcode = DisasmData::AdaptOpcode(opcode);
  this->ofs << "  " << opcode << " ";
  this->printOperandList(opcode, ea, inst);

  /// TAKE THIS OUT ///
  this->ofs << std::endl;
}

void PrettyPrinter::printInstructionNop() { this->ofs << PrettyPrinter::StrNOP << std::endl; }

void PrettyPrinter::printEA(gtirb::Addr ea) {
  this->ofs << "          ";

  if (this->getDebug() == true) {
    this->ofs << std::hex << uint64_t(ea) << ": " << std::dec;
  }
}

void PrettyPrinter::printOperandList(const std::string& opcode, const gtirb::Addr ea,
                                     const cs_insn& inst) {
  std::string str_operands[4];

  auto& detail = inst.detail->x86;
  const auto& module = this->disasm->ir.modules()[0];
  auto findSymbolic = [&module, &detail, ea](int index) {
    // FIXME: we're faking the operand offset here, assuming it's equal
    // to index. This works as long as the disassembler does the same
    // thing, but it isn't right.

    // Note: disassembler currently puts the dest operand last and uses
    // 1-based operand indices. Capstone puts the dest first and uses
    // zero-based indices. Translate here.
    if (index == 0) {
      index = detail.op_count - 1;
    } else {
      index--;
    }
    index++;

    if (auto found = module.findSymbolicExpression(ea + index);
        found != module.symbolic_expr_end()) {
      return &*found;
    } else {
      return static_cast<const gtirb::SymbolicExpression*>(nullptr);
    }
  };

  auto opCount = detail.op_count;
  // Operands are implicit for various MOVS* instructions. But there is also
  // an SSE2 instruction named MOVSD which has explicit operands.
  if ((inst.id == X86_INS_MOVSB || inst.id == X86_INS_MOVSW || inst.id == X86_INS_MOVSD ||
       inst.id == X86_INS_MOVSQ) &&
      inst.detail->groups[0] != X86_GRP_SSE2) {
    opCount = 0;
  }

  for (int i = 0; i < opCount; i++) {
    if (i != 0) {
      this->ofs << ",";
    }
    this->ofs << this->buildOperand(opcode, findSymbolic(i), inst, ea, i);
  }
}

std::string PrettyPrinter::buildOperand(const std::string& opcode,
                                        const gtirb::SymbolicExpression* symbolic,
                                        const cs_insn& inst, gtirb::Addr ea, uint64_t index) {
  const auto& op = inst.detail->x86.operands[index];
  switch (op.type) {
  case X86_OP_REG:
    return this->buildOpRegdirect(op);
  case X86_OP_IMM:
    return this->buildOpImmediate(opcode, symbolic, inst, ea, index);
    break;
  case X86_OP_MEM:
    return this->buildOpIndirect(symbolic, inst, ea, index);
  case X86_OP_FP:
    std::cerr << "floating point operations not implemented\n";
    exit(1);
  case X86_OP_INVALID:
    std::cerr << "invalid operand\n";
    exit(1);
  }

  return {};
}

std::string PrettyPrinter::buildOpRegdirect(const cs_x86_op& op) {
  assert(op.type == X86_OP_REG);
  return DisasmData::AdaptRegister(str_toupper(cs_reg_name(this->csHandle, op.reg)));
}

std::string PrettyPrinter::buildOpImmediate(const std::string& opcode,
                                            const gtirb::SymbolicExpression* symbolic,
                                            const cs_insn& inst, gtirb::Addr ea, uint64_t index) {
  const auto& detail = inst.detail->x86;
  const auto& op = detail.operands[index];

  // Correct sign of the immediate.
  // Capstone seems to take the original bytes and pad them with zeroes to
  // fill an int64_t. But that doesn't preserve the sign, so e.g. -1 (1 byte)
  // becomes 255 (2 bytes).
  // Casting to the correct type and then storing back into an int64_t yields
  // the correct result.
  int64_t imm;
  switch (op.size) {
  case 1:
    imm = int8_t(op.imm);
    break;
  case 2:
    imm = int16_t(op.imm);
    break;
  case 4:
    imm = int32_t(op.imm);
    break;
  default:
    imm = op.imm;
  }

  assert(op.type == X86_OP_IMM);
  if (symbolic) {
    const auto& pltReferences = std::get<std::map<gtirb::Addr, gtirb::table::ValueType>>(
        *this->disasm->ir.getTable("pltCodeReferences"));
    const auto p = pltReferences.find(gtirb::Addr(ea));
    if (p != pltReferences.end()) {
      return PrettyPrinter::StrOffset + " " + std::get<std::string>(p->second);
    }

    if (auto* s = std::get_if<gtirb::SymAddrConst>(symbolic); s != nullptr) {
      auto* sym = s->Sym.get(this->disasm->context);
      if (opcode == "call") {
        assert(s->Displacement == 0);
        if (this->skipEA(gtirb::Addr(imm))) {
          return std::to_string(imm);
        } else {
          return sym->getName();
        }
      }

      if (s->Displacement == 0) {
        if (detail.op_count == 1 || index == 1) {
          auto ref = this->disasm->getGlobalSymbolReference(gtirb::Addr(imm));
          if (ref.empty() == false) {
            return PrettyPrinter::StrOffset + " " + ref;
          } else {
            return PrettyPrinter::StrOffset + " " + GetSymbolToPrint(gtirb::Addr(imm));
          }
        }

        return GetSymbolToPrint(gtirb::Addr(imm));
      } else {
        std::stringstream ss;
        ss << PrettyPrinter::StrOffset << " " << sym->getName() << "+" << s->Displacement;
        return ss.str();
      }
    }
  }

  return std::to_string(imm);
}

std::string PrettyPrinter::buildOpIndirect(const gtirb::SymbolicExpression* symbolic,
                                           const cs_insn& inst, gtirb::Addr ea, uint64_t index) {
  const auto& detail = inst.detail->x86;
  const auto& op = detail.operands[index];
  assert(op.type == X86_OP_MEM);
  const auto sizeName = DisasmData::GetSizeName(op.size * 8);

  auto baseReg =
      str_toupper(op.mem.base == X86_REG_INVALID ? "" : cs_reg_name(this->csHandle, op.mem.base));
  auto indexReg =
      str_toupper(op.mem.index == X86_REG_INVALID ? "" : cs_reg_name(this->csHandle, op.mem.index));

  auto putSegmentRegister = [this, op](const std::string& term) {
    if (op.mem.segment != X86_REG_INVALID) {
      return str_toupper(cs_reg_name(this->csHandle, op.mem.segment)) + ":[" + term + "]";
    }

    return "[" + term + "]";
  };

  // Case 1
  if (op.mem.disp == 0) {
    if (op.mem.segment == X86_REG_INVALID && op.mem.base == X86_REG_INVALID &&
        op.mem.index == X86_REG_INVALID) {
      return sizeName + std::string{" [0]"};
    }
  }

  // Case 2
  if (baseReg == std::string{"RIP"} && op.mem.scale == 1) {
    if (op.mem.segment == X86_REG_INVALID && op.mem.index == X86_REG_INVALID) {
      if (std::get_if<gtirb::SymAddrConst>(symbolic) != nullptr) {
        auto address = ea + op.mem.disp + inst.size;
        auto symbol = this->disasm->getGlobalSymbolReference(address);

        if (!symbol.empty()) {
          return sizeName + " " + symbol + PrettyPrinter::StrRIP;
        } else {
          auto symbolToPrint = GetSymbolToPrint(address);
          return sizeName + " " + symbolToPrint + PrettyPrinter::StrRIP;
        }
      }
    }
  }

  // Case 3
  if (op.mem.base != X86_REG_INVALID && op.mem.index == X86_REG_INVALID && op.mem.disp == 0) {
    auto adapted = DisasmData::AdaptRegister(baseReg);
    return sizeName + " " + putSegmentRegister(adapted);
  }

  // Case 4
  if (op.mem.base == X86_REG_INVALID && op.mem.index == X86_REG_INVALID) {
    auto symbol = this->disasm->getGlobalSymbolReference(gtirb::Addr(op.mem.disp));
    if (symbol.empty() == false) {
      return sizeName + putSegmentRegister(symbol);
    }

    auto [offset, sign] = this->getOffsetAndSign(symbolic, op.mem.disp);
    std::string term = std::string{sign} + offset;
    return sizeName + " " + putSegmentRegister(term);
  }

  // Case 5
  if (op.mem.index == X86_REG_INVALID) {
    auto adapted = DisasmData::AdaptRegister(baseReg);
    auto [offset, sign] = this->getOffsetAndSign(symbolic, op.mem.disp);
    std::string term = adapted + std::string{sign} + offset;
    return sizeName + " " + putSegmentRegister(term);
  }

  // Case 6
  if (op.mem.base == X86_REG_INVALID) {
    auto adapted = DisasmData::AdaptRegister(indexReg);
    auto [offset, sign] = this->getOffsetAndSign(symbolic, op.mem.disp);
    std::string term = adapted + "*" + std::to_string(op.mem.scale) + std::string{sign} + offset;
    return sizeName + " " + putSegmentRegister(term);
  }

  // Case 7
  if (op.mem.disp == 0) {
    auto adapted1 = DisasmData::AdaptRegister(baseReg);
    auto adapted2 = DisasmData::AdaptRegister(indexReg);
    std::string term = adapted1 + "+" + adapted2 + "*" + std::to_string(op.mem.scale);
    return sizeName + " " + putSegmentRegister(term);
  }

  // Case 8
  auto adapted1 = DisasmData::AdaptRegister(baseReg);
  auto adapted2 = DisasmData::AdaptRegister(indexReg);
  auto [offset, sign] = this->getOffsetAndSign(symbolic, op.mem.disp);
  std::string term =
      adapted1 + "+" + adapted2 + "*" + std::to_string(op.mem.scale) + std::string{sign} + offset;
  return sizeName + " " + putSegmentRegister(term);
}

void PrettyPrinter::printDataGroups() {
  auto& ir = this->disasm->ir;
  const auto& module = ir.modules()[0];

  const auto& pltReferences =
      std::get<std::map<gtirb::Addr, gtirb::table::ValueType>>(*ir.getTable("pltDataReferences"));
  const auto& stringEAs = std::get<std::vector<gtirb::Addr>>(*ir.getTable("stringEAs"));

  for (auto& ds : this->disasm->getDataSections()) {
    auto sectionPtr = this->disasm->getSection(std::get<std::string>(ds["name"]));

    std::vector<const gtirb::DataObject*> dataGroups;
    for (auto i : std::get<std::vector<gtirb::UUID>>(ds["dataGroups"])) {
      auto* d = gtirb::NodeRef<gtirb::DataObject>(i).get(this->disasm->context);
      dataGroups.push_back(d);
    }

    if (isSectionSkipped(sectionPtr->getName()) && !this->debug)
      continue;

    // Print section header...
    this->printSectionHeader(sectionPtr->getName(), std::get<int64_t>(ds["alignment"]));

    // Print data for this section...
    for (auto dg = std::begin(dataGroups); dg != std::end(dataGroups); ++dg) {
      bool exclude = false;
      auto* data = *dg;
      auto foundSymbol = module.findSymbols(data->getAddress());

      if (sectionPtr->getName() == ".init_array" || sectionPtr->getName() == ".fini_array") {
        auto dgNext = dg;
        dgNext++;

        if (dgNext != std::end(dataGroups)) {
          exclude = this->getIsPointerToExcludedCode(foundSymbol.empty(), module, *dg, *dgNext);
        } else {
          exclude = this->getIsPointerToExcludedCode(foundSymbol.empty(), module, *dg, nullptr);
        }
      }

      if (exclude == false) {
        auto printTab = [this, &data]() {
          this->ofs << PrettyPrinter::StrTab;

          if (this->debug == true) {
            this->ofs << std::hex << uint64_t(data->getAddress()) << std::dec << ":";
          }
        };

        // Print all symbols
        for (const auto& s : foundSymbol) {
          this->ofs << s.getName() << ":\n";
        }
        // Also print local label just in case. There is still some code that makes up
        // ".L_<ea>" references without having a corresponding symbol.
        if (!foundSymbol.empty()) {
          this->ofs << ".L_" << std::hex << uint64_t(data->getAddress()) << ":\n" << std::dec;
        }

        const auto& foundSymbolic = module.findSymbolicExpression(data->getAddress());
        const auto p = pltReferences.find(data->getAddress());
        if (p != pltReferences.end()) {
          printTab();
          this->printEA(p->first);
          this->ofs << ".quad " << std::get<std::string>(p->second);
          this->ofs << std::endl;
        } else if (std::find(stringEAs.begin(), stringEAs.end(), data->getAddress()) !=
                   stringEAs.end()) {
          printTab();
          this->printString(*data);
          this->ofs << std::endl;
        } else if (foundSymbolic != module.symbolic_expr_end()) {
          if (auto* s = std::get_if<gtirb::SymAddrConst>(&*foundSymbolic); s != nullptr) {
            auto* sym = s->Sym.get(this->disasm->context);
            printTab();
            if (s->Displacement != 0)
              this->ofs << ".quad " << sym->getName() << "+" << s->Displacement;
            else
              this->ofs << ".quad " << sym->getName();
            this->ofs << std::endl;
          } else if (auto* sa = std::get_if<gtirb::SymAddrAddr>(&*foundSymbolic); sa != nullptr) {
            auto* sym1 = sa->Sym1.get(this->disasm->context);
            auto* sym2 = sa->Sym2.get(this->disasm->context);
            printTab();
            this->printEA(data->getAddress());
            this->ofs << ".long " << sym1->getName() << "-" << sym2->getName();
            this->ofs << std::endl;
          }
        } else {
          for (auto byte : getBytes(this->disasm->ir.modules()[0].getImageByteMap(), *data)) {
            printTab();
            this->ofs << ".byte 0x" << std::hex << static_cast<uint32_t>(byte) << std::dec;
            this->ofs << std::endl;
          }
        }
      }
    }

    // End label
    const auto endAddress = addressLimit(*sectionPtr);
    std::string next_section = this->disasm->getSectionName(endAddress);
    if (next_section.empty() == true ||
        (next_section != StrSectionBSS && getDataSectionDescriptor(next_section) == nullptr)) {
      // This is no the start of a new section, so print the label.
      this->printLabel(endAddress);
      this->ofs << std::endl;
    }
  }
}

void PrettyPrinter::printString(const gtirb::DataObject& x) {
  auto cleanByte = [](uint8_t b) {
    std::string cleaned;
    cleaned += b;
    cleaned = boost::replace_all_copy(cleaned, "\\", "\\\\");
    cleaned = boost::replace_all_copy(cleaned, "\"", "\\\"");
    cleaned = boost::replace_all_copy(cleaned, "\n", "\\n");
    cleaned = boost::replace_all_copy(cleaned, "\t", "\\t");
    cleaned = boost::replace_all_copy(cleaned, "\v", "\\v");
    cleaned = boost::replace_all_copy(cleaned, "\b", "\\b");
    cleaned = boost::replace_all_copy(cleaned, "\r", "\\r");
    cleaned = boost::replace_all_copy(cleaned, "\a", "\\a");
    cleaned = boost::replace_all_copy(cleaned, "\'", "\\'");

    return cleaned;
  };

  this->ofs << ".string \"";

  for (auto& b : getBytes(this->disasm->ir.modules()[0].getImageByteMap(), x)) {
    if (b != std::byte(0)) {
      this->ofs << cleanByte(uint8_t(b));
    }
  }

  this->ofs << "\"";
}

void PrettyPrinter::printBSS() {
  auto bssSection = this->disasm->getSection(PrettyPrinter::StrSectionBSS);

  if (bssSection != nullptr) {
    this->printSectionHeader(PrettyPrinter::StrSectionBSS, 16);
    const auto& bssData = std::get<std::vector<gtirb::UUID>>(*this->disasm->ir.getTable("bssData"));

    // Special case.
    if (!bssData.empty() &&
        gtirb::NodeRef<gtirb::DataObject>(bssData.at(0)).get(this->disasm->context)->getAddress() !=
            bssSection->getAddress()) {
      const auto current = bssSection->getAddress();
      const auto next =
          gtirb::NodeRef<gtirb::DataObject>(bssData.at(0)).get(this->disasm->context)->getAddress();

      this->printLabel(current);
      this->ofs << " .zero " << next - current;
    }
    this->ofs << std::endl;

    for (size_t i = 0; i < bssData.size(); ++i) {
      const auto& current =
          *gtirb::NodeRef<gtirb::DataObject>(bssData.at(i)).get(this->disasm->context);
      this->printLabel(current.getAddress());

      if (current.getSize() == 0) {
        this->ofs << "\n";
      } else {
        this->ofs << " .zero " << current.getSize() << "\n";
      }
    }

    this->printLabel(addressLimit(*bssSection));
    this->ofs << std::endl;
  }
}

bool PrettyPrinter::skipEA(const gtirb::Addr x) const {
  if (this->debug == false) {
    for (const auto& s : this->disasm->getSections()) {
      const auto found = std::find(std::begin(PrettyPrinter::AsmSkipSection),
                                   std::end(PrettyPrinter::AsmSkipSection), s.getName());

      if (found != std::end(PrettyPrinter::AsmSkipSection) && containsAddr(s, gtirb::Addr(x))) {
        return true;
      }
    }

    gtirb::Addr xFunctionAddress{0};
    const auto functionEntries =
        std::get<std::vector<gtirb::Addr>>(*this->disasm->ir.getTable("functionEntry"));

    for (auto fe = std::begin(functionEntries); fe != std::end(functionEntries); ++fe) {
      auto feNext = fe;
      feNext++;

      if (x >= *fe && x < *feNext) {
        xFunctionAddress = *fe;
        continue;
      }
    }

    std::string xFunctionName{};
    for (const auto& sym :
         this->disasm->ir.modules()[0].findSymbols(gtirb::Addr(xFunctionAddress))) {
      if (this->disasm->isFunction(sym)) {
        xFunctionName = sym.getName();
        break;
      }
    }

    // if we have a function address.
    // and that funciton address has a name.
    // is that name in our skip list?

    if (xFunctionName.empty() == false) {
      const auto found = std::find(std::begin(PrettyPrinter::AsmSkipFunction),
                                   std::end(PrettyPrinter::AsmSkipFunction), xFunctionName);
      return found != std::end(PrettyPrinter::AsmSkipFunction);
    }
  }

  return false;
}

void PrettyPrinter::printZeros(uint64_t x) {
  for (uint64_t i = 0; i < x; i++) {
    this->ofs << PrettyPrinter::StrZeroByte << std::endl;
  }
}

std::pair<std::string, char>
PrettyPrinter::getOffsetAndSign(const gtirb::SymbolicExpression* symbolic, int64_t offset) const {
  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic); s != nullptr) {
    auto* sym = s->Sym.get(this->disasm->context);
    if (s->Displacement == 0) {
      return {sym->getName(), '+'};
    } else if (s->Displacement > 0) {
      return {sym->getName() + "+" + std::to_string(s->Displacement), '+'};
    } else {
      return {sym->getName() + std::to_string(s->Displacement), '+'};
    }
  }

  if (offset < 0) {
    return {std::to_string(-offset), '-'};
  }
  return {std::to_string(offset), '+'};
}

bool PrettyPrinter::getIsPointerToExcludedCode(bool hasLabel, const gtirb::Module& module,
                                               const gtirb::DataObject* dg,
                                               const gtirb::DataObject* dgNext) {
  // If we have a label followed by a pointer.
  if (hasLabel && dgNext) {
    if (auto foundSymbolic = module.findSymbolicExpression(dgNext->getAddress());
        foundSymbolic != module.symbolic_expr_end()) {
      if (auto* s = std::get_if<gtirb::SymAddrConst>(&*foundSymbolic); s != nullptr) {
        auto* sym = s->Sym.get(this->disasm->context);
        return this->skipEA(sym->getAddress());
      }
    }
  }

  // Or if we just have a pointer...
  if (auto foundSymbolic = module.findSymbolicExpression(dg->getAddress());
      foundSymbolic != module.symbolic_expr_end()) {
    if (auto* s = std::get_if<gtirb::SymAddrConst>(&*foundSymbolic)) {
      auto* sym = s->Sym.get(this->disasm->context);
      return this->skipEA(sym->getAddress());
    }
  }

  return false;
}

std::string PrettyPrinter::GetSymbolToPrint(gtirb::Addr x) {
  std::stringstream ss;
  ss << ".L_" << std::hex << uint64_t(x) << std::dec;
  return ss.str();
}

int64_t PrettyPrinter::GetNeededPadding(int64_t alignment, int64_t currentAlignment,
                                        int64_t requiredAlignment) {
  if (alignment >= currentAlignment) {
    return alignment - currentAlignment;
  }

  return (alignment + requiredAlignment) - currentAlignment;
}

bool PrettyPrinter::GetIsNullReg(const std::string& x) {
  const std::vector<std::string> adapt{"NullReg64", "NullReg32", "NullReg16", "NullSReg"};

  const auto found = std::find(std::begin(adapt), std::end(adapt), x);
  return (found != std::end(adapt));
}

bool PrettyPrinter::isSectionSkipped(const std::string& name) {
  const auto foundSkipSection = std::find(std::begin(PrettyPrinter::AsmSkipSection),
                                          std::end(PrettyPrinter::AsmSkipSection), name);
  return foundSkipSection != std::end(PrettyPrinter::AsmSkipSection);
}

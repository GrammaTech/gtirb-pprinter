#include "PrettyPrinter.h"
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

PrettyPrinter::PrettyPrinter() {}

void PrettyPrinter::setDebug(bool x) { this->debug = x; }

bool PrettyPrinter::getDebug() const { return this->debug; }

std::string PrettyPrinter::prettyPrint(DisasmData* x) {
  this->disasm = x;
  this->ofs.clear();

  this->printHeader();

  // Make a vector of block pointers so we can modify it in AdjustPadding
  // below. It would probably be better for AdjustPadding to modify the CFG.
  auto blockRange = gtirb::blocks(this->disasm->ir.getModules()[0].getCFG());
  std::vector<gtirb::Block*> blocks;
  std::transform(blockRange.begin(), blockRange.end(), std::back_inserter(blocks),
                 [](auto& b) { return &b; });

  if (this->getDebug() == true) {
    DisasmData::AdjustPadding(blocks);
  }

  for (const auto* b : blocks) {
    this->printBlock(*b);
  }

  this->printDataGroups();

  this->printBSS();

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
  if (this->skipEA(x.getAddress()) == false) {
    const auto& table = std::get<std::map<gtirb::UUID, gtirb::table::ValueType>>(
        *this->disasm->ir.getTable("blockInstructions"));
    auto blockInfo = table.find(x.getUUID());
    if (blockInfo != table.end()) {
      this->condPrintSectionHeader(x);
      this->printFunctionHeader(x.getAddress());
      this->printLabel(x.getAddress());
      this->ofs << std::endl;

      // Reconstruct a vector of EAs from raw bytes stored in the table.
      auto bytes = std::get<std::string>(blockInfo->second);
      std::vector<gtirb::Addr> instructions(bytes.size() / sizeof(gtirb::Addr));
      memcpy(instructions.data(), bytes.data(), bytes.size());
      for (const auto& inst : instructions) {
        this->printInstruction(inst);
      }
    } else {
      const auto nopCount = x.getSize();
      this->ofs << std::endl;

      const auto bac = BlockAreaComment(this->ofs, "No instruciton padding.");

      // Fill in the correct number of nops.
      for (uint64_t i = 0; i < nopCount; ++i) {
        this->printInstructionNop();
      }
    }
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

void PrettyPrinter::printInstruction(gtirb::Addr ea) {
  this->printEA(ea);
  auto inst = this->disasm->getDecodedInstruction(ea);
  auto prefix = inst->Prefix;
  auto opcode = str_tolower(inst->Opcode);
  uint64_t operands[4] = {inst->Op1, inst->Op2, inst->Op3, inst->Op4};

  ////////////////////////////////////////////////////////////////////
  // special cases

  if (opcode == std::string{"nop"}) {
    for (uint64_t i = 0; i < inst->Size; ++i)
      this->ofs << " " << opcode << std::endl;
    return;
  }

  // MOVS and CMPS have the operand implicit but size suffix
  if ((boost::algorithm::ends_with(opcode, std::string{"movs"}) ||
       boost::algorithm::ends_with(opcode, std::string{"cmps"})) &&
      operands[1] == 0 && operands[2] == 0) {
    auto opInd = this->disasm->getOpIndirect(operands[0]);

    if (opInd != nullptr) {
      // do not print the first operand
      operands[0] = 0;
      opcode = opcode + disasm->GetSizeSuffix(*opInd);
    }
  }

  // FDIV_TO, FMUL_TO, FSUBR_TO, etc.
  if (boost::algorithm::ends_with(opcode, std::string{"_to"})) {
    opcode = boost::replace_all_copy(opcode, "_to", "");
    operands[1] = operands[0];
    operands[0] = disasm->getOpRegdirectCode("ST");
  }
  if (boost::algorithm::starts_with(opcode, std::string{"fcmov"})) {
    operands[1] = operands[0];
    operands[0] = disasm->getOpRegdirectCode("ST");
  }
  // for 'loop' with rcx, the operand is implicit
  if (boost::algorithm::starts_with(opcode, std::string{"loop"})) {
    auto reg = disasm->getOpRegdirect(operands[0]);
    if (reg != nullptr && reg->Register == std::string{"RCX"}) {
      operands[0] = 0;
    }
  }
  // print a new line if there is a lock prefix
  if (prefix == std::string{"lock"}) {
    prefix = "lock\n";
  }
  //////////////////////////////////////////////////////////////////////
  opcode = DisasmData::AdaptOpcode(opcode);
  this->ofs << " " << prefix << " " << opcode << " ";
  this->printOperandList(opcode, ea, operands);

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
                                     const uint64_t* const operands) {
  std::string str_operands[4];

  const auto& symbolic = this->disasm->ir.getModules()[0].getSymbolicExpressions();
  auto findSymbolic = [&symbolic, ea](int index) {
    // FIXME: we're faking the operand offset here, assuming it's equal
    // to index. This works as long as the disassembler does the same
    // thing, but it isn't right.
    if (auto found = symbolic.find(ea + index); found != symbolic.end()) {
      return &found->second;
    } else {
      return static_cast<const gtirb::SymbolicExpression*>(nullptr);
    }
  };

  str_operands[0] = this->buildOperand(opcode, findSymbolic(1), operands[0], ea, 1);
  str_operands[1] = this->buildOperand(opcode, findSymbolic(2), operands[1], ea, 2);
  str_operands[2] = this->buildOperand(opcode, findSymbolic(3), operands[2], ea, 3);
  str_operands[3] = this->buildOperand(opcode, findSymbolic(4), operands[3], ea, 4);

  uint dest_op_idx = 0;
  for (int i = 3; i >= 0; --i) {
    if (str_operands[i].empty() == false) {
      dest_op_idx = i;
      break;
    }
  }
  // print destination operand
  if (str_operands[dest_op_idx].empty() == false)
    this->ofs << str_operands[dest_op_idx];
  // print source operands
  for (uint i = 0; i < dest_op_idx; ++i)
    if (str_operands[i].empty() == false)
      this->ofs << "," << str_operands[i];
}

std::string PrettyPrinter::buildOperand(const std::string& opcode,
                                        const gtirb::SymbolicExpression* symbolic, uint64_t operand,
                                        gtirb::Addr ea, uint64_t index) {
  auto opReg = this->disasm->getOpRegdirect(operand);
  if (opReg != nullptr) {
    return this->buildOpRegdirect(opReg, ea, index);
  }

  auto opImm = this->disasm->getOpImmediate(operand);
  if (opImm != nullptr) {
    return this->buildOpImmediate(opcode, symbolic, opImm, ea, index);
  }

  auto opInd = this->disasm->getOpIndirect(operand);
  if (opInd != nullptr) {
    return this->buildOpIndirect(symbolic, opInd, ea);
  }

  return std::string{};
}

std::string PrettyPrinter::buildOpRegdirect(const OpRegdirect* const op, gtirb::Addr /*ea*/,
                                            uint64_t /*index*/) {
  return DisasmData::AdaptRegister(op->Register);
}

std::string PrettyPrinter::buildOpImmediate(const std::string& opcode,
                                            const gtirb::SymbolicExpression* symbolic,
                                            const OpImmediate* const op, gtirb::Addr ea,
                                            uint64_t index) {
  if (symbolic) {
    const auto& pltReferences = std::get<std::map<gtirb::Addr, gtirb::table::ValueType>>(
        *this->disasm->ir.getTable("pltCodeReferences"));
    const auto p = pltReferences.find(gtirb::Addr(ea));
    if (p != pltReferences.end()) {
      return PrettyPrinter::StrOffset + " " + std::get<std::string>(p->second);
    }

    if (auto* s = std::get_if<gtirb::SymAddrConst>(symbolic); s != nullptr) {
      if (opcode == "call") {
        assert(s->Displacement == 0);
        if (this->skipEA(gtirb::Addr(op->Immediate))) {
          return std::to_string(op->Immediate);
        } else {
          return s->Sym->getName();
        }
      }

      if (s->Displacement == 0) {
        if (index == 1) {
          auto ref = this->disasm->getGlobalSymbolReference(gtirb::Addr(op->Immediate));
          if (ref.empty() == false) {
            return PrettyPrinter::StrOffset + " " + ref;
          } else {
            return PrettyPrinter::StrOffset + " " + GetSymbolToPrint(gtirb::Addr(op->Immediate));
          }
        }

        return GetSymbolToPrint(gtirb::Addr(op->Immediate));
      } else {
        std::stringstream ss;
        ss << PrettyPrinter::StrOffset << " " << s->Sym->getName() << "+" << s->Displacement;
        return ss.str();
      }
    }
  }

  return std::to_string(op->Immediate);
}

std::string PrettyPrinter::buildOpIndirect(const gtirb::SymbolicExpression* symbolic,
                                           const OpIndirect* const op, gtirb::Addr ea) {
  const auto sizeName = DisasmData::GetSizeName(op->Size);

  auto putSegmentRegister = [op](const std::string& term) {
    if (PrettyPrinter::GetIsNullReg(op->SReg) == false) {
      return op->SReg + ":[" + term + "]";
    }

    return "[" + term + "]";
  };

  // Case 1
  if (op->Offset == 0) {
    if (PrettyPrinter::GetIsNullReg(op->SReg) && PrettyPrinter::GetIsNullReg(op->Reg1) &&
        PrettyPrinter::GetIsNullReg(op->Reg2)) {
      return sizeName + std::string{" [0]"};
    }
  }

  // Case 2
  if (op->Reg1 == std::string{"RIP"} && op->Multiplier == 1) {
    if (PrettyPrinter::GetIsNullReg(op->SReg) && PrettyPrinter::GetIsNullReg(op->Reg2)) {
      if (std::get_if<gtirb::SymAddrConst>(symbolic) != nullptr) {
        auto instruction = this->disasm->getDecodedInstruction(ea);
        auto address = ea + op->Offset + instruction->Size;
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
  if (PrettyPrinter::GetIsNullReg(op->Reg1) == false &&
      PrettyPrinter::GetIsNullReg(op->Reg2) == true && op->Offset == 0) {
    auto adapted = DisasmData::AdaptRegister(op->Reg1);
    return sizeName + " " + putSegmentRegister(adapted);
  }

  // Case 4
  if (PrettyPrinter::GetIsNullReg(op->Reg1) == true &&
      PrettyPrinter::GetIsNullReg(op->Reg2) == true) {
    auto symbol = this->disasm->getGlobalSymbolReference(gtirb::Addr(op->Offset));
    if (symbol.empty() == false) {
      return sizeName + putSegmentRegister(symbol);
    }

    auto [offset, sign] = this->getOffsetAndSign(symbolic, op->Offset);
    std::string term = std::string{sign} + offset;
    return sizeName + " " + putSegmentRegister(term);
  }

  // Case 5
  if (PrettyPrinter::GetIsNullReg(op->Reg2) == true) {
    auto adapted = DisasmData::AdaptRegister(op->Reg1);
    auto [offset, sign] = this->getOffsetAndSign(symbolic, op->Offset);
    std::string term = adapted + std::string{sign} + offset;
    return sizeName + " " + putSegmentRegister(term);
  }

  // Case 6
  if (PrettyPrinter::GetIsNullReg(op->Reg1) == true) {
    auto adapted = DisasmData::AdaptRegister(op->Reg2);
    auto [offset, sign] = this->getOffsetAndSign(symbolic, op->Offset);
    std::string term = adapted + "*" + std::to_string(op->Multiplier) + std::string{sign} + offset;
    return sizeName + " " + putSegmentRegister(term);
  }

  // Case 7
  if (op->Offset == 0) {
    auto adapted1 = DisasmData::AdaptRegister(op->Reg1);
    auto adapted2 = DisasmData::AdaptRegister(op->Reg2);
    std::string term = adapted1 + "+" + adapted2 + "*" + std::to_string(op->Multiplier);
    return sizeName + " " + putSegmentRegister(term);
  }

  // Case 8
  auto adapted1 = DisasmData::AdaptRegister(op->Reg1);
  auto adapted2 = DisasmData::AdaptRegister(op->Reg2);
  auto [offset, sign] = this->getOffsetAndSign(symbolic, op->Offset);
  std::string term =
      adapted1 + "+" + adapted2 + "*" + std::to_string(op->Multiplier) + std::string{sign} + offset;
  return sizeName + " " + putSegmentRegister(term);
}

void PrettyPrinter::printDataGroups() {
  auto& ir = this->disasm->ir;

  const auto& pltReferences =
      std::get<std::map<gtirb::Addr, gtirb::table::ValueType>>(*ir.getTable("pltDataReferences"));
  const auto& stringEAs = std::get<std::vector<gtirb::Addr>>(*ir.getTable("stringEAs"));
  const auto& symbolic = ir.getModules()[0].getSymbolicExpressions();
  const auto& symbolSet = ir.getModules()[0].getSymbols();

  for (auto& ds : this->disasm->getDataSections()) {
    auto sectionPtr = this->disasm->getSection(std::get<std::string>(ds["name"]));

    std::vector<const gtirb::DataObject*> dataGroups;
    for (auto i : std::get<std::vector<gtirb::UUID>>(ds["dataGroups"])) {
      gtirb::DataObject* d = gtirb::NodeRef<gtirb::DataObject>(i);
      dataGroups.push_back(d);
    }

    if (isSectionSkipped(sectionPtr->getName()) && !this->debug)
      continue;

    // Print section header...
    this->printSectionHeader(sectionPtr->getName(), std::get<int64_t>(ds["alignment"]));

    // Print data for this section...
    for (auto dg = std::begin(dataGroups); dg != std::end(dataGroups); ++dg) {
      bool exclude = false;
      auto data = dynamic_cast<const gtirb::DataObject*>(*dg);
      auto foundSymbol = gtirb::findSymbols(symbolSet, data->getAddress());

      if (sectionPtr->getName() == ".init_array" || sectionPtr->getName() == ".fini_array") {
        auto dgNext = dg;
        dgNext++;

        if (dgNext != std::end(dataGroups)) {
          exclude = this->getIsPointerToExcludedCode(foundSymbol.empty(), symbolic, *dg, *dgNext);
        } else {
          exclude = this->getIsPointerToExcludedCode(foundSymbol.empty(), symbolic, *dg, nullptr);
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
        for (const auto s : foundSymbol) {
          this->ofs << s->getName() << ":\n";
        }
        // Also print local label just in case. There is still some code that makes up
        // ".L_<ea>" references without having a corresponding symbol.
        if (!foundSymbol.empty()) {
          this->ofs << ".L_" << std::hex << uint64_t(data->getAddress()) << ":\n" << std::dec;
        }

        const auto& foundSymbolic = symbolic.find(data->getAddress());
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
        } else if (foundSymbolic != symbolic.end()) {
          if (auto* s = std::get_if<gtirb::SymAddrConst>(&foundSymbolic->second); s != nullptr) {
            printTab();
            if (s->Displacement != 0)
                this->ofs << ".quad " << s->Sym->getName()<< "+"<< s->Displacement;
            else
                this->ofs << ".quad " << s->Sym->getName();
            this->ofs << std::endl;
          } else if (auto* sa = std::get_if<gtirb::SymAddrAddr>(&foundSymbolic->second);
                     sa != nullptr) {
            printTab();
            this->printEA(data->getAddress());
            this->ofs << ".long " << sa->Sym1->getName() << "-" << sa->Sym2->getName();
            this->ofs << std::endl;
          }
        } else {
          for (auto byte : getBytes(this->disasm->ir.getModules()[0].getImageByteMap(), *data)) {
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

  for (auto& b : getBytes(this->disasm->ir.getModules()[0].getImageByteMap(), x)) {
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
    if (!bssData.empty() && gtirb::NodeRef<gtirb::DataObject>(bssData.at(0))->getAddress() !=
                                bssSection->getAddress()) {
      const auto current = bssSection->getAddress();
      const auto next = gtirb::NodeRef<gtirb::DataObject>(bssData.at(0))->getAddress();

      this->printLabel(current);
      this->ofs << " .zero " << next - current;
    }
    this->ofs << std::endl;

    for (size_t i = 0; i < bssData.size(); ++i) {
      const auto& current = *gtirb::NodeRef<gtirb::DataObject>(bssData.at(i));
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
         gtirb::findSymbols(this->disasm->getSymbols(), gtirb::Addr(xFunctionAddress))) {
      if (this->disasm->isFunction(*sym)) {
        xFunctionName = sym->getName();
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
    if (s->Displacement == 0) {
      return {s->Sym->getName(), '+'};
    } else if (s->Displacement > 0) {
      return {s->Sym->getName() + "+" + std::to_string(s->Displacement), '+'};
    } else {
      return {s->Sym->getName() + std::to_string(s->Displacement), '+'};
    }
  }

  if (offset < 0) {
    return {std::to_string(-offset), '-'};
  }
  return {std::to_string(offset), '+'};
}

bool PrettyPrinter::getIsPointerToExcludedCode(bool hasLabel,
                                               const gtirb::SymbolicExpressionSet& symbolic,
                                               const gtirb::DataObject* dg,
                                               const gtirb::DataObject* dgNext) {
  // If we have a label followed by a pointer.
  if (hasLabel && dgNext) {
    if (auto foundSymbolic = symbolic.find(dgNext->getAddress()); foundSymbolic != symbolic.end()) {
      if (auto* sym = std::get_if<gtirb::SymAddrConst>(&foundSymbolic->second); sym != nullptr) {
        return this->skipEA(sym->Sym->getAddress());
      }
    }
  }

  // Or if we just have a pointer...
  if (auto foundSymbolic = symbolic.find(dg->getAddress()); foundSymbolic != symbolic.end()) {
    if (auto* sym = std::get_if<gtirb::SymAddrConst>(&foundSymbolic->second)) {
      return this->skipEA(sym->Sym->getAddress());
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

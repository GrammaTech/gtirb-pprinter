//===- PrettyPrinter.cpp ----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2018 GrammaTech, Inc.
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
#include "PrettyPrinter.h"
#include <capstone/capstone.h>
#include <boost/algorithm/string/replace.hpp>
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

template <class T> T* nodeFromUUID(gtirb::Context& C, gtirb::UUID id) {
  return dyn_cast_or_null<T>(gtirb::Node::getByUUID(C, id));
}

///
/// Print a comment that automatically scopes.
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
void PrettyPrinter::keepFunction(const std::string functionName){
    AsmSkipFunction.erase(functionName);
}
void PrettyPrinter::skipFunction(const std::string functionName){
    AsmSkipFunction.insert(functionName);
}
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
  if(!this->condPrintGlobalSymbol(ea))
      this->ofs << ".L_" << std::hex << uint64_t(ea) << ":" << std::dec;
}

bool PrettyPrinter::condPrintGlobalSymbol(gtirb::Addr ea) {
  bool printed=false;
  for (const auto& sym : this->disasm->ir.modules()[0].findSymbols(ea)) {
    auto name = this->disasm->getAdaptedSymbolName(&sym);
    if (!name.empty()){
      this->ofs << name << ":" << std::endl;
      printed=true;
    }
  }
  return printed;
}

void PrettyPrinter::printInstruction(const cs_insn& inst) {
  gtirb::Addr ea(inst.address);
  printComment(ea);
  this->printEA(ea);
  auto opcode = str_tolower(inst.mnemonic);

  ////////////////////////////////////////////////////////////////////
  // special cases

  if (opcode == std::string{"nop"}) {
    for (uint64_t i = 0; i < inst.size; ++i)
      this->ofs << " " << opcode << std::endl;
    return;
  }
  this->ofs << "  " << opcode << " ";
  this->printOperandList(opcode, ea, inst);

  /// TAKE THIS OUT ///
  this->ofs << std::endl;
}

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
    return this->buildOpIndirect(symbolic, inst, index);
  case X86_OP_INVALID:
    std::cerr << "invalid operand\n";
    exit(1);
  }

  return {};
}

std::string PrettyPrinter::buildOpRegdirect(const cs_x86_op& op) {
  assert(op.type == X86_OP_REG);
  return getRegisterName(op.reg);
}

std::string PrettyPrinter::buildOpImmediate(const std::string& opcode,
                                            const gtirb::SymbolicExpression* symbolic,
                                            const cs_insn& inst, gtirb::Addr ea, uint64_t index) {
  const auto& detail = inst.detail->x86;
  const auto& op = detail.operands[index];
  assert(op.type == X86_OP_IMM);

  // plt reference
  const auto& pltReferences =
      *this->disasm->ir.getAuxData("pltCodeReferences")->get<std::map<gtirb::Addr, std::string>>();
  const auto p = pltReferences.find(gtirb::Addr(ea));
  if (p != pltReferences.end()) {
    if(opcode == "call" || opcode == "jmp")
        return p->second+"@PLT";
    else
        return PrettyPrinter::StrOffset +" "+p->second;
  }
  // not symbolic
  if (!symbolic)
      return std::to_string(op.imm);

  // symbolic
  auto* s = std::get_if<gtirb::SymAddrConst>(symbolic);
  assert(s != nullptr);

  // the symbol points to a skipped destination
  if (this->skipEA(s->Sym->getAddress().value()))
      return std::to_string(op.imm);

  auto offsetLabel = opcode == "call" ? "" : PrettyPrinter::StrOffset;
  std::stringstream ss;
  ss << offsetLabel << " " << this->disasm->getAdaptedSymbolNameDefault(s->Sym)
     << getAddendString(s->Offset);
  return ss.str();
}

std::string PrettyPrinter::buildOpIndirect(const gtirb::SymbolicExpression* symbolic,
                                           const cs_insn& inst, uint64_t index) {
  const auto& detail = inst.detail->x86;
  const auto& op = detail.operands[index];
  assert(op.type == X86_OP_MEM);
  std::stringstream operandStream;
  bool first = true;
  const auto sizeName = DisasmData::GetSizeName(op.size * 8);
  operandStream << sizeName << " ";

  if (op.mem.segment != X86_REG_INVALID)
    operandStream << getRegisterName(op.mem.segment) << ":";

  operandStream << "[";

  if (op.mem.base != X86_REG_INVALID) {
    first = false;
    operandStream << getRegisterName(op.mem.base);
  }

  if (op.mem.index != X86_REG_INVALID) {

    if (!first)
      operandStream << "+";
    first = false;
    operandStream << getRegisterName(op.mem.index) << "*" << std::to_string(op.mem.scale);
  }

  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic); s != nullptr) {
      if(s->Sym->getAddress().has_value() && this->skipEA(s->Sym->getAddress().value())) {
             operandStream << getAddendString(op.mem.disp, first);
      } else {
          operandStream << "+";
          printSymbolicExpression(s, operandStream);
      }
  } else {
      operandStream << getAddendString(op.mem.disp, first);
  }
  operandStream << "]";
  return operandStream.str();
}

void PrettyPrinter::printDataGroups() {
  for (const auto& [name, alignment, dataIDs] : this->disasm->getDataSections()) {
    auto sectionPtr = this->disasm->getSection(name);

    std::vector<const gtirb::DataObject*> dataGroups;
    for (auto i : dataIDs) {
      dataGroups.push_back(nodeFromUUID<gtirb::DataObject>(this->disasm->context, i));
    }

    if (isSectionSkipped(sectionPtr->getName()))
      continue;

    // print header
    this->printSectionHeader(sectionPtr->getName(), alignment);
    // Print data for this section
    for (auto& dataGroup : dataGroups) {
      if (shouldExcludeDataElement(sectionPtr->getName(), *dataGroup))
        continue;
      printDataObject(*dataGroup);
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

bool PrettyPrinter::shouldExcludeDataElement(const std::string& sectionName,
                                             const gtirb::DataObject& dataGroup) {
  return (sectionName == ".init_array" || sectionName == ".fini_array") &&
         this->isPointerToExcludedCode(dataGroup);
}

bool PrettyPrinter::isPointerToExcludedCode(const gtirb::DataObject& dataGroup) {
  auto& ir = this->disasm->ir;
  const auto& module = ir.modules()[0];
  if (auto foundSymbolic = module.findSymbolicExpression(dataGroup.getAddress());
      foundSymbolic != module.symbolic_expr_end()) {
    if (auto* s = std::get_if<gtirb::SymAddrConst>(&*foundSymbolic)) {
      return this->skipEA(s->Sym->getAddress().value());
    }
  }
  return false;
}

void PrettyPrinter::printDataObject(const gtirb::DataObject& dataGroup) {
  auto& ir = this->disasm->ir;
  const auto& module = ir.modules()[0];
  const auto& stringEAs = *ir.getAuxData("stringEAs")->get<std::vector<gtirb::Addr>>();

  printComment(dataGroup.getAddress());
  printLabel(dataGroup.getAddress());
  this->ofs << PrettyPrinter::StrTab;
  if (this->debug)
    this->ofs << std::hex << uint64_t(dataGroup.getAddress()) << std::dec << ":";

  const auto& foundSymbolic = module.findSymbolicExpression(dataGroup.getAddress());
  if (foundSymbolic != module.symbolic_expr_end()) {
    printSymbolicData(dataGroup.getAddress(), &*foundSymbolic);
    this->ofs << std::endl;

  } else if (std::find(stringEAs.begin(), stringEAs.end(), dataGroup.getAddress()) !=
             stringEAs.end()) {
    this->printString(dataGroup);
    this->ofs << std::endl;

  } else {
    for (auto byte : getBytes(this->disasm->ir.modules()[0].getImageByteMap(), dataGroup)) {
      this->ofs << ".byte 0x" << std::hex << static_cast<uint32_t>(byte) << std::dec << std::endl;
    }
  }
}

void PrettyPrinter::printComment(const gtirb::Addr ea){
    if (!this->debug)
        return;
    const auto& comments = *this->disasm->ir.getAuxData("comments")->get<std::map<gtirb::Addr, std::string>>();
    const auto p = comments.find(ea);
    if (p != comments.end()) {
        this->ofs << "# "<< p->second <<std::endl;
    }
}

void PrettyPrinter::printSymbolicData(const gtirb::Addr addr,
                                      const gtirb::SymbolicExpression* symbolic) {
  const auto& pltReferences =
      *this->disasm->ir.getAuxData("pltDataReferences")->get<std::map<gtirb::Addr, std::string>>();

  const auto p = pltReferences.find(addr);
  if (p != pltReferences.end()) {
    this->ofs << ".quad " << p->second;

  } else if (auto* s = std::get_if<gtirb::SymAddrConst>(symbolic); s != nullptr) {

    this->ofs << ".quad ";
    printSymbolicExpression(s, this->ofs);
  } else if (auto* sa = std::get_if<gtirb::SymAddrAddr>(symbolic); sa != nullptr) {
    this->ofs << ".long ";
    printSymbolicExpression(sa, this->ofs);
  }
}

void PrettyPrinter::printSymbolicExpression(const gtirb::SymAddrConst* sexpr,
                                            std::stringstream& stream) {
  stream << this->disasm->getAdaptedSymbolNameDefault(sexpr->Sym);
  stream << getAddendString(sexpr->Offset);
}

void PrettyPrinter::printSymbolicExpression(const gtirb::SymAddrAddr* sexpr,
                                            std::stringstream& stream) {
  stream << sexpr->Sym1->getName() << "-" << sexpr->Sym2->getName();
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
    const auto& bssData = *this->disasm->ir.getAuxData("bssData")->get<std::vector<gtirb::UUID>>();

    // Special case.
    if (!bssData.empty() &&
        nodeFromUUID<gtirb::DataObject>(this->disasm->context, bssData.at(0))->getAddress() !=
            bssSection->getAddress()) {
      const auto current = bssSection->getAddress();
      const auto next =
          nodeFromUUID<gtirb::DataObject>(this->disasm->context, bssData.at(0))->getAddress();
      this->printLabel(current);
      this->ofs << " .zero " << next - current;
    }
    this->ofs << std::endl;

    for (size_t i = 0; i < bssData.size(); ++i) {
      const auto& current = *nodeFromUUID<gtirb::DataObject>(this->disasm->context, bssData.at(i));
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
  return !this->debug && (isInSkippedSection(x) || isInSkippedFunction(x));
}

bool PrettyPrinter::isInSkippedSection(const gtirb::Addr x) const {
  for (const auto& s : this->disasm->getSections()) {
    if (AsmSkipSection.count(s.getName()) && containsAddr(s, gtirb::Addr(x))) {
      return true;
    }
  }
  return false;
}

bool PrettyPrinter::isInSkippedFunction(const gtirb::Addr x) const {
  std::string xFunctionName = getContainerFunctionName(x);
  if (xFunctionName.empty())
    return false;
  return AsmSkipFunction.count(xFunctionName);
}

std::string PrettyPrinter::getContainerFunctionName(const gtirb::Addr x) const {
  gtirb::Addr xFunctionAddress{0};
  const auto functionEntries =
      *this->disasm->ir.getAuxData("functionEntry")->get<std::vector<gtirb::Addr>>();

  for (auto fe = std::begin(functionEntries); fe != std::end(functionEntries); ++fe) {
    auto feNext = fe;
    feNext++;

    if (x >= *fe && x < *feNext) {
      xFunctionAddress = *fe;
      continue;
    }
  }
  return this->disasm->getFunctionName(xFunctionAddress);
}

std::string PrettyPrinter::getRegisterName(unsigned int reg) {
  return DisasmData::AdaptRegister(
      str_toupper(reg == X86_REG_INVALID ? "" : cs_reg_name(this->csHandle, reg)));
}

std::string PrettyPrinter::getAddendString(int64_t number, bool first) {
  if (number < 0 || first)
    return std::to_string(number);
  if (number == 0)
    return std::string("");
  return "+" + std::to_string(number);
}

bool PrettyPrinter::isSectionSkipped(const std::string& name) {
  if (this->debug)
    return false;
  return AsmSkipSection.count(name);
}

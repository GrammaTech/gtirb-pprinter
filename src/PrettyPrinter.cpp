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
#include "DisasmData.h"
#include "string_utils.h"
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

using namespace std::rel_ops;

template <class T> T* nodeFromUUID(gtirb::Context& C, gtirb::UUID id) {
  return dyn_cast_or_null<T>(gtirb::Node::getByUUID(C, id));
}

///
/// Print a comment that automatically scopes.
///
class BlockAreaComment {
public:
  BlockAreaComment(std::ostream& ss, std::string m = std::string{},
                   std::function<void()> f = []() {})
      : ofs{ss}, message{std::move(m)}, func{std::move(f)} {
    ofs << '\n';

    if (message.empty() == false) {
      ofs << "# BEGIN - " << this->message << '\n';
    }

    func();
  }

  ~BlockAreaComment() {
    func();

    if (message.empty() == false) {
      ofs << "# END   - " << this->message << '\n';
    }

    ofs << '\n';
  }

  std::ostream& ofs;
  const std::string message;
  std::function<void()> func;
};

std::map<std::string, PrettyPrinter::factory>& PrettyPrinter::getFactories() {
  static std::map<std::string, PrettyPrinter::factory> factories;
  return factories;
}

bool PrettyPrinter::registerPrinter(std::initializer_list<const char*> flavor, factory f) {
  if (f) {
    for (const char* name : flavor)
      getFactories()[name] = f;
    return true;
  } else {
    for (const char* name : flavor)
      getFactories().erase(name);
    return false;
  }
}

std::set<std::string> PrettyPrinter::getRegisteredFlavors() {
  std::set<std::string> flavors;
  for (const std::pair<std::string, factory>& entry : getFactories())
    flavors.insert(entry.first);
  return flavors;
}

void PrettyPrinter::setFlavor(const std::string& flavor_name) {
  if (getFactories().find(flavor_name) == getFactories().end())
    throw std::out_of_range("unknown flavor");
  this->flavor = flavor_name;
}

std::string PrettyPrinter::getFlavor() const { return this->flavor; }

void PrettyPrinter::setDebug(bool x) { this->debug = x; }

bool PrettyPrinter::getDebug() const { return this->debug; }
void PrettyPrinter::keepFunction(const std::string functionName) {
  AsmSkipFunction.erase(functionName);
}
void PrettyPrinter::skipFunction(const std::string functionName) {
  AsmSkipFunction.insert(functionName);
}

std::unique_ptr<AbstractPP> PrettyPrinter::prettyPrint(gtirb::Context& context, gtirb::IR& ir) {
  return getFactories().at(flavor)(context, ir, AsmSkipFunction, debug);
}

AbstractPP::AbstractPP(gtirb::Context& context, gtirb::IR& ir,
                       const PrettyPrinter::string_range& skip_funcs, bool dbg)
    : AsmSkipFunction(skip_funcs.begin(), skip_funcs.end()), disasm(context, ir), debug(dbg) {
  assert(cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle) == CS_ERR_OK && "Capstone failure");
}

AbstractPP::~AbstractPP() { cs_close(&this->csHandle); }

std::optional<std::string> AbstractPP::getPltCodeSymName(gtirb::Addr ea) {
  const auto* pltReferences =
      getAuxData<std::map<gtirb::Addr, std::string>>(this->disasm.ir, "pltCodeReferences");
  if (pltReferences) {
    const auto p = pltReferences->find(gtirb::Addr(ea));
    if (p != pltReferences->end())
      return p->second;
  }
  return std::nullopt;
}

std::ostream& AbstractPP::print(std::ostream& os) {
  this->printHeader(os);

  for (const gtirb::Block& b : gtirb::blocks(this->disasm.ir.modules()[0].getCFG())) {
    this->printBlock(os, b);
  }

  this->printDataGroups(os);

  this->printBSS(os);

  return os;
}

void AbstractPP::printBlock(std::ostream& os, const gtirb::Block& x) {
  if (this->skipEA(x.getAddress())) {
    return;
  }

  this->condPrintSectionHeader(os, x);
  this->printFunctionHeader(os, x.getAddress());
  this->printLabel(os, x.getAddress());
  os << '\n';

  cs_insn* insn;
  cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);

  auto bytes2 = getBytes(this->disasm.ir.modules()[0].getImageByteMap(), x);
  size_t count = cs_disasm(this->csHandle, reinterpret_cast<const uint8_t*>(&bytes2[0]),
                           bytes2.size(), uint64_t(x.getAddress()), 0, &insn);

  // Exception-safe cleanup of instructions
  std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> freeInsn(
      insn, [count](cs_insn* i) { cs_free(i, count); });

  for (size_t i = 0; i < count; i++) {
    this->printInstruction(os, insn[i]);
    os << '\n';
  }
}

void AbstractPP::condPrintSectionHeader(std::ostream& os, const gtirb::Block& x) {
  const std::string& name = this->disasm.getSectionName(x.getAddress());

  if (!name.empty())
    this->printSectionHeader(os, name);
}

void AbstractPP::printSectionHeader(std::ostream& os, const std::string& x, uint64_t alignment) {
  os << '\n';
  this->printBar(os);

  if (x == AbstractPP::StrSectionText) {
    os << AbstractPP::StrSectionText << '\n';
  } else if (x == AbstractPP::StrSectionBSS) {
    os << AbstractPP::StrSectionBSS << '\n';
    os << ".align " << alignment << '\n';
  } else {
    os << AbstractPP::StrSection << ' ' << x << '\n';

    if (alignment != 0) {
      os << ".align " << alignment << '\n';
    }
  }

  this->printBar(os);
  os << '\n';
}

void AbstractPP::printBar(std::ostream& os, bool heavy) {
  if (heavy == true) {
    os << "#===================================\n";
  } else {
    os << "#-----------------------------------\n";
  }
}

void AbstractPP::printFunctionHeader(std::ostream& os, gtirb::Addr ea) {
  const std::string& name = this->disasm.getFunctionName(ea);

  if (name.empty() == false) {
    const BlockAreaComment bac(os, "Function Header", [this, &os]() { this->printBar(os, false); });

    // enforce maximum alignment
    uint64_t x(ea);
    if (x % 8 == 0) {
      os << ".align 8\n";
    } else if (x % 2 == 0) {
      os << ".align 2\n";
    }

    os << AbstractPP::StrSectionGlobal << ' ' << name << '\n';
    os << AbstractPP::StrSectionType << ' ' << name << ", @function\n";
    os << name << ":\n";
  }
}

void AbstractPP::printLabel(std::ostream& os, gtirb::Addr ea) {
  if (!this->condPrintGlobalSymbol(os, ea))
    os << ".L_" << std::hex << uint64_t(ea) << ':' << std::dec;
}

std::string AbstractPP::getAdaptedSymbolNameDefault(const gtirb::Symbol* symbol) const {
  if (symbol->getAddress()) {
    std::string destName = this->disasm.getRelocatedDestination(symbol->getAddress().value());
    if (!destName.empty()) {
      return destName;
    }
  }
  if (this->disasm.isAmbiguousSymbol(symbol->getName())) {
    return DisasmData::GetSymbolToPrint(symbol->getAddress().value());
  }

  return DisasmData::AvoidRegNameConflicts(DisasmData::CleanSymbolNameSuffix(symbol->getName()));
}

std::string AbstractPP::getAdaptedSymbolName(const gtirb::Symbol* symbol) const {
  std::string name = DisasmData::CleanSymbolNameSuffix(symbol->getName());
  if (!this->disasm.isAmbiguousSymbol(symbol->getName()) &&
      !this->disasm.isRelocated(name)) // && !DisasmData::GetIsReservedSymbol(name)
    return DisasmData::AvoidRegNameConflicts(name);
  return std::string{};
}

bool AbstractPP::condPrintGlobalSymbol(std::ostream& os, gtirb::Addr ea) {
  bool printed = false;
  for (const gtirb::Symbol& sym : this->disasm.ir.modules()[0].findSymbols(ea)) {
    std::string name = this->getAdaptedSymbolName(&sym);
    if (!name.empty()) {
      os << name << ":\n";
      printed = true;
    }
  }
  return printed;
}

void AbstractPP::printInstruction(std::ostream& os, const cs_insn& inst) {
  gtirb::Addr ea(inst.address);
  printComment(os, ea);
  this->printEA(os, ea);
  std::string opcode = str_tolower(inst.mnemonic);

  ////////////////////////////////////////////////////////////////////
  // special cases

  if (inst.id == X86_INS_NOP) {
    os << "  " << AbstractPP::StrNOP;
    for (uint64_t i = 1; i < inst.size; ++i) {
      ea += 1;
      os << '\n';
      printComment(os, ea);
      this->printEA(os, ea);
      os << "  " << AbstractPP::StrNOP;
    }
    return;
  }
  os << "  " << opcode << ' ';
  this->printOperandList(os, opcode, ea, inst);
}

void AbstractPP::printEA(std::ostream& os, gtirb::Addr ea) {
  os << StrTab;
  if (this->debug) {
    os << std::hex << uint64_t(ea) << ": " << std::dec;
  }
}

void AbstractPP::printOperandList(std::ostream& os, const std::string& opcode, const gtirb::Addr ea,
                                  const cs_insn& inst) {
  std::string str_operands[4];
  cs_x86& detail = inst.detail->x86;
  const gtirb::Module& module = this->disasm.ir.modules()[0];
  uint8_t opCount = detail.op_count;

  // Operands are implicit for various MOVS* instructions. But there is also
  // an SSE2 instruction named MOVSD which has explicit operands.
  if ((inst.id == X86_INS_MOVSB || inst.id == X86_INS_MOVSW || inst.id == X86_INS_MOVSD ||
       inst.id == X86_INS_MOVSQ) &&
      inst.detail->groups[0] != X86_GRP_SSE2) {
    opCount = 0;
  }

  for (int i = 0; i < opCount; i++) {
    if (i != 0) {
      os << ',';
    }
    int index = getGtirbOpIndex(i, opCount);
    const gtirb::SymbolicExpression* symbolic = nullptr;
    auto found = module.findSymbolicExpression(ea + index);
    if (found != module.symbolic_expr_end())
      symbolic = &*found;
    this->printOperand(os, opcode, symbolic, inst, ea, i);
  }
}

void AbstractPP::printOperand(std::ostream& os, const std::string& opcode,
                              const gtirb::SymbolicExpression* symbolic, const cs_insn& inst,
                              gtirb::Addr ea, uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  switch (op.type) {
  case X86_OP_REG:
    this->printOpRegdirect(os, inst, op);
    return;
  case X86_OP_IMM:
    this->printOpImmediate(os, opcode, symbolic, inst, ea, index);
    return;
  case X86_OP_MEM:
    this->printOpIndirect(os, symbolic, inst, index);
    return;
  case X86_OP_INVALID:
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

void AbstractPP::printDataGroups(std::ostream& os) {
  std::vector<std::tuple<std::string, int, std::vector<gtirb::UUID>>>* dataSections =
      this->disasm.getDataSections();
  if (!dataSections)
    return;
  for (const auto& [name, alignment, dataIDs] : *dataSections) {
    const gtirb::Section* sectionPtr = this->disasm.getSection(name);

    std::vector<const gtirb::DataObject*> dataGroups;
    for (gtirb::UUID i : dataIDs) {
      dataGroups.push_back(nodeFromUUID<gtirb::DataObject>(this->disasm.context, i));
    }

    if (isSectionSkipped(sectionPtr->getName()))
      continue;

    // print header
    this->printSectionHeader(os, sectionPtr->getName(), alignment);
    // Print data for this section
    for (const gtirb::DataObject* dataGroup : dataGroups) {
      if (shouldExcludeDataElement(sectionPtr->getName(), *dataGroup))
        continue;
      printDataObject(os, *dataGroup);
    }

    // End label
    const gtirb::Addr endAddress = addressLimit(*sectionPtr);
    std::string next_section = this->disasm.getSectionName(endAddress);
    if (next_section.empty() == true ||
        (next_section != StrSectionBSS && getDataSectionDescriptor(next_section) == nullptr)) {
      // This is no the start of a new section, so print the label.
      this->printLabel(os, endAddress);
      os << '\n';
    }
  }
}

bool AbstractPP::shouldExcludeDataElement(const std::string& sectionName,
                                          const gtirb::DataObject& dataGroup) {
  return (sectionName == ".init_array" || sectionName == ".fini_array") &&
         this->isPointerToExcludedCode(dataGroup);
}

bool AbstractPP::isPointerToExcludedCode(const gtirb::DataObject& dataGroup) {
  gtirb::IR& ir = this->disasm.ir;
  const gtirb::Module& module = ir.modules()[0];
  if (auto foundSymbolic = module.findSymbolicExpression(dataGroup.getAddress());
      foundSymbolic != module.symbolic_expr_end()) {
    if (const auto* s = std::get_if<gtirb::SymAddrConst>(&*foundSymbolic)) {
      return this->skipEA(s->Sym->getAddress().value());
    }
  }
  return false;
}

void AbstractPP::printDataObject(std::ostream& os, const gtirb::DataObject& dataGroup) {
  gtirb::IR& ir = this->disasm.ir;
  const gtirb::Module& module = ir.modules()[0];
  const auto* stringEAs = getAuxData<std::vector<gtirb::Addr>>(ir, "stringEAs");

  printComment(os, dataGroup.getAddress());
  printLabel(os, dataGroup.getAddress());
  os << AbstractPP::StrTab;
  if (this->debug)
    os << std::hex << uint64_t(dataGroup.getAddress()) << std::dec << ':';

  const auto& foundSymbolic = module.findSymbolicExpression(dataGroup.getAddress());
  if (foundSymbolic != module.symbolic_expr_end()) {
    printSymbolicData(os, dataGroup.getAddress(), &*foundSymbolic);
    os << '\n';

  } else if (stringEAs && std::find(stringEAs->begin(), stringEAs->end(), dataGroup.getAddress()) !=
                              stringEAs->end()) {
    this->printString(os, dataGroup);
    os << '\n';

  } else {
    for (std::byte byte : getBytes(this->disasm.ir.modules()[0].getImageByteMap(), dataGroup)) {
      os << ".byte 0x" << std::hex << static_cast<uint32_t>(byte) << std::dec << '\n';
    }
  }
}

void AbstractPP::printComment(std::ostream& os, const gtirb::Addr ea) {
  if (!this->debug)
    return;
  const auto* comments =
      getAuxData<std::map<gtirb::Addr, std::string>>(this->disasm.ir, "comments");
  if (comments) {
    const auto p = comments->find(ea);
    if (p != comments->end()) {
      os << "# " << p->second << '\n';
    }
  }
}

void AbstractPP::printSymbolicData(std::ostream& os, const gtirb::Addr addr,
                                   const gtirb::SymbolicExpression* symbolic) {
  const auto* pltReferences =
      getAuxData<std::map<gtirb::Addr, std::string>>(this->disasm.ir, "pltDataReferences");

  if (pltReferences) {
    const auto p = pltReferences->find(addr);
    if (p != pltReferences->end()) {
      os << ".quad " << p->second;
      return;
    }
  }
  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    os << ".quad ";
    printSymbolicExpression(os, s);
  } else if (const auto* sa = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
    os << ".long ";
    printSymbolicExpression(os, sa);
  }
}

void AbstractPP::printSymbolicExpression(std::ostream& os, const gtirb::SymAddrConst* sexpr) {
  os << this->getAdaptedSymbolNameDefault(sexpr->Sym);
  os << getAddendString(sexpr->Offset);
}

void AbstractPP::printSymbolicExpression(std::ostream& os, const gtirb::SymAddrAddr* sexpr) {
  // FIXME: why doesn't this use getAdaptedSymbolNameDefault()?
  os << sexpr->Sym1->getName() << '-' << sexpr->Sym2->getName();
}

void AbstractPP::printString(std::ostream& os, const gtirb::DataObject& x) {
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

  os << ".string \"";

  for (const std::byte& b : getBytes(this->disasm.ir.modules()[0].getImageByteMap(), x)) {
    if (b != std::byte(0)) {
      os << cleanByte(uint8_t(b));
    }
  }

  os << '"';
}

void AbstractPP::printBSS(std::ostream& os) {
  const gtirb::Section* bssSection = this->disasm.getSection(AbstractPP::StrSectionBSS);

  if (bssSection) {
    this->printSectionHeader(os, AbstractPP::StrSectionBSS, 16);
    const auto* bssData = getAuxData<std::vector<gtirb::UUID>>(this->disasm.ir, "bssData");

    // Special case.
    if (bssData && !bssData->empty()) {
      auto* data = nodeFromUUID<gtirb::DataObject>(this->disasm.context, bssData->at(0));
      if (data && data->getAddress() != bssSection->getAddress()) {
        const gtirb::Addr current = bssSection->getAddress();
        const gtirb::Addr next = data->getAddress();
        this->printLabel(os, current);
        os << " .zero " << next - current;
      }
      os << '\n';

      for (size_t i = 0; i < bssData->size(); ++i) {
        const auto* current = nodeFromUUID<gtirb::DataObject>(this->disasm.context, bssData->at(i));
        if (!current)
          continue;
        this->printLabel(os, current->getAddress());
        if (current->getSize() == 0) {
          os << '\n';
        } else {
          os << " .zero " << current->getSize() << '\n';
        }
      }
    }

    this->printLabel(os, addressLimit(*bssSection));
    os << '\n';
  }
}

bool AbstractPP::skipEA(const gtirb::Addr x) const {
  return !this->debug && (isInSkippedSection(x) || isInSkippedFunction(x));
}

bool AbstractPP::isInSkippedSection(const gtirb::Addr x) const {
  for (const gtirb::Section& s : this->disasm.getSections()) {
    if (AsmSkipSection.count(s.getName()) && containsAddr(s, gtirb::Addr(x))) {
      return true;
    }
  }
  return false;
}

bool AbstractPP::isInSkippedFunction(const gtirb::Addr x) const {
  std::string xFunctionName = getContainerFunctionName(x);
  if (xFunctionName.empty())
    return false;
  return AsmSkipFunction.count(xFunctionName);
}

std::string AbstractPP::getContainerFunctionName(const gtirb::Addr x) const {
  gtirb::Addr xFunctionAddress{0};
  auto* functionEntries = getAuxData<std::vector<gtirb::Addr>>(this->disasm.ir, "functionEntry");
  if (functionEntries) {
    for (auto fe = std::begin(*functionEntries); fe != std::end(*functionEntries); ++fe) {
      auto feNext = fe;
      feNext++;

      if (x >= *fe && x < *feNext) {
        xFunctionAddress = *fe;
        continue;
      }
    }
  }
  return this->disasm.getFunctionName(xFunctionAddress);
}

std::string AbstractPP::getRegisterName(unsigned int reg) const {
  return DisasmData::AdaptRegister(
      str_toupper(reg == X86_REG_INVALID ? "" : cs_reg_name(this->csHandle, reg)));
}

std::string AbstractPP::getAddendString(int64_t number, bool first) {
  if (number < 0 || first)
    return std::to_string(number);
  if (number == 0)
    return std::string("");
  return "+" + std::to_string(number);
}

bool AbstractPP::isSectionSkipped(const std::string& name) {
  if (this->debug)
    return false;
  return AsmSkipSection.count(name);
}

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
#include <boost/algorithm/string/replace.hpp>
#include <boost/lexical_cast.hpp>
#include <capstone/capstone.h>
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

    if (!message.empty()) {
      ofs << "# BEGIN - " << this->message << '\n';
    }

    func();
  }

  ~BlockAreaComment() {
    func();

    if (!message.empty()) {
      ofs << "# END   - " << this->message << '\n';
    }

    ofs << '\n';
  }

  std::ostream& ofs;
  const std::string message;
  std::function<void()> func;
};

static std::map<std::string, ::gtirb_pprint::factory>& getFactories() {
  static std::map<std::string, gtirb_pprint::factory> factories;
  return factories;
}

namespace gtirb_pprint {

bool registerPrinter(std::initializer_list<std::string> syntaxes, factory f) {
  assert(f && "Cannot register null factory!");
  assert(syntaxes.size() > 0 && "No syntaxes to register!");
  for (const std::string& name : syntaxes)
    getFactories()[name] = f;
  return true;
}

std::set<std::string> getRegisteredSyntaxes() {
  std::set<std::string> syntaxes;
  for (const std::pair<std::string, factory>& entry : getFactories())
    syntaxes.insert(entry.first);
  return syntaxes;
}

PrettyPrinter::PrettyPrinter()
    : m_skip_funcs{"_start",
                   "deregister_tm_clones",
                   "register_tm_clones",
                   "__do_global_dtors_aux",
                   "frame_dummy",
                   "__libc_csu_fini",
                   "__libc_csu_init",
                   "_dl_relocate_static_pie"},
      m_syntax{"intel"}, m_debug{NoDebug} {}

void PrettyPrinter::setSyntax(const std::string& syntax) {
  assert(getFactories().find(syntax) != getFactories().end());
  m_syntax = syntax;
}

const std::string& PrettyPrinter::getSyntax() const { return m_syntax; }

void PrettyPrinter::setDebug(bool do_debug) {
  m_debug = do_debug ? DebugMessages : NoDebug;
}

bool PrettyPrinter::getDebug() const { return m_debug == DebugMessages; }

const std::set<std::string>& PrettyPrinter::getSkippedFunctions() const {
  return m_skip_funcs;
}

void PrettyPrinter::skipFunction(const std::string& functionName) {
  m_skip_funcs.insert(functionName);
}

void PrettyPrinter::keepFunction(const std::string& functionName) {
  m_skip_funcs.erase(functionName);
}

std::error_condition PrettyPrinter::print(std::ostream& stream,
                                          gtirb::Context& context,
                                          gtirb::IR& ir) const {
  getFactories()
      .at(m_syntax)(context, ir, m_skip_funcs, m_debug)
      ->print(stream);
  return std::error_condition{};
}

PrettyPrinterBase::PrettyPrinterBase(gtirb::Context& context, gtirb::IR& ir,
                                     const string_range& skip_funcs,
                                     DebugStyle dbg)
    : AsmSkipFunction(skip_funcs.begin(), skip_funcs.end()),
      disasm(context, ir), debug(dbg == DebugMessages ? true : false) {
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");
  const gtirb::Module& module = *this->disasm.ir.modules().begin();
  for (const gtirb::Section& section : module.sections())
    this->sections[section.getAddress()] = &section;
}

PrettyPrinterBase::~PrettyPrinterBase() { cs_close(&this->csHandle); }

const gtirb::SymAddrConst* PrettyPrinterBase::getSymbolicImmediate(
    const gtirb::SymbolicExpression* symex) {
  if (symex) {
    const auto* s = std::get_if<gtirb::SymAddrConst>(symex);
    assert(s != nullptr && "symbolic operands must be 'address[+offset]'");
    return s;
  }
  return nullptr;
}

std::ostream& PrettyPrinterBase::print(std::ostream& os) {
  this->printHeader(os);
  // FIXME: simplify once block interation order is guaranteed by gtirb
  const gtirb::Module& module = *this->disasm.ir.modules().begin();
  auto address_order_block = [](const gtirb::Block* a, const gtirb::Block* b) {
    return a->getAddress() < b->getAddress();
  };
  std::vector<const gtirb::Block*> blocks;
  for (const gtirb::Block& block : gtirb::blocks(module.getCFG())) {
    blocks.push_back(&block);
  }
  std::sort(blocks.begin(), blocks.end(), address_order_block);
  auto blockIt = blocks.begin();
  auto dataIt = module.data_begin();
  gtirb::Addr last{0};
  gtirb::Addr nextAddr{0};
  while (blockIt != blocks.end() && dataIt != module.data_end()) {
    if ((*blockIt)->getAddress() <= dataIt->getAddress()) {
      nextAddr = (*blockIt)->getAddress();
      if (nextAddr < last) {
        printOverlapWarning(os, nextAddr);
      } else {
        if (nextAddr > last)
          printSymbolDefinitionsAtAddress(os, last);
        printBlock(os, **blockIt);
        last = (*blockIt)->getAddress() + (*blockIt)->getSize();
      }
      blockIt++;
    } else {
      nextAddr = dataIt->getAddress();
      if (nextAddr < last) {
        printOverlapWarning(os, nextAddr);
      } else {
        if (nextAddr > last)
          printSymbolDefinitionsAtAddress(os, last);
        printDataObject(os, *dataIt);
        last = dataIt->getAddress() + dataIt->getSize();
      }
      dataIt++;
    }
  }
  for (; blockIt != blocks.end(); blockIt++) {
    nextAddr = (*blockIt)->getAddress();
    if (nextAddr < last) {
      printOverlapWarning(os, (*blockIt)->getAddress());
    } else {
      if (nextAddr > last)
        printSymbolDefinitionsAtAddress(os, last);
      printBlock(os, **blockIt);
      last = (*blockIt)->getAddress() + (*blockIt)->getSize();
    }
  }
  for (; dataIt != module.data_end(); dataIt++) {
    nextAddr = dataIt->getAddress();
    if (nextAddr < last) {
      printOverlapWarning(os, nextAddr);
    } else {
      if (nextAddr > last)
        printSymbolDefinitionsAtAddress(os, last);

      printDataObject(os, *dataIt);
      last = dataIt->getAddress() + dataIt->getSize();
    }
  }
  printSymbolDefinitionsAtAddress(os, last);
  return os;
}

void PrettyPrinterBase::printOverlapWarning(std::ostream& os,
                                            const gtirb::Addr addr) {
  os << "# WARNING: found overlapping element at address " << std::hex
     << static_cast<uint64_t>(addr) << ": " << std::dec;
}
void PrettyPrinterBase::printBlock(std::ostream& os, const gtirb::Block& x) {
  printSectionHeader(os, x.getAddress());
  if (skipEA(x.getAddress())) {
    return;
  }
  printFunctionHeader(os, x.getAddress());
  printSymbolDefinitionsAtAddress(os, x.getAddress());
  os << '\n';

  cs_insn* insn;
  cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);

  gtirb::ImageByteMap::const_range bytes2 =
      getBytes(this->disasm.ir.modules().begin()->getImageByteMap(), x);
  size_t count =
      cs_disasm(this->csHandle, reinterpret_cast<const uint8_t*>(&bytes2[0]),
                bytes2.size(), static_cast<uint64_t>(x.getAddress()), 0, &insn);

  // Exception-safe cleanup of instructions
  std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> freeInsn(
      insn, [count](cs_insn* i) { cs_free(i, count); });

  for (size_t i = 0; i < count; i++) {
    printInstruction(os, insn[i]);
    os << '\n';
  }
}

void PrettyPrinterBase::printSectionHeader(std::ostream& os,
                                           const gtirb::Addr addr) {
  auto found = sections.find(addr);
  if (found == sections.end())
    return;
  std::string sectionName = found->second->getName();
  if (AsmSkipSection.count(sectionName))
    return;
  os << '\n';
  this->printBar(os);
  if (sectionName == PrettyPrinterBase::StrSectionText) {
    os << PrettyPrinterBase::StrSectionText << '\n';
  } else if (sectionName == PrettyPrinterBase::StrSectionBSS) {
    os << PrettyPrinterBase::StrSectionBSS << '\n';
  } else {
    os << PrettyPrinterBase::StrSection << ' ' << sectionName << '\n';
  }
  if (AsmArraySection.count(sectionName))
    os << ".align 8\n";
  else
    printAlignment(os, addr);
  this->printBar(os);
  os << '\n';
}

void PrettyPrinterBase::printBar(std::ostream& os, bool heavy) {
  if (heavy) {
    os << "#===================================\n";
  } else {
    os << "#-----------------------------------\n";
  }
}

void PrettyPrinterBase::printFunctionHeader(std::ostream& os,
                                            gtirb::Addr addr) {
  const std::string& name = this->disasm.getFunctionName(addr);

  if (!name.empty()) {
    const BlockAreaComment bac(os, "Function Header",
                               [this, &os]() { this->printBar(os, false); });
    printAlignment(os, addr);
    os << PrettyPrinterBase::StrSectionGlobal << ' ' << name << '\n';
    os << PrettyPrinterBase::StrSectionType << ' ' << name << ", @function\n";
    os << name << ":\n";
  }
}

void PrettyPrinterBase::printSymbolReference(std::ostream& os,
                                             const gtirb::Symbol* symbol,
                                             bool isAbsolute) const {
  std::optional<std::string> forwardedName =
      disasm.getForwardedSymbolName(symbol, isAbsolute);
  if (forwardedName) {
    os << forwardedName.value();
    return;
  }
  if (symbol->getAddress() && this->skipEA(*symbol->getAddress())) {
    os << static_cast<uint64_t>(*symbol->getAddress());
    return;
  }
  if (this->disasm.isAmbiguousSymbol(symbol->getName()))
    os << DisasmData::GetSymbolToPrint(*symbol->getAddress());
  else
    os << DisasmData::AvoidRegNameConflicts(symbol->getName());
}

void PrettyPrinterBase::printSymbolDefinitionsAtAddress(std::ostream& os,
                                                        gtirb::Addr ea) {
  for (const gtirb::Symbol& symbol :
       this->disasm.ir.modules().begin()->findSymbols(ea)) {
    if (this->disasm.isAmbiguousSymbol(symbol.getName()))
      os << DisasmData::GetSymbolToPrint(*symbol.getAddress()) << ":\n";
    else
      os << DisasmData::AvoidRegNameConflicts(symbol.getName()) << ":\n";
  }
}

void PrettyPrinterBase::printInstruction(std::ostream& os,
                                         const cs_insn& inst) {
  gtirb::Addr ea(inst.address);
  printComment(os, ea);
  printEA(os, ea);

  ////////////////////////////////////////////////////////////////////
  // special cases

  if (inst.id == X86_INS_NOP) {
    os << "  " << PrettyPrinterBase::StrNOP;
    for (uint64_t i = 1; i < inst.size; ++i) {
      ea += 1;
      os << '\n';
      printComment(os, ea);
      printEA(os, ea);
      os << "  " << PrettyPrinterBase::StrNOP;
    }
    return;
  }

  // end special cases
  ////////////////////////////////////////////////////////////////////

  std::string opcode = ascii_str_tolower(inst.mnemonic);
  os << "  " << opcode << ' ';
  printOperandList(os, ea, inst);
}

void PrettyPrinterBase::printEA(std::ostream& os, gtirb::Addr ea) {
  os << StrTab;
  if (this->debug) {
    os << std::hex << static_cast<uint64_t>(ea) << ": " << std::dec;
  }
}

void PrettyPrinterBase::printOperandList(std::ostream& os, const gtirb::Addr ea,
                                         const cs_insn& inst) {
  cs_x86& detail = inst.detail->x86;
  const gtirb::Module& module = *this->disasm.ir.modules().begin();
  uint8_t opCount = detail.op_count;

  // Operands are implicit for various MOVS* instructions. But there is also
  // an SSE2 instruction named MOVSD which has explicit operands.
  if ((inst.id == X86_INS_MOVSB || inst.id == X86_INS_MOVSW ||
       inst.id == X86_INS_MOVSD || inst.id == X86_INS_MOVSQ) &&
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
    printOperand(os, symbolic, inst, i);
  }
}

void PrettyPrinterBase::printOperand(std::ostream& os,
                                     const gtirb::SymbolicExpression* symbolic,
                                     const cs_insn& inst, uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  switch (op.type) {
  case X86_OP_REG:
    printOpRegdirect(os, inst, op);
    return;
  case X86_OP_IMM:
    printOpImmediate(os, symbolic, inst, index);
    return;
  case X86_OP_MEM:
    printOpIndirect(os, symbolic, inst, index);
    return;
  case X86_OP_INVALID:
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

void PrettyPrinterBase::printDataObject(std::ostream& os,
                                        const gtirb::DataObject& dataObject) {
  gtirb::Addr addr = dataObject.getAddress();
  printSectionHeader(os, addr);
  if (skipEA(addr)) {
    return;
  }
  printComment(os, addr);
  printSymbolDefinitionsAtAddress(os, addr);
  os << PrettyPrinterBase::StrTab;
  if (this->debug)
    os << std::hex << static_cast<uint64_t>(addr) << std::dec << ':';
  const auto section = getContainerSection(addr);
  assert(section && "Found a data object outside all sections");
  if (shouldExcludeDataElement(**section, dataObject))
    return;
  if ((*section)->getName() == StrSectionBSS)
    printZeroDataObject(os, dataObject);
  else
    printNonZeroDataObject(os, dataObject);
}

void PrettyPrinterBase::printNonZeroDataObject(
    std::ostream& os, const gtirb::DataObject& dataObject) {
  const gtirb::Module& module = *this->disasm.ir.modules().begin();
  const auto* stringEAs =
      getAuxData<std::vector<gtirb::Addr>>(this->disasm.ir, "stringEAs");
  const auto& foundSymbolic =
      module.findSymbolicExpression(dataObject.getAddress());
  if (foundSymbolic != module.symbolic_expr_end()) {
    printSymbolicData(os, &*foundSymbolic);
    os << '\n';
  } else if (stringEAs &&
             std::find(stringEAs->begin(), stringEAs->end(),
                       dataObject.getAddress()) != stringEAs->end()) {
    this->printString(os, dataObject);
    os << '\n';
  } else {
    for (std::byte byte : getBytes(module.getImageByteMap(), dataObject)) {
      os << ".byte 0x" << std::hex << static_cast<uint32_t>(byte) << std::dec
         << '\n';
    }
  }
}

void PrettyPrinterBase::printZeroDataObject(
    std::ostream& os, const gtirb::DataObject& dataObject) {
  os << " .zero " << dataObject.getSize() << '\n';
}

void PrettyPrinterBase::printComment(std::ostream& os, const gtirb::Addr ea) {
  if (!this->debug)
    return;
  if (const auto* comments = getAuxData<std::map<gtirb::Addr, std::string>>(
          this->disasm.ir, "comments")) {
    const auto p = comments->find(ea);
    if (p != comments->end()) {
      os << "# " << p->second << '\n';
    }
  }
}

void PrettyPrinterBase::printSymbolicData(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic) {
  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    os << ".quad ";
    printSymbolicExpression(os, s, true);
  } else if (const auto* sa = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
    os << ".long ";
    printSymbolicExpression(os, sa, true);
  }
}

void PrettyPrinterBase::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrConst* sexpr, bool inData) {
  printSymbolReference(os, sexpr->Sym, inData);
  printAddend(os, sexpr->Offset);
}

void PrettyPrinterBase::printSymbolicExpression(std::ostream& os,
                                                const gtirb::SymAddrAddr* sexpr,
                                                bool inData) {
  printSymbolReference(os, sexpr->Sym1, inData);
  os << '-';
  printSymbolReference(os, sexpr->Sym2, inData);
}

void PrettyPrinterBase::printString(std::ostream& os,
                                    const gtirb::DataObject& x) {
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

  for (const std::byte& b :
       getBytes(this->disasm.ir.modules().begin()->getImageByteMap(), x)) {
    if (b != std::byte(0)) {
      os << cleanByte(uint8_t(b));
    }
  }

  os << '"';
}

bool PrettyPrinterBase::shouldExcludeDataElement(
    const gtirb::Section& section, const gtirb::DataObject& dataObject) {
  if (!AsmArraySection.count(section.getName()))
    return false;
  const gtirb::Module& module = *this->disasm.ir.modules().begin();
  auto foundSymbolic = module.findSymbolicExpression(dataObject.getAddress());
  if (foundSymbolic != module.symbolic_expr_end()) {
    if (const auto* s = std::get_if<gtirb::SymAddrConst>(&*foundSymbolic)) {
      return this->skipEA(*s->Sym->getAddress());
    }
  }
  return false;
}

bool PrettyPrinterBase::skipEA(const gtirb::Addr x) const {
  return !this->debug && (isInSkippedSection(x) || isInSkippedFunction(x));
}

bool PrettyPrinterBase::isInSkippedSection(const gtirb::Addr addr) const {
  if (debug)
    return false;
  const auto section = getContainerSection(addr);
  return section && AsmSkipSection.count((*section)->getName());
}

bool PrettyPrinterBase::isInSkippedFunction(const gtirb::Addr x) const {
  std::optional<std::string> xFunctionName = getContainerFunctionName(x);
  if (!xFunctionName)
    return false;
  return AsmSkipFunction.count(*xFunctionName);
}

std::optional<std::string>
PrettyPrinterBase::getContainerFunctionName(const gtirb::Addr x) const {
  const auto* functionEntries =
      getAuxData<std::vector<gtirb::Addr>>(this->disasm.ir, "functionEntry");
  if (!functionEntries)
    return std::nullopt;

  const auto mod = std::find_if(this->disasm.ir.begin(), this->disasm.ir.end(),
                                [x](const gtirb::Module& module) {
                                  return gtirb::containsAddr(module, x);
                                });
  if (mod == this->disasm.ir.end())
    return std::nullopt;

  auto fe = std::lower_bound(functionEntries->rbegin(), functionEntries->rend(),
                             x, std::greater<>());
  if (fe == functionEntries->rend() || !gtirb::containsAddr(*mod, *fe))
    return std::nullopt;

  return this->disasm.getFunctionName(*fe);
}

const std::optional<const gtirb::Section*>
PrettyPrinterBase::getContainerSection(const gtirb::Addr addr) const {
  auto found = sections.upper_bound(addr);
  if (found == sections.begin())
    return std::nullopt;
  // go to the previous one
  found--;
  if (containsAddr(*(found->second), addr) ||
      addressLimit(*(found->second)) == addr)
    return found->second;
  else
    return std::nullopt;
}

std::string PrettyPrinterBase::getRegisterName(unsigned int reg) const {
  return ascii_str_toupper(
      reg == X86_REG_INVALID ? "" : cs_reg_name(this->csHandle, reg));
}

void PrettyPrinterBase::printAddend(std::ostream& os, int64_t number,
                                    bool first) {
  if (number < 0 || first) {
    os << number;
    return;
  }
  if (number == 0)
    return;
  os << "+" << number;
}

void PrettyPrinterBase::printAlignment(std::ostream& os, gtirb::Addr addr) {
  // Enforce maximum alignment
  uint64_t x{addr};
  if (x % 16 == 0) {
    os << ".align 16\n";
    return;
  }
  if (x % 8 == 0) {
    os << ".align 8\n";
    return;
  }
  if (x % 2 == 0) {
    os << ".align 2\n";
    return;
  }
}

} // namespace gtirb_pprint

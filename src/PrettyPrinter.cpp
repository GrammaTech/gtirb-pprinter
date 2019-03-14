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
}

PrettyPrinterBase::~PrettyPrinterBase() { cs_close(&this->csHandle); }

std::optional<std::string>
PrettyPrinterBase::getPltCodeSymName(gtirb::Addr ea) {
  if (const auto* pltReferences =
          getAuxData<std::map<gtirb::Addr, std::string>>(this->disasm.ir,
                                                         "pltCodeReferences")) {
    const auto p = pltReferences->find(gtirb::Addr(ea));
    if (p != pltReferences->end())
      return p->second;
  }
  return std::nullopt;
}

const gtirb::SymAddrConst* PrettyPrinterBase::getSymbolicImmediate(
    const gtirb::SymbolicExpression* symex) {
  if (symex) {
    const auto* s = std::get_if<gtirb::SymAddrConst>(symex);
    assert(s != nullptr && "symbolic operands must be 'address[+offset]'");
    if (!this->skipEA(*s->Sym->getAddress()))
      return s;
  }
  return nullptr;
}

std::ostream& PrettyPrinterBase::print(std::ostream& os) {
  this->printHeader(os);
  for (const gtirb::Block& b :
       gtirb::blocks(this->disasm.ir.modules()[0].getCFG())) {
    this->printBlock(os, b);
  }
  this->printDataGroups(os);
  this->printBSS(os);
  this->printUndefinedSymbols(os);
  return os;
}

void PrettyPrinterBase::printUndefinedSymbols(std::ostream& os) {
  for (const auto& sym : this->disasm.ir.modules()[0].symbols()) {
    if (sym.getStorageKind() == gtirb::Symbol::StorageKind::Undefined)
      os << ".weak \"" << sym.getName() << "\"" << std::endl;
  }
}

void PrettyPrinterBase::printBlock(std::ostream& os, const gtirb::Block& x) {
  if (this->skipEA(x.getAddress())) {
    return;
  }

  this->condPrintSectionHeader(os, x);
  this->printFunctionHeader(os, x.getAddress());
  this->printLabel(os, x.getAddress());
  os << '\n';

  cs_insn* insn;
  cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);

  gtirb::ImageByteMap::const_range bytes2 =
      getBytes(this->disasm.ir.modules()[0].getImageByteMap(), x);
  size_t count =
      cs_disasm(this->csHandle, reinterpret_cast<const uint8_t*>(&bytes2[0]),
                bytes2.size(), static_cast<uint64_t>(x.getAddress()), 0, &insn);

  // Exception-safe cleanup of instructions
  std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> freeInsn(
      insn, [count](cs_insn* i) { cs_free(i, count); });

  for (size_t i = 0; i < count; i++) {
    this->printInstruction(os, insn[i]);
    os << '\n';
  }
}

void PrettyPrinterBase::condPrintSectionHeader(std::ostream& os,
                                               const gtirb::Block& x) {
  const std::string& name = this->disasm.getSectionName(x.getAddress());

  if (!name.empty())
    this->printSectionHeader(os, name);
}

void PrettyPrinterBase::printSectionHeader(std::ostream& os,
                                           const std::string& x,
                                           uint64_t alignment) {
  os << '\n';
  this->printBar(os);

  if (x == PrettyPrinterBase::StrSectionText) {
    os << PrettyPrinterBase::StrSectionText << '\n';
  } else if (x == PrettyPrinterBase::StrSectionBSS) {
    os << PrettyPrinterBase::StrSectionBSS << '\n';
    os << ".align " << alignment << '\n';
  } else {
    os << PrettyPrinterBase::StrSection << ' ' << x << '\n';

    if (alignment != 0) {
      os << ".align " << alignment << '\n';
    }
  }

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

void PrettyPrinterBase::printFunctionHeader(std::ostream& os, gtirb::Addr ea) {
  const std::string& name = this->disasm.getFunctionName(ea);

  if (!name.empty()) {
    const BlockAreaComment bac(os, "Function Header",
                               [this, &os]() { this->printBar(os, false); });

    // Enforce maximum alignment
    uint64_t x{ea};
    if (x % 8 == 0) {
      os << ".align 8\n";
    } else if (x % 2 == 0) {
      os << ".align 2\n";
    }

    os << PrettyPrinterBase::StrSectionGlobal << ' ' << name << '\n';
    os << PrettyPrinterBase::StrSectionType << ' ' << name << ", @function\n";
    os << name << ":\n";
  }
}

void PrettyPrinterBase::printLabel(std::ostream& os, gtirb::Addr ea) {
  if (!this->condPrintGlobalSymbol(os, ea))
    os << ".L_" << std::hex << static_cast<uint64_t>(ea) << ':' << std::dec;
}

std::string PrettyPrinterBase::getAdaptedSymbolNameDefault(
    const gtirb::Symbol* symbol) const {
  if (symbol->getAddress()) {
    std::string destName =
        this->disasm.getRelocatedDestination(*symbol->getAddress());
    if (!destName.empty()) {
      return destName;
    }
  }
  if (this->disasm.isAmbiguousSymbol(symbol->getName())) {
    return DisasmData::GetSymbolToPrint(*symbol->getAddress());
  }

  return DisasmData::AvoidRegNameConflicts(
      DisasmData::CleanSymbolNameSuffix(symbol->getName()));
}

std::string
PrettyPrinterBase::getAdaptedSymbolName(const gtirb::Symbol* symbol) const {
  std::string name = DisasmData::CleanSymbolNameSuffix(symbol->getName());
  if (!this->disasm.isAmbiguousSymbol(symbol->getName()) &&
      !this->disasm.isRelocated(name))
    return DisasmData::AvoidRegNameConflicts(name);
  return std::string{};
}

bool PrettyPrinterBase::condPrintGlobalSymbol(std::ostream& os,
                                              gtirb::Addr ea) {
  bool printed = false;
  for (const gtirb::Symbol& sym :
       this->disasm.ir.modules()[0].findSymbols(ea)) {
    std::string name = this->getAdaptedSymbolName(&sym);
    if (!name.empty()) {
      os << name << ":\n";
      printed = true;
    }
  }
  return printed;
}

void PrettyPrinterBase::printInstruction(std::ostream& os,
                                         const cs_insn& inst) {
  gtirb::Addr ea(inst.address);
  printComment(os, ea);
  this->printEA(os, ea);

  ////////////////////////////////////////////////////////////////////
  // special cases

  if (inst.id == X86_INS_NOP) {
    os << "  " << PrettyPrinterBase::StrNOP;
    for (uint64_t i = 1; i < inst.size; ++i) {
      ea += 1;
      os << '\n';
      printComment(os, ea);
      this->printEA(os, ea);
      os << "  " << PrettyPrinterBase::StrNOP;
    }
    return;
  }

  // end special cases
  ////////////////////////////////////////////////////////////////////

  std::string opcode = ascii_str_tolower(inst.mnemonic);
  os << "  " << opcode << ' ';
  this->printOperandList(os, ea, inst);
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
  const gtirb::Module& module = this->disasm.ir.modules()[0];
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
    this->printOperand(os, symbolic, inst, ea, i);
  }
}

void PrettyPrinterBase::printOperand(std::ostream& os,
                                     const gtirb::SymbolicExpression* symbolic,
                                     const cs_insn& inst, gtirb::Addr ea,
                                     uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  switch (op.type) {
  case X86_OP_REG:
    this->printOpRegdirect(os, inst, op);
    return;
  case X86_OP_IMM:
    this->printOpImmediate(os, symbolic, inst, ea, index);
    return;
  case X86_OP_MEM:
    this->printOpIndirect(os, symbolic, inst, index);
    return;
  case X86_OP_INVALID:
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

void PrettyPrinterBase::printDataGroups(std::ostream& os) {
  const std::vector<std::tuple<std::string, int, std::vector<gtirb::UUID>>>*
      dataSections = this->disasm.getDataSections();
  if (!dataSections)
    return;
  for (const auto& [name, alignment, dataIDs] : *dataSections) {
    const gtirb::Section* sectionPtr = this->disasm.getSection(name);

    std::vector<const gtirb::DataObject*> dataGroups;
    for (gtirb::UUID i : dataIDs) {
      dataGroups.push_back(
          nodeFromUUID<gtirb::DataObject>(this->disasm.context, i));
    }

    if (isSectionSkipped(sectionPtr->getName()))
      continue;

    // Print header
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
    if (next_section.empty() ||
        (next_section != StrSectionBSS &&
         getDataSectionDescriptor(next_section) == nullptr)) {
      // This is no the start of a new section, so print the label.
      this->printLabel(os, endAddress);
      os << '\n';
    }
  }
}

bool PrettyPrinterBase::shouldExcludeDataElement(
    const std::string& sectionName, const gtirb::DataObject& dataGroup) {
  return (sectionName == ".init_array" || sectionName == ".fini_array") &&
         this->isPointerToExcludedCode(dataGroup);
}

bool PrettyPrinterBase::isPointerToExcludedCode(
    const gtirb::DataObject& dataGroup) {
  gtirb::IR& ir = this->disasm.ir;
  const gtirb::Module& module = ir.modules()[0];
  if (auto foundSymbolic =
          module.findSymbolicExpression(dataGroup.getAddress());
      foundSymbolic != module.symbolic_expr_end()) {
    if (const auto* s = std::get_if<gtirb::SymAddrConst>(&*foundSymbolic)) {
      return this->skipEA(*s->Sym->getAddress());
    }
  }
  return false;
}

void PrettyPrinterBase::printDataObject(std::ostream& os,
                                        const gtirb::DataObject& dataGroup) {
  gtirb::IR& ir = this->disasm.ir;
  const gtirb::Module& module = ir.modules()[0];
  const auto* stringEAs = getAuxData<std::vector<gtirb::Addr>>(ir, "stringEAs");

  printComment(os, dataGroup.getAddress());
  printLabel(os, dataGroup.getAddress());
  os << PrettyPrinterBase::StrTab;
  if (this->debug)
    os << std::hex << static_cast<uint64_t>(dataGroup.getAddress()) << std::dec
       << ':';

  const auto& foundSymbolic =
      module.findSymbolicExpression(dataGroup.getAddress());
  if (foundSymbolic != module.symbolic_expr_end()) {
    printSymbolicData(os, dataGroup.getAddress(), &*foundSymbolic);
    os << '\n';

  } else if (stringEAs &&
             std::find(stringEAs->begin(), stringEAs->end(),
                       dataGroup.getAddress()) != stringEAs->end()) {
    this->printString(os, dataGroup);
    os << '\n';

  } else {
    for (std::byte byte :
         getBytes(this->disasm.ir.modules()[0].getImageByteMap(), dataGroup)) {
      os << ".byte 0x" << std::hex << static_cast<uint32_t>(byte) << std::dec
         << '\n';
    }
  }
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
    std::ostream& os, const gtirb::Addr addr,
    const gtirb::SymbolicExpression* symbolic) {
  if (const auto* pltReferences =
          getAuxData<std::map<gtirb::Addr, std::string>>(this->disasm.ir,
                                                         "pltDataReferences")) {
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

void PrettyPrinterBase::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrConst* sexpr) {
  os << this->getAdaptedSymbolNameDefault(sexpr->Sym);
  os << getAddendString(sexpr->Offset);
}

void PrettyPrinterBase::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrAddr* sexpr) {
  // FIXME: Why doesn't this use getAdaptedSymbolNameDefault()?
  os << sexpr->Sym1->getName() << '-' << sexpr->Sym2->getName();
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
       getBytes(this->disasm.ir.modules()[0].getImageByteMap(), x)) {
    if (b != std::byte(0)) {
      os << cleanByte(uint8_t(b));
    }
  }

  os << '"';
}

void PrettyPrinterBase::printBSS(std::ostream& os) {
  if (const gtirb::Section* bssSection =
          this->disasm.getSection(PrettyPrinterBase::StrSectionBSS)) {
    this->printSectionHeader(os, PrettyPrinterBase::StrSectionBSS, 16);
    const auto* bssData =
        getAuxData<std::vector<gtirb::UUID>>(this->disasm.ir, "bssData");

    // Special case for auxilary bss data.
    if (bssData && !bssData->empty()) {
      auto* data =
          nodeFromUUID<gtirb::DataObject>(this->disasm.context, bssData->at(0));
      if (data && data->getAddress() != bssSection->getAddress()) {
        const gtirb::Addr current = bssSection->getAddress();
        const gtirb::Addr next = data->getAddress();
        this->printLabel(os, current);
        os << " .zero " << next - current;
      }
      os << '\n';

      for (const gtirb::UUID& uuid : *bssData) {
        const auto* current =
            nodeFromUUID<gtirb::DataObject>(this->disasm.context, uuid);
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

bool PrettyPrinterBase::skipEA(const gtirb::Addr x) const {
  return !this->debug && (isInSkippedSection(x) || isInSkippedFunction(x));
}

bool PrettyPrinterBase::isInSkippedSection(const gtirb::Addr x) const {
  for (const gtirb::Section& s : this->disasm.getSections()) {
    if (AsmSkipSection.count(s.getName()) && containsAddr(s, gtirb::Addr(x))) {
      return true;
    }
  }
  return false;
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

std::string PrettyPrinterBase::getRegisterName(unsigned int reg) const {
  return DisasmData::AdaptRegister(ascii_str_toupper(
      reg == X86_REG_INVALID ? "" : cs_reg_name(this->csHandle, reg)));
}

std::string PrettyPrinterBase::getAddendString(int64_t number, bool first) {
  if (number < 0 || first)
    return std::to_string(number);
  if (number == 0)
    return std::string("");
  return "+" + std::to_string(number);
}

bool PrettyPrinterBase::isSectionSkipped(const std::string& name) {
  if (this->debug)
    return false;
  return AsmSkipSection.count(name);
}

} // namespace gtirb_pprint

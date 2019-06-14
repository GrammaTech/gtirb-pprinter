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

#include "string_utils.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <capstone/capstone.h>
#include <fstream>
#include <gtirb/gtirb.hpp>
#include <iomanip>
#include <iostream>
#include <regex>
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

void PrettyPrinter::linkAssembly(std::string output_filename,
                                 gtirb::Context &ctx, gtirb::IR &ir) const {
  // Write the assembly to a temp file
  std::string t = "/tmp/fileXXXXXX.S";
  std::string cmd = "";
  char asmPath[PATH_MAX];

  std::set<std::string> lib_paths, lib_flags;

  strcpy(asmPath, t.c_str());  /* Copy template */
  close(mkstemps(asmPath, 2)); /* Create and open temp file */

  std::ofstream ofs;
  ofs.open(asmPath);
  if (ofs.is_open() == true) {
    this->print(ofs, ctx, ir);
    ofs.close();
  }
  std::regex r("^lib([\\s\\S]*)\\.so.*");
  if (const auto *libraries =
          ir.modules().begin()->getAuxData<std::map<std::string, std::string>>(
              "libraries")) {
    for (const auto &library : *libraries) {
      lib_paths.insert(library.second);
      std::smatch m;
      if (std::regex_search(library.first, m, r))
        lib_flags.insert(m[1]);
    }
  }
  cmd.append("g++ ");
  cmd.append("-o " + output_filename + " ");
  cmd.append(std::string(asmPath) + " ");
  for (const auto &lib_path : lib_paths) {
    cmd.append("-L" + lib_path + " ");
    cmd.append("-Wl,-rpath," + lib_path + " ");
  }

  for (const auto &lib_flag : lib_flags) {
    cmd.append("-l" + lib_flag + " ");
  }

  FILE *ldd = popen(cmd.c_str(), "r");
  std::string output;
  if (ldd) {
    char line[1024];
    while (!feof(ldd) && fgets(line, 1024, ldd))
      output.append(line);

    int status = pclose(ldd);
    if (status < 0) {
      perror(NULL);
      std::cout << "The g++ command failed with : \n" << output;
    }
  }

  unlink(asmPath);
}

std::error_condition PrettyPrinter::print(std::ostream& stream,
                                          gtirb::Context& context,
                                          gtirb::IR& ir) const {
  getFactories()
      .at(m_syntax)(context, ir, m_skip_funcs, m_debug)
      ->print(stream);
  return std::error_condition{};
}

PrettyPrinterBase::PrettyPrinterBase(gtirb::Context& context_, gtirb::IR& ir_,
                                     const string_range& skip_funcs,
                                     DebugStyle dbg)
    : AsmSkipFunction(skip_funcs.begin(), skip_funcs.end()),
      debug(dbg == DebugMessages ? true : false), context(context_), ir(ir_),
      functionEntry() {
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");

  if (const auto* functionEntries =
          ir.modules()
              .begin()
              ->getAuxData<std::map<gtirb::UUID, std::set<gtirb::UUID>>>(
                  "functionEntries")) {
    for (auto const& function : *functionEntries) {
      for (auto& entryBlockUUID : function.second) {
        auto block = nodeFromUUID<gtirb::Block>(context, entryBlockUUID);
        functionEntry.push_back(block->getAddress());
      }
    }
    std::sort(functionEntry.begin(), functionEntry.end());
  }
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
  printHeader(os);
  // FIXME: simplify once block interation order is guaranteed by gtirb
  const gtirb::Module& module = *this->ir.modules().begin();
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
  while (blockIt != blocks.end() && dataIt != module.data_end()) {
    if ((*blockIt)->getAddress() <= dataIt->getAddress()) {
      last = printBlockOrWarning(os, **blockIt, last);
      blockIt++;
    } else {
      last = printDataObjectOrWarning(os, *dataIt, last);
      dataIt++;
    }
  }
  for (; blockIt != blocks.end(); blockIt++)
    last = printBlockOrWarning(os, **blockIt, last);
  for (; dataIt != module.data_end(); dataIt++)
    last = printDataObjectOrWarning(os, *dataIt, last);
  printSymbolDefinitionsAtAddress(os, last);
  return os;
}

gtirb::Addr PrettyPrinterBase::printBlockOrWarning(std::ostream& os,
                                                   const gtirb::Block& block,
                                                   gtirb::Addr last) {
  gtirb::Addr nextAddr = block.getAddress();
  if (nextAddr < last) {
    printOverlapWarning(os, nextAddr);
    return last;
  } else {
    if (nextAddr > last)
      printSymbolDefinitionsAtAddress(os, last);
    printBlock(os, block);
    return block.getAddress() + block.getSize();
  }
}

gtirb::Addr PrettyPrinterBase::printDataObjectOrWarning(
    std::ostream& os, const gtirb::DataObject& dataObject, gtirb::Addr last) {
  gtirb::Addr nextAddr = dataObject.getAddress();
  if (nextAddr < last) {
    printOverlapWarning(os, nextAddr);
    return last;
  } else {
    if (nextAddr > last)
      printSymbolDefinitionsAtAddress(os, last);
    printDataObject(os, dataObject);
    return dataObject.getAddress() + dataObject.getSize();
  }
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
      getBytes(this->ir.modules().begin()->getImageByteMap(), x);
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
  const auto found_section = this->ir.modules().begin()->findSection(addr);
  if (found_section.begin() == found_section.end())
    return;
  if (found_section.begin()->getAddress() != addr)
    return;
  std::string sectionName = found_section.begin()->getName();
  if (AsmSkipSection.count(sectionName))
    return;
  os << '\n';
  printBar(os);
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
  printBar(os);
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
  const std::string& name = this->getFunctionName(addr);

  if (!name.empty()) {
    const BlockAreaComment bac(os, "Function Header",
                               [this, &os]() { printBar(os, false); });
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
      getForwardedSymbolName(symbol, isAbsolute);
  if (forwardedName) {
    os << forwardedName.value();
    return;
  }
  if (symbol->getAddress() && skipEA(*symbol->getAddress())) {
    os << static_cast<uint64_t>(*symbol->getAddress());
    return;
  }
  if (this->isAmbiguousSymbol(symbol->getName()))
    os << GetSymbolToPrint(*symbol->getAddress());
  else
    os << AvoidRegNameConflicts(symbol->getName());
}

void PrettyPrinterBase::printSymbolDefinitionsAtAddress(std::ostream& os,
                                                        gtirb::Addr ea) {
  for (const gtirb::Symbol& symbol :
       this->ir.modules().begin()->findSymbols(ea)) {
    if (this->isAmbiguousSymbol(symbol.getName()))
      os << GetSymbolToPrint(*symbol.getAddress()) << ":\n";
    else
      os << AvoidRegNameConflicts(symbol.getName()) << ":\n";
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
  const gtirb::Module& module = *this->ir.modules().begin();
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
  gtirb::Module& module = *this->ir.modules().begin();
  const auto& foundSymbolic =
      module.findSymbolicExpression(dataObject.getAddress());
  if (foundSymbolic != module.symbolic_expr_end()) {
    printSymbolicData(os, &*foundSymbolic);
    os << '\n';
    return;
  }
  const auto* types =
      module.getAuxData<std::map<gtirb::UUID, std::string>>("types");
  if (types) {
    auto foundType = types->find(dataObject.getUUID());
    if (foundType != types->end() && foundType->second == "char[]") {
      printString(os, dataObject);
      os << '\n';
      return;
    }
  }
  for (std::byte byte : getBytes(module.getImageByteMap(), dataObject)) {
    os << ".byte 0x" << std::hex << static_cast<uint32_t>(byte) << std::dec
       << '\n';
  }
}

void PrettyPrinterBase::printZeroDataObject(
    std::ostream& os, const gtirb::DataObject& dataObject) {
  os << " .zero " << dataObject.getSize() << '\n';
}

void PrettyPrinterBase::printComment(std::ostream& os, const gtirb::Addr ea) {
  if (!this->debug)
    return;

  if (const auto* comments =
          this->ir.modules()
              .begin()
              ->getAuxData<std::map<gtirb::Addr, std::string>>("comments")) {
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
       getBytes(this->ir.modules().begin()->getImageByteMap(), x)) {
    if (b != std::byte(0)) {
      os << cleanByte(uint8_t(b));
    }
  }

  os << '"';
}

bool PrettyPrinterBase::shouldExcludeDataElement(
    const gtirb::Section& section, const gtirb::DataObject& dataObject) const {
  if (!AsmArraySection.count(section.getName()))
    return false;
  const gtirb::Module& module = *this->ir.modules().begin();
  auto foundSymbolic = module.findSymbolicExpression(dataObject.getAddress());
  if (foundSymbolic != module.symbolic_expr_end()) {
    if (const auto* s = std::get_if<gtirb::SymAddrConst>(&*foundSymbolic)) {
      return skipEA(*s->Sym->getAddress());
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
  auto it = std::upper_bound(this->functionEntry.begin(),
                             this->functionEntry.end(), x);
  if (it == this->functionEntry.begin())
    return std::nullopt;
  it--;
  return this->getFunctionName(*it);
}

const std::optional<const gtirb::Section*>
PrettyPrinterBase::getContainerSection(const gtirb::Addr addr) const {
  auto found_sections = this->ir.begin()->findSection(addr);
  if (found_sections.begin() == found_sections.end())
    return std::nullopt;
  else
    return &*found_sections.begin();
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
  if (x % 4 == 0) {
    os << ".align 4\n";
    return;
  }
  if (x % 2 == 0) {
    os << ".align 2\n";
    return;
  }
}

std::string PrettyPrinterBase::getFunctionName(gtirb::Addr x) const {
  // Is this address an entry point to a function with a symbol?
  bool entry_point = std::binary_search(this->functionEntry.begin(),
                                        this->functionEntry.end(), x);
  if (entry_point) {
    for (gtirb::Symbol& s : this->ir.modules().begin()->findSymbols(x)) {
      std::stringstream name(s.getName());
      if (isAmbiguousSymbol(s.getName())) {
        name.seekp(0, std::ios_base::end);
        name << '_' << std::hex << static_cast<uint64_t>(x);
      }
      return name.str();
    }
  }

  // Is this a function entry with no associated symbol?
  if (entry_point) {
    std::stringstream name;
    name << "unknown_function_" << std::hex << static_cast<uint64_t>(x);
    return name.str();
  }

  // This doesn't seem to be a function.
  return std::string{};
}

std::string PrettyPrinterBase::GetSymbolToPrint(gtirb::Addr x) {
  std::stringstream ss;
  ss << ".L_" << std::hex << uint64_t(x) << std::dec;
  return ss.str();
}

std::optional<std::string>
PrettyPrinterBase::getForwardedSymbolName(const gtirb::Symbol* symbol,
                                          bool isAbsolute) const {
  const auto* symbolForwarding =
      ir.modules().begin()->getAuxData<std::map<gtirb::UUID, gtirb::UUID>>(
          "symbolForwarding");

  if (symbolForwarding) {
    auto found = symbolForwarding->find(symbol->getUUID());
    if (found != symbolForwarding->end()) {
      gtirb::Node* destSymbol = gtirb::Node::getByUUID(context, found->second);
      return (cast<gtirb::Symbol>(destSymbol))->getName() +
             getForwardedSymbolEnding(symbol, isAbsolute);
    }
  }
  return {};
}

std::string
PrettyPrinterBase::getForwardedSymbolEnding(const gtirb::Symbol* symbol,
                                            bool isAbsolute) const {
  if (symbol->getAddress()) {
    gtirb::Addr addr = *symbol->getAddress();
    const auto container_sections =
        this->ir.modules().begin()->findSection(addr);
    if (container_sections.begin() == container_sections.end())
      return std::string{};
    std::string section_name = container_sections.begin()->getName();
    if (!isAbsolute && (section_name == ".plt" || section_name == ".plt.got"))
      return std::string{"@PLT"};
    if (section_name == ".got" || section_name == ".got.plt")
      return std::string{"@GOTPCREL"};
  }
  return std::string{};
}

bool PrettyPrinterBase::isAmbiguousSymbol(const std::string& name) const {
  // Are there multiple symbols with this name?
  auto found = this->ir.modules().begin()->findSymbols(name);
  return distance(begin(found), end(found)) > 1;
}

std::string PrettyPrinterBase::GetSizeName(uint64_t x) {
  return GetSizeName(std::to_string(x));
}

std::string PrettyPrinterBase::GetSizeName(const std::string& x) {
  static const std::map<std::string, std::string> adapt{
      {"128", ""},         {"0", ""},           {"80", "TBYTE PTR"},
      {"64", "QWORD PTR"}, {"32", "DWORD PTR"}, {"16", "WORD PTR"},
      {"8", "BYTE PTR"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  assert("Unknown Size");

  return x;
}

std::string PrettyPrinterBase::GetSizeSuffix(uint64_t x) {
  return GetSizeSuffix(std::to_string(x));
}

std::string PrettyPrinterBase::GetSizeSuffix(const std::string& x) {
  static const std::map<std::string, std::string> adapt{
      {"128", ""}, {"0", ""},   {"80", "t"}, {"64", "q"},
      {"32", "d"}, {"16", "w"}, {"8", "b"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  assert("Unknown Size");

  return x;
}

std::string PrettyPrinterBase::AvoidRegNameConflicts(const std::string& x) {
  const std::vector<std::string> adapt{"FS",  "MOD", "DIV", "NOT", "mod", "div",
                                       "not", "and", "or",  "shr", "Si"};

  if (const auto found = std::find(std::begin(adapt), std::end(adapt), x);
      found != std::end(adapt)) {
    return x + "_renamed";
  }

  return x;
}

} // namespace gtirb_pprint

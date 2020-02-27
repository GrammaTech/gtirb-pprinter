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
#include "PrettyPrinter.hpp"

#include "AuxDataSchema.hpp"
#include "string_utils.hpp"
#include <boost/algorithm/string/replace.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <capstone/capstone.h>
#include <fstream>
#include <gtirb/gtirb.hpp>
#include <iomanip>
#include <iostream>
#include <utility>
#include <variant>

template <class T> T* nodeFromUUID(gtirb::Context& C, gtirb::UUID id) {
  return dyn_cast_or_null<T>(gtirb::Node::getByUUID(C, id));
}

static std::map<std::tuple<std::string, std::string>,
                std::shared_ptr<::gtirb_pprint::PrettyPrinterFactory>>&
getFactories() {
  static std::map<std::tuple<std::string, std::string>,
                  std::shared_ptr<::gtirb_pprint::PrettyPrinterFactory>>
      factories;
  return factories;
}

static std::map<std::string, std::string>& getSyntaxes() {
  static std::map<std::string, std::string> defaults;
  return defaults;
}

namespace gtirb_pprint {

bool registerPrinter(std::initializer_list<std::string> formats,
                     std::initializer_list<std::string> syntaxes,
                     std::shared_ptr<PrettyPrinterFactory> f, bool isDefault) {
  assert(formats.size() > 0 && "No formats to register!");
  assert(syntaxes.size() > 0 && "No syntaxes to register!");
  for (const std::string& format : formats) {
    for (const std::string& syntax : syntaxes) {
      getFactories()[std::make_tuple(format, syntax)] = std::move(f);
      if (isDefault)
        setDefaultSyntax(format, syntax);
    }
  }
  return true;
}

std::set<std::tuple<std::string, std::string>> getRegisteredTargets() {
  std::set<std::tuple<std::string, std::string>> targets;
  for (const auto& entry : getFactories())
    targets.insert(entry.first);
  return targets;
}

std::string getModuleFileFormat(const gtirb::Module& module) {
  switch ((int)module.getFileFormat()) {
  case (int)gtirb::FileFormat::Undefined:
    return "undefined";
  case (int)gtirb::FileFormat::COFF:
    return "coff";
  case (int)gtirb::FileFormat::ELF:
    return "elf";
  case (int)gtirb::FileFormat::PE:
    return "pe";
  case (int)gtirb::FileFormat::IdaProDb32:
  case (int)gtirb::FileFormat::IdaProDb64:
    return "idb";
  case (int)gtirb::FileFormat::XCOFF:
    return "xcoff";
  case (int)gtirb::FileFormat::MACHO:
    return "macho";
  case (int)gtirb::FileFormat::RAW:
    return "raw";
  }
  return "undefined";
}

void setDefaultSyntax(const std::string& format, const std::string& syntax) {
  getSyntaxes()[format] = syntax;
}

std::optional<std::string> getDefaultSyntax(const std::string& format) {
  std::map<std::string, std::string> defaults = getSyntaxes();
  auto it = defaults.find(format);
  return it != defaults.end() ? std::make_optional(it->second) : std::nullopt;
}

void PrettyPrinter::setTarget(
    const std::tuple<std::string, std::string>& target) {
  assert(getFactories().find(target) != getFactories().end());
  const auto& [format, syntax] = target;
  m_format = format;
  m_syntax = syntax;
}

void PrettyPrinter::setFormat(const std::string& format) {
  const std::string& syntax = getDefaultSyntax(format).value_or("");
  setTarget(std::make_tuple(format, syntax));
}

void PrettyPrinter::setDebug(bool do_debug) {
  m_debug = do_debug ? DebugMessages : NoDebug;
}

bool PrettyPrinter::getDebug() const { return m_debug == DebugMessages; }

std::error_condition PrettyPrinter::print(std::ostream& stream,
                                          gtirb::Context& context,
                                          gtirb::Module& module) const {
  // Find pretty printer factory.
  auto target = std::make_tuple(m_format, m_syntax);
  if (m_format.empty()) {
    const std::string& format = gtirb_pprint::getModuleFileFormat(module);
    const std::string& syntax = getDefaultSyntax(format).value_or("");
    target = std::make_tuple(format, syntax);
  }
  const std::shared_ptr<PrettyPrinterFactory> factory =
      getFactories().at(target);

  // Configure printing policy.
  PrintingPolicy policy(factory->defaultPrintingPolicy());
  policy.debug = m_debug;
  SymbolPolicy.apply(policy.skipFunctions);
  SectionPolicy.apply(policy.skipSections);
  ArraySectionPolicy.apply(policy.arraySections);

  // Create the pretty printer and print the IR.
  factory->create(context, module, policy)->print(stream);

  return std::error_condition{};
}

PrettyPrinterBase::PrettyPrinterBase(gtirb::Context& context_,
                                     gtirb::Module& module_,
                                     const Syntax& syntax_,
                                     const PrintingPolicy& policy_)
    : syntax(syntax_), policy(policy_),
      debug(policy.debug == DebugMessages ? true : false), context(context_),
      module(module_), functionEntry(), functionLastBlock() {
  [[maybe_unused]] cs_err err =
      cs_open(CS_ARCH_X86, CS_MODE_64, &this->csHandle);
  assert(err == CS_ERR_OK && "Capstone failure");

  if (const auto* functionEntries =
          module.getAuxData<gtirb::schema::FunctionEntries>()) {
    for (auto const& function : *functionEntries) {
      for (auto& entryBlockUUID : function.second) {
        const auto* block =
            nodeFromUUID<gtirb::CodeBlock>(context, entryBlockUUID);
        assert(block && "UUID references non-existent block.");
        if (block)
          functionEntry.insert(*block->getAddress());
      }
    }
  }

  if (const auto* functionBlocks =
          module.getAuxData<gtirb::schema::FunctionBlocks>()) {
    for (auto const& function : *functionBlocks) {
      assert(function.second.size() > 0);
      gtirb::Addr lastAddr{0};
      for (auto& blockUUID : function.second) {
        const auto* block = nodeFromUUID<gtirb::CodeBlock>(context, blockUUID);
        assert(block && "UUID references non-existent block.");
        if (block && block->getAddress() > lastAddr)
          lastAddr = *block->getAddress();
      }
      functionLastBlock.insert(lastAddr);
    }
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

  for (const auto& section : module.sections()) {
    printSection(os, section);
  }

  printFooter(os);
  return os;
}

void PrettyPrinterBase::printOverlapWarning(std::ostream& os,
                                            const gtirb::Addr addr) {
  std::ios_base::fmtflags flags = os.flags();
  os << syntax.comment() << " WARNING: found overlapping element at address "
     << std::hex << static_cast<uint64_t>(addr) << ": ";
  os.flags(flags);
}

void PrettyPrinterBase::printCodeBlock(std::ostream& os,
                                       const gtirb::CodeBlock& x) {
  if (shouldSkip(x)) {
    return;
  }
  printFunctionHeader(os, *x.getAddress());
  os << '\n';

  for (const auto& sym :
       x.getByteInterval()->getSection()->getModule()->findSymbols(x)) {
    printSymbolDefinition(os, sym);
  }

  cs_insn* insn;
  cs_option(this->csHandle, CS_OPT_DETAIL, CS_OPT_ON);

  size_t count = cs_disasm(this->csHandle, x.rawBytes<uint8_t>(), x.getSize(),
                           static_cast<uint64_t>(*x.getAddress()), 0, &insn);

  // Exception-safe cleanup of instructions
  std::unique_ptr<cs_insn, std::function<void(cs_insn*)>> freeInsn(
      insn, [count](cs_insn* i) { cs_free(i, count); });

  gtirb::Offset offset(x.getUUID(), 0);
  for (size_t i = 0; i < count; i++) {
    fixupInstruction(insn[i]);
    printInstruction(os, insn[i], offset);
    offset.Displacement += insn[i].size;
    os << '\n';
  }
  // print any CFI directives located at the end of the block
  // e.g. '.cfi_endproc' is usually attached to the end of the block
  printCFIDirectives(os, offset);
  printFunctionFooter(os, *x.getAddress());
}

void PrettyPrinterBase::printSectionHeader(std::ostream& os,
                                           const gtirb::Section& section) {
  std::string sectionName = section.getName();
  os << '\n';
  printBar(os);
  if (sectionName == syntax.textSection()) {
    os << syntax.text() << '\n';
  } else if (sectionName == syntax.dataSection()) {
    os << syntax.data() << '\n';
  } else if (sectionName == syntax.bssSection()) {
    os << syntax.bss() << '\n';
  } else {
    printSectionHeaderDirective(os, section);
    printSectionProperties(os, section);
    os << std::endl;
  }
  if (policy.arraySections.count(sectionName))
    os << syntax.align() << " 8\n";
  else
    printAlignment(os, *section.getAddress());
  printBar(os);
  os << '\n';
}

void PrettyPrinterBase::printSectionFooter(std::ostream& os,
                                           const gtirb::Section& section) {
  printBar(os);
  printSectionFooterDirective(os, section);
  printBar(os);
}

void PrettyPrinterBase::printBar(std::ostream& os, bool heavy) {
  if (heavy) {
    os << syntax.comment() << "===================================\n";
  } else {
    os << syntax.comment() << "-----------------------------------\n";
  }
}

void PrettyPrinterBase::printSymbolReference(std::ostream& os,
                                             const gtirb::Symbol* symbol,
                                             bool inData) const {
  std::optional<std::string> forwardedName =
      getForwardedSymbolName(symbol, inData);
  if (forwardedName) {
    os << forwardedName.value();
    return;
  }
  if (shouldSkip(*symbol)) {
    os << static_cast<uint64_t>(*symbol->getAddress());
    return;
  }
  if (this->isAmbiguousSymbol(symbol->getName()))
    os << getSymbolName(*symbol->getAddress());
  else
    os << syntax.formatSymbolName(symbol->getName());
}

void PrettyPrinterBase::printSymbolDefinition(std::ostream& os,
                                              const gtirb::Symbol& symbol) {
  if (isAmbiguousSymbol(symbol.getName())) {
    os << getSymbolName(*symbol.getAddress()) << ":\n";
  } else {
    os << syntax.formatSymbolName(symbol.getName()) << ":\n";
  }
}

void PrettyPrinterBase::fixupInstruction(cs_insn& inst) {
  cs_x86& detail = inst.detail->x86;

  // Operands are implicit for various MOVS* instructions. But there is also
  // an SSE2 instruction named MOVSD which has explicit operands.
  if ((inst.id == X86_INS_MOVSB || inst.id == X86_INS_MOVSW ||
       inst.id == X86_INS_MOVSD || inst.id == X86_INS_MOVSQ) &&
      inst.detail->groups[0] != X86_GRP_SSE2) {
    detail.op_count = 0;
  }

  // Register operands are implicit for STOS* instructions.
  if (inst.id == X86_INS_STOSB || inst.id == X86_INS_STOSW ||
      inst.id == X86_INS_STOSD || inst.id == X86_INS_STOSQ) {
    detail.op_count = 1;
  }

  // IMUL: third operand is a signed number, but it is decoded as unsigned.
  if (inst.id == X86_INS_IMUL && detail.op_count == 3) {
    cs_x86_op& op = detail.operands[2];
    op.imm = static_cast<int32_t>(op.imm);
  }

  // GCC assembler does not like endbr64 instructions
  if (inst.id == X86_INS_ENDBR64) {
    inst.id = X86_INS_NOP;
  }

  // The first operand of fxch  st(0) is implicit
  if (inst.id == X86_INS_FXCH && detail.op_count == 2) {
    detail.operands[0] = detail.operands[1];
    detail.op_count = 1;
  }

  // Comisd loads 64 bits from memory not 128
  if (inst.id == X86_INS_COMISD && detail.op_count == 2 &&
      detail.operands[1].type == X86_OP_MEM && detail.operands[1].size == 16) {
    detail.operands[1].size = 8;
  }

  // FXSAVE operands should not have a size annotation
  if (inst.id == X86_INS_FXSAVE && detail.op_count == 1) {
    detail.operands[0].size = 0;
  }
}

void PrettyPrinterBase::printInstruction(std::ostream& os, const cs_insn& inst,
                                         const gtirb::Offset& offset) {

  gtirb::Addr ea(inst.address);
  printComments(os, offset, inst.size);
  printCFIDirectives(os, offset);
  printEA(os, ea);

  ////////////////////////////////////////////////////////////////////
  // special cases

  if (inst.id == X86_INS_NOP) {
    os << "  " << syntax.nop();
    for (uint64_t i = 1; i < inst.size; ++i) {
      ea += 1;
      os << '\n';
      printEA(os, ea);
      os << "  " << syntax.nop();
    }
    return;
  }

  // TODO: Add 'padding' aux data to skipEA logic to decide if we should skip
  //       int3 padding blocks.
  if (inst.id == X86_INS_INT3) {
    return;
  }

  // end special cases
  ////////////////////////////////////////////////////////////////////

  std::string opcode = ascii_str_tolower(inst.mnemonic);
  os << "  " << opcode << ' ';
  printOperandList(os, inst);
}

void PrettyPrinterBase::printEA(std::ostream& os, gtirb::Addr ea) {
  os << syntax.tab();
  if (this->debug) {
    os << std::hex << static_cast<uint64_t>(ea) << ": " << std::dec;
  }
}

void PrettyPrinterBase::printOperandList(std::ostream& os,
                                         const cs_insn& inst) {
  cs_x86& detail = inst.detail->x86;
  uint8_t opCount = detail.op_count;

  for (int i = 0; i < opCount; i++) {
    if (i != 0) {
      os << ',';
    }
    printOperand(os, inst, i);
  }
}

void PrettyPrinterBase::printOperand(std::ostream& os, const cs_insn& inst,
                                     uint64_t index) {
  gtirb::Addr ea(inst.address);
  const cs_x86_op& op = inst.detail->x86.operands[index];

  const gtirb::SymbolicExpression* symbolic = nullptr;
  uint8_t immOffset = inst.detail->x86.encoding.imm_offset;
  uint8_t dispOffset = inst.detail->x86.encoding.disp_offset;

  switch (op.type) {
  case X86_OP_REG:
    printOpRegdirect(os, inst, op);
    return;
  case X86_OP_IMM: {
    auto found = module.findSymbolicExpressionsAt(ea + immOffset);
    if (!found.empty())
      symbolic = &found.begin()->getSymbolicExpression();
  }
    printOpImmediate(os, symbolic, inst, index);
    return;
  case X86_OP_MEM:
    if (dispOffset > 0) {
      auto found = module.findSymbolicExpressionsAt(ea + dispOffset);
      if (!found.empty())
        symbolic = &found.begin()->getSymbolicExpression();
    }
    printOpIndirect(os, symbolic, inst, index);
    return;
  case X86_OP_INVALID:
    std::cerr << "invalid operand\n";
    exit(1);
  }
}

void PrettyPrinterBase::printDataBlock(std::ostream& os,
                                       const gtirb::DataBlock& dataObject) {
  if (shouldSkip(dataObject)) {
    return;
  }

  for (const auto& sym :
       dataObject.getByteInterval()->getSection()->getModule()->findSymbols(
           dataObject)) {
    printSymbolDefinition(os, sym);
  }

  gtirb::Addr addr = *dataObject.getAddress();
  printComments(os, gtirb::Offset(dataObject.getUUID(), 0),
                dataObject.getSize());
  if (this->debug)
    os << std::hex << static_cast<uint64_t>(addr) << std::dec << ':';

  const auto& foundSymbolic =
      module.findSymbolicExpressionsAt(*dataObject.getAddress());
  auto dataObjectBytes = dataObject.bytes<uint8_t>();
  if (std::all_of(dataObjectBytes.begin(), dataObjectBytes.end(),
                  [](uint8_t x) { return x == 0; }) &&
      foundSymbolic.empty())
    printZeroDataBlock(os, dataObject);
  else
    printNonZeroDataBlock(os, dataObject);
}

void PrettyPrinterBase::printNonZeroDataBlock(
    std::ostream& os, const gtirb::DataBlock& dataObject) {
  const auto& foundSymbolic =
      module.findSymbolicExpressionsAt(*dataObject.getAddress());
  if (!foundSymbolic.empty()) {
    os << syntax.tab();
    printSymbolicData(os, &foundSymbolic.begin()->getSymbolicExpression(),
                      dataObject);
    os << '\n';
    return;
  }
  const auto* types = module.getAuxData<gtirb::schema::Encodings>();
  if (types) {
    auto foundType = types->find(dataObject.getUUID());
    if (foundType != types->end() && foundType->second == "string") {
      os << syntax.tab();
      printString(os, dataObject);
      os << '\n';
      return;
    }
  }
  for (auto byte : dataObject.bytes<uint8_t>()) {
    os << syntax.tab();
    printByte(os, static_cast<std::byte>(static_cast<unsigned char>(byte)));
  }
}

void PrettyPrinterBase::printZeroDataBlock(std::ostream& os,
                                           const gtirb::DataBlock& dataObject) {
  os << syntax.tab();
  os << " .zero " << dataObject.getSize() << '\n';
}

void PrettyPrinterBase::printComments(std::ostream& os,
                                      const gtirb::Offset& offset,
                                      uint64_t range) {
  if (!this->debug)
    return;

  if (const auto* comments = module.getAuxData<gtirb::schema::Comments>()) {
    gtirb::Offset endOffset(offset.ElementId, offset.Displacement + range);
    for (auto p = comments->lower_bound(offset);
         p != comments->end() && p->first < endOffset; ++p) {
      os << syntax.comment();
      if (p->first.Displacement > offset.Displacement)
        os << "+" << p->first.Displacement - offset.Displacement << ":";
      os << " " << p->second << '\n';
    }
  }
}

void PrettyPrinterBase::printCFIDirectives(std::ostream& os,
                                           const gtirb::Offset& offset) {
  const auto* cfiDirectives = module.getAuxData<gtirb::schema::CfiDirectives>();
  if (!cfiDirectives)
    return;
  const auto entry = cfiDirectives->find(offset);
  if (entry == cfiDirectives->end())
    return;

  for (auto& cfiDirective : entry->second) {
    os << std::get<0>(cfiDirective) << " ";
    const std::vector<int64_t>& operands = std::get<1>(cfiDirective);
    for (auto it = operands.begin(); it != operands.end(); it++) {
      if (it != operands.begin())
        os << ", ";
      os << *it;
    }

    gtirb::Symbol* symbol =
        nodeFromUUID<gtirb::Symbol>(context, std::get<2>(cfiDirective));
    if (symbol) {
      if (operands.size() > 0)
        os << ", ";
      printSymbolReference(os, symbol, true);
    }

    os << std::endl;
  }
}

void PrettyPrinterBase::printSymbolicData(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const gtirb::DataBlock& dataObject) {
  printDataBlockType(os, dataObject);
  os << " ";
  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    printSymbolicExpression(os, s, true);
  } else if (const auto* sa = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
    printSymbolicExpression(os, sa, true);
  }
}

void PrettyPrinterBase::printDataBlockType(std::ostream& os,
                                           const gtirb::DataBlock& dataObject) {
  const auto* types = module.getAuxData<gtirb::schema::Encodings>();
  if (types) {
    auto foundType = types->find(dataObject.getUUID());
    if (foundType != types->end()) {
      os << "." << foundType->second;
      return;
    }
  }
  switch (dataObject.getSize()) {
  case 1:
    os << syntax.byteData();
    break;
  case 2:
    os << syntax.wordData();
    break;
  case 4:
    os << syntax.longData();
    break;
  case 8:
    os << syntax.quadData();
    break;
  default:
    assert("Data object with unknown type has incompatible size");
    break;
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
                                    const gtirb::DataBlock& x) {
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

  os << syntax.string() << " \"";

  for (auto b : x.bytes<uint8_t>()) {
    if (b != 0) {
      os << cleanByte(b);
    }
  }

  os << '"';
}

bool PrettyPrinterBase::shouldSkip(const gtirb::Section& section) const {
  return !this->debug && policy.skipSections.count(section.getName());
}

bool PrettyPrinterBase::shouldSkip(const gtirb::Symbol& symbol) const {
  if (debug) {
    return false;
  }

  if (symbol.hasReferent()) {
    const auto* Referent = symbol.getReferent<gtirb::Node>();
    if (auto* CB = dyn_cast<gtirb::CodeBlock>(Referent)) {
      return shouldSkip(*CB);
    } else if (auto* DB = dyn_cast<gtirb::DataBlock>(Referent)) {
      return shouldSkip(*DB);
    } else if (isa<gtirb::ProxyBlock>(Referent)) {
      return false;
    } else {
      assert(!"non block in symbol referent!");
    }
  } else if (auto Addr = symbol.getAddress()) {
    auto FunctionName = getContainerFunctionName(*Addr);
    return FunctionName && policy.skipFunctions.count(*FunctionName);
  } else {
    return false;
  }
}

bool PrettyPrinterBase::shouldSkip(const gtirb::CodeBlock& block) const {
  if (debug) {
    return false;
  }

  auto FunctionName = getContainerFunctionName(*block.getAddress());
  return FunctionName && policy.skipFunctions.count(*FunctionName);
}

bool PrettyPrinterBase::shouldSkip(const gtirb::DataBlock& block) const {
  if (debug) {
    return false;
  }

  for (const auto& sym : module.findSymbols(block)) {
    if (policy.skipFunctions.count(sym.getName())) {
      return true;
    }
  }

  return false;
}

bool PrettyPrinterBase::isFunctionEntry(const gtirb::Addr x) const {
  return functionEntry.count(x) > 0;
}

bool PrettyPrinterBase::isFunctionLastBlock(const gtirb::Addr x) const {
  return functionLastBlock.count(x) > 0;
}

std::optional<std::string>
PrettyPrinterBase::getContainerFunctionName(const gtirb::Addr x) const {
  auto it = functionEntry.upper_bound(x);
  if (it == functionEntry.begin())
    return std::nullopt;
  it--;
  return this->getFunctionName(*it);
}

const std::optional<const gtirb::Section*>
PrettyPrinterBase::getContainerSection(const gtirb::Addr addr) const {
  auto found_sections = module.findSectionsOn(addr);
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
    os << syntax.align() << " 16\n";
    return;
  }
  if (x % 8 == 0) {
    os << syntax.align() << " 8\n";
    return;
  }
  if (x % 4 == 0) {
    os << syntax.align() << " 4\n";
    return;
  }
  if (x % 2 == 0) {
    os << syntax.align() << " 2\n";
    return;
  }
}

std::string PrettyPrinterBase::getFunctionName(gtirb::Addr x) const {
  // Is this address an entry point to a function with a symbol?
  bool entry_point = isFunctionEntry(x);

  if (entry_point) {
    const auto symbols = module.findSymbols(x);
    if (!symbols.empty()) {
      const gtirb::Symbol& s = symbols.front();
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

std::string PrettyPrinterBase::getSymbolName(gtirb::Addr x) const {
  std::stringstream ss;
  ss << ".L_" << std::hex << uint64_t(x) << std::dec;
  return ss.str();
}

std::optional<std::string>
PrettyPrinterBase::getForwardedSymbolName(const gtirb::Symbol* symbol,
                                          bool inData) const {
  const auto* symbolForwarding =
      module.getAuxData<gtirb::schema::SymbolForwarding>();

  if (symbolForwarding) {
    auto found = symbolForwarding->find(symbol->getUUID());
    if (found != symbolForwarding->end()) {
      gtirb::Node* destSymbol = gtirb::Node::getByUUID(context, found->second);
      return (cast<gtirb::Symbol>(destSymbol))->getName() +
             getForwardedSymbolEnding(symbol, inData);
    }
  }
  return {};
}

std::string
PrettyPrinterBase::getForwardedSymbolEnding(const gtirb::Symbol* symbol,
                                            bool inData) const {
  if (symbol->getAddress()) {
    gtirb::Addr addr = *symbol->getAddress();
    const auto container_sections = module.findSectionsOn(addr);
    if (container_sections.begin() == container_sections.end())
      return std::string{};
    std::string section_name = container_sections.begin()->getName();
    if (!inData && (section_name == ".plt" || section_name == ".plt.got"))
      return std::string{"@PLT"};
    if (section_name == ".got" || section_name == ".got.plt")
      return std::string{"@GOTPCREL"};
  }
  return std::string{};
}

bool PrettyPrinterBase::isAmbiguousSymbol(const std::string& name) const {
  // Are there multiple symbols with this name?
  auto found = module.findSymbols(name);
  return distance(begin(found), end(found)) > 1;
}

void PrettyPrinterBase::printSection(std::ostream& os,
                                     const gtirb::Section& section) {
  if (shouldSkip(section)) {
    return;
  }

  printSectionHeader(os, section);

  for (const auto& Block : section.blocks()) {
    if (auto* CB = dyn_cast<gtirb::CodeBlock>(&Block)) {
      printCodeBlock(os, *CB);
    } else if (auto* DB = dyn_cast<gtirb::DataBlock>(&Block)) {
      printDataBlock(os, *DB);
    } else {
      assert(!"non block in block iterator!");
    }
  }

  printSectionFooter(os, section);
}

void registerAuxDataTypes() {
  using namespace gtirb::schema;
  gtirb::AuxDataContainer::registerAuxDataType<Comments>();
  gtirb::AuxDataContainer::registerAuxDataType<FunctionEntries>();
  gtirb::AuxDataContainer::registerAuxDataType<FunctionBlocks>();
  gtirb::AuxDataContainer::registerAuxDataType<SymbolForwarding>();
  gtirb::AuxDataContainer::registerAuxDataType<Encodings>();
  gtirb::AuxDataContainer::registerAuxDataType<ElfSectionProperties>();
  gtirb::AuxDataContainer::registerAuxDataType<PeSectionProperties>();
  gtirb::AuxDataContainer::registerAuxDataType<CfiDirectives>();
  gtirb::AuxDataContainer::registerAuxDataType<Libraries>();
  gtirb::AuxDataContainer::registerAuxDataType<LibraryPaths>();
  gtirb::AuxDataContainer::registerAuxDataType<DataDirectories>();
  gtirb::AuxDataContainer::registerAuxDataType<BaseAddress>();
  gtirb::AuxDataContainer::registerAuxDataType<PeImportedSymbols>();
  gtirb::AuxDataContainer::registerAuxDataType<PeExportedSymbols>();
}

} // namespace gtirb_pprint

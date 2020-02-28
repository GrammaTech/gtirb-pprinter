//===- MasmPrinter.cpp ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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

#include "MasmPrettyPrinter.hpp"

#include "regex"
#include "string_utils.hpp"
#include <boost/algorithm/string/replace.hpp>

namespace gtirb_pprint {

std::string MasmSyntax::formatSectionName(const std::string& x) const {
  std::string name(x);
  if (name[0] == '.')
    name[0] = '_';
  return ascii_str_toupper(name);
}

std::string MasmSyntax::formatFunctionName(const std::string& x) const {
  std::string name(x);
  if (name[0] == '.')
    name[0] = '$';
  return name;
}

std::string MasmSyntax::formatSymbolName(const std::string& x) const {
  std::string name = avoidRegNameConflicts(x);
  if (name[0] == '.')
    name[0] = '$';
  return name;
}

MasmPrettyPrinter::MasmPrettyPrinter(gtirb::Context& context_,
                                     gtirb::Module& module_,
                                     const MasmSyntax& syntax_,
                                     const PrintingPolicy& policy_)
    : PePrettyPrinter(context_, module_, syntax_, policy_),
      masmSyntax(syntax_) {

  const auto* BaseAddress = module.getAuxData<gtirb::Addr>("baseAddress");
  if (BaseAddress) {
    ImageBase = *BaseAddress;
  }

  if (gtirb::CodeBlock* Block = module.getEntryPoint(); Block->getAddress()) {
    auto* EntryPoint =
        gtirb::Symbol::Create(context, *(Block->getAddress()), "__EntryPoint");
    module.addSymbol(EntryPoint);
    Exports.insert(EntryPoint->getUUID());
  }

  const auto* SymbolTypes =
      module.getAuxData<std::map<gtirb::UUID, std::string>>("symbolType");
  if (SymbolTypes) {
    for (const auto& [UUID, Type] : *SymbolTypes) {
      if (Type == "EXTERN") {
        Imports.insert(UUID);
      } else if (Type == "PUBLIC") {
        Exports.insert(UUID);
      }
    }
  }
}

void MasmPrettyPrinter::printIncludes(std::ostream& os) {
  const auto* libraries =
      module.getAuxData<std::vector<std::string>>("libraries");
  if (libraries) {
    for (const auto& library : *libraries) {
      // Include replacement libs.
      bool replaced = false;
      for (const auto& [pattern, replacements] : dllLibraries) {
        std::regex re(pattern, std::regex::icase);
        if (std::regex_match(library, re)) {
          for (const auto& lib : replacements) {
            os << "INCLUDELIB " << lib << '\n';
          }
          replaced = true;
        }
      }
      // Include DLL as LIB.
      if (!replaced) {
        os << "INCLUDELIB "
           << boost::ireplace_last_copy(library, ".dll", ".lib") << '\n';
      }
    }
  }
  os << '\n';
}

void MasmPrettyPrinter::printExterns(std::ostream& os) {
  // Declare EXTERN symbols
  if (const auto* symbolForwarding =
          module.getAuxData<std::map<gtirb::UUID, gtirb::UUID>>(
              "symbolForwarding")) {
    std::set<std::string> externs;
    for (auto& forward : *symbolForwarding) {
      if (const auto* symbol = dyn_cast_or_null<gtirb::Symbol>(
              gtirb::Node::getByUUID(context, forward.second))) {
        externs.insert(symbol->getName());
      }
    }
    for (auto& name : externs) {
      os << masmSyntax.extrn() << ' ' << name << ":PROC\n";
    }
  }

  os << '\n' << masmSyntax.extrn() << " __ImageBase:BYTE\n";

  os << '\n';
}

void MasmPrettyPrinter::printHeader(std::ostream& os) {
  printIncludes(os);
  printExterns(os);
}

void MasmPrettyPrinter::printSectionHeaderDirective(
    std::ostream& os, const gtirb::Section& section) {
  std::string section_name = syntax.formatSectionName(section.getName());
  os << section_name << ' ' << syntax.section();
}
void MasmPrettyPrinter::printSectionProperties(std::ostream& os,
                                               const gtirb::Section& section) {
  const auto* peSectionProperties =
      module.getAuxData<std::map<gtirb::UUID, uint64_t>>("peSectionProperties");
  if (!peSectionProperties)
    return;
  const auto sectionProperties = peSectionProperties->find(section.getUUID());
  if (sectionProperties == peSectionProperties->end())
    return;
  uint64_t flags = sectionProperties->second;

  if (flags & IMAGE_SCN_MEM_READ)
    os << " READ";
  if (flags & IMAGE_SCN_MEM_WRITE)
    os << " WRITE";
  if (flags & IMAGE_SCN_MEM_EXECUTE)
    os << " EXECUTE";
  if (flags & IMAGE_SCN_MEM_SHARED)
    os << " SHARED";
  if (flags & IMAGE_SCN_MEM_NOT_PAGED)
    os << " NOPAGE";
  if (flags & IMAGE_SCN_MEM_NOT_CACHED)
    os << " NOCACHE";
  if (flags & IMAGE_SCN_MEM_DISCARDABLE)
    os << " DISCARD";
  if (flags & IMAGE_SCN_CNT_CODE)
    os << " 'CODE'";
  if (flags & IMAGE_SCN_CNT_INITIALIZED_DATA)
    os << " 'DATA'";
};

void MasmPrettyPrinter::printSectionFooterDirective(
    std::ostream& os, const gtirb::Section& section) {
  std::string section_name = syntax.formatSectionName(section.getName());

  // Special .CODE .DATA and .DATA? directives do not need footers.
  if (section_name == "_TEXT" || section_name == "_DATA" ||
      section_name == "_BSS") {
    os << syntax.comment() << ' ' << section_name << ' ' << masmSyntax.ends();
    return;
  }

  os << section_name << ' ' << masmSyntax.ends();
}

void MasmPrettyPrinter::printFunctionHeader(std::ostream& os,
                                            gtirb::Addr addr) {
  // Print public definitions
  for (const gtirb::Symbol& symbol : module.findSymbols(addr)) {
    if (Exports.count(symbol.getUUID())) {
      os << '\n' << syntax.global() << ' ' << symbol.getName() << '\n';
    }
  }

  const std::string& name =
      syntax.formatFunctionName(this->getFunctionName(addr));
  if (!name.empty()) {
    // TODO: Use PROC/ENDP blocks
    // os << name << ' ' << masmSyntax.proc() << '\n';
    os << name << ":\n";
  }
}

void MasmPrettyPrinter::printFunctionFooter(std::ostream& /* os */,
                                            gtirb::Addr /* addr */) {
  // TODO: Use PROC/ENDP blocks
  // if (!isFunctionLastBlock(addr))
  //   return;
  // const std::optional<std::string>& name = getContainerFunctionName(addr);
  // if (name && !name->empty()) {
  //   os << syntax.formatFunctionName(*name) << ' ' << masmSyntax.endp()
  //      << "\n\n";
  // }
}

void MasmPrettyPrinter::fixupInstruction(cs_insn& inst) {

  // Change GAS-specific MOVABS opcode to equivalent MOV opcode.
  if (inst.id == X86_INS_MOVABS) {
    std::string_view mnemonic(inst.mnemonic);
    if (mnemonic.size() > 3) {
      inst.mnemonic[3] = '\0';
    }
  }

  PrettyPrinterBase::fixupInstruction(inst);
}

void MasmPrettyPrinter::printSymbolDefinitionsAtAddress(std::ostream& os,
                                                        gtirb::Addr ea,
                                                        bool inData) {
  if (isFunctionEntry(ea) || ea == gtirb::Addr(0)) {
    return;
  }

  // Print public definitions
  for (const gtirb::Symbol& symbol : module.findSymbols(ea)) {
    if (Exports.count(symbol.getUUID())) {
      if (symbol.getAddress()) {
        os << '\n' << syntax.global() << ' ' << symbol.getName() << '\n';
      }
    }
  }

  // Print label
  PrettyPrinterBase::printSymbolDefinitionsAtAddress(os, ea, false);

  if (inData) {
    // Print name for data object
    if (!module.findSymbols(ea).empty()) {
      os << 'N' << getSymbolName(ea).substr(2);
    }
  }
}

void MasmPrettyPrinter::printOpRegdirect(std::ostream& os,
                                         const cs_insn& /*inst*/,
                                         const cs_x86_op& op) {
  assert(op.type == X86_OP_REG &&
         "printOpRegdirect called without a register operand");
  os << getRegisterName(op.reg);
}

void MasmPrettyPrinter::printOpImmediate(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_x86_op& op = inst.detail->x86.operands[index];
  assert(op.type == X86_OP_IMM &&
         "printOpImmediate called without an immediate operand");

  bool is_call = cs_insn_group(this->csHandle, &inst, CS_GRP_CALL);
  bool is_jump = cs_insn_group(this->csHandle, &inst, CS_GRP_JUMP);

  if (const gtirb::SymAddrConst* s = this->getSymbolicImmediate(symbolic)) {
    // The operand is symbolic.

    // Symbols for skipped addresses degrade to literals.
    std::optional<gtirb::Addr> addr = s->Sym->getAddress();
    bool becomes_literal = (addr && skipEA(*addr));

    if (!is_call && !is_jump && !becomes_literal)
      os << masmSyntax.offset() << ' ';

    printSymbolicExpression(os, s, !is_call && !is_jump);
  } else {
    // The operand is just a number.
    os << op.imm;
  }
}

void MasmPrettyPrinter::printOpIndirect(
    std::ostream& os, const gtirb::SymbolicExpression* symbolic,
    const cs_insn& inst, uint64_t index) {
  const cs_x86& detail = inst.detail->x86;
  const cs_x86_op& op = detail.operands[index];
  assert(op.type == X86_OP_MEM &&
         "printOpIndirect called without a memory operand");
  bool first = true;

  // Replace indirect reference to EXTERN with direct reference.
  //   e.g.  call QWORD PTR [puts]
  //         call puts
  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    std::optional<std::string> forwardedName =
        getForwardedSymbolName(s->Sym, true);
    if (forwardedName) {
      os << *forwardedName;
      return;
    }
  }

  uint64_t size = op.size;

  //////////////////////////////////////////////////////////////////////////////
  // Capstone incorrectly gives memory operands XMMWORD size.
  if (inst.id == X86_INS_COMISD || inst.id == X86_INS_VCOMISD) {
    size = 8;
  }
  if (inst.id == X86_INS_COMISS) {
    size = 4;
  }
  //////////////////////////////////////////////////////////////////////////////

  if (std::optional<std::string> sizeName = syntax.getSizeName(size * 8))
    os << *sizeName << " PTR ";

  if (op.mem.segment != X86_REG_INVALID)
    os << getRegisterName(op.mem.segment) << ':';

  os << '[';

  if (op.mem.base != X86_REG_INVALID && op.mem.base != X86_REG_RIP) {
    first = false;
    os << getRegisterName(op.mem.base);
  }

  if (op.mem.base == X86_REG_RIP && symbolic == nullptr) {
    if (gtirb::Addr(inst.address + inst.size + op.mem.disp) == ImageBase) {
      os << "__ImageBase]";
      return;
    }
  }

  if (op.mem.index != X86_REG_INVALID) {
    if (!first)
      os << '+';
    first = false;
    os << getRegisterName(op.mem.index) << '*' << std::to_string(op.mem.scale);
  }

  if (const auto* s = std::get_if<gtirb::SymAddrConst>(symbolic)) {
    if (!first)
      os << '+';

    printSymbolicExpression(os, s, false);
  } else if (const auto* rel = std::get_if<gtirb::SymAddrAddr>(symbolic)) {
    if (std::optional<gtirb::Addr> Addr = rel->Sym1->getAddress(); Addr) {
      os << "+(" << masmSyntax.imagerel() << ' ' << 'N'
         << getSymbolName(*Addr).substr(2) << ")";
    }
  } else {
    printAddend(os, op.mem.disp, first);
  }
  os << ']';
}

void MasmPrettyPrinter::printSymbolicExpression(
    std::ostream& os, const gtirb::SymAddrConst* sexpr, bool inData) {
  PrettyPrinterBase::printSymbolicExpression(os, sexpr, inData);
}

void MasmPrettyPrinter::printSymbolicExpression(std::ostream& os,
                                                const gtirb::SymAddrAddr* sexpr,
                                                bool inData) {
  if (inData && sexpr->Sym2->getAddress() == ImageBase) {
    os << masmSyntax.imagerel() << ' ';
    printSymbolReference(os, sexpr->Sym1, inData);
    return;
  }

  PrettyPrinterBase::printSymbolicExpression(os, sexpr, inData);
}

void MasmPrettyPrinter::printByte(std::ostream& os, std::byte byte) {
  // Byte constants must start with a number for the MASM assembler.
  os << syntax.byteData() << " 0" << std::hex << std::setfill('0')
     << std::setw(2) << static_cast<uint32_t>(byte) << 'H' << std::dec << '\n';
}

void MasmPrettyPrinter::printZeroDataBlock(std::ostream& os,
                                           const gtirb::DataBlock& dataObject) {
  os << syntax.tab();
  os << "DB " << dataObject.getSize() << " DUP(0)" << '\n';
}

void MasmPrettyPrinter::printString(std::ostream& os,
                                    const gtirb::DataBlock& x) {

  std::string Chunk{""};
  for (uint8_t b : x.bytes<uint8_t>()) {
    // NOTE: MASM only supports strings smaller than 256 bytes.
    //  and  MASM only supports statements with 50 comma-separated items.
    if (Chunk.size() >= 64) {
      boost::replace_all(Chunk, "'", "''");
      os << syntax.tab() << syntax.string() << " '" << Chunk << "'\n";
      Chunk.clear();
    }

    // Aggegrate printable characters
    if (std::isprint(b)) {
      Chunk.append(1, b);
      continue;
    }

    // Found non-printable character, output previous chunk and print byte
    if (!Chunk.empty()) {
      boost::replace_all(Chunk, "'", "''");
      os << syntax.tab() << syntax.string() << " '" << Chunk << "'\n";
      Chunk.clear();
    }
    os << syntax.tab();
    printByte(os, static_cast<std::byte>(b));
  }
}

void MasmPrettyPrinter::printFooter(std::ostream& os) {
  os << '\n' << masmSyntax.end();
}

std::string MasmPrettyPrinter::getSymbolName(gtirb::Addr x) const {
  std::stringstream ss;
  ss << "$L_" << std::hex << uint64_t(x) << std::dec;
  return ss.str();
}

const PrintingPolicy& MasmPrettyPrinterFactory::defaultPrintingPolicy() const {
  return MasmPrettyPrinter::defaultPrintingPolicy();
}

std::unique_ptr<PrettyPrinterBase>
MasmPrettyPrinterFactory::create(gtirb::Context& context, gtirb::Module& module,
                                 const PrintingPolicy& policy) {
  static const MasmSyntax syntax{};
  return std::make_unique<MasmPrettyPrinter>(context, module, syntax, policy);
}

volatile bool MasmPrettyPrinter::registered = registerPrinter(
    {"pe"}, {"masm"}, std::make_shared<MasmPrettyPrinterFactory>(), true);

} // namespace gtirb_pprint

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

MasmPrettyPrinter::MasmPrettyPrinter(gtirb::Context& context_, gtirb::IR& ir_,
                                     const MasmSyntax& syntax_,
                                     const PrintingPolicy& policy_)
    : PePrettyPrinter(context_, ir_, syntax_, policy_), masmSyntax(syntax_) {

  gtirb::Module& Module = *ir.modules().begin();
  gtirb::ImageByteMap& ImageByteMap = Module.getImageByteMap();

  // FIXME: How should we handle entry point label?
  gtirb::Addr Entry = ImageByteMap.getEntryPointAddress();
  auto* EntrySymbol = gtirb::Symbol::Create(context, Entry, "__entry__",
                                            gtirb::Symbol::StorageKind::Normal);
  Module.addSymbol(EntrySymbol);

  for (const gtirb::SymbolicExpression Symbolic : Module.symbolic_exprs()) {
    if (const auto* RelSymbolic = std::get_if<gtirb::SymAddrAddr>(&Symbolic)) {
      if (std::optional<gtirb::Addr> Addr = RelSymbolic->Sym1->getAddress();
          Addr && *Addr == ImageByteMap.getBaseAddress()) {
        if (Addr = RelSymbolic->Sym2->getAddress(); Addr) {
          namedDataObjects.insert(static_cast<uint64_t>(*Addr));
        }
      }
    }
  }
}

void MasmPrettyPrinter::printIncludes(std::ostream& os) {
  const auto* libraries =
      ir.modules().begin()->getAuxData<std::vector<std::string>>("libraries");
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
          ir.modules().begin()->getAuxData<std::map<gtirb::UUID, gtirb::UUID>>(
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

void MasmPrettyPrinter::printPublics(std::ostream& os) {
  for (const auto& symbol : this->ir.modules().begin()->symbols()) {
    if (symbol.getStorageKind() == gtirb::Symbol::StorageKind::Normal) {
      os << syntax.global() << ' ' << symbol.getName() << '\n';
    }
  }
}

void MasmPrettyPrinter::printHeader(std::ostream& os) {
  printIncludes(os);
  printExterns(os);
  printPublics(os);
}

void MasmPrettyPrinter::printSectionHeaderDirective(
    std::ostream& os, const gtirb::Section& section) {
  std::string section_name = syntax.formatSectionName(section.getName());
  os << section_name << ' ' << syntax.section();
}
void MasmPrettyPrinter::printSectionProperties(std::ostream& os,
                                               const gtirb::Section& section) {
  const auto* peSectionProperties =
      this->ir.modules().begin()->getAuxData<std::map<gtirb::UUID, uint64_t>>(
          "peSectionProperties");
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
  const std::string& name =
      syntax.formatFunctionName(this->getFunctionName(addr));
  if (!name.empty()) {
    // TODO: Use PROC/ENDP blocks
    os << syntax.comment() << ' ' << name << ' ' << masmSyntax.proc() << '\n';
    os << name << ":\n";
  }
}

void MasmPrettyPrinter::printFunctionFooter(std::ostream& os,
                                            gtirb::Addr addr) {
  if (!isFunctionLastBlock(addr))
    return;
  const std::optional<std::string>& name = getContainerFunctionName(addr);
  if (name && !name->empty()) {
    // TODO: Use PROC/ENDP blocks
    os << syntax.comment() << ' ' << syntax.formatFunctionName(*name) << ' '
       << masmSyntax.endp() << "\n\n";
  }
}

void MasmPrettyPrinter::printSymbolDefinitionsAtAddress(std::ostream& os,
                                                        gtirb::Addr ea) {
  if (isFunctionEntry(ea))
    return;
  PrettyPrinterBase::printSymbolDefinitionsAtAddress(os, ea);
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

  // FIXME: Replaces indirect reference to EXTERN with direct reference.
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

  // TODO: Apply this special case in the printer base.
  if (inst.id == X86_INS_COMISD || inst.id == X86_INS_VCOMISD) {
    // Capstone incorrectly gives memory operands XMMWORD size.
    size = 8;
  }

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
    if (inst.address + inst.size + op.mem.disp == 0) {
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
    os << "+(" << masmSyntax.imagerel() << ' ';

    // TODO: make helper func
    uint64_t ea = static_cast<uint64_t>(*rel->Sym2->getAddress());
    std::ios_base::fmtflags flags = os.flags();
    os << "N_" << std::hex << ea;
    os.flags(flags);

    os << ")";
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
  if (inData && sexpr->Sym1->getName() == ".L_0") {
    os << "(IMAGEREL ";
    printSymbolReference(os, sexpr->Sym2, inData);
    os << ")";
    return;
  }

  PrettyPrinterBase::printSymbolicExpression(os, sexpr, inData);
}

void MasmPrettyPrinter::printByte(std::ostream& os, std::byte byte) {
  // Byte constants must start with a number for the MASM assembler.
  os << syntax.byteData() << " 0" << std::hex << std::setfill('0')
     << std::setw(2) << static_cast<uint32_t>(byte) << 'H' << std::dec << '\n';
}

void MasmPrettyPrinter::printNonZeroDataObject(
    std::ostream& os, const gtirb::DataObject& dataObject) {

  uint64_t ea = static_cast<uint64_t>(dataObject.getAddress());
  if (namedDataObjects.count(ea) > 0) {
    // TODO: use a helper func
    std::ios_base::fmtflags flags = os.flags();
    os << "N_" << std::hex << ea << ' ';
    os.flags(flags);
  }

  PrettyPrinterBase::printNonZeroDataObject(os, dataObject);
}

void MasmPrettyPrinter::printZeroDataObject(
    std::ostream& os, const gtirb::DataObject& dataObject) {
  os << syntax.tab();
  os << "DB " << dataObject.getSize() << " DUP(0)" << '\n';
}

void MasmPrettyPrinter::printString(std::ostream& os,
                                    const gtirb::DataObject& x) {

  os << syntax.string() << ' ';
  bool open = false;
  bool prev = false;

  for (const std::byte& b :
       getBytes(this->ir.modules().begin()->getImageByteMap(), x)) {

    switch (uint8_t(b)) {
    case 0:
      continue;
    case '"':
    case '\n':
    case '\t':
    case '\v':
    case '\b':
    case '\r':
    case '\a':
    case '\'':
      if (open) {
        os << '"';
      }
      if (prev) {
        os << ", ";
      }
      os << std::hex << std::setfill('0') << std::setw(2)
         << static_cast<uint32_t>(b) << 'H' << std::dec;
      prev = true;
      open = false;
      break;
    default:
      if (!prev && !open) {
        os << '"';
      }
      if (prev && !open) {
        os << ", \"";
      }
      os << uint8_t(b);
      prev = true;
      open = true;
    }
  }

  if (open) {
    os << '"';
  }
  os << ", 0";
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
MasmPrettyPrinterFactory::create(gtirb::Context& context, gtirb::IR& ir,
                                 const PrintingPolicy& policy) {
  static const MasmSyntax syntax{};
  return std::make_unique<MasmPrettyPrinter>(context, ir, syntax, policy);
}

volatile bool MasmPrettyPrinter::registered = registerPrinter(
    {"pe"}, {"masm"}, std::make_shared<MasmPrettyPrinterFactory>(), true);

} // namespace gtirb_pprint

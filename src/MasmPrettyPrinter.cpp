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

std::optional<std::string> MasmSyntax::getSizeName(uint64_t bits) const {
  switch (bits) {
  case 128:
    return "XMMWORD";
  case 256:
    return "YMMWORD";
  }
  return Syntax::getSizeName(bits);
};

MasmPrettyPrinter::MasmPrettyPrinter(gtirb::Context& context_, gtirb::IR& ir_,
                                     const MasmSyntax& syntax_,
                                     const PrintingPolicy& policy_)
    : PePrettyPrinter(context_, ir_, syntax_, policy_), masmSyntax(syntax_) {}

void MasmPrettyPrinter::printHeader(std::ostream& os) {
  // FIXME: Should all imported libraries be included?
  const auto* libraries =
      ir.modules().begin()->getAuxData<std::vector<std::string>>("libraries");
  if (libraries) {
    for (const auto& library : *libraries)
      os << "INCLUDELIB " << boost::replace_last_copy(library, "dll", "lib")
         << '\n';
  }

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

  // FIXME:
  // Declare the function at the entrypoint as a PUBLIC symbol.
  gtirb::ImageByteMap& IBM = this->ir.modules().begin()->getImageByteMap();
  gtirb::Addr entryPoint = IBM.getEntryPointAddress();
  std::string functionName = getFunctionName(entryPoint);
  if (!functionName.empty()) {
    os << syntax.global() << ' ' << functionName << '\n';
  }
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
    if (!is_call && !is_jump)
      os << masmSyntax.offset() << ' ';
    this->printSymbolicExpression(os, s, !is_call && !is_jump);
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

  if (std::optional<std::string> size = syntax.getSizeName(op.size * 8))
    os << *size << " PTR ";

  if (op.mem.segment != X86_REG_INVALID)
    os << getRegisterName(op.mem.segment) << ':';

  os << '[';

  if (op.mem.base != X86_REG_INVALID && op.mem.base != X86_REG_RIP) {
    first = false;
    os << getRegisterName(op.mem.base);
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
  } else {
    printAddend(os, op.mem.disp, first);
  }
  os << ']';
}

void MasmPrettyPrinter::printByte(std::ostream& os, std::byte byte) {
  // Byte constants must start with a number for the MASM assembler.
  os << syntax.byteData() << " 0" << std::hex << std::setfill('0')
     << std::setw(2) << static_cast<uint32_t>(byte) << 'H' << std::dec << '\n';
}

void MasmPrettyPrinter::printZeroDataObject(
    std::ostream& os, const gtirb::DataObject& dataObject) {
  os << syntax.tab();
  os << "DB " << dataObject.getSize() << " DUP(0)" << '\n';
}

void MasmPrettyPrinter::printString(std::ostream& os,
                                    const gtirb::DataObject& x) {
  PrettyPrinterBase::printString(os, x);
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

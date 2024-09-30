//===- MasmPrettyPrinter.hpp ------------------------------------*- C++ -*-===//
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
#ifndef GTIRB_PP_MASM_PRINTER_H
#define GTIRB_PP_MASM_PRINTER_H

#include "PePrettyPrinter.hpp"

namespace gtirb_pprint {

class DEBLOAT_PRETTYPRINTER_EXPORT_API MasmSyntax : public Syntax {
public:
  // Styles
  const std::string& comment() const override { return CommentStyle; }

  // Common directives
  const std::string& string() const override { return StringDirective; }

  const std::string& byteData() const override { return ByteDirective; }
  const std::string& longData() const override { return LongDirective; }
  const std::string& quadData() const override { return QuadDirective; }
  const std::string& wordData() const override { return WordDirective; }

  const std::string& text() const override { return TextDirective; }
  const std::string& data() const override { return DataDirective; }
  const std::string& bss() const override { return BssDirective; }

  const std::string& section() const override { return SectionDirective; }
  const std::string& global() const override { return GlobalDirective; }
  const std::string& align() const override { return AlignDirective; }

  const std::string& programCounter() const override {
    return ProgramCounterName;
  }

  // MASM directives
  const std::string& offset() const { return OffsetDirective; }
  const std::string& extrn() const { return ExternDirective; }
  const std::string& imagerel() const { return ImageRelDirective; }

  const std::string& ends() const { return EndsDirective; }
  const std::string& proc() const { return ProcDirective; }
  const std::string& endp() const { return EndpDirective; }
  const std::string& end() const { return EndDirective; }

  // Formatting helpers
  std::string formatSectionName(const std::string& x) const override;
  std::string formatFunctionName(const std::string& x) const override;
  std::string avoidRegNameConflicts(const std::string& x) const override;
  std::string formatSymbolName(const std::string& x) const override;

private:
  const std::string CommentStyle{";"};

  const std::string StringDirective{"DB"};

  const std::string ByteDirective{"BYTE"};
  const std::string LongDirective{"DWORD"};
  const std::string QuadDirective{"QWORD"};
  const std::string WordDirective{"WORD"};

  const std::string TextDirective{".CODE"};
  const std::string DataDirective{".DATA"};
  const std::string BssDirective{".DATA?"};

  const std::string ProgramCounterName{"$"};

  const std::string SectionDirective{"SEGMENT"};
  const std::string GlobalDirective{"PUBLIC"};
  const std::string AlignDirective{"ALIGN"};
  const std::string ExternDirective{"EXTERN"};
  const std::string OffsetDirective{"OFFSET"};
  const std::string ImageRelDirective{"IMAGEREL"};

  const std::string EndsDirective{"ENDS"};
  const std::string ProcDirective{"PROC"};
  const std::string EndpDirective{"ENDP"};
  const std::string EndDirective{"END"};
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API MasmPrettyPrinter
    : public PePrettyPrinter {
public:
  MasmPrettyPrinter(gtirb::Context& context, const gtirb::Module& module,
                    const MasmSyntax& syntax, const PrintingPolicy& policy);

protected:
  const MasmSyntax& masmSyntax;

  void printIncludes(std::ostream& os);
  void printExterns(std::ostream& os);

  std::string getSymbolName(const gtirb::Symbol& Symbol) const override;
  void fixupInstruction(cs_insn& inst) override;
  void printHeader(std::ostream& os) override;
  void printFooter(std::ostream& os) override;

  void printSectionHeader(std::ostream& os,
                          const gtirb::Section& section) override;
  void printSectionHeaderDirective(std::ostream& os,
                                   const gtirb::Section& section) override;
  void printSectionProperties(std::ostream& os,
                              const gtirb::Section& section) override;
  void printSectionFooterDirective(std::ostream& os,
                                   const gtirb::Section& addr) override;

  // Print the "FunctionSymbol ENDP" label.
  void printFunctionEnd(std::ostream& OS,
                        const gtirb::Symbol& FunctionSymbol) override;

  void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                        uint64_t index) override;
  void printOpImmediate(std::ostream& os,
                        const gtirb::SymbolicExpression* symbolic,
                        const cs_insn& inst, uint64_t index) override;
  void printOpIndirect(std::ostream& os,
                       const gtirb::SymbolicExpression* symbolic,
                       const cs_insn& inst, uint64_t index) override;

  std::optional<std::string>
  getForwardedSymbolName(const gtirb::Symbol* symbol) const override;

  std::string getRegisterName(unsigned int Reg) const override;

  void printSymbolDefinition(std::ostream& os,
                             const gtirb::Symbol& symbol) override;
  void printSymbolDefinitionRelativeToPC(std::ostream& os,
                                         const gtirb::Symbol& symbol,
                                         gtirb::Addr pc) override;
  void printIntegralSymbol(std::ostream& os,
                           const gtirb::Symbol& symbol) override;
  void printUndefinedSymbol(std::ostream& /*os*/,
                            const gtirb::Symbol& /*symbol*/) override{};

  void printSymbolicExpression(std::ostream& os,
                               const gtirb::SymAddrConst* sexpr,
                               bool inData = false) override;
  void printSymbolicExpression(std::ostream& os,
                               const gtirb::SymAddrAddr* sexpr,
                               bool inData = false) override;

  void printByte(std::ostream& os, std::byte byte) override;
  void printZeroDataBlock(std::ostream& os, const gtirb::DataBlock& dataObject,
                          uint64_t offset) override;

  bool printSymbolReference(std::ostream& os,
                            const gtirb::Symbol* symbol) override;
  void printString(std::ostream& Stream, const gtirb::DataBlock& Block,
                   uint64_t Offset, bool NullTerminated = true) override;

  std::optional<uint64_t>
  adjustAlignment(const gtirb::DataBlock& Block,
                  const std::optional<uint64_t>& Align) override;

private:
  gtirb::Addr BaseAddress;
  const gtirb::Symbol* ImageBase;
  std::optional<const gtirb::Symbol*> EntryPoint;
  std::unordered_set<gtirb::UUID> Imports;
  std::unordered_set<gtirb::UUID> Exports;
  std::unordered_map<gtirb::UUID, std::string> RenamedSections;
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API MasmPrettyPrinterFactory
    : public PePrettyPrinterFactory {
public:
  std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, const gtirb::Module& module,
         const PrintingPolicy& policy) override;
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API UasmPrettyPrinter
    : public MasmPrettyPrinter {

public:
  UasmPrettyPrinter(gtirb::Context& context_, const gtirb::Module& module_,
                    const MasmSyntax& syntax_, const PrintingPolicy& policy_)
      : MasmPrettyPrinter(context_, module_, syntax_, policy_) {}
  void printHeader(std::ostream& os) override;
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API UasmPrettyPrinterFactory
    : public PePrettyPrinterFactory {
public:
  std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, const gtirb::Module& module,
         const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_MASM_PRINTER_H */

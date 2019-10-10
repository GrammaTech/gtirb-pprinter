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

class MasmSyntax : public Syntax {
public:
  MasmSyntax();

  // Styles
  const std::string& comment() const override;

  // Common directives
  const std::string& string() const override;

  const std::string& byteData() const override;
  const std::string& longData() const override;
  const std::string& quadData() const override;
  const std::string& wordData() const override;

  const std::string& text() const override;
  const std::string& data() const override;
  const std::string& bss() const override;

  const std::string& section() const override;
  const std::string& global() const override;
  const std::string& align() const override;
  const std::string& extrn() const;
  const std::string& offset() const;

  // MASM directives
  const std::string& ends() const;
  const std::string& proc() const;
  const std::string& endp() const;
  const std::string& end() const;

  // Formatting helpers
  std::string formatSectionName(const std::string& x) const override;
  std::string formatFunctionName(const std::string& x) const override;
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

  const std::string SectionDirective{"SEGMENT"};
  const std::string GlobalDirective{"PUBLIC"};
  const std::string AlignDirective{"ALIGN"};
  const std::string ExternDirective{"EXTERN"};
  const std::string OffsetDirective{"OFFSET"};

  const std::string EndsDirective{"ENDS"};
  const std::string ProcDirective{"PROC"};
  const std::string EndpDirective{"ENDP"};
  const std::string EndDirective{"END"};
};

class MasmPrettyPrinter : public PePrettyPrinter {
public:
  MasmPrettyPrinter(gtirb::Context& context, gtirb::IR& ir,
                    const MasmSyntax& syntax, const PrintingPolicy& policy);

protected:
  const MasmSyntax& masmSyntax;

  void printHeader(std::ostream& os) override;
  void printFooter(std::ostream& os) override;

  void printSectionHeaderDirective(std::ostream& os,
                                   const gtirb::Section& section) override;
  void printSectionProperties(std::ostream& os,
                              const gtirb::Section& section) override;
  void printSectionFooterDirective(std::ostream& os,
                                   const gtirb::Section& addr) override;

  void printFunctionHeader(std::ostream& os, gtirb::Addr addr) override;
  void printFunctionFooter(std::ostream& os, gtirb::Addr addr) override;

  void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                        const cs_x86_op& op) override;
  void printOpImmediate(std::ostream& os,
                        const gtirb::SymbolicExpression* symbolic,
                        const cs_insn& inst, uint64_t index) override;
  void printOpIndirect(std::ostream& os,
                       const gtirb::SymbolicExpression* symbolic,
                       const cs_insn& inst, uint64_t index) override;

  void printSymbolDefinitionsAtAddress(std::ostream& os,
                                       gtirb::Addr ea) override;

  void printByte(std::ostream& os, std::byte byte) override;

  void printZeroDataObject(std::ostream& os,
                           const gtirb::DataObject& dataObject) override;

  void printString(std::ostream& os, const gtirb::DataObject& x) override;

  std::string getSymbolName(gtirb::Addr x) const override;

private:
  static volatile bool registered;
};

class MasmPrettyPrinterFactory : public PrettyPrinterFactory {
public:
  const PrintingPolicy& defaultPrintingPolicy() const override;
  std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, gtirb::IR& ir,
         const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_MASM_PRINTER_H */

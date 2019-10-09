//===- ElfPrettyPrinter.hpp -------------------------------------*- C++ -*-===//
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
#ifndef GTIRB_PP_ELF_PRINTER_H
#define GTIRB_PP_ELF_PRINTER_H

#include "PrettyPrinter.hpp"

namespace gtirb_pprint {

class ElfSyntax : public Syntax {
public:
  const std::string& comment() const override { return CommentStyle; }

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

  const std::string& type() const { return TypeDirective; }

private:
  const std::string CommentStyle{"#"};

  const std::string StringDirective{".string"};

  const std::string ByteDirective{".byte"};
  const std::string LongDirective{".long"};
  const std::string QuadDirective{".quad"};
  const std::string WordDirective{".word"};

  const std::string TextDirective{".text"};
  const std::string DataDirective{".data"};
  const std::string BssDirective{".bss"};

  const std::string SectionDirective{".section"};
  const std::string GlobalDirective{".globl"};
  const std::string AlignDirective{".align"};
  const std::string TypeDirective{".type"};
};

class ElfPrettyPrinter : public PrettyPrinterBase {
public:
  ElfPrettyPrinter(gtirb::Context& context, gtirb::IR& ir,
                   const ElfSyntax& syntax, const PrintingPolicy& policy);

  static const PrintingPolicy& defaultPrintingPolicy();

protected:
  const ElfSyntax& elfSyntax;

  void printFooter(std::ostream& os) override;

  void printSectionHeaderDirective(std::ostream& os,
                                   const gtirb::Section& section) override;
  void printSectionProperties(std::ostream& os,
                              const gtirb::Section& section) override;
  void printSectionFooterDirective(std::ostream& os,
                                   const gtirb::Section& addr) override;
  void printFunctionHeader(std::ostream& os, gtirb::Addr addr) override;
  void printFunctionFooter(std::ostream& os, gtirb::Addr addr) override;

  void printByte(std::ostream& os, std::byte byte) override;

  bool
  shouldExcludeDataElement(const gtirb::Section& section,
                           const gtirb::DataObject& dataObject) const override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_ELF_PRINTER_H */

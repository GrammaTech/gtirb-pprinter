//===- ElfPrinter.h -------------------------------------------*- C++ -*-===//
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

#include "PrettyPrinter.h"

namespace gtirb_pprint {

class ElfSyntax : public Syntax {
public:
  ElfSyntax();

  const std::string& Comment() const override;

  const std::string& Byte() const override;
  const std::string& Long() const override;
  const std::string& Quad() const override;
  const std::string& Word() const override;

  const std::string& Text() const override;
  const std::string& Data() const override;
  const std::string& Bss() const override;

  const std::string& Section() const override;
  const std::string& Global() const override;
  const std::string& Align() const override;
  const std::string& Type() const;

private:
  const std::string commentStyle{"#"};

  const std::string byteDirective{".byte"};
  const std::string longDirective{".long"};
  const std::string quadDirective{".quad"};
  const std::string wordDirective{".word"};

  const std::string textDirective{".text"};
  const std::string dataDirective{".data"};
  const std::string bssDirective{".bss"};

  const std::string sectionDirective{".section"};
  const std::string globalDirective{".globl"};
  const std::string alignDirective{".align"};
  const std::string typeDirective{".type"};
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

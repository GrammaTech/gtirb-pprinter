//===- IntelIcxPrettyPrinter.h ---------------------------------*- C++ -*-===//
//
//  Copyright (C) 2021 GrammaTech, Inc.
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
//===---------------------------------------------------------------------===//
#ifndef GTIRB_PP_INTEL_ICX_PRINTER_H
#define GTIRB_PP_INTEL_ICX_PRINTER_H

#include "IntelPrettyPrinter.hpp"

namespace gtirb_pprint {

class DEBLOAT_PRETTYPRINTER_EXPORT_API IcxAssembler : public ClangAssembler {
public:
  virtual std::string cleanSingleQuote(const std::string& s) const
  {
      // Do not add escape for single-quote
      return s;
  };
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API IntelIcxPrettyPrinter
    : public IntelPrettyPrinter {
public:
  IntelIcxPrettyPrinter(gtirb::Context& context, gtirb::Module& module,
                        const IntelSyntax& syntax, const IcxAssembler& assembler,
                        const PrintingPolicy& policy);
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API IntelIcxPrettyPrinterFactory
    : public IntelPrettyPrinterFactory {
public:
  std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, gtirb::Module& module,
         const PrintingPolicy& policy) override;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_INTEL_ICX_PRINTER_H */

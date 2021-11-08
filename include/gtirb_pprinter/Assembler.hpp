//===- Assembler.hpp -------------------------------------------*- C++ -*-===//
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
#ifndef GTIRB_PP_ASSEMBLER_H
#define GTIRB_PP_ASSEMBLER_H

#include "Export.hpp"
#include <optional>
#include <string>

namespace gtirb_pprint {

class DEBLOAT_PRETTYPRINTER_EXPORT_API Assembler {
public:
  virtual ~Assembler() = default;

  virtual std::string escapeByte(uint8_t b) const;
  virtual std::string escapeSingleQuote(const std::string& s) const;
};

class DEBLOAT_PRETTYPRINTER_EXPORT_API GasAssembler : public Assembler {};

class DEBLOAT_PRETTYPRINTER_EXPORT_API ClangAssembler : public Assembler {};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_ASSEMBLER_H */

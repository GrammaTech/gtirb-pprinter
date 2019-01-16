//===- NasmPrinter.h --------------------------------------------*- C++ -*-===//
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
#pragma once

#include "PrettyPrinter.h"

class NasmPP : public AbstractPP {
public:
  NasmPP(gtirb::Context& context, gtirb::IR& ir, const std::unordered_set<std::string>& skip_funcs,
         bool dbg);

protected:
  virtual int getGtirbOpIndex(int index, int opCount) const override;

  virtual void printHeader(std::ostream& os) override;
  virtual void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                const cs_x86_op& op) override;
  virtual void printOpImmediate(std::ostream& os, const std::string& opcode,
                                const gtirb::SymbolicExpression* symbolic, const cs_insn& inst,
                                gtirb::Addr ea, uint64_t index) override;
  virtual void printOpIndirect(std::ostream& os, const gtirb::SymbolicExpression* symbolic,
                               const cs_insn& inst, uint64_t index) override;

  static constexpr char StrOffset[]{"OFFSET"};

private:
  static bool registered;
};

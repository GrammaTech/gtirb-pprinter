//===- PrettyPrinter.h ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2018 GrammaTech, Inc.
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

#include <capstone/capstone.h>
#include <cstdint>
#include <iosfwd>
#include <list>
#include <map>
#include <string>
#include <vector>
#include "DisasmData.h"

///
/// \class PrettyPrinter
///
/// Port of the prolog pretty printer.
///
class PrettyPrinter {
public:
  PrettyPrinter();
  ~PrettyPrinter();

  void setDebug(bool x);
  bool getDebug() const;

  ///
  /// Pretty print to a string
  ///
  std::string prettyPrint(gtirb::Context& context, gtirb::IR* ir);

protected:
  /// Constants to reduce (eliminate) magical strings inside the printer.
  const std::string StrOffset{"OFFSET"};
  const std::string StrZeroByte{".byte 0x00"};
  const std::string StrNOP{"nop"};
  const std::string StrSection{".section"};
  const std::string StrSectionText{".text"};
  const std::string StrSectionBSS{".bss"};
  const std::string StrSectionGlobal{".globl"};
  const std::string StrSectionType{".type"};
  const std::string StrTab{"          "};

  const std::array<std::string, 7> AsmSkipSection{
      {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt"}};

  const std::array<std::string, 8> AsmSkipFunction{
      {"_start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux",
       "frame_dummy", "__libc_csu_fini", "__libc_csu_init", "_dl_relocate_static_pie"}};

  void printBar(bool heavy = true);
  void printBlock(const gtirb::Block& x);
  void printEA(gtirb::Addr ea);
  void printFunctionHeader(gtirb::Addr ea);
  void printHeader();
  void printInstruction(const cs_insn& inst);
  void printInstructionNop();
  void printLabel(gtirb::Addr ea);
  void printSectionHeader(const std::string& x, uint64_t alignment = 0);
  void printOperandList(const std::string& opcode, const gtirb::Addr ea, const cs_insn& inst);
  void printComment(const gtirb::Addr ea);
  void printDataGroups();

  void printBSS();

  std::string buildOperand(const std::string& opcode, const gtirb::SymbolicExpression* symbolic,
                           const cs_insn& inst, gtirb::Addr ea, uint64_t index);
  std::string buildOpRegdirect(const cs_x86_op& op);
  std::string buildOpImmediate(const std::string& opcode, const gtirb::SymbolicExpression* symbolic,
                               const cs_insn& inst, gtirb::Addr ea, uint64_t index);
  std::string buildOpIndirect(const gtirb::SymbolicExpression* symbolic, const cs_insn& inst,
                              uint64_t index);

  void printDataObject(const gtirb::DataObject& dataGroup);
  void printString(const gtirb::DataObject& x);
  void printSymbolicData(const gtirb::Addr addr, const gtirb::SymbolicExpression* symbolic);
  void printSymbolicExpression(const gtirb::SymAddrConst* sexpr, std::stringstream& stream);
  void printSymbolicExpression(const gtirb::SymAddrAddr* sexpr, std::stringstream& stream);
  bool condPrintGlobalSymbol(gtirb::Addr ea);
  void condPrintSectionHeader(const gtirb::Block& x);

  bool shouldExcludeDataElement(const std::string& sectionName, const gtirb::DataObject& dataGroup);
  bool isPointerToExcludedCode(const gtirb::DataObject& dataGroup);

  bool skipEA(const gtirb::Addr x) const;
  bool isInSkippedSection(const gtirb::Addr x) const;
  bool isInSkippedFunction(const gtirb::Addr x) const;
  std::string getContainerFunctionName(const gtirb::Addr x) const;
  bool isSectionSkipped(const std::string& name);

  std::string getRegisterName(unsigned int reg);
  std::string avoidRegNameConflicts(const std::string& x);
  std::string getAddendString(int64_t number, bool first = false);

private:
  csh csHandle;
  std::stringstream ofs;
  std::unique_ptr<DisasmData> disasm{nullptr};
  bool debug{false};
};

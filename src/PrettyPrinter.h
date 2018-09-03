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
  const std::string StrRIP{"[RIP]"};
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

  void printDataGroups();
  void printString(const gtirb::DataObject& x);

  void printBSS();

  std::string buildOperand(const std::string& opcode, const gtirb::SymbolicExpression* symbolic,
                           const cs_insn& inst, gtirb::Addr ea, uint64_t index);
  std::string buildOpRegdirect(const cs_x86_op& op);
  std::string buildOpImmediate(const std::string& opcode, const gtirb::SymbolicExpression* symbolic,
                               const cs_insn& inst, gtirb::Addr ea, uint64_t index);
  std::string buildOpIndirect(const gtirb::SymbolicExpression* symbolic, const cs_insn& inst,
                              gtirb::Addr ea, uint64_t index);

  void condPrintGlobalSymbol(gtirb::Addr ea);
  void condPrintSectionHeader(const gtirb::Block& x);

  bool skipEA(const gtirb::Addr x) const;
  bool isSectionSkipped(const std::string& name);
  // % avoid_reg_name_conflics
  std::string avoidRegNameConflicts(const std::string& x);
  void printZeros(uint64_t x);

  std::pair<std::string, char> getOffsetAndSign(const gtirb::SymbolicExpression* symbolic,
                                                int64_t offset) const;
  bool getIsPointerToExcludedCode(bool hasLabel, const gtirb::Module& module,
                                  const gtirb::DataObject* dg, const gtirb::DataObject* dgNext);

  // Static utility functions.

  static int64_t GetNeededPadding(int64_t alignment, int64_t currentAlignment,
                                  int64_t requiredAlignment);
  static std::string GetSymbolToPrint(gtirb::Addr x);
  static bool GetIsNullReg(const std::string& x);

private:
  csh csHandle;
  std::stringstream ofs;
  std::unique_ptr<DisasmData> disasm{nullptr};
  bool debug{false};
};

#pragma once

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
class PrettyPrinter
{
public:
    PrettyPrinter();

    void setDebug(bool x);
    bool getDebug() const;

    ///
    /// Pretty print to the given file name.
    ///
    std::string prettyPrint(DisasmData* x);

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

    const std::array<std::string, 7> AsmSkipFunction{
        {"_start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux",
         "frame_dummy", "__libc_csu_fini", "__libc_csu_init"}};

    void printBar(bool heavy = true);
    void printBlock(const gtirb::Block& x);
    void printEA(uint64_t ea);
    void printFunctionHeader(uint64_t ea);
    void printHeader();
    void printInstruction(const gtirb::Instruction& instruction);
    void printInstructionNop();
    void printLabel(uint64_t ea);
    void printSectionHeader(const std::string& x, uint64_t alignment = 0);
    void printOperandList(const gtirb::Instruction& instruction, const uint64_t* const operands);

    void printDataGroups();
    void printLabelMarker(const gtirb::DataLabelMarker* const x);
    void printPLTReference(const gtirb::DataPLTReference* const x);
    void printPointer(const gtirb::DataPointer* const x);
    void printPointerDiff(const gtirb::DataPointerDiff* const x);
    void printString(const gtirb::DataString* const x);
    void printRawByte(const gtirb::DataRawByte* const x);

    void printBSS();

    std::string buildOperand(gtirb::Instruction::SymbolicOperand symbolic, uint64_t operand,
                             uint64_t ea, uint64_t index);
    std::string buildOpRegdirect(const OpRegdirect* const op, uint64_t ea, uint64_t index);
    std::string buildOpImmediate(gtirb::Instruction::SymbolicOperand symbolic,
                                 const OpImmediate* const op, uint64_t ea, uint64_t index);
    std::string buildOpIndirect(gtirb::Instruction::SymbolicOperand symbolic,
                                const OpIndirect* const op, uint64_t ea, uint64_t index);
    std::string buildAdjustMovedDataLabel(uint64_t ea, uint64_t value);

    void condPrintGlobalSymbol(uint64_t ea);
    void condPrintSectionHeader(const gtirb::Block& x);

    bool skipEA(const uint64_t x) const;
    bool isSectionSkipped(const std::string& name);
    // % avoid_reg_name_conflics
    std::string avoidRegNameConflicts(const std::string& x);
    void printZeros(uint64_t x);

    std::pair<std::string, char> getOffsetAndSign(gtirb::Instruction::SymbolicOperand symbolic,
                                                  int64_t offset, uint64_t ea,
                                                  uint64_t index) const;
    bool getIsPointerToExcludedCode(const gtirb::Data* dg, const gtirb::Data* dgNext);

    // Static utility functions.

    static int64_t GetNeededPadding(int64_t alignment, int64_t currentAlignment,
                                    int64_t requiredAlignment);
    static std::string GetSymbolToPrint(uint64_t x);
    static bool GetIsNullReg(const std::string& x);

private:
    std::stringstream ofs;
    DisasmData* disasm{nullptr};
    bool debug{false};
};

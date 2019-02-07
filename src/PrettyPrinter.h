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
#ifndef GTIRB_PP_PRETTY_PRINTER_H
#define GTIRB_PP_PRETTY_PRINTER_H

#include "DisasmData.h"
#include <boost/range/any_range.hpp>
#include <capstone/capstone.h>
#include <cstdint>
#include <initializer_list>
#include <iosfwd>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

/// \brief Pretty-print GTIRB representations.
namespace gtirb_pprint {
class PrettyPrinterBase;
/// Whether a pretty printer should include debugging messages in it output.
enum DebugStyle { NoDebug, DebugMessages };

/// A range containing strings. These can be standard library containers or
/// pairs of iterators, for example.
using string_range = boost::any_range<std::string, boost::forward_traversal_tag,
                                      std::string&, std::ptrdiff_t>;

/// The type of the factories that may be registered. A factory is simply
/// something that can be called with an allocation context, the IR to pretty
/// print, the set of function names to skip during printing, and a boolean
/// indicating whether to include debugging output.
///
using factory = std::function<std::unique_ptr<PrettyPrinterBase>(
    gtirb::Context& context, gtirb::IR& ir, const string_range&, DebugStyle)>;

/// Register a factory for creating pretty printer objects. The factory will
/// be used to generate the syntaxes named in the initialization list. For
/// example, \code registerPrinter({"foo", "bar"}, theFactory); \endcode
///
/// \param syntaxes the (non-empty) syntaxes produced by the factory
/// \param f        the (non-empty) \link factory object
///
/// \return \c true.
bool registerPrinter(std::initializer_list<std::string> syntaxes, factory f);

/// Return the current set of syntaxes with registered factories.
std::set<std::string> getRegisteredSyntaxes();

/// Default set of functions to skip during printing.
const std::set<std::string>& getDefaultSkippedFunctions();

/// Get a pretty printer to print the given IR in a particular syntax. The
/// syntax must be one of the syntaxes reported by getRegisteredSyntaxes().
///
/// \param context Context containing the IR
/// \param ir      IR to print
/// \param syntax  name of the registered syntax to print
///
/// \return a pointer to the pretty printer object
std::unique_ptr<PrettyPrinterBase>
getPrinter(gtirb::Context& context, gtirb::IR& ir, const std::string& syntax);

/// Pretty print an IR to a stream. The syntax must be one of the syntaxes
/// reported by getRegisteredSyntaxes().
///
/// The supported DebugStyles are DebugMessages, which included debugging
/// comments in the output and includes all functions and sections, and
/// NoDebug, which does not.
///
/// \param stream        stream to print to
/// \param context       Context containing the IR
/// \param ir            IR to print
/// \param skipFunctions range of names of functions that should not be printed
/// \param syntax        name of the registered syntax to output
/// \param debug         whether to enable debugging-style output
///
/// \return a condition indicating if there was an error, or condition 0 if
/// there were no errors.
std::error_condition prettyPrint(std::ostream& stream, gtirb::Context& context,
                                 gtirb::IR& ir, string_range skipFunctions,
                                 const std::string& syntax, DebugStyle debug);

/// Pretty print an IR to a stream. The syntax must be one of the syntaxes
/// reported by getRegisteredSyntaxes(). Equivalent to
/// \code
/// prettyPrint(stream, context, ir, skipFunctions, syntax, NoDebug)
/// \endcode
///
/// \param stream        stream to print to
/// \param context       Context containing the IR
/// \param ir            IR to print
/// \param skipFunctions range of names of functions that should not be printed
/// \param syntax        name of the registered syntax to output
///
/// \return a condition indicating if there was an error, or condition 0 if
/// there were no errors.
std::error_condition prettyPrint(std::ostream& stream, gtirb::Context& context,
                                 gtirb::IR& ir, string_range skipFunctions,
                                 const std::string& syntax);

/// Pretty print an IR to a stream. The syntax must be one of the syntaxes
/// reported by getRegisteredSyntaxes(). Equivalent to
/// \code
/// prettyPrint(stream, context, ir, getDefaultSkippedFunctions(), syntax,
/// NoDebug) \endcode
///
/// \param stream        stream to print to
/// \param context       Context containing the IR
/// \param ir            IR to print
/// \param syntax        name of the registered syntax to output
///
/// \return a condition indicating if there was an error, or condition 0 if
/// there were no errors.
std::error_condition prettyPrint(std::ostream& stream, gtirb::Context& context,
                                 gtirb::IR& ir, const std::string& syntax);

/// The pretty-printer interface. There is only one exposed function, \link
/// print().
class PrettyPrinterBase {
public:
  PrettyPrinterBase(gtirb::Context& context, gtirb::IR& ir,
                    const string_range& skip_funcs, DebugStyle dbg);
  virtual ~PrettyPrinterBase();

  virtual std::ostream& print(std::ostream& out);

protected:
  /// Constants to reduce (eliminate) magical strings inside the printer.
  const std::string StrZeroByte{".byte 0x00"};
  const std::string StrNOP{"nop"};
  const std::string StrSection{".section"};
  const std::string StrSectionText{".text"};
  const std::string StrSectionBSS{".bss"};
  const std::string StrSectionGlobal{".globl"};
  const std::string StrSectionType{".type"};
  const std::string StrTab{"          "};

  /// Sections to avoid printing.
  std::unordered_set<std::string> AsmSkipSection{
      {".comment", ".plt", ".init", ".fini", ".got", ".plt.got", ".got.plt"}};

  /// Functions to avoid printing.
  std::unordered_set<std::string> AsmSkipFunction;

  /// Returns the symbol name for the PLT code at the referenced address, if it
  /// exists.
  ///
  /// \param the address to look up.
  virtual std::optional<std::string> getPltCodeSymName(gtirb::Addr ea);

  /// Return the SymAddrConst expression if it refers to a printed symbol.
  ///
  /// \param symex the SymbolicExpression to check
  virtual const gtirb::SymAddrConst*
  getSymbolicImmediate(const gtirb::SymbolicExpression* symex);

  // FIXME: I don't actually understand when to use one or the other of these
  // two functions. Someone needs to document this to make it clear (or remove
  // one of the functions).
  //
  // If the symbol is ambiguous, return a label containing the address instead.
  //
  virtual std::string
  getAdaptedSymbolNameDefault(const gtirb::Symbol* symbol) const;
  virtual std::string getAdaptedSymbolName(const gtirb::Symbol* symbol) const;

  /// Get the index of an operand in the GTIRB, given the index of the operand
  /// in the Capstone instruction.
  ///
  /// NOTE: The GTIRB operands are indexed as if they were in an array:
  ///   auto operands[] = {<unused>, src1, src2, ..., dst}
  ///
  /// \param index   the Capstone index of the operand
  /// \param opCount the total number of operands in the instruction
  virtual int getGtirbOpIndex(int index, int opCount) const = 0;
  virtual std::string getRegisterName(unsigned int reg) const;

  virtual void printBar(std::ostream& os, bool heavy = true);
  virtual void printHeader(std::ostream& os) = 0;
  virtual void condPrintSectionHeader(std::ostream& os, const gtirb::Block& x);
  virtual void printSectionHeader(std::ostream& os, const std::string& x,
                                  uint64_t alignment = 0);
  virtual void printFunctionHeader(std::ostream& os, gtirb::Addr ea);
  virtual void printBlock(std::ostream& os, const gtirb::Block& x);
  virtual void printLabel(std::ostream& os, gtirb::Addr ea);

  /// Print a single instruction to the stream. This implementation prints the
  /// mnemonic provided by Capstone, then calls printOperandList(). Thus, it is
  /// probably sufficient for most subclasses to configure Capstone to produce
  /// the correct mnemonics (e.g., to include an operand size suffix) and not
  /// modify this method.
  ///
  /// \param os   the output stream to print to
  /// \param inst the instruction to print
  virtual void printInstruction(std::ostream& os, const cs_insn& inst);

  virtual void printEA(std::ostream& os, gtirb::Addr ea);
  virtual void printOperandList(std::ostream& os, const gtirb::Addr ea,
                                const cs_insn& inst);
  virtual void printComment(std::ostream& os, const gtirb::Addr ea);
  virtual void printDataGroups(std::ostream& os);
  virtual void printDataObject(std::ostream& os,
                               const gtirb::DataObject& dataGroup);
  virtual void printSymbolicData(std::ostream& os, const gtirb::Addr addr,
                                 const gtirb::SymbolicExpression* symbolic);
  virtual void printSymbolicExpression(std::ostream& os,
                                       const gtirb::SymAddrConst* sexpr);
  virtual void printSymbolicExpression(std::ostream& os,
                                       const gtirb::SymAddrAddr* sexpr);

  virtual void printBSS(std::ostream& os);
  virtual void printString(std::ostream& os, const gtirb::DataObject& x);

  virtual void printOperand(std::ostream& os,
                            const gtirb::SymbolicExpression* symbolic,
                            const cs_insn& inst, gtirb::Addr ea,
                            uint64_t index);
  virtual void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                const cs_x86_op& op) = 0;
  virtual void printOpImmediate(std::ostream& os,
                                const gtirb::SymbolicExpression* symbolic,
                                const cs_insn& inst, gtirb::Addr ea,
                                uint64_t index) = 0;
  virtual void printOpIndirect(std::ostream& os,
                               const gtirb::SymbolicExpression* symbolic,
                               const cs_insn& inst, uint64_t index) = 0;

  virtual bool condPrintGlobalSymbol(std::ostream& os, gtirb::Addr ea);

  bool shouldExcludeDataElement(const std::string& sectionName,
                                const gtirb::DataObject& dataGroup);
  bool isPointerToExcludedCode(const gtirb::DataObject& dataGroup);

  bool skipEA(const gtirb::Addr x) const;
  bool isInSkippedSection(const gtirb::Addr x) const;
  bool isInSkippedFunction(const gtirb::Addr x) const;

  /// Get the name of the function containing an effective address. This
  /// implementation assumes that functions are tightly packed within a
  /// module; that is, it assumes that all addresses from the start of one
  /// function to the next is part of the first. It also assumes that the
  /// body of the last function in a module extends to the end of the module.
  ///
  /// The locations of the functions are found in the "functionEntry" AuxData
  /// table.
  ///
  /// \param x the address to check
  ///
  /// \return the name of the containing function if one is found.
  std::optional<std::string>
  getContainerFunctionName(const gtirb::Addr x) const;
  bool isSectionSkipped(const std::string& name);

  std::string avoidRegNameConflicts(const std::string& x);
  std::string getAddendString(int64_t number, bool first = false);

  csh csHandle;
  DisasmData disasm;
  bool debug;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_PRETTY_PRINTER_H */

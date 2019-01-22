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
#include "DisasmData.h"

class AbstractPP;

///
/// \class PrettyPrinter
///
/// The PrettyPrinter class is actually a factory/builder for pretty-printers. It allows different
/// pretty-printer implementations to be registered to target different output formats.
///
class PrettyPrinter {
public:
  using string_range = boost::any_range<std::string, boost::forward_traversal_tag, std::string&, std::ptrdiff_t>;
  ///
  /// The type of the factories that may be registered. A factory is simply something that can be
  /// called with an allocation context, the IR to pretty print, the set of function names to skip
  /// during printing, and a boolean indicating whether to include debugging output.
  ///
  using factory = std::function<std::unique_ptr<AbstractPP>(
      gtirb::Context& context, gtirb::IR& ir, const string_range&, bool)>;

  /// Register a factory for creating pretty printer objects. The factory will be used for the
  /// flavors named in the initialization list. For example,
  /// \code
  /// PrettyPrinter::registerPrinter({"foo", "bar"}, theFactory);
  /// \endcode
  /// If the factory is empty (e.g, a \c nullptr), the registry is not changed.
  ///
  /// \param flavors the flavors produced by the factory
  /// \param f       the \link factory object
  ///
  /// \return \c true if the registry was updated, otherwise \c false.
  static bool registerPrinter(std::initializer_list<const char*> flavors, factory f);

  /// Return the current set of registered flavors.
  static std::set<std::string> getRegisteredFlavors();

  /// Set the flavor of output to generate.
  ///
  /// \param flavor the name of a registered flavor
  void setFlavor(const std::string& flavor);

  /// Return the flavor of output that would currently be generated.
  std::string getFlavor() const;

  /// Enable or disable debugging output.
  ///
  /// \param x whether to enable (\c true) or disable (\c false) debugging output.
  void setDebug(bool x);

  /// Return whether debugging output is enabled.
  bool getDebug() const;

  /// Do not skip the named function when printing.
  ///
  /// \param functionName the name of the function to skip.
  void keepFunction(const std::string& functionName);

  /// Skip the named function when printing.
  ///
  /// \param functionName the name of the function to skip.
  void skipFunction(const std::string& functionName);

  ///
  /// Pretty print to a string. This actually builds the pretty-printer object of the current
  /// flavor for the given IR. Since the pretty-printer has an appropriate \c operator<< and can
  /// only print the one IR to a stream anyway, this method will often be called directly as an
  /// argument to an output stream:
  /// \code
  /// PrettyPrinter pp;
  /// // ...
  /// std::cout << pp.prettyPrint(context, ir);
  /// \endcode
  ///
  std::unique_ptr<AbstractPP> prettyPrint(gtirb::Context& context, gtirb::IR& ir);

private:
  // To avoid issues with static initialization order, the singleton map of factories is a
  // function-local static object that can be accessed with this function.
  static std::map<std::string, factory>& getFactories();

  /// Initial set of functions to skip during printing.
  std::unordered_set<std::string> AsmSkipFunction{
      {"_start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux",
       "frame_dummy", "__libc_csu_fini", "__libc_csu_init", "_dl_relocate_static_pie"}};

  /// Default flavor is "nasm".
  std::string flavor{"nasm"};

  /// Debugging is disabled by default.
  bool debug{false};
};

/// The pretty-printer interface. There is only one exposed function, \link print().
class AbstractPP {
public:
  AbstractPP(gtirb::Context& context, gtirb::IR& ir, const PrettyPrinter::string_range& skip_funcs,
             bool dbg);
  virtual ~AbstractPP();

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

  /// Returns the symbol name for the PLT code at the referenced address, if it exists.
  ///
  /// \param the address to look up.
  virtual std::optional<std::string> getPltCodeSymName(gtirb::Addr ea);

  // FIXME: I don't actually understand when to use one or the other of these two functions.
  // Someone needs to document this to make it clear (or remove one of the functions).
  //
  // If the symbol is ambiguous, return a label containing the address instead.
  //
  virtual std::string getAdaptedSymbolNameDefault(const gtirb::Symbol* symbol) const;
  virtual std::string getAdaptedSymbolName(const gtirb::Symbol* symbol) const;

  /// Get the index of an operand in the GTIRB, given the index of the operand in the Capstone
  /// instruction.
  ///
  /// \param index   the Capstone index of the operand
  /// \param opCount the total number of operands in the instruction
  virtual int getGtirbOpIndex(int index, int opCount) const = 0;
  virtual std::string getRegisterName(unsigned int reg) const;

  virtual void printBar(std::ostream& os, bool heavy = true);
  virtual void printHeader(std::ostream& os) = 0;
  virtual void condPrintSectionHeader(std::ostream& os, const gtirb::Block& x);
  virtual void printSectionHeader(std::ostream& os, const std::string& x, uint64_t alignment = 0);
  virtual void printFunctionHeader(std::ostream& os, gtirb::Addr ea);
  virtual void printBlock(std::ostream& os, const gtirb::Block& x);
  virtual void printLabel(std::ostream& os, gtirb::Addr ea);
  virtual void printInstruction(std::ostream& os, const cs_insn& inst);
  virtual void printEA(std::ostream& os, gtirb::Addr ea);
  virtual void printOperandList(std::ostream& os, const std::string& opcode, const gtirb::Addr ea,
                                const cs_insn& inst);
  virtual void printComment(std::ostream& os, const gtirb::Addr ea);
  virtual void printDataGroups(std::ostream& os);
  virtual void printDataObject(std::ostream& os, const gtirb::DataObject& dataGroup);
  virtual void printSymbolicData(std::ostream& os, const gtirb::Addr addr,
                                 const gtirb::SymbolicExpression* symbolic);
  virtual void printSymbolicExpression(std::ostream& os, const gtirb::SymAddrConst* sexpr);
  virtual void printSymbolicExpression(std::ostream& os, const gtirb::SymAddrAddr* sexpr);

  virtual void printBSS(std::ostream& os);
  virtual void printString(std::ostream& os, const gtirb::DataObject& x);

  virtual void printOperand(std::ostream& os, const std::string& opcode,
                            const gtirb::SymbolicExpression* symbolic, const cs_insn& inst,
                            gtirb::Addr ea, uint64_t index);
  virtual void printOpRegdirect(std::ostream& os, const cs_insn& inst, const cs_x86_op& op) = 0;
  virtual void printOpImmediate(std::ostream& os, const std::string& opcode,
                                const gtirb::SymbolicExpression* symbolic, const cs_insn& inst,
                                gtirb::Addr ea, uint64_t index) = 0;
  virtual void printOpIndirect(std::ostream& os, const gtirb::SymbolicExpression* symbolic,
                               const cs_insn& inst, uint64_t index) = 0;

  virtual bool condPrintGlobalSymbol(std::ostream& os, gtirb::Addr ea);

  bool shouldExcludeDataElement(const std::string& sectionName, const gtirb::DataObject& dataGroup);
  bool isPointerToExcludedCode(const gtirb::DataObject& dataGroup);

  bool skipEA(const gtirb::Addr x) const;
  bool isInSkippedSection(const gtirb::Addr x) const;
  bool isInSkippedFunction(const gtirb::Addr x) const;
  std::string getContainerFunctionName(const gtirb::Addr x) const;
  bool isSectionSkipped(const std::string& name);

  std::string avoidRegNameConflicts(const std::string& x);
  std::string getAddendString(int64_t number, bool first = false);

  csh csHandle;
  DisasmData disasm;
  bool debug{false};
};

/// Print the wrapped IR to a stream.
inline std::ostream& operator<<(std::ostream& out, const std::unique_ptr<AbstractPP>& pp) {
  return pp->print(out);
}

#endif /* GTIRB_PP_PRETTY_PRINTER_H */

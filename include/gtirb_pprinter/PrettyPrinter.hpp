//===- PrettyPrinter.hpp ----------------------------------------*- C++ -*-===//
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

#include "Export.hpp"
#include "Syntax.hpp"

#include <gtirb/gtirb.hpp>

#include <boost/range/any_range.hpp>
#include <capstone/capstone.h>
#include <cstdint>
#include <initializer_list>
#include <iosfwd>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

/// \brief Pretty-print GTIRB representations.
namespace gtirb_pprint {

struct PrintingPolicy;
class PrettyPrinterFactory;
class PrettyPrinterBase;

/// Whether a pretty printer should include debugging messages in it output.
enum DebugStyle { NoDebug, DebugMessages };

/// A range containing strings. These can be standard library containers or
/// pairs of iterators, for example.
using string_range = boost::any_range<std::string, boost::forward_traversal_tag,
                                      std::string&, std::ptrdiff_t>;

/// Register a factory for creating pretty printer objects. The factory will be
/// used to load a default \link PrintingPolicy and create a pretty printer for
/// the formats and syntaxes named in the initialization lists.
///
/// For example, \code registerPrinter({"foo"}, {"bar"}, theFactory);
/// \endcode
///
/// \param formats    the (non-empty) formats produced by the factory
/// \param syntaxes   the (non-empty) syntaxes produced by the factory
/// \param f          the (non-empty) \link PrettyPrinterFactory object
/// \param isDefault  optionally make this the default factory for the
///                   named format and syntax parameters
///
/// \return \c true.
DEBLOAT_PRETTYPRINTER_EXPORT_API bool
registerPrinter(std::initializer_list<std::string> formats,
                std::initializer_list<std::string> syntaxes,
                std::shared_ptr<PrettyPrinterFactory> f,
                bool isDefault = false);

/// Return the current set of syntaxes with registered factories.
DEBLOAT_PRETTYPRINTER_EXPORT_API std::set<std::tuple<std::string, std::string>>
getRegisteredTargets();

/// Return the file format of a GTIRB module.
DEBLOAT_PRETTYPRINTER_EXPORT_API std::string
getModuleFileFormat(const gtirb::Module& module);

/// Set the default syntax for a file format.
DEBLOAT_PRETTYPRINTER_EXPORT_API void
setDefaultSyntax(const std::string& format, const std::string& syntax);

/// Return the default syntax for a file format.
DEBLOAT_PRETTYPRINTER_EXPORT_API std::optional<std::string>
getDefaultSyntax(const std::string& format);

/// A set of options to give to PrettyPrinterBase's policy in one category.
/// Essentially, contains whether or not a set of strings to skip is cleared,
/// and what strings are added/removed from the set to skip.
class DEBLOAT_PRETTYPRINTER_EXPORT_API PolicyOptions {
public:
  void skip(const std::string& s) { Skip.insert(s); }

  void keep(const std::string& s) { Keep.insert(s); }

  void useDefaults(bool value = true) { UseDefaults = value; }

  void apply(std::unordered_set<std::string>& c) const {
    if (!UseDefaults) {
      c.clear();
    }
    c.insert(Skip.begin(), Skip.end());
    c.erase(Keep.begin(), Keep.end());
  }

private:
  std::unordered_set<std::string> Skip, Keep;
  bool UseDefaults = true;
};

/// The primary interface for pretty-printing GTIRB objects. The typical flow
/// is to create a PrettyPrinter, configure it (e.g., set the output syntax,
/// enable/disable debugging messages, etc.), then print one or more IR objects.
class DEBLOAT_PRETTYPRINTER_EXPORT_API PrettyPrinter {
public:
  /// Construct a PrettyPrinter with the default configuration.
  PrettyPrinter() = default;

  PrettyPrinter(const PrettyPrinter&) = default;
  PrettyPrinter(PrettyPrinter&&) = default;
  PrettyPrinter& operator=(const PrettyPrinter&) = default;
  PrettyPrinter& operator=(PrettyPrinter&&) = default;

  /// Set the target for which to pretty print. It is the caller's
  /// responsibility to ensure that the target name has been registered.
  ///
  /// \param target compound indentifier of target format and syntax
  void setTarget(const std::tuple<std::string, std::string>& target);

  /// Set the file format for which to pretty print.
  ///
  /// \param format indentifier of target format
  void setFormat(const std::string& format);

  /// Enable or disable debugging messages inside the pretty-printed code.
  ///
  /// \param do_debug whether to enable debugging messages
  void setDebug(bool do_debug);

  /// Indicates whether debugging messages are currently enable or disabled.
  ///
  /// \return \c true if debugging messages are currently enabled, otherwise
  /// \c false.
  bool getDebug() const;

  /// Pretty-print the IR module to a stream. The default output target is
  /// deduced from the file format of the IR if it is not explicitly set with
  /// \link setTarget.
  ///
  /// \param stream  the stream to print to
  /// \param context context to use for allocating AuxData objects if needed
  /// \param module      the module to pretty-print
  ///
  /// \return a condition indicating if there was an error, or condition 0 if
  /// there were no errors.
  std::error_condition print(std::ostream& stream, gtirb::Context& context,
                             gtirb::Module& module) const;

  PolicyOptions& functionPolicy() { return FunctionPolicy; }
  const PolicyOptions& functionPolicy() const { return FunctionPolicy; }

  PolicyOptions& symbolPolicy() { return SymbolPolicy; }
  const PolicyOptions& symbolPolicy() const { return SymbolPolicy; }

  PolicyOptions& sectionPolicy() { return SectionPolicy; }
  const PolicyOptions& sectionPolicy() const { return SectionPolicy; }

  PolicyOptions& arraySectionPolicy() { return ArraySectionPolicy; }
  const PolicyOptions& arraySectionPolicy() const { return ArraySectionPolicy; }

private:
  std::string m_format;
  std::string m_syntax;
  DebugStyle m_debug;
  PolicyOptions FunctionPolicy, SymbolPolicy, SectionPolicy, ArraySectionPolicy;
};

struct DEBLOAT_PRETTYPRINTER_EXPORT_API PrintingPolicy {
  /// Functions to avoid printing the contents and labels of.
  std::unordered_set<std::string> skipFunctions;

  /// Symbols to avoid printing the labels of.
  std::unordered_set<std::string> skipSymbols;

  /// Sections to avoid printing.
  std::unordered_set<std::string> skipSections;

  // These sections have a couple of special cases for data objects. They
  // usually contain entries that need to be ignored (the compiler will add them
  // again) and require special alignment of 8
  std::unordered_set<std::string> arraySections;

  DebugStyle debug = NoDebug;
};

/// Abstract factory - encloses default printing configuration and a method for
/// building the target pretty printer.
class DEBLOAT_PRETTYPRINTER_EXPORT_API PrettyPrinterFactory {
public:
  virtual ~PrettyPrinterFactory() = default;

  /// Load the default printing policy.
  virtual const PrintingPolicy& defaultPrintingPolicy() const = 0;

  /// Create the pretty printer instance.
  virtual std::unique_ptr<PrettyPrinterBase>
  create(gtirb::Context& context, gtirb::Module& module,
         const PrintingPolicy& policy) = 0;
};

/// The pretty-printer interface. There is only one exposed function, \link
/// print().
class DEBLOAT_PRETTYPRINTER_EXPORT_API PrettyPrinterBase {
public:
  PrettyPrinterBase(gtirb::Context& context, gtirb::Module& module,
                    const Syntax& syntax, const PrintingPolicy& policy);
  virtual ~PrettyPrinterBase();

  virtual std::ostream& print(std::ostream& out);

protected:
  const Syntax& syntax;
  PrintingPolicy policy;

  /// Return the SymAddrConst expression if it refers to a printed symbol.
  ///
  /// \param symex the SymbolicExpression to check
  virtual const gtirb::SymAddrConst*
  getSymbolicImmediate(const gtirb::SymbolicExpression* symex);

  virtual std::string getRegisterName(unsigned int reg) const;

  virtual void printBar(std::ostream& os, bool heavy = true);
  virtual void printHeader(std::ostream& os) = 0;
  virtual void printFooter(std::ostream& os) = 0;
  virtual void printAlignment(std::ostream& os, const gtirb::Addr addr);
  virtual void printSection(std::ostream& os, const gtirb::Section& section);
  virtual void printSectionHeader(std::ostream& os,
                                  const gtirb::Section& section);
  virtual void printSectionHeaderDirective(std::ostream& os,
                                           const gtirb::Section& addr) = 0;
  virtual void printSectionProperties(std::ostream& os,
                                      const gtirb::Section& addr) = 0;
  virtual void printSectionFooter(std::ostream& os,
                                  const gtirb::Section& section);
  virtual void printSectionFooterDirective(std::ostream& os,
                                           const gtirb::Section& section) = 0;
  virtual void printFunctionHeader(std::ostream& os, gtirb::Addr addr) = 0;
  virtual void printFunctionFooter(std::ostream& os, gtirb::Addr addr) = 0;
  virtual void printBlock(std::ostream& os, const gtirb::CodeBlock& block);
  virtual void printBlock(std::ostream& os, const gtirb::DataBlock& block);
  virtual void printBlockContents(std::ostream& os,
                                  const gtirb::CodeBlock& block,
                                  uint64_t offset);
  virtual void printBlockContents(std::ostream& os,
                                  const gtirb::DataBlock& block,
                                  uint64_t offset);
  virtual void printNonZeroDataBlock(std::ostream& os,
                                     const gtirb::DataBlock& dataObject,
                                     uint64_t offset);
  virtual void printZeroDataBlock(std::ostream& os,
                                  const gtirb::DataBlock& dataObject,
                                  uint64_t offset);
  virtual void printByte(std::ostream& os, std::byte byte) = 0;

  virtual void fixupInstruction(cs_insn& inst);

  /// Print a single instruction to the stream. This implementation prints the
  /// mnemonic provided by Capstone, then calls printOperandList(). Thus, it is
  /// probably sufficient for most subclasses to configure Capstone to produce
  /// the correct mnemonics (e.g., to include an operand size suffix) and not
  /// modify this method.
  ///
  /// \param os   the output stream to print to
  /// \param inst the instruction to print
  /// \param insnOffset   the offset of the instruction
  virtual void printInstruction(std::ostream& os, const gtirb::CodeBlock& block,
                                const cs_insn& inst,
                                const gtirb::Offset& offset);

  virtual void printEA(std::ostream& os, gtirb::Addr ea);
  virtual void printOperandList(std::ostream& os, const gtirb::CodeBlock& block,
                                const cs_insn& inst);
  virtual void printComments(std::ostream& os, const gtirb::Offset& offset,
                             uint64_t range);
  virtual void printCFIDirectives(std::ostream& os, const gtirb::Offset& ea);
  virtual void printSymbolicData(
      std::ostream& os,
      const gtirb::ByteInterval::ConstSymbolicExpressionElement& SEE,
      uint64_t Size, std::optional<std::string> Type);
  virtual void printSymbolicDataType(
      std::ostream& os,
      const gtirb::ByteInterval::ConstSymbolicExpressionElement& SEE,
      uint64_t Size, std::optional<std::string> Type);
  virtual void printSymbolicExpression(std::ostream& os,
                                       const gtirb::SymAddrConst* sexpr,
                                       bool inData = false);
  virtual void printSymbolicExpression(std::ostream& os,
                                       const gtirb::SymAddrAddr* sexpr,
                                       bool inData = false);
  // print a symbol in a symbolic expression
  // if the symbol is ambiguous print a symbol with the address instead.
  // if the symbol is forwarded (e.g. a plt reference) print the forwarded
  // symbol with the adequate ending (e.g. @PLT)
  virtual void printSymbolReference(std::ostream& os,
                                    const gtirb::Symbol* symbol,
                                    bool inData) const;
  virtual void printAddend(std::ostream& os, int64_t number,
                           bool first = false);
  virtual void printString(std::ostream& os, const gtirb::DataBlock& x,
                           uint64_t offset);

  virtual void printOperand(std::ostream& os, const gtirb::CodeBlock& block,
                            const cs_insn& inst, uint64_t index);
  virtual void printOpRegdirect(std::ostream& os, const cs_insn& inst,
                                const cs_x86_op& op) = 0;
  virtual void printOpImmediate(std::ostream& os,
                                const gtirb::SymbolicExpression* symbolic,
                                const cs_insn& inst, uint64_t index) = 0;
  virtual void printOpIndirect(std::ostream& os,
                               const gtirb::SymbolicExpression* symbolic,
                               const cs_insn& inst, uint64_t index) = 0;

  virtual void printSymbolDefinition(std::ostream& os,
                                     const gtirb::Symbol& symbol);
  virtual void printOverlapWarning(std::ostream& os, gtirb::Addr ea);
  virtual void printSymbolDefinitionRelativeToPC(std::ostream& os,
                                                 const gtirb::Symbol& symbol,
                                                 gtirb::Addr pc) = 0;
  virtual void printIntegralSymbol(std::ostream& os,
                                   const gtirb::Symbol& symbol) = 0;

  virtual bool shouldSkip(const gtirb::Section& section) const;
  virtual bool shouldSkip(const gtirb::Symbol& symbol) const;
  virtual bool shouldSkip(const gtirb::CodeBlock& block) const;
  virtual bool shouldSkip(const gtirb::DataBlock& block) const;

  // This method assumes sections do not overlap
  const std::optional<const gtirb::Section*>
  getContainerSection(const gtirb::Addr addr) const;

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

  bool isFunctionEntry(const gtirb::Addr x) const;
  bool isFunctionLastBlock(const gtirb::Addr x) const;

  csh csHandle;

  bool debug;

  gtirb::Context& context;
  gtirb::Module& module;

  virtual std::string getFunctionName(gtirb::Addr x) const;
  virtual std::string getSymbolName(const gtirb::Symbol& symbol) const;
  virtual std::optional<std::string>
  getForwardedSymbolName(const gtirb::Symbol* symbol, bool inData) const;

  bool isAmbiguousSymbol(const std::string& ea) const;

  // Currently, this only works for symbolic expressions in data blocks.
  // For the symbolic expressions that are part of code blocks, Capstone
  // always provides the information using the instruction context, so
  // printCodeBlock, etc. doesn't bother to call this method.
  uint64_t getSymbolicExpressionSize(
      const gtirb::ByteInterval::ConstSymbolicExpressionElement& SEE) const;

private:
  std::set<gtirb::Addr> functionEntry;
  std::set<gtirb::Addr> functionLastBlock;
  gtirb::Addr programCounter;

  std::string getForwardedSymbolEnding(const gtirb::Symbol* symbol,
                                       bool inData) const;

  template <typename BlockType>
  void printBlockImpl(std::ostream& os, BlockType& block);
};

/// !brief Register AuxData types used by the pretty printer.
DEBLOAT_PRETTYPRINTER_EXPORT_API void registerAuxDataTypes();

} // namespace gtirb_pprint

#endif /* GTIRB_PP_PRETTY_PRINTER_H */

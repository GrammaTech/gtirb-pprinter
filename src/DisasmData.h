#pragma once

#include <cstdint>
#include <gtirb/gtirb.hpp>
#include <iosfwd>
#include <list>
#include <map>
#include <string>
#include <vector>
#include "Export.h"
#include "Table.h"

///
/// \class DisasmData
///
/// Port of the prolog disasm.
///
class DEBLOAT_PRETTYPRINTER_EXPORT_API DisasmData {
public:
  DisasmData(gtirb::Context& context, gtirb::IR* ir);

  gtirb::Context& context;
  gtirb::IR& ir;

  const gtirb::Module::section_range getSections() const;
  std::vector<std::string>* getAmbiguousSymbol();
  std::vector<gtirb::table::InnerMapType>& getDataSections();

  bool isFunction(const gtirb::Symbol& sym) const;
  std::string getSectionName(gtirb::Addr x) const;
  std::string getFunctionName(gtirb::Addr x) const;
  std::string getGlobalSymbolReference(gtirb::Addr ea) const;
  std::string getGlobalSymbolName(gtirb::Addr ea) const;
  bool isRelocated(const std::string& x) const;
  const gtirb::Section* getSection(const std::string& x) const;

  bool getIsAmbiguousSymbol(const std::string& ea) const;

  static std::string CleanSymbolNameSuffix(std::string x);
  static std::string AdaptOpcode(const std::string& x);
  static std::string AdaptRegister(const std::string& x);
  static std::string GetSizeName(uint64_t x);
  static std::string GetSizeName(const std::string& x);
  static std::string GetSizeSuffix(uint64_t x);
  static std::string GetSizeSuffix(const std::string& x);
  static bool GetIsReservedSymbol(const std::string& x);
  static std::string AvoidRegNameConflicts(const std::string& x);

private:
  std::vector<gtirb::Addr> functionEAs;
  std::vector<std::string> ambiguous_symbol;
  std::vector<gtirb::Addr> start_function;
  std::vector<gtirb::Addr> main_function;
  std::vector<gtirb::Addr> function_entry;
};

const std::pair<std::string, int>* getDataSectionDescriptor(const std::string& name);

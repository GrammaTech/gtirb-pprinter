//===- DisasmData.h ---------------------------------------------*- C++ -*-===//
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
#ifndef GTIRB_PP_DISASM_DATA_H
#define GTIRB_PP_DISASM_DATA_H

/// \file DisasmData.h

#include "Export.h"
#include <cstdint>
#include <gtirb/gtirb.hpp>
#include <iosfwd>
#include <list>
#include <map>
#include <optional>
#include <string>
#include <vector>

template <typename T> T* getAuxData(gtirb::IR& ir, const std::string& name) {
  gtirb::AuxData* data = ir.getAuxData(name);
  return data ? data->get<T>() : nullptr;
}

///
/// \class DisasmData
///
/// Interface to collect information from GTIRB for pretty-printing.
///
class DEBLOAT_PRETTYPRINTER_EXPORT_API DisasmData {
public:
  DisasmData(gtirb::Context& context, gtirb::IR& ir);

  gtirb::Context& context;
  gtirb::IR& ir;

  const gtirb::Module::section_range getSections() const;
  std::vector<std::string>* getAmbiguousSymbol();
  const std::vector<std::tuple<std::string, int, std::vector<gtirb::UUID>>>*
  getDataSections();

  std::string getSectionName(gtirb::Addr x) const;
  std::string getFunctionName(gtirb::Addr x) const;

  bool isRelocated(const std::string& x) const;
  std::string getRelocatedDestination(const gtirb::Addr& addr) const;
  const gtirb::Section* getSection(const std::string& x) const;

  bool isAmbiguousSymbol(const std::string& ea) const;

  static std::string GetSymbolToPrint(gtirb::Addr x);
  static std::string CleanSymbolNameSuffix(std::string x);
  static std::string AdaptRegister(const std::string& x);
  static std::string GetSizeName(uint64_t x);
  static std::string GetSizeName(const std::string& x);
  static std::string GetSizeSuffix(uint64_t x);
  static std::string GetSizeSuffix(const std::string& x);
  static std::string AvoidRegNameConflicts(const std::string& x);

private:
  std::optional<gtirb::Addr> start_function;
  std::optional<gtirb::Addr> main_function;

  // This should be kept sorted to enable fast searches.
  std::vector<gtirb::Addr> functionEntry;
};

const std::pair<std::string, int>*
getDataSectionDescriptor(const std::string& name);

#endif /* GTIRB_PP_DISASM_DATA_H */

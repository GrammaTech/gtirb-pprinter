//===- DisasmData.cpp -------------------------------------------*- C++ -*-===//
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
#include "DisasmData.h"
#include <boost/range/algorithm/find_if.hpp>
#include <fstream>
#include <gsl/gsl>
#include <gtirb/gtirb.hpp>
#include <iostream>
#include <utility>
#include <variant>

using namespace std::rel_ops;

DisasmData::DisasmData(gtirb::Context& context_, gtirb::IR& ir_)
    : context(context_), ir(ir_), functionEntry() {
  if (const auto* entries =
          getAuxData<std::vector<gtirb::Addr>>(ir, "functionEntry"))
    functionEntry.insert(functionEntry.end(), entries->begin(), entries->end());
  std::sort(functionEntry.begin(), functionEntry.end());
}

std::string DisasmData::getSectionName(gtirb::Addr x) const {
  const gtirb::Module::section_range& sections = ir.modules()[0].sections();
  const auto& match = find_if(
      sections, [x](const gtirb::Section& s) { return s.getAddress() == x; });

  if (match != sections.end()) {
    return match->getName();
  }

  return std::string{};
}

std::string DisasmData::getFunctionName(gtirb::Addr x) const {
  // Is this address an entry point to a function with a symbol?
  bool entry_point = std::binary_search(this->functionEntry.begin(),
                                        this->functionEntry.end(), x);
  if (entry_point) {
    for (gtirb::Symbol& s : this->ir.modules()[0].findSymbols(x)) {
      std::stringstream name(s.getName());
      if (this->isAmbiguousSymbol(s.getName())) {
        name.seekp(0, std::ios_base::end);
        name << '_' << std::hex << static_cast<uint64_t>(x);
      }
      return name.str();
    }
  }

  // Is this a function entry with no associated symbol?
  if (entry_point) {
    std::stringstream name;
    name << "unknown_function_" << std::hex << static_cast<uint64_t>(x);
    return name.str();
  }

  // This doesn't seem to be a function.
  return std::string{};
}

std::string DisasmData::GetSymbolToPrint(gtirb::Addr x) {
  std::stringstream ss;
  ss << ".L_" << std::hex << uint64_t(x) << std::dec;
  return ss.str();
}

std::optional<std::string>
DisasmData::getForwardedSymbolName(const gtirb::Symbol* symbol,
                                   bool isAbsolute) const {
  auto* symbolForwarding =
      getAuxData<std::map<gtirb::UUID, gtirb::UUID>>(ir, "symbolForwarding");
  if (symbolForwarding) {
    auto found = symbolForwarding->find(symbol->getUUID());
    if (found != symbolForwarding->end()) {
      gtirb::Node* destSymbol = gtirb::Node::getByUUID(context, found->second);
      return (cast<gtirb::Symbol>(destSymbol))->getName() +
             getForwardedSymbolEnding(symbol, isAbsolute);
    }
  }
  return {};
}

std::string DisasmData::getForwardedSymbolEnding(const gtirb::Symbol* symbol,
                                                 bool isAbsolute) const {
  if (symbol->getAddress()) {
    gtirb::Addr addr = *symbol->getAddress();
    const gtirb::Section* section;
    if ((section = this->getSection(".plt")) && containsAddr(*section, addr) &&
        !isAbsolute)
      return std::string{"@PLT"};
    if ((section = this->getSection(".plt.got")) &&
        containsAddr(*section, addr) && !isAbsolute)
      return std::string{"@PLT"};
    if ((section = this->getSection(".got")) && containsAddr(*section, addr))
      return std::string{"@GOTPCREL"};
    if ((section = this->getSection(".got.plt")) &&
        containsAddr(*section, addr))
      return std::string{"@GOTPCREL"};
  }
  return std::string{};
}

const gtirb::Section* DisasmData::getSection(const std::string& x) const {
  auto sections = ir.modules()[0].sections();
  const auto found =
      std::find_if(sections.begin(), sections.end(),
                   [x](const auto& element) { return element.getName() == x; });

  if (found != sections.end()) {
    return &(*found);
  }

  return nullptr;
}

bool DisasmData::isAmbiguousSymbol(const std::string& name) const {
  // Are there multiple symbols with this name?
  auto found = this->ir.modules()[0].findSymbols(name);
  return distance(begin(found), end(found)) > 1;
}

std::string DisasmData::GetSizeName(uint64_t x) {
  return DisasmData::GetSizeName(std::to_string(x));
}

std::string DisasmData::GetSizeName(const std::string& x) {
  const std::map<std::string, std::string> adapt{
      {"128", ""},         {"0", ""},           {"80", "TBYTE PTR"},
      {"64", "QWORD PTR"}, {"32", "DWORD PTR"}, {"16", "WORD PTR"},
      {"8", "BYTE PTR"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  assert("Unknown Size");

  return x;
}

std::string DisasmData::GetSizeSuffix(uint64_t x) {
  return DisasmData::GetSizeSuffix(std::to_string(x));
}

std::string DisasmData::GetSizeSuffix(const std::string& x) {
  const std::map<std::string, std::string> adapt{
      {"128", ""}, {"0", ""},   {"80", "t"}, {"64", "q"},
      {"32", "d"}, {"16", "w"}, {"8", "b"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  assert("Unknown Size");

  return x;
}

std::string DisasmData::AvoidRegNameConflicts(const std::string& x) {
  const std::vector<std::string> adapt{"FS",  "MOD", "DIV", "NOT", "mod",
                                       "div", "not", "and", "or"};

  if (const auto found = std::find(std::begin(adapt), std::end(adapt), x);
      found != std::end(adapt)) {
    return x + "_renamed";
  }

  return x;
}

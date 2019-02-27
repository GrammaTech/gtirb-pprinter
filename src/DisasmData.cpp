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
    : context(context_), ir(ir_), start_function(), main_function(),
      functionEntry() {
  if (const auto* entries =
          getAuxData<std::vector<gtirb::Addr>>(ir, "functionEntry"))
    functionEntry.insert(functionEntry.end(), entries->begin(), entries->end());
  std::sort(functionEntry.begin(), functionEntry.end());

  if (const auto* startFuncs =
          getAuxData<std::vector<gtirb::Addr>>(ir, "startFunction");
      startFuncs && !startFuncs->empty())
    start_function = (*startFuncs)[0];

  if (const auto* mainFuncs =
          getAuxData<std::vector<gtirb::Addr>>(ir, "mainFunction");
      mainFuncs && !mainFuncs->empty())
    main_function = (*mainFuncs)[0];
}

const gtirb::Module::section_range DisasmData::getSections() const {
  return this->ir.modules()[0].sections();
}

const std::vector<std::tuple<std::string, int, std::vector<gtirb::UUID>>>*
DisasmData::getDataSections() {
  using table_type =
      std::vector<std::tuple<std::string, int, std::vector<gtirb::UUID>>>;
  return getAuxData<table_type>(ir, "dataSections");
}

std::string DisasmData::getSectionName(gtirb::Addr x) const {
  const gtirb::Module::section_range& sections = this->getSections();
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

  // Is this the address of a special function?
  if (this->main_function && x == *this->main_function) {
    return "main";
  } else if (this->start_function && x == *this->start_function) {
    return "_start";
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

std::string DisasmData::getRelocatedDestination(const gtirb::Addr& addr) const {
  if (const auto* relocations = getAuxData<
          std::map<gtirb::Addr, std::tuple<std::string, std::string>>>(
          ir, "relocations")) {
    const auto found = relocations->find(addr);
    if (found != std::end(*relocations) &&
        std::get<0>(found->second) == "R_X86_64_GLOB_DAT")
      return std::get<1>(found->second) + "@GOTPCREL";
  }
  return std::string{};
}

bool DisasmData::isRelocated(const std::string& x) const {
  const auto* relocations =
      getAuxData<std::map<gtirb::Addr, std::tuple<std::string, std::string>>>(
          ir, "relocations");
  if (!relocations)
    return false;

  const auto found = std::find_if(
      std::begin(*relocations), std::end(*relocations),
      [x](const auto& element) { return get<1>(element.second) == x; });

  return found != std::end(*relocations);
}

const gtirb::Section* DisasmData::getSection(const std::string& x) const {
  const auto found =
      std::find_if(getSections().begin(), getSections().end(),
                   [x](const auto& element) { return element.getName() == x; });

  if (found != getSections().end()) {
    return &(*found);
  }

  return nullptr;
}

bool DisasmData::isAmbiguousSymbol(const std::string& name) const {
  // Are there multiple symbols with this name?
  auto found = this->ir.modules()[0].findSymbols(name);
  return distance(begin(found), end(found)) > 1;
}

std::string DisasmData::CleanSymbolNameSuffix(std::string x) {
  return x.substr(0, x.find_first_of('@'));
}

// FIXME: get rid of this function once capstone returns the right name for all
// registers
std::string DisasmData::AdaptRegister(const std::string& x) {
  const std::map<std::string, std::string> adapt{{"ST(0", "ST(0)"}};
  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  return x;
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

// Name, Alignment pairs describing data sections.
const std::array<std::pair<std::string, int>, 7> DataSectionDescriptors{{
    {".got", 8},         //
    {".got.plt", 8},     //
    {".data.rel.ro", 8}, //
    {".init_array", 8},  //
    {".fini_array", 8},  //
    {".rodata", 16},     //
    {".data", 16}        //
}};

const std::pair<std::string, int>*
getDataSectionDescriptor(const std::string& name) {
  const auto foundDataSection = std::find_if(
      std::begin(DataSectionDescriptors), std::end(DataSectionDescriptors),
      [name](const auto& dsd) { return dsd.first == name; });
  if (foundDataSection != std::end(DataSectionDescriptors))
    return foundDataSection;
  else
    return nullptr;
}

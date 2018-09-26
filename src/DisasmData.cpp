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
#include <fstream>
#include <gsl/gsl>
#include <gtirb/gtirb.hpp>
#include <iostream>
#include <utility>
#include <variant>

using namespace std::rel_ops;

DisasmData::DisasmData(gtirb::Context& context_, gtirb::IR* ir_)
    : context(context_), ir(*ir_),
      functionEAs(*ir_->getTable("functionEAs")->get<std::vector<gtirb::Addr>>()),
      start_function(*ir_->getTable("mainFunction")->get<std::vector<gtirb::Addr>>()),
      main_function(*ir_->getTable("mainFunction")->get<std::vector<gtirb::Addr>>()) {}

const gtirb::Module::section_range DisasmData::getSections() const {
  return this->ir.modules()[0].sections();
}

std::vector<std::tuple<std::string, int, std::vector<gtirb::UUID>>>& DisasmData::getDataSections() {
  return *this->ir.getTable("dataSections")
              ->get<std::vector<std::tuple<std::string, int, std::vector<gtirb::UUID>>>>();
}

std::string DisasmData::getSectionName(gtirb::Addr x) const {
  const auto& sections = this->getSections();
  const auto& match =
      find_if(sections.begin(), sections.end(), [x](const auto& s) { return s.getAddress() == x; });

  if (match != sections.end()) {
    return match->getName();
  }

  return std::string{};
}

bool DisasmData::isFunction(const gtirb::Symbol& sym) const {
  return std::binary_search(this->functionEAs.begin(), this->functionEAs.end(), sym.getAddress());
}

std::string DisasmData::getFunctionName(gtirb::Addr x) const {
  for (auto& s : this->ir.modules()[0].findSymbols(x)) {
    if (isFunction(s)) {
      std::stringstream name;
      name << s.getName();

      if (this->isAmbiguousSymbol(s.getName()) == true) {
        name << "_" << std::hex << uint64_t(x);
      }

      return name.str();
    }
  }

  if (x == this->main_function[0]) {
    return "main";
  } else if (x == this->start_function[0]) {
    return "_start";
  }

  // or is this a funciton entry?
  for (auto f : this->function_entry) {
    if (x == f) {
      std::stringstream ss;
      ss << "unknown_function_" << std::hex << uint64_t(x);
      return ss.str();
    }
  }

  return std::string{};
}

// If the symbol is ambiguous print return a label with the address
// This is used for printing a symbolic expression
std::string DisasmData::getAdaptedSymbolNameDefault(const gtirb::Symbol* symbol) const {
    if(symbol->getAddress().has_value()){
        std::string destName=getRelocatedDestination(symbol->getAddress().value());
        if(!destName.empty())
            return destName;
    }
    if (isAmbiguousSymbol(symbol->getName()))
        return DisasmData::GetSymbolToPrint(symbol->getAddress().value());

    return DisasmData::AvoidRegNameConflicts(DisasmData::CleanSymbolNameSuffix(symbol->getName()));
}

// If the symbol is ambiguous or relocated return an empty string
// This is used for printing the label
std::string DisasmData::getAdaptedSymbolName(const gtirb::Symbol* symbol) const {
  auto name = DisasmData::CleanSymbolNameSuffix(symbol->getName());
  if (!isAmbiguousSymbol(symbol->getName()) &&
      !this->isRelocated(name)) // &&   !DisasmData::GetIsReservedSymbol(name)
    return DisasmData::AvoidRegNameConflicts(name);
  return std::string{};
}

std::string DisasmData::GetSymbolToPrint(gtirb::Addr x) {
  std::stringstream ss;
  ss << ".L_" << std::hex << uint64_t(x) << std::dec;
  return ss.str();
}

std::string  DisasmData::getRelocatedDestination(const gtirb::Addr& addr) const {
    const auto& relocations =
            *ir.getTable("relocations")
            ->get<std::map<gtirb::Addr, std::tuple<std::string, std::string>>>();
    const auto found = std::find_if(std::begin(relocations), std::end(relocations),
                                    [addr](const auto& element) {
        return element.first== addr;
    });
    if(found!=std::end(relocations) && std::get<0>(found->second)=="R_X86_64_GLOB_DAT")
        return std::get<1>(found->second)+"@GOTPCREL";
    return std::string{};
}

bool DisasmData::isRelocated(const std::string& x) const {
  const auto& relocations =
      *ir.getTable("relocations")
           ->get<std::map<gtirb::Addr, std::tuple<std::string, std::string>>>();
  const auto found = std::find_if(std::begin(relocations), std::end(relocations),
                                  [x](const auto& element) { return get<1>(element.second) == x; });

  return found != std::end(relocations);
}

const gtirb::Section* DisasmData::getSection(const std::string& x) const {
  const auto found = std::find_if(getSections().begin(), getSections().end(),
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

// FIXME: get rid of this function once capstone returns the right name for all registers
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
      {"128", ""},         {"0", ""},          {"80", "TBYTE PTR"}, {"64", "QWORD PTR"},
      {"32", "DWORD PTR"}, {"16", "WORD PTR"}, {"8", "BYTE PTR"}};

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
  const std::map<std::string, std::string> adapt{{"128", ""}, {"0", ""},   {"80", "t"}, {"64", "q"},
                                                 {"32", "d"}, {"16", "w"}, {"8", "b"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  assert("Unknown Size");

  return x;
}

std::string DisasmData::AvoidRegNameConflicts(const std::string& x) {
  const std::vector<std::string> adapt{"FS", "MOD", "DIV", "NOT", "mod", "div", "not", "and", "or"};

  if (const auto found = std::find(std::begin(adapt), std::end(adapt), x);
      found != std::end(adapt)) {
    return x + "_renamed";
  }

  return x;
}

// Name, Alignment.
const std::array<std::pair<std::string, int>, 7> DataSectionDescriptors{{
    {".got", 8},         //
    {".got.plt", 8},     //
    {".data.rel.ro", 8}, //
    {".init_array", 8},  //
    {".fini_array", 8},  //
    {".rodata", 16},     //
    {".data", 16}        //
}};

const std::pair<std::string, int>* getDataSectionDescriptor(const std::string& name) {
  const auto foundDataSection =
      std::find_if(std::begin(DataSectionDescriptors), std::end(DataSectionDescriptors),
                   [name](const auto& dsd) { return dsd.first == name; });
  if (foundDataSection != std::end(DataSectionDescriptors))
    return foundDataSection;
  else
    return nullptr;
}

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
#include <boost/algorithm/string/trim.hpp>
#include <boost/archive/polymorphic_text_iarchive.hpp>
#include <boost/archive/polymorphic_text_oarchive.hpp>
#include <boost/lexical_cast.hpp>
#include <fstream>
#include <gsl/gsl>
#include <gtirb/gtirb.hpp>
#include <iostream>
#include <utility>
#include <variant>

using namespace std::rel_ops;

DisasmData::DisasmData(gtirb::Context& context_, gtirb::IR* ir_)
    : context(context_), ir(*ir_),
      functionEAs(std::get<std::vector<gtirb::Addr>>(*ir_->getTable("functionEAs"))),
      ambiguous_symbol(std::get<std::vector<std::string>>(*ir_->getTable("ambiguousSymbol"))),
      start_function(std::get<std::vector<gtirb::Addr>>(*ir_->getTable("mainFunction"))),
      main_function(std::get<std::vector<gtirb::Addr>>(*ir_->getTable("mainFunction"))) {}

const gtirb::Module::section_range DisasmData::getSections() const {
  return this->ir.modules()[0].sections();
}

std::vector<gtirb::table::InnerMapType>& DisasmData::getDataSections() {
  return std::get<std::vector<gtirb::table::InnerMapType>>(*this->ir.getTable("dataSections"));
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

// function_complete_name
std::string DisasmData::getFunctionName(gtirb::Addr x) const {
  for (auto& s : this->ir.modules()[0].findSymbols(x)) {
    if (isFunction(s)) {
      std::stringstream name;
      name << s.getName();

      if (this->getIsAmbiguousSymbol(s.getName()) == true) {
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

std::string DisasmData::getAdaptedSymbolNameDefault(const gtirb::Symbol* symbol) const{
    if (getIsAmbiguousSymbol(symbol->getName()))
            return DisasmData::GetSymbolToPrint(symbol->getAddress());

    return DisasmData::AvoidRegNameConflicts(
            DisasmData::CleanSymbolNameSuffix(
                    symbol->getName()));

}

std::string DisasmData::getAdaptedSymbolName(const gtirb::Symbol* symbol) const{
    auto name=DisasmData::CleanSymbolNameSuffix(symbol->getName());
    if (!getIsAmbiguousSymbol(symbol->getName())&&  !this->isRelocated(name))  // &&   !DisasmData::GetIsReservedSymbol(name)
        return DisasmData::AvoidRegNameConflicts(name);
    return std::string{};
}

std::string DisasmData::GetSymbolToPrint(gtirb::Addr x) {
  std::stringstream ss;
  ss << ".L_" << std::hex << uint64_t(x) << std::dec;
  return ss.str();
}

bool DisasmData::isRelocated(const std::string& x) const {
  const auto& relocations =
      std::get<std::map<gtirb::Addr, gtirb::table::ValueType>>(*ir.getTable("relocations"));
  const auto found =
      std::find_if(std::begin(relocations), std::end(relocations), [x](const auto& element) {
        const auto& r = std::get<gtirb::table::InnerMapType>(element.second);
        return std::get<std::string>(r.at("name")) == x;
      });

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

bool DisasmData::getIsAmbiguousSymbol(const std::string& name) const {
  const auto found =
      std::find(std::begin(this->ambiguous_symbol), std::end(this->ambiguous_symbol), name);
  return found != std::end(this->ambiguous_symbol);
}

std::string DisasmData::CleanSymbolNameSuffix(std::string x) {
  return x.substr(0, x.find_first_of('@'));
}


//FIXME: get rid of this function once capstone returns the right name for all registers
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

bool DisasmData::GetIsReservedSymbol(const std::string& x) {
  if (x.length() > 2) {
    return ((x[0] == '_') && (x[1] == '_'));
  }

  return false;
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

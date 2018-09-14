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

std::string DisasmData::getGlobalSymbolReference(gtirb::Addr ea) const {
  // FIXME: when reworking gtirb data structures, make it possible to do
  // "containsAddr" queries directly and efficiently.
  using SymbolMap = std::multimap<gtirb::Addr, const gtirb::Symbol*>;
  SymbolMap symbols;
  for (const auto& s : this->ir.modules()[0].symbols()) {
    symbols.emplace(s.getAddress(), &s);
  }

  auto end = symbols.rend();
  for (auto it = std::reverse_iterator<SymbolMap::const_iterator>(
           symbols.upper_bound(gtirb::Addr(ea))); //
       it != end && it->second->getAddress() <= ea; it++) {
    const auto& sym = *it->second;
    auto* data = sym.getDataReferent().get(this->context);

    /// \todo This will need looked at again to cover the logic
    if (data && containsAddr(*data, gtirb::Addr(ea))) {
      auto displacement = ea - sym.getAddress();

      // in a function with non-zero displacement we do not use the relative addressing
      if (displacement > 0 && isFunction(sym)) {
        return std::string{};
      }
      if (sym.getStorageKind() != gtirb::Symbol::StorageKind::Local) {
        // %do not print labels for symbols that have to be relocated
        const auto name = DisasmData::CleanSymbolNameSuffix(sym.getName());

        if (DisasmData::GetIsReservedSymbol(name) == false) {
          if (displacement > 0) {
            return DisasmData::AvoidRegNameConflicts(name) + "+" + std::to_string(displacement);
          } else {
            return DisasmData::AvoidRegNameConflicts(name);
          }
        }
      }
    }
  }

  const auto& relocations =
      std::get<std::map<gtirb::Addr, gtirb::table::ValueType>>(*ir.getTable("relocations"));
  if (auto found = relocations.find(gtirb::Addr(ea)); found != relocations.end()) {
    const auto& r = std::get<gtirb::table::InnerMapType>(found->second);
    const auto& name = std::get<std::string>(r.at("name"));

    if (std::get<std::string>(r.at("type")) == std::string{"R_X86_64_GLOB_DAT"}) {
      return DisasmData::AvoidRegNameConflicts(name) + "@GOTPCREL";
    } else {
      return DisasmData::AvoidRegNameConflicts(name);
    }
  }

  return std::string{};
}

std::string DisasmData::getGlobalSymbolName(gtirb::Addr ea) const {
  for (const auto& sym : this->ir.modules()[0].findSymbols(gtirb::Addr(ea))) {
    if (sym.getAddress() == ea) {
      if ((sym.getStorageKind() != gtirb::Symbol::StorageKind::Local)) {
        // %do not print labels for symbols that have to be relocated
        const auto name = DisasmData::CleanSymbolNameSuffix(sym.getName());

        // if it is not relocated...
        if (!this->isRelocated(name) && !DisasmData::GetIsReservedSymbol(name)) {
          return std::string{DisasmData::AvoidRegNameConflicts(name)};
        }
      }
    }
  }

  return std::string{};
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

std::string DisasmData::AdaptOpcode(const std::string& x) {
  const std::map<std::string, std::string> adapt{{"movsd2", "movsd"}, {"imul2", "imul"},
                                                 {"imul3", "imul"},   {"imul1", "imul"},
                                                 {"cmpsd3", "cmpsd"}, {"out_i", "out"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  return x;
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

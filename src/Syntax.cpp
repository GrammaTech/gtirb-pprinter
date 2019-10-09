//===- Syntax.cpp -----------------------------------------------*- C++ -*-===//
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
#include "Syntax.hpp"

#include <boost/range/algorithm/find_if.hpp>
#include <map>
#include <vector>

namespace gtirb_pprint {

const std::string& Syntax::tab() const { return TabStyle; }

const std::string& Syntax::textSection() const { return TextSection; }
const std::string& Syntax::dataSection() const { return DataSection; }
const std::string& Syntax::bssSection() const { return BssSection; }

const std::string& Syntax::nop() const { return NopDirective; }
const std::string& Syntax::zeroByte() const { return ZeroByteDirective; }

std::string Syntax::getSizeName(uint64_t x) const {
  return getSizeName(std::to_string(x));
}

std::string Syntax::getSizeName(const std::string& x) const {
  static const std::map<std::string, std::string> adapt{{"80", "TBYTE PTR"},
                                                        {"64", "QWORD PTR"},
                                                        {"32", "DWORD PTR"},
                                                        {"16", "WORD PTR"},
                                                        {"8", "BYTE PTR"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }
  return std::string();
}

std::string Syntax::getSizeSuffix(uint64_t x) const {
  return getSizeSuffix(std::to_string(x));
}

std::string Syntax::getSizeSuffix(const std::string& x) const {
  static const std::map<std::string, std::string> adapt{
      {"80", "t"}, {"64", "q"}, {"32", "d"}, {"16", "w"}, {"8", "b"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }
  return std::string();
}

std::string Syntax::formatSectionName(const std::string& x) const { return x; }

std::string Syntax::formatFunctionName(const std::string& x) const { return x; }

std::string Syntax::formatSymbolName(const std::string& x) const {
  return avoidRegNameConflicts(x);
}

std::string Syntax::avoidRegNameConflicts(const std::string& x) const {
  const std::vector<std::string> adapt{"FS",  "MOD", "DIV", "NOT", "mod", "div",
                                       "not", "and", "or",  "shr", "Si"};

  if (const auto found = std::find(std::begin(adapt), std::end(adapt), x);
      found != std::end(adapt)) {
    return x + "_renamed";
  }

  return x;
}

} // namespace gtirb_pprint

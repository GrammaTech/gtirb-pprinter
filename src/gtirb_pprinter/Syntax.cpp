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

#include <boost/algorithm/string/replace.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <map>
#include <vector>

namespace gtirb_pprint {

std::optional<std::string> Syntax::getSizeName(uint64_t bits) const {
  switch (bits) {
  case 256:
    return "YMMWORD";
  case 128:
    return "XMMWORD";
  case 80:
    return "TBYTE";
  case 64:
    return "QWORD";
  case 32:
    return "DWORD";
  case 16:
    return "WORD";
  case 8:
    return "BYTE";
  }
  return std::nullopt;
}

std::string Syntax::formatSectionName(const std::string& Name) const {
  return Name;
}

std::string Syntax::formatFunctionName(const std::string& Name) const {
  return Name;
}

std::string Syntax::formatSymbolName(const std::string& Name) const {
  return Name;
}

std::string Syntax::avoidRegNameConflicts(const std::string& Name) const {

  const std::vector<std::string> Adapt{
      "FS", "MOD", "NOT", "Di", "Si", "SP", "SS", "AND", "OR", "SHR",
      "fs", "mod", "not", "di", "si", "sp", "ss", "and", "or", "shr"};

  if (const auto found = std::find(std::begin(Adapt), std::end(Adapt), Name);
      found != std::end(Adapt)) {
    return Name + "_renamed";
  }
  return Name;
}

std::string Syntax::escapeByte(uint8_t b) const {
  switch (b) {
  case '\\':
    return std::string("\\\\");
  case '\"':
    return std::string("\\\"");
  case '\n':
    return std::string("\\n");
  case '\t':
    return std::string("\\t");
  case '\b':
    return std::string("\\b");
  case '\f':
    return std::string("\\f");
  case '\r':
    return std::string("\\r");
  case '\a':
    return std::string("\\a");
  default:
    return std::string(1, b);
  }
}

} // namespace gtirb_pprint

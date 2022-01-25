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

std::string Syntax::formatSectionName(const std::string& x) const { return x; }

std::string Syntax::formatFunctionName(const std::string& x) const { return x; }

std::string Syntax::formatSymbolName(const std::string& x) const { return x; }

std::string Syntax::avoidRegNameConflicts(const std::string& x) const {

  const std::vector<std::string> adapt{"FS", "MOD", "NOT", "Di",  "Si",  "AND",
                                       "OR", "SHR", "fs",  "mod", "not", "di",
                                       "si", "and", "or",  "shr"};

  if (const auto found = std::find(std::begin(adapt), std::end(adapt), x);
      found != std::end(adapt)) {
    return x + "_renamed";
  }
  return x;
}

} // namespace gtirb_pprint

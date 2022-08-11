//===- Assembler.cpp -------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2021 GrammaTech, Inc.
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
//===---------------------------------------------------------------------===//
#include "Assembler.hpp"

#include <boost/algorithm/string/replace.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <map>
#include <vector>

namespace gtirb_pprint {

std::string Assembler::escapeByte(uint8_t b) const {
  std::string cleaned;
  cleaned += b;
  cleaned = boost::replace_all_copy(cleaned, "\\", "\\\\");
  cleaned = boost::replace_all_copy(cleaned, "\"", "\\\"");
  cleaned = boost::replace_all_copy(cleaned, "\n", "\\n");
  cleaned = boost::replace_all_copy(cleaned, "\t", "\\t");
  cleaned = boost::replace_all_copy(cleaned, "\v", "\\v");
  cleaned = boost::replace_all_copy(cleaned, "\b", "\\b");
  cleaned = boost::replace_all_copy(cleaned, "\r", "\\r");
  cleaned = boost::replace_all_copy(cleaned, "\a", "\\a");

  return cleaned;
}

} // namespace gtirb_pprint

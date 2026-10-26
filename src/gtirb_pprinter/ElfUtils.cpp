//===- FileUtils.cpp -------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2026 GrammaTech, Inc.
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
#include "ElfUtils.hpp"
#include "AuxDataUtils.hpp"

#include <algorithm>

namespace gtirb_pprint {

bool isDynamicallyLinked(const gtirb::Module& Module) {
  return !Module.findSections(".dynamic").empty();
}

bool linkerGeneratesInterp(const gtirb::Module& Module) {
  const auto BinaryType = aux_data::getBinaryType(Module);
  return isDynamicallyLinked(Module) &&
         std::find(BinaryType.begin(), BinaryType.end(), "SHARED") ==
             BinaryType.end();
}

} // namespace gtirb_pprint

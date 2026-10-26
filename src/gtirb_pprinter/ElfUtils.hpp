//===- ElfUtils.hpp ---------------------------------------------*- C++ -*-===//
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
#ifndef GTIRB_PP_ElfUtils_H
#define GTIRB_PP_ElfUtils_H

#include <gtirb/gtirb.hpp>

namespace gtirb_pprint {

/**
True if the module is dynamically linked: it has a .dynamic section.
*/
bool isDynamicallyLinked(const gtirb::Module& Module);

/**
True if the linker generates .interp for the module: it is a dynamically
linked executable.
*/
bool linkerGeneratesInterp(const gtirb::Module& Module);

} // namespace gtirb_pprint

#endif

//===- ElfVersionScriptPrinter.hpp ------------------------------*- C++ -*-===//
//
//  Copyright (C) 2022 GrammaTech, Inc.
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
#ifndef GTIRB_PP_ELFVERSIONSCRIPT_PRINTER_H
#define GTIRB_PP_ELFVERSIONSCRIPT_PRINTER_H

#include <fstream>
#include <gtirb/gtirb.hpp>

#include "Export.hpp"

namespace gtirb_pprint {

/// \brief print ELF version scripts from GTIRB representations.
DEBLOAT_PRETTYPRINTER_EXPORT_API bool
printVersionScript(const gtirb::IR& IR, std::ofstream& VersionScript);

} // namespace gtirb_pprint

#endif /* GTIRB_PP_ELFVERSIONSCRIPT_PRINTER_H */

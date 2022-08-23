//===- Fixup.hpp ----------------------------------------*- C++ -*-===//
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
#ifndef GT_PPRINTER_FIXUP_H
#define GT_PPRINTER_FIXUP_H
#include "Export.hpp"

namespace gtirb {
class Context;
class Module;
} // namespace gtirb

namespace gtirb_pprint {
class PrettyPrinter;

/// Transforms a GTIRB module to make it acceptable to
/// the assembler.
/// For ELF shared object modules, this consists of removing
/// any direct references to global symbols and replacing them
/// with indirect ones
/// For PE modules, this means ensuring that the entry symbols
/// are correctly named.
/// \param Ctx
/// \param Mod
/// \param Printer
void DEBLOAT_PRETTYPRINTER_EXPORT_API applyFixups(gtirb::Context& Ctx,
                                                  gtirb::Module& Mod,
                                                  const PrettyPrinter& Printer);

/// Turn any direct references to global symbols, which
/// are illegal relocations in shared objects, into
/// indirect references
void fixupSharedObject(gtirb::Context& Ctx, gtirb::Module& Mod);

/// Ensure that PE entry symbols are correctly named
void fixupPESymbols(gtirb::Context& Ctx, gtirb::Module& Mod);

} // namespace gtirb_pprint

#endif

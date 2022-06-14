//===- gtirb_layout.hpp ------------------------------------------- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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
#ifndef GTIRB_LAYOUT_H
#define GTIRB_LAYOUT_H

#include "Export.hpp"
#include <gtirb/gtirb.hpp>

namespace gtirb_layout {

/// Register AuxData types used by gtirb_layout.
void GTIRB_LAYOUT_EXPORT_API registerAuxDataTypes();

/// Determine whether any ByteIntervals in the IR require new addresses before
/// it can be printed.
///
/// \param Ir  IR to check.
///
/// \return \c true if the IR cannot be pretty printed.
bool GTIRB_LAYOUT_EXPORT_API layoutRequired(gtirb::IR& Ir);

/// Determine whether any ByteIntervals in the Module require new addresses
/// before it can be printed.
///
/// \param M  Module to check.
///
/// \return \c true if the Module cannot be pretty printed.
bool GTIRB_LAYOUT_EXPORT_API layoutRequired(
    gtirb::Module& M, std::unordered_set<std::string> SkipSections = {});

/// Assigns referents to every integral symbol that preserve the symbol's
/// address. If a block does not exist at the required address, a new block
/// will be created.
///
/// \param Ctx  Context to create new blocks in.
/// \param M    Module containing symbols to modify.
void GTIRB_LAYOUT_EXPORT_API fixIntegralSymbols(gtirb::Context& Ctx,
                                                gtirb::Module& M);

/// Assigns addresses to byte intervals in the module to make it printable.
bool GTIRB_LAYOUT_EXPORT_API layoutModule(gtirb::Context& Ctx,
                                          gtirb::Module& M);

/// Removes addresses from the byte intervals in a module. Automatically calls
/// \ref fixIntegralSymbols to ensure symbols remain linked to the byte
/// intervals after their addresses change.
///
/// \param Ctx Context to use for \c fixIntegralSymbols.
/// \param M   Module to remove the layout from.
///
/// \return \c true.
bool GTIRB_LAYOUT_EXPORT_API removeModuleLayout(gtirb::Context& Ctx,
                                                gtirb::Module& M);
} // namespace gtirb_layout

#endif /* GTIRB_LAYOUT_H */

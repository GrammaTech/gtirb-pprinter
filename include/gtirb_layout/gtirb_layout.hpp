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
bool GTIRB_LAYOUT_EXPORT_API layoutRequired(gtirb::IR& ir);
void GTIRB_LAYOUT_EXPORT_API fixIntegralSymbols(gtirb::Context& Ctx,
                                                gtirb::Module& M);
bool GTIRB_LAYOUT_EXPORT_API layoutModule(gtirb::Context& Ctx,
                                          gtirb::Module& M);
bool GTIRB_LAYOUT_EXPORT_API removeModuleLayout(gtirb::Context& Ctx,
                                                gtirb::Module& M);
} // namespace gtirb_layout

#endif /* GTIRB_LAYOUT_H */

//===- ForceLinking.hpp -----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
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
#ifndef GTIRB_PPRINTER_FORCE_LINKING_H
#define GTIRB_PPRINTER_FORCE_LINKING_H

namespace gtirb_pprint {
extern volatile bool IntelPrettyPrinterAnchorSource;
[[maybe_unused]] static bool IntelPrettyPrinterAnchorDest =
    IntelPrettyPrinterAnchorSource;

extern volatile bool AttPrettyPrinterAnchorSource;
[[maybe_unused]] static bool AttPrettyPrinterAnchorDest =
    AttPrettyPrinterAnchorSource;
} // namespace gtirb_pprint

#endif /* GTIRB_PPRINTER_FORCE_LINKING_H */

//===- version.h ------------------------------------------------*- C++ -*-===//
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

#ifndef GTIRB_PPRINTER_VERSION_H
#define GTIRB_PPRINTER_VERSION_H

/**@def GTIRB_PPRINTER_MAJOR_VERSION
   Major Version
*/
#define GTIRB_PPRINTER_MAJOR_VERSION 0

/**@def GTIRB_PPRINTER_MINOR_VERSION
   Minor Version
*/
#define GTIRB_PPRINTER_MINOR_VERSION 1

/**@def GTIRB_PPRINTER_PATCH_VERSION
   Patch Version
*/
#define GTIRB_PPRINTER_PATCH_VERSION 0

#define GTIRB_PPRINTER_STR_HELPER(x) #x
#define GTIRB_PPRINTER_STR(x) GTIRB_PPRINTER_STR_HELPER(x)

/// \file version.h
/// \brief Holds the version macros. Read from version.txt

/**@def GTIRB_PPRINTER_VERSION_STRING
   Full version
*/
#define GTIRB_PPRINTER_VERSION_STRING                                          \
  (GTIRB_PPRINTER_STR(GTIRB_PPRINTER_MAJOR_VERSION) "." GTIRB_PPRINTER_STR(    \
      GTIRB_PPRINTER_MINOR_VERSION) "." GTIRB_PPRINTER_STR(GTIRB_PPRINTER_PATCH_VERSION))

#endif

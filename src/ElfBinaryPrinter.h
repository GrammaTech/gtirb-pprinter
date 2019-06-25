//===- ElfBinaryPrinter.h ------------------------------------------*- C++ ---//
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
#ifndef GTIRB_PP_ELF_BINARY_PRINTER_H
#define GTIRB_PP_ELF_BINARY_PRINTER_H

#include "BinaryPrinter.h"

#include <gtirb/gtirb.hpp>

#include <vector>
#include <string>

/// \brief ElfBinary-print GTIRB representations.
namespace gtirb_bprint {
  class ElfBinaryPrinter : public BinaryPrinter {
  public:
    /// Construct a ElfBinaryPrinter with the default configuration.
    ElfBinaryPrinter() {}

    ElfBinaryPrinter(const ElfBinaryPrinter&) = default;
    ElfBinaryPrinter(ElfBinaryPrinter&&) = default;
    ElfBinaryPrinter& operator=(const ElfBinaryPrinter&) = default;
    ElfBinaryPrinter& operator=(ElfBinaryPrinter&&) = default;
    
    int link(std::string output_filename,
	     const std::vector<std::string>& library_paths,
	     const gtirb_pprint::PrettyPrinter& pp,
	     gtirb::Context& context, gtirb::IR& ir) const;    
  };
} // namespace gtirb_bprint
  
#endif /* GTIRB_PP_ELF_BINARY_PRINTER_H */

//===- PeBinaryPrinter.hpp -----------------------------------------*- C++ ---//
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
#ifndef GTIRB_PP_PE_BINARY_PRINTER_H
#define GTIRB_PP_PE_BINARY_PRINTER_H

#include "BinaryPrinter.hpp"
#include "file_utils.hpp"

#include <gtirb/gtirb.hpp>

#include <iostream>
#include <string>
#include <vector>

namespace gtirb_bprint {

class TempFile;

// Command-line argument wrapper for `lib.exe' or alternate library utility.
struct PeLibOptions {
  const std::string& DefFile;               // .DEF
  const std::string& LibFile;               // .LIB
  const std::optional<std::string> Machine; // /MACHINE:
};

// Command-line argument wrapper for `ml64.exe' or alternate assembler.
struct PeAssembleOptions {
  const std::string& Compiland; // .ASM
  const std::string& OutputFile;
  const std::vector<std::string>& ExtraCompileArgs;
  const std::vector<std::string>& LibraryPaths;
};

// Command-line argument wrapper for `ml64.exe' and `link.exe' or alternatives.
struct PeLinkOptions {
  const std::string& OutputFile;

  const std::vector<TempFile>& Compilands;     // .ASM
  const std::vector<std::string>& Resources;   // .RES
  const std::optional<std::string>& ExportDef; // .DEF

  const std::optional<std::string>& EntryPoint; // /ENTRY:
  const std::optional<std::string>& Subsystem;  // /SUBYSTEM:

  const bool Dll;

  const std::vector<std::string>& ExtraCompileArgs;
  const std::vector<std::string>& LibraryPaths;
};

// Type helpers for dynamic assemble and link command resolution.
using PeCommand = std::pair<std::string, std::vector<std::string>>;

using PeLibCommand = std::function<PeCommand(const PeLibOptions&)>;
using PeAssembleCommand = std::function<PeCommand(const PeAssembleOptions&)>;
using PeLinkCommand = std::function<PeCommand(const PeLinkOptions&)>;

PeLibCommand findPeLibCommand();
PeAssembleCommand findPeAssembleCommand();
PeLinkCommand findPeLinkCommand();

class DEBLOAT_PRETTYPRINTER_EXPORT_API PeBinaryPrinter : public BinaryPrinter {
public:
  PeBinaryPrinter(const gtirb_pprint::PrettyPrinter& Printer,
                  const std::vector<std::string>& ExtraCompileArgs,
                  const std::vector<std::string>& LibraryPaths);

  // Assemble do not link the first module.
  int assemble(const std::string& Path, gtirb::Context& Context,
               gtirb::Module& Module) const override;

  // Assemble and link all modules.
  int link(const std::string& Path, gtirb::Context& Context,
           gtirb::IR& IR) const override;

protected:
  // Generate DEF files for imported libaries (temp files).
  bool prepareImportDefs(
      const gtirb::IR& IR,
      std::map<std::string, std::unique_ptr<TempFile>>& ImportDefs) const;

  // Generate LIB files from DEF files with `lib.exe' or alternative utility.
  bool prepareImportLibs(const gtirb::IR& IR,
                         std::vector<std::string>& ImportLibs) const;

  // Generated a DEF file with all exports in this file.
  bool prepareExportDef(gtirb::IR& IR, TempFile& Def) const;

  // Generate RES files for all embeded PE resources.
  bool prepareResources(gtirb::IR& IR, gtirb::Context& Context,
                        std::vector<std::string>& Resources) const;

  // Locate a LIB utility and construct the command-line.
  std::pair<std::string, std::vector<std::string>>
  libCommand(const PeLibOptions& Options) const {
    auto LibTool = findPeLibCommand();
    return LibTool(Options);
  }

  // Locate an assembler and construct the "assemble" command-line.
  std::pair<std::string, std::vector<std::string>>
  assembleCommand(const PeAssembleOptions& Options) const {
    auto Assemble = findPeAssembleCommand();
    return Assemble(Options);
  }

  // Locate an assembler and construct the "assemble and link" command line.
  std::pair<std::string, std::vector<std::string>>
  linkCommand(const PeLinkOptions& Options) const {
    auto AssembleLink = findPeLinkCommand();
    return AssembleLink(Options);
  }
};

} // namespace gtirb_bprint

#endif /* GTIRB_PP_PE_BINARY_PRINTER_H */

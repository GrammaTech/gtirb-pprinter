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

#include <string>
#include <vector>

namespace gtirb_bprint {

class TempFile;

// Command-line argument wrapper for `lib.exe' or alternate library utility.
struct PeLibOptions {
  const std::string& DefFile;
  const std::string& LibFile;
  const std::optional<std::string> Machine;
};

// Command-line argument wrapper for `ml64.exe' or alternate assembler.
struct PeAssembleOptions {
  const std::string& Compiland;
  const std::string& OutputFile;
  const std::optional<std::string> Machine;
  const std::vector<std::string>& ExtraCompileArgs;
  const std::vector<std::string>& LibraryPaths;
};

// Command-line argument wrapper for `ml64.exe' and `link.exe' or alternatives.
struct PeLinkOptions {
  const std::string& OutputFile;

  const std::vector<TempFile>& Compilands;
  const std::vector<std::string>& Resources;
  const std::optional<std::string>& ExportDef;

  const std::optional<std::string>& EntryPoint;
  const std::optional<std::string>& Subsystem;
  const std::optional<std::string> Machine;

  const bool Dll;

  const std::vector<std::string>& ExtraCompileArgs;
  const std::vector<std::string>& LibraryPaths;
};

// Type helpers for command lookup and command-line argument builders.
using CommandList =
    std::vector<std::pair<std::string, std::vector<std::string>>>;

using PeLib = std::function<CommandList(const PeLibOptions&)>;
using PeAssemble = std::function<CommandList(const PeAssembleOptions&)>;
using PeLink = std::function<CommandList(const PeLinkOptions&)>;
using PeAssembleLink = std::function<CommandList(const PeLinkOptions&)>;

// Tool lookup helpers.
PeLib peLib();
PeAssemble peAssemble();
PeLink peLink();
PeAssembleLink peAssembleLink();

class DEBLOAT_PRETTYPRINTER_EXPORT_API PeBinaryPrinter : public BinaryPrinter {
public:
  PeBinaryPrinter(const gtirb_pprint::PrettyPrinter& Printer,
                  const std::vector<std::string>& ExtraCompileArgs,
                  const std::vector<std::string>& LibraryPaths);

  // Assemble a module but do not link the object.
  int assemble(const std::string& OutputFile, gtirb::Context& Context,
               gtirb::Module& Module) const override;

  // Assemble and link all modules.
  int link(const std::string& OutputFile, gtirb::Context& Context,
           gtirb::IR& IR) const override;

protected:
  // Generate DEF files for imported libaries (temp files).
  bool prepareImportDefs(
      const gtirb::IR& IR,
      std::map<std::string, std::unique_ptr<TempFile>>& ImportDefs) const;

  // Generated a DEF file with all exports.
  bool prepareExportDef(gtirb::IR& IR, TempFile& Def) const;

  // Generate RES files for all embedded PE resources.
  bool prepareResources(gtirb::IR& IR, gtirb::Context& Context,
                        std::vector<std::string>& Resources) const;

  // Locate a PE library utility and build a command list.
  CommandList libCommands(const PeLibOptions& Options) const {
    PeLib Lib = peLib();
    return Lib(Options);
  }

  // Locate an assembler and construct the "assemble only" command list.
  CommandList assembleCommands(const PeAssembleOptions& Options) const {
    PeAssemble Assemble = peAssemble();
    return Assemble(Options);
  }

  // Locate an assembler and construct the "assemble and link" command list.
  CommandList linkCommands(const PeLinkOptions& Options) const {
    PeAssembleLink AssembleLink = peAssembleLink();
    return AssembleLink(Options);
  }
};

} // namespace gtirb_bprint

#endif /* GTIRB_PP_PE_BINARY_PRINTER_H */

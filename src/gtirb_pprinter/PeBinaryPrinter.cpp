//===- PeBinaryPrinter.cpp --------------------------------------*- C++ -*-===//
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
#include "PeBinaryPrinter.hpp"
#include "AuxDataSchema.hpp"
#include "driver/Logger.h"
#include "file_utils.hpp"
#include <iostream>

namespace {

std::optional<std::string> getPeMachine(const gtirb::IR& IR) {
  for (const gtirb::Module& Module : IR.modules()) {
    switch (Module.getISA()) {
    case gtirb::ISA::IA32:
      return "X86";
    case gtirb::ISA::X64:
      return "X64";
    default:
      break;
    }
  }
  return std::nullopt;
}

// Find an entrypoint symbol defined in any Module.
// NOTE: `ml64.exe' cannot automatically determine what the entrypoint is.
std::optional<std::string> getEntrySymbol(const gtirb::IR& IR) {
  // Find the first Module with an entry point.
  auto Found = std::find_if(
      IR.modules_begin(), IR.modules_end(),
      [](const gtirb::Module& M) { return M.getEntryPoint() != nullptr; });

  // Find first symbol referencing the entry CodeBlock.
  if (Found != IR.modules_end()) {
    const gtirb::CodeBlock* Block = Found->getEntryPoint();
    if (Block && Block->getAddress()) {
      auto It = Found->findSymbols(*Block->getAddress());

      std::string Name = (&*It.begin())->getName();

      // ML (PE32) will implicitly prefix the symbol with an additional '_', so
      // we remove one for the command-line option.
      if (Found->getISA() == gtirb::ISA::IA32 && Name.size() &&
          Name[0] == '_') {
        Name = Name.substr(1);
      }

      return Name;
    }
  }
  return std::nullopt;
}

std::optional<std::string> getPeSubsystem(const gtirb::IR& IR) {

  // Find the first Module with an entry point.
  auto Found = std::find_if(
      IR.modules_begin(), IR.modules_end(),
      [](const gtirb::Module& M) { return M.getEntryPoint() != nullptr; });

  // Reference the Module's `binaryType' AuxData table for the subsystem label.
  if (Found != IR.modules_end()) {
    if (auto* T = Found->getAuxData<gtirb::schema::BinaryType>()) {
      if (std::find(T->begin(), T->end(), "WINDOWS_GUI") != T->end()) {
        return "windows";
      } else if (std::find(T->begin(), T->end(), "WINDOWS_CUI") != T->end()) {
        return "console";
      }
    }
  }

  return std::nullopt;
}

bool isPeDll(const gtirb::IR& IR) {
  for (const gtirb::Module& Module : IR.modules()) {
    if (auto* Table = Module.getAuxData<gtirb::schema::BinaryType>()) {
      if (std::find(Table->begin(), Table->end(), "DLL") != Table->end()) {
        return true;
      }
    }
  }
  return false;
}

} // namespace

namespace gtirb_bprint {

bool PeBinaryPrinter::prepareImportDefs(
    const gtirb::IR& IR,
    std::map<std::string, std::unique_ptr<TempFile>>& ImportDefs) const {

  std::cerr << "Preparing Import libs...\n";
  for (const gtirb::Module& Module : IR.modules()) {

    std::cerr << "Module: " << Module.getBinaryPath() << "\n";
    auto* PeImports = Module.getAuxData<gtirb::schema::ImportEntries>();
    if (!PeImports) {
      LOG_INFO << "\tNo import entries.\n";
      continue;
    }

    // For each import in the AuxData table.
    for (const auto& [Addr, Ordinal, Name, Import] : *PeImports) {
      (void)Addr; // unused binding

      auto It = ImportDefs.find(Import);

      if (It == ImportDefs.end()) {
        // Create a new (temporary) DEF file.
        ImportDefs[Import] = std::make_unique<TempFile>(".def");
        It = ImportDefs.find(Import);
        std::ostream& Stream = static_cast<std::ostream&>(*(It->second));
        Stream << "LIBRARY \"" << It->first << "\"\n\nEXPORTS\n";
      }

      // Write the entry to the DEF file.
      std::ostream& Stream = static_cast<std::ostream&>(*(It->second));
      if (Ordinal != -1) {
        Stream << Name << " @ " << Ordinal << " NONAME\n";
      } else {
        Stream << Name << "\n";
      }
    }
  }

  // Close the temporary files.
  for (auto& It : ImportDefs) {
    It.second->close();
  }

  return true;
}

bool PeBinaryPrinter::prepareImportLibs(
    const gtirb::IR& IR, std::vector<std::string>& ImportLibs) const {

  // Prepare `.DEF' import definition files.
  std::map<std::string, std::unique_ptr<TempFile>> ImportDefs;
  if (!prepareImportDefs(IR, ImportDefs)) {
    std::cerr << "ERROR: Unable to write import `.DEF' files.";
    return false;
  }

  std::optional<std::string> Machine = getPeMachine(IR);

  // Generate `.LIB' files from `.DEF' files with the lib utility.
  for (auto& [Import, Temp] : ImportDefs) {
    std::string DefFile = Temp->fileName();
    std::string LibFile = replaceExtension(Import, ".lib");

    const auto& [LibTool, Args] = libCommand(DefFile, LibFile, Machine);

    if (std::optional<int> Rc = execute(LibTool, Args)) {
      if (*Rc) {
        std::cerr << "ERROR: lib returned: " << *Rc << "\n";
        return false;
      } else {
        std::cout << "Generated " << LibFile << "\n";
      }
      ImportLibs.push_back(LibFile);
    } else {
      std::cerr << "ERROR: Unable to find `" << LibTool << "'\n";
      return false;
    }

    ImportLibs.push_back(LibFile);
  }

  return true;
}

bool PeBinaryPrinter::prepareExportDef(gtirb::IR& IR, TempFile& Def) const {
  std::vector<std::string> Exports;

  for (const gtirb::Module& Module : IR.modules()) {
    std::cerr << "Generating export DEF file ...\n";

    auto* PeExports = Module.getAuxData<gtirb::schema::ExportEntries>();
    if (!PeExports) {
      std::cerr << "\tNo export entries.\n";
      continue;
    }

    for (const auto& [Addr, Ordinal, Name] : *PeExports) {
      (void)Addr; // unused binding

      std::string Extra;
      auto It = Module.findSymbols(Name);
      if (It.begin()->getReferent<gtirb::DataBlock>()) {
        Extra = " DATA";
      }

      std::stringstream Stream;
      if (Ordinal != -1) {
        Stream << Name << " @ " << Ordinal << Extra << "\n";
      } else {
        Stream << Name << Extra << "\n";
      }
      Exports.push_back(Stream.str());
    }
  }

  if (!Exports.empty()) {
    std::ostream& Stream = static_cast<std::ostream&>(Def);
    Stream << "\nEXPORTS\n";
    for (std::string& Export : Exports) {
      Stream << Export;
    }
  }

  Def.close();
  return !Exports.empty();
}

bool PeBinaryPrinter::prepareResources(
    gtirb::IR& ir, gtirb::Context& ctx,
    std::vector<std::string>& resourceFiles) const {

  for (gtirb::Module& m : ir.modules()) {
    // For each import in the AuxData table.
    auto* pe_resources = m.getAuxData<gtirb::schema::PEResources>();
    if (!pe_resources) {
      continue;
    }

    std::ofstream resfile;
    std::string resfilename = replaceExtension(m.getBinaryPath(), ".res");
    resfile.open(resfilename, std::ios::binary | std::ios::trunc);
    if (!resfile.is_open()) {
      LOG_ERROR << "Unable to open resource file: " << resfilename << "\n";
      return false;
    }

    // File header
    const uint8_t file_header[] = {
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
        0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define WR(tf, d, n) tf.write(reinterpret_cast<const char*>(d), n)

    WR(resfile, &file_header, 32);

    // .. followed by a list of header/data blocks
    for (const auto& [header, offset, data_len] : *pe_resources) {
      // resource header
      WR(resfile, header.data(), header.size());

      const auto* bi = dyn_cast_or_null<gtirb::ByteInterval>(
          gtirb::Node::getByUUID(ctx, offset.ElementId));

      uint64_t bi_offset = offset.Displacement;

      if (bi) {
        // resource data
        const uint8_t* resource_data =
            reinterpret_cast<const uint8_t*>(bi->rawBytes<const uint8_t*>()) +
            bi_offset;
        if (bi_offset + data_len > bi->getSize()) {
          std::cout << "[WARNING] PE - Insufficient data in byte interval for "
                       "resource.\n";
        }

        // data longer than the bi provides.
        if (resource_data) {
          WR(resfile, resource_data, data_len);
        } else
          std::cout << "[WARNING] PE - Unable to get resource data\n";

        // padding to align subsequent headers
        if (data_len % 4 != 0) {
          uint32_t tmp = 0x0000;
          WR(resfile, &tmp, 4 - data_len % 4);
        }
      } else
        std::cout << "[WARNING] PE - Could not find byte interval for resource "
                     "data\n";
    }

    resfile.close();
    resourceFiles.push_back(resfilename);
  }
  return true;
}

PeBinaryPrinter::PeBinaryPrinter(
    const gtirb_pprint::PrettyPrinter& Printer_,
    const std::vector<std::string>& ExtraCompileArgs_,
    const std::vector<std::string>& LibraryPaths_)
    : BinaryPrinter(Printer_, ExtraCompileArgs_, LibraryPaths_) {}

int PeBinaryPrinter::assemble(const std::string& Path, gtirb::Context& Context,
                              gtirb::Module& Module) const {
  // Print the Module to a temporary assembly file.
  TempFile Asm;
  if (!prepareSource(Context, Module, Asm)) {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  const auto& [Assembler, Args] = assembleCommand(Asm.fileName(), Path);

  // Invoke the assembler.
  if (std::optional<int> Rc = execute(Assembler, Args)) {
    if (*Rc)
      std::cerr << "ERROR: assembler returned: " << *Rc << "\n";
    return *Rc;
  }
  std::cerr << "ERROR: could not find the assembler '" << Assembler
            << "' on the PATH.\n";
  return -1;
}

int PeBinaryPrinter::link(const std::string& OutputFile,
                          gtirb::Context& Context, gtirb::IR& IR) const {

  // Prepare all ASM sources (temp files).
  std::vector<TempFile> Compilands;
  if (!prepareSources(Context, IR, Compilands)) {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  // Generate LIB import libraries for the linker.
  std::vector<std::string> ImportLibs;
  if (!prepareImportLibs(IR, ImportLibs)) {
    std::cerr << "ERROR: Unable to generate import `.LIB' files.";
    return -1;
  }

  // Generate a DEF file for all exports.
  TempFile DefFile(".def");
  std::optional<std::string> ExportDef;
  if (prepareExportDef(IR, DefFile)) {
    ExportDef = DefFile.fileName();
  }

  // Prepare RES resource files for the linker.
  std::vector<std::string> Resources;
  if (!prepareResources(IR, Context, Resources)) {
    std::cerr << "ERROR: Unable to generate resource files.";
    return -1;
  }

  // Find a named symbol for the entry point.
  std::optional<std::string> EntryPoint = getEntrySymbol(IR);

  // Find the PE subsystem.
  std::optional<std::string> Subsystem = getPeSubsystem(IR);

  // Find the PE binary type.
  bool Dll = isPeDll(IR);

  // Build the command-line.
  const PeBinaryOptions& Options = {
      OutputFile, Compilands, Resources, ExportDef, EntryPoint, Subsystem, Dll};
  const auto& [Assembler, Args] = linkCommand(Options);

  // Invoke the assembler or linker.
  if (std::optional<int> Rc = execute(Assembler, Args)) {
    if (*Rc)
      std::cerr << "ERROR: assembler returned: " << *Rc << "\n";
    return *Rc;
  }
  std::cerr << "ERROR: could not find the assembler '" << Assembler
            << "' on the PATH.\n";
  return -1;
}

std::pair<std::string, std::vector<std::string>>
PeBinaryPrinter::libCommand(const std::string& DefFile,
                            const std::string& LibFile,
                            const std::optional<std::string> Machine) const {
  std::vector<std::string> Args = {
      "/NOLOGO",
      "/DEF:" + DefFile,
      "/OUT:" + LibFile,
  };
  if (Machine) {
    Args.push_back("/MACHINE:" + *Machine);
  }
  return {"lib.exe", Args};
}

std::pair<std::string, std::vector<std::string>>
PeBinaryPrinter::assembleCommand(const std::string& AssemblyFile,
                                 const std::string& OutputFile) const {
  std::vector<std::string> Args = {
      // Disable the banner for the assembler.
      "/nologo",
      // Set one-time options like the output file name.
      "/Fe", OutputFile,
      // Set per-compiland options, if any.
      "/c", "/Fo", OutputFile,
      // Set the file to be assembled.
      AssemblyFile};

  // Copy in any user-supplied, command-line arguments.
  std::copy(ExtraCompileArgs.begin(), ExtraCompileArgs.end(),
            std::back_inserter(Args));

  return {"ml64.exe", Args};
}

std::pair<std::string, std::vector<std::string>>
PeBinaryPrinter::linkCommand(const PeBinaryOptions& Options) const {

  // Build the assembler command-line arguments.
  std::vector<std::string> Args;

  // Disable the banner for the assembler.
  Args.push_back("/nologo");

  // Set one-time options like the output file name.
  Args.push_back("/Fe");
  Args.push_back(Options.OutputFile);

  // Set per-compiland options, if any.
  for (const TempFile& Compiland : Options.Compilands) {
    // Copy in any user-supplied, command-line arguments.
    std::copy(ExtraCompileArgs.begin(), ExtraCompileArgs.end(),
              std::back_inserter(Args));
    // The last thing before the next compiland is the file to be assembled.
    Args.push_back(Compiland.fileName());
  }

  // Build the linker command-line arguments.
  Args.push_back("/link");

  // Disable the banner for the linker.
  Args.push_back("/nologo");

  // Add exports DEF file.
  if (Options.ExportDef) {
    Args.push_back("/DEF:" + *Options.ExportDef);
  }

  // Add RES resource files.
  for (const std::string& Resource : Options.Resources) {
    Args.push_back(Resource);
  }

  // Add PE entry point.
  if (Options.EntryPoint) {
    Args.push_back("/ENTRY:" + *Options.EntryPoint);
  } else {
    Args.push_back("/NOENTRY");
  }

  // Add PE subsystem.
  if (Options.Subsystem) {
    Args.push_back("/SUBSYSTEM:" + *Options.Subsystem);
  }

  // Add shared library flag.
  if (Options.Dll) {
    Args.push_back("/DLL");
  }

  return {"ml64.exe", Args};
}

} // namespace gtirb_bprint

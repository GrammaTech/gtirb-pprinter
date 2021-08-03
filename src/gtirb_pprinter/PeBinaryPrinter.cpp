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

#include <boost/filesystem.hpp>
#include <boost/process/io.hpp>
#include <boost/process/search_path.hpp>
#include <boost/process/system.hpp>

namespace fs = boost::filesystem;
namespace bp = boost::process;

namespace {

// Map GTIRB ISA to MSVC /MACHINE: strings.
std::optional<std::string> getPeMachine(const gtirb::Module& Module) {
  switch (Module.getISA()) {
  case gtirb::ISA::IA32:
    return "X86";
  case gtirb::ISA::X64:
    return "X64";
  default:
    break;
  }
  return std::nullopt;
}

std::optional<std::string> getPeMachine(const gtirb::IR& IR) {
  if (const auto& It = IR.modules(); !It.empty()) {
    return getPeMachine(*It.begin());
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

// Read LLVM bin directory path from `llvm-config --bindir'.
std::optional<std::string> llvmBinDir() {
  bp::ipstream InputStream;
  bp::child Child(bp::search_path("llvm-config"), "--bindir",
                  bp::std_out > InputStream);

  std::string Line;
  if (Child.running() && std::getline(InputStream, Line) && !Line.empty()) {
    return Line;
  }

  return std::nullopt;
}

} // namespace

namespace gtirb_bprint {

int executeCommands(const CommandList& Commands) {
  for (const auto& [Command, Args] : Commands) {
    {
      std::stringstream Stream;
      Stream << "Execute: " << Command;
      for (const auto& Arg : Args) {
        Stream << " " << Arg;
      }
      LOG_INFO << Stream.str() << "\n";
    }

    if (std::optional<int> Rc = execute(Command, Args)) {
      if (*Rc) {
        LOG_ERROR << Command << ": non-zero exit code: " << *Rc << "\n";
        return -1;
      }
      continue;
    }
    LOG_ERROR << "could not find `" << Command << "' on the PATH.\n";
    return -1;
  }
  return 0;
}

inline void appendCommands(CommandList& T, CommandList& U) {
  T.insert(T.end(), std::make_move_iterator(U.begin()),
           std::make_move_iterator(U.end()));
}

bool PeBinaryPrinter::prepareImportDefs(
    const gtirb::IR& IR,
    std::map<std::string, std::unique_ptr<TempFile>>& ImportDefs) const {

  LOG_INFO << "Preparing import LIB files...\n";
  for (const gtirb::Module& Module : IR.modules()) {

    auto* PeImports = Module.getAuxData<gtirb::schema::ImportEntries>();
    if (!PeImports) {
      LOG_INFO << "Module: " << Module.getBinaryPath()
               << ": No import entries.\n";
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

bool PeBinaryPrinter::prepareExportDef(gtirb::IR& IR, TempFile& Def) const {
  std::vector<std::string> Exports;

  for (const gtirb::Module& Module : IR.modules()) {
    LOG_INFO << "Preparing exports DEF file...\n";

    auto* PeExports = Module.getAuxData<gtirb::schema::ExportEntries>();
    if (!PeExports) {
      LOG_INFO << "Module: " << Module.getBinaryPath()
               << ": No export entries.\n";
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
    const gtirb::IR& IR, const gtirb::Context& Context,
    std::vector<std::string>& Resources) const {

  LOG_INFO << "Preparing resource RES files...\n";
  for (const gtirb::Module& Module : IR.modules()) {

    auto* Table = Module.getAuxData<gtirb::schema::PEResources>();
    if (!Table) {
      LOG_INFO << "Module: " << Module.getBinaryPath() << ": No resources.\n";
      continue;
    }

    std::ofstream Stream;
    std::string Filename = replaceExtension(Module.getBinaryPath(), ".res");
    Stream.open(Filename, std::ios::binary | std::ios::trunc);
    if (!Stream.is_open()) {
      LOG_ERROR << "Unable to open resource file: " << Filename << "\n";
      return false;
    }

    // RES file header ...
    const uint8_t FileHeader[] = {
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
        0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    Stream.write(reinterpret_cast<const char*>(&FileHeader), 32);

    // ... followed by a list of header/data blocks.
    for (const auto& [Header, Offset, Size] : *Table) {
      // Write resource header.
      Stream.write(reinterpret_cast<const char*>(Header.data()), Header.size());

      const gtirb::ByteInterval* ByteInterval =
          dyn_cast_or_null<gtirb::ByteInterval>(
              gtirb::Node::getByUUID(Context, Offset.ElementId));

      if (ByteInterval) {
        // Write resource data.
        auto Data =
            ByteInterval->rawBytes<const uint8_t>() + Offset.Displacement;

        if (Offset.Displacement + Size > ByteInterval->getSize()) {
          LOG_DEBUG << "Insufficient data in byte interval for PE resource.\n";
        }

        // Data is longer than the ByteInterval provides.
        if (Data) {
          Stream.write(reinterpret_cast<const char*>(Data), Size);
        } else {
          LOG_DEBUG << "Unable to get PE resource data\n";
        }

        // Write padding to align subsequent headers.
        if (Size % 4 != 0) {
          uint32_t tmp = 0x0000;
          Stream.write(reinterpret_cast<const char*>(&tmp), 4 - Size % 4);
        }
      } else {
        LOG_DEBUG << "Could not find byte interval for PE resource data.\n";
      }
    }

    Stream.close();
    Resources.push_back(Filename);
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
    LOG_ERROR << "Failed to write assembly to temporary file.\n";
    return -1;
  }

  // Find the target platform.
  std::optional<std::string> Machine = getPeMachine(Module);

  return executeCommands(assembleCommands(
      {Asm.fileName(), Path, Machine, ExtraCompileArgs, LibraryPaths}));
}

int PeBinaryPrinter::link(const std::string& OutputFile,
                          gtirb::Context& Context, gtirb::IR& IR) const {
  // Prepare all ASM sources (temp files).
  std::vector<TempFile> Compilands;
  if (!prepareSources(Context, IR, Compilands)) {
    LOG_ERROR << "Failed to write assembly to temporary file.\n";
    return -1;
  }

  // Prepare DEF import definition files (temp files).
  std::map<std::string, std::unique_ptr<TempFile>> ImportDefs;
  if (!prepareImportDefs(IR, ImportDefs)) {
    LOG_ERROR << "Failed to write import .DEF files.";
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
    LOG_ERROR << "Failed to write resource .RES files.";
    return -1;
  }

  // Find a named symbol for the entry point.
  std::optional<std::string> EntryPoint = getEntrySymbol(IR);

  // Find the PE subsystem.
  std::optional<std::string> Subsystem = getPeSubsystem(IR);

  // Find the target platform.
  std::optional<std::string> Machine = getPeMachine(IR);

  // Find the PE binary type.
  bool Dll = isPeDll(IR);

  // Build the list of commands.
  CommandList Commands;

  // Add commands to generate .LIB files from import .DEF files.
  for (auto& [Import, Temp] : ImportDefs) {
    std::string Def = Temp->fileName();
    std::string Lib = replaceExtension(Import, ".lib");

    CommandList LibCommands = libCommands({Def, Lib, Machine});
    appendCommands(Commands, LibCommands);
  }

  // Add assemble-link commands.
  CommandList LinkCommands =
      linkCommands({OutputFile, Compilands, Resources, ExportDef, EntryPoint,
                    Subsystem, Machine, Dll, ExtraCompileArgs, LibraryPaths});
  appendCommands(Commands, LinkCommands);

  // Execute the assemble-link command list.
  return executeCommands(Commands);
}

int PeBinaryPrinter::libs(const gtirb::IR& IR) const {
  // Prepare DEF import definition files (temp files).
  std::map<std::string, std::unique_ptr<TempFile>> ImportDefs;
  if (!prepareImportDefs(IR, ImportDefs)) {
    LOG_ERROR << "Failed to write import .DEF files.";
    return -1;
  }

  // Find the target platform.
  std::optional<std::string> Machine = getPeMachine(IR);

  // Build the list of commands.
  CommandList Commands;

  // Add commands to generate .LIB files from import .DEF files.
  for (auto& [Import, Temp] : ImportDefs) {
    std::string Def = Temp->fileName();
    std::string Lib = replaceExtension(Import, ".lib");

    CommandList LibCommands = libCommands({Def, Lib, Machine});
    appendCommands(Commands, LibCommands);
  }

  return executeCommands(Commands);
}

int PeBinaryPrinter::resources(const gtirb::IR& IR,
                               const gtirb::Context& Context) const {
  // Prepare RES resource files for the linker.
  std::vector<std::string> Resources;
  if (!prepareResources(IR, Context, Resources)) {
    LOG_ERROR << "Failed to write resource .RES files.";
    return -1;
  }

  return 0;
}

// lib.exe /DEF:X.def /OUT:X.lib
// Input: DEF  Output: LIB
CommandList msvcLib(const PeLibOptions& Options) {
  std::vector<std::string> Args = {
      "/NOLOGO",
      "/DEF:" + Options.DefFile,
      "/OUT:" + Options.LibFile,
  };
  if (Options.Machine) {
    Args.push_back("/MACHINE:" + *Options.Machine);
  }
  return {{"lib.exe", Args}};
}

// ml64.exe/ml.exe /c ...
// Input: ASM  Output: OBJ
CommandList msvcAssemble(const PeAssembleOptions& Options) {
  std::vector<std::string> Args = {
      // Disable the banner for the assembler.
      "/nologo",
      // Set one-time options like the output file name.
      "/Fe", Options.OutputFile,
      // Set per-compiland options, if any.
      "/c", "/Fo", Options.OutputFile,
      // Set the file to be assembled.
      Options.Compiland};

  // Copy in any user-supplied, command-line arguments.
  std::copy(Options.ExtraCompileArgs.begin(), Options.ExtraCompileArgs.end(),
            std::back_inserter(Args));

  const std::string& Assembler =
      Options.Machine == "X64" ? "ml64.exe" : "ml.exe";

  return {{Assembler, Args}};
}

// link.exe
// Input: OBJ  Output: PE32(+)
CommandList msvcLink(const PeLinkOptions& Options) {
  std::vector<std::string> Args = {
      // Disable the banner for the assembler.
      "/NOLOGO",
      // Set one-time options like the output file name.
      "/OUT:" + Options.OutputFile,
  };

  // Add exports DEF file.
  if (Options.ExportDef) {
    Args.push_back("/DEF:" + *Options.ExportDef);
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

  // Add user-specified library paths.
  for (const std::string& Path : Options.LibraryPaths) {
    Args.push_back("/LIBPATH:" + Path);
  }

  // Add all OBJ files.
  for (const TempFile& Compiland : Options.Compilands) {
    std::string File = fs::path(Compiland.fileName()).filename().string();
    File = replaceExtension(File, ".obj");
    Args.push_back(File);
  }

  return {{"link.exe", Args}};
}

// Single-command assemble and link:
// ml64.exe/ml.exe ... /link ...
// Input: .ASM  Output: PE32(+)
CommandList msvcAssembleLink(const PeLinkOptions& Options) {

  // Build the assembler command-line arguments.
  std::vector<std::string> Args;

  // Disable the banner for the assembler.
  Args.push_back("/nologo");

  // Set one-time options like the output file name.
  Args.push_back("/Fe");
  Args.push_back(Options.OutputFile);

  // Add all Module assembly sources (temp files).
  for (const TempFile& Compiland : Options.Compilands) {
    Args.push_back(Compiland.fileName());
  }

  // Add user-supplied command-line arguments.
  std::copy(Options.ExtraCompileArgs.begin(), Options.ExtraCompileArgs.end(),
            std::back_inserter(Args));

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

  // Add user-specified library paths.
  for (const std::string& Path : Options.LibraryPaths) {
    Args.push_back("/LIBPATH:" + Path);
  }

  const std::string& Assembler =
      Options.Machine == "X64" ? "ml64.exe" : "ml.exe";

  return {{Assembler, Args}};
}

// llvm-dlltool -dX.def -lX.lib ...
// Input: DEF  Output: LIB
CommandList llvmDllTool(const PeLibOptions& Options) {
  std::vector<std::string> Args = {
      "-d", Options.DefFile,
      "-l", Options.LibFile,
      "-m", Options.Machine == "X86" ? "i386" : "i386:x86-64"};
  return {{"llvm-dlltool", Args}};
}

// lld-link /DEF:X.def /OUT:X.lib ...
// Input: DEF  Output: LIB
CommandList llvmLib(const PeLibOptions& Options) {
  std::vector<std::string> Args = {
      "/DEF:" + Options.DefFile,
      "/OUT:" + Options.LibFile,
  };
  if (Options.Machine) {
    Args.push_back("/MACHINE:" + *Options.Machine);
  }
  return {{"lld-link", Args}};
}

// lld-link
// Input: OBJ  Output: PE32(+)
CommandList llvmLink(const PeLinkOptions& Options) {

  std::vector<std::string> Args = {
      // Disable the banner for the assembler.
      "/nologo",
      // Set one-time options like the output file name.
      "/out:" + Options.OutputFile,
  };

  // Add exports DEF file.
  if (Options.ExportDef) {
    Args.push_back("/def:" + *Options.ExportDef);
  }

  // Add PE entry point.
  if (Options.EntryPoint) {
    Args.push_back("/entry:" + *Options.EntryPoint);
  }

  // Add PE subsystem.
  if (Options.Subsystem) {
    Args.push_back("/subsystem:" + *Options.Subsystem);
  }

  // Add shared library flag.
  if (Options.Dll) {
    Args.push_back("/dll");
  }

  if (Options.Machine) {
    Args.push_back("/machine:" + *Options.Machine);
  }

  // Add user-specified library paths.
  for (const std::string& Path : Options.LibraryPaths) {
    Args.push_back("/libpath:" + Path);
  }

  // Add all OBJ files.
  for (const TempFile& Compiland : Options.Compilands) {
    std::string File = fs::path(Compiland.fileName()).filename().string();
    File = replaceExtension(File, ".obj");
    Args.push_back(File);
  }

  // Add RES resource files.
  for (const std::string& Resource : Options.Resources) {
    Args.push_back(Resource);
  }

  return {{"lld-link", Args}};
}

// uasm -win64/-coff -Fo ...
// Input: ASM  Output: OBJ
CommandList uasmAssemble(const PeAssembleOptions& Options) {
  // Map PE machine target to UASM output format.
  const std::string& Format = Options.Machine == "X64" ? "-win64" : "-coff";

  std::vector<std::string> Args = {// Disable the banner for the assembler.
                                   "-nologo", "-less",
                                   // Set output format.
                                   Format,
                                   // Add common options.
                                   "-safeseh",
                                   // Set object file name.
                                   "-Fo", Options.OutputFile,
                                   // Lastly, specify assembly file.
                                   Options.Compiland};

  // Add user-supplied, command-line arguments.
  std::copy(Options.ExtraCompileArgs.begin(), Options.ExtraCompileArgs.end(),
            std::back_inserter(Args));

  return {{"uasm", Args}};
}

// uasm -win64/-coff ...
// <LINK>
// Input: ASM  Output: PE32(+)
CommandList uasmAssembleLink(const PeLinkOptions& Options) {
  // Map PE machine target to UASM output format.
  const std::string& Format = Options.Machine == "X64" ? "-win64" : "-coff";

  std::vector<std::string> Args = {// Disable the banner for the assembler.
                                   "-nologo", "-less",
                                   // Add common options.
                                   "-safeseh",
                                   // Set output format.
                                   Format};

  // Add user-supplied, command-line arguments.
  std::copy(Options.ExtraCompileArgs.begin(), Options.ExtraCompileArgs.end(),
            std::back_inserter(Args));

  for (const TempFile& Compiland : Options.Compilands) {
    std::string File = fs::path(Compiland.fileName()).filename().string();
    File = replaceExtension(File, ".obj");
    Args.push_back("-Fo");
    Args.push_back(std::move(File));
    Args.push_back(Compiland.fileName());
  }

  CommandList Commands = {{"uasm", Args}};

  // Find linker and add link commands.
  auto Link = peLink();
  CommandList LinkCommands = Link(Options);
  appendCommands(Commands, LinkCommands);

  return Commands;
}

// Locate `lib.exe' or alternative PE library tool.
PeLib peLib() {
  // Prefer MSVC `lib.exe'.
  fs::path Path = bp::search_path("lib.exe");
  if (!Path.empty()) {
    return msvcLib;
  }

  // Add LLVM bin directory to PATH.
  if (std::optional<std::string> Dir = llvmBinDir()) {
    auto Env = boost::this_process::environment();
    Env["PATH"] += ":" + *Dir;
  }

  // Fallback to `llvm-dlltool'.
  Path = bp::search_path("llvm-dlltool");
  if (!Path.empty()) {
    return llvmDllTool;
  }

  // Fallback to `lld-link':
  // When `link.exe' is invoked with `/DEF:' and no input files, it behaves as
  // `lib.exe' would. LLVM's `lld-link' emulates this behavior.
  Path = bp::search_path("lld-link");
  if (!Path.empty()) {
    return llvmLib;
  }

  return msvcLib;
}

// Locate `link.exe' or alternative PE linker.
PeLink peLink() {
  // Prefer MSVC `link.exe'.
  fs::path Path = bp::search_path("link.exe");
  if (!Path.empty()) {
    return msvcLink;
  }

  // Fallback to `lld-link'.
  Path = bp::search_path("lld-link");
  if (!Path.empty()) {
    return llvmLink;
  }

  return msvcLink;
}

// Locate MSVC `ml' or `uasm' MASM assembler.
PeAssemble peAssemble() {
  // Prefer MSVC assembler.
  fs::path Path = bp::search_path("cl");
  if (!Path.empty()) {
    return msvcAssemble;
  }

  // Fallback to UASM.
  Path = bp::search_path("uasm");
  if (!Path.empty()) {
    return uasmAssemble;
  }

  return msvcAssemble;
}

// Locate "assemble and link" tools.
PeAssembleLink peAssembleLink() {
  // Prefer single, compound MSVC command.
  fs::path Path = bp::search_path("cl");
  if (!Path.empty()) {
    return msvcAssembleLink;
  }

  // Fallback to UASM and a subsequent link command.
  Path = bp::search_path("uasm");
  if (!Path.empty()) {
    return uasmAssembleLink;
  }

  return msvcAssembleLink;
}

} // namespace gtirb_bprint

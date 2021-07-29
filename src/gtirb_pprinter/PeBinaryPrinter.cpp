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

namespace gtirb_bprint {
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

bool PeBinaryPrinter::prepareDefFile(gtirb::IR& ir, TempFile& defFile) const {

  std::vector<std::string> export_defs;

  for (gtirb::Module& m : ir.modules()) {
    LOG_INFO << "Preparing DEF file...\n";
    auto* pe_exports = m.getAuxData<gtirb::schema::ExportEntries>();
    if (!pe_exports) {
      LOG_INFO << "\tNo export entries.\n";
      continue;
    }

    for (const auto& [addr, ordinal, fnName] : *pe_exports) {
      std::string extra;
      (void)addr; // silence unused var warning in MSVC < 15.7
      auto syms = m.findSymbols(fnName);
      if (syms.begin()->getReferent<gtirb::DataBlock>())
        extra = " DATA";

      std::stringstream ss;
      if (ordinal != -1) {
        ss << fnName << " @ " << ordinal << extra << "\n";
      } else {
        ss << fnName << extra << "\n";
      }
      export_defs.push_back(ss.str());
    }
  }

  if (!export_defs.empty()) {
    std::ostream& os = static_cast<std::ostream&>(defFile);
    os << "\nEXPORTS\n";
    for (auto& export_def : export_defs) {
      os << export_def;
    }
  }

  defFile.close();
  return !export_defs.empty();
}

// Generate DEF files for imported libaries (temp files).
bool PeBinaryPrinter::prepareImportDefs(
    const gtirb::IR& IR,
    std::map<std::string, std::unique_ptr<TempFile>>& ImportDefs) const {

  LOG_INFO << "Preparing Import libs...\n";
  for (const gtirb::Module& M : IR.modules()) {

    LOG_INFO << "Module: " << M.getBinaryPath() << "\n";
    auto* PeImports = M.getAuxData<gtirb::schema::ImportEntries>();
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

  // Generate `.LIB' files from `.DEF' files with the lib utility.
  for (auto& [Import, Temp] : ImportDefs) {
    std::string Def = Temp->fileName();
    std::string Lib = replaceExtension(Import, ".lib");
    if (Library->lib(Def, Lib)) {
      return false;
    }
    ImportLibs.push_back(Lib);
  }

  return true;
}

void PeBinaryPrinter::prepareLinkerArguments(
    gtirb::IR& ir, std::vector<std::string>& resourceFiles, std::string defFile,
    std::vector<std::string>& args) const {
  // Start the linker arguments.
  args.push_back("/link");

  // Disable the banner for the linker.
  args.push_back("/nologo");

  // Add def file
  if (!defFile.empty()) {
    args.push_back("/DEF:" + defFile);
  }

  // If the user specified additional library paths, tell the linker about
  // them now. Note, there is no way to do this for ml, as it does not
  // accept linker command line arguments.
  for (const std::string& libPath : LibraryPaths)
    args.push_back("/LIBPATH:" + libPath);

  // Add resource files
  for (const std::string& resfile : resourceFiles)
    args.push_back(resfile);

  // If there's an entrypoint defined in any module, specify it on the
  // command line. This works around the fact that ml64 cannot automatically
  // determine what the entrypoint is.
  if (auto Iter = std::find_if(
          ir.modules_begin(), ir.modules_end(),
          [](const gtirb::Module& M) { return M.getEntryPoint() != nullptr; });
      Iter != ir.modules_end()) {

    if (gtirb::CodeBlock* Block = Iter->getEntryPoint();
        Block && Block->getAddress()) {
      auto entry_syms = Iter->findSymbols(*Block->getAddress());
      std::string Name = (&*entry_syms.begin())->getName();
      if (Iter->getISA() == gtirb::ISA::IA32 && Name.size() && Name[0] == '_') {
        Name = Name.substr(1);
      }
      args.push_back("/ENTRY:" + Name);
    } else {
      args.push_back("/NOENTRY");
    }

    if (auto* Table = Iter->getAuxData<gtirb::schema::BinaryType>()) {
      if (std::find(Table->begin(), Table->end(), "WINDOWS_GUI") !=
          Table->end()) {
        args.push_back("/SUBSYSTEM:windows");
      } else if (std::find(Table->begin(), Table->end(), "WINDOWS_CUI") !=
                 Table->end()) {
        args.push_back("/SUBSYSTEM:console");
      }
    }
  }

  for (gtirb::Module& Module : ir.modules()) {
    if (auto* Table = Module.getAuxData<gtirb::schema::BinaryType>()) {
      if (std::find(Table->begin(), Table->end(), "DLL") != Table->end()) {
        args.push_back("/DLL");
        break;
      }
    }
  }
}

static std::unique_ptr<PeAssembler>
getPeAssembler(const std::vector<std::string>& ExtraArgs) {
  return std::make_unique<Ml64Assembler>(ExtraArgs);
}

static std::unique_ptr<PeLibrary>
getPeLibrary(const std::vector<std::string>& LibraryPaths) {
  return std::make_unique<MsvcLib>(LibraryPaths);
}

int MsvcAssembler::assemble(const std::string& I, const std::string& O) {
  std::vector<std::string> Args = {
      // Disable the banner for the assembler.
      "/nologo",
      // Set one-time options like the output file name.
      "/Fe", O,
      // Set compiland arguments.
      "/c", "/Fo", O};

  // Copy in any user-supplied command line arguments.
  std::copy(ExtraArgs.begin(), ExtraArgs.end(), std::back_inserter(Args));

  // The last thing before the next file is the file to be assembled.
  Args.push_back(I);

  // Execute `ml.exe' or `ml64.exe'.
  return run(Args);
};

int MsvcLib::lib(const std::string& Def, const std::string& Lib) {
  // Prepare `lib.exe' command-line arguments.
  std::vector<std::string> Args = {
      "/nologo",
      "/DEF:" + Def,
      "/OUT:" + Lib,
  };

  // Execute `lib.exe'.
  return run(Args);
}

PeBinaryPrinter::PeBinaryPrinter(
    const gtirb_pprint::PrettyPrinter& prettyPrinter,
    const std::vector<std::string>& extraCompileArgs,
    const std::vector<std::string>& libraryPaths)
    : BinaryPrinter(prettyPrinter, extraCompileArgs, libraryPaths),
      Assembler(getPeAssembler(extraCompileArgs)),
      Library(getPeLibrary(libraryPaths)) {}

int PeBinaryPrinter::assemble(const std::string& Path, gtirb::Context& Context,
                              gtirb::Module& Module) const {
  TempFile Asm;
  if (!prepareSource(Context, Module, Asm)) {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }
  return Assembler->assemble(Asm.fileName(), Path);
}

int PeBinaryPrinter::link(const std::string& /* outputFilename */,
                          gtirb::Context& ctx, gtirb::IR& ir) {

  for (const auto& Module : ir.modules()) {
    if (Module.getISA() == gtirb::ISA::IA32) {
      compiler = "ml";
      break;
    }
  }

  // Prepare all of the files we're going to generate assembly into.
  std::vector<TempFile> tempFiles;
  if (!prepareSources(ctx, ir, tempFiles)) {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  // Generate import libraries for the linker.
  std::vector<std::string> ImportLibs;
  if (!prepareImportLibs(ir, ImportLibs)) {
    std::cerr << "ERROR: Unable to generate import `.LIB' files.";
    return -1;
  }

  TempFile defFile(".def");
  std::string defFileName;
  if (prepareDefFile(ir, defFile)) {
    defFileName = defFile.fileName();
  }

  // Prepare resource files for the linker
  std::vector<std::string> resourceFiles;
  if (!prepareResources(ir, ctx, resourceFiles)) {
    std::cerr << "ERROR: Unable to generate resource files.";
    return -1;
  }

  // Collect linker arguments
  std::vector<std::string> args;
  prepareLinkerArguments(ir, resourceFiles, defFileName, args);

  // Invoke the assembler.
  if (std::optional<int> ret = execute(compiler, args)) {
    if (*ret)
      std::cerr << "ERROR: assembler returned: " << *ret << "\n";
    return *ret;
  }
  std::cerr << "ERROR: could not find the assembler '" << compiler
            << "' on the PATH.\n";
  return -1;
}

} // namespace gtirb_bprint

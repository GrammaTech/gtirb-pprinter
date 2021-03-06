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
void PeBinaryPrinter::prepareAssemblerArguments(
    const std::vector<TempFile>& compilands, const std::string& outputFilename,
    const std::vector<std::string>& perCompilandExtraArgs,
    std::vector<std::string>& args) const {
  // FIXME: various improvements left to be made:
  // * gtirb-pprinter doesn't currently support x86, so support for the ml
  // assembler is incomplete.
  // * GTIRB does not yet provide access to the PE32 header, so there's no way
  // to determine whether the module was an executable or a DLL, what subsystem
  // the module was compiled for, what the stack size is, etc. We are currently
  // treating everything as an executable unless it has no entrypoint, and are
  // using symbols in the module to guess whether it's a console application
  // or not.
  // * The user can specify command line arguments, but there's no way to
  // distinguish between options to ml64.exe per compiland or options to
  // link.exe for the whole executable.

  // Disable the banner for the assembler.
  args.push_back("/nologo");

  // Set one-time options like the output file name.
  args.push_back("/Fe");
  args.push_back(outputFilename);

  // Set per-compiland options, if any.
  for (const TempFile& compiland : compilands) {
    // Copy in any program-supplied command line arguments.
    std::copy(perCompilandExtraArgs.begin(), perCompilandExtraArgs.end(),
              std::back_inserter(args));
    // Copy in any user-supplied command line arguments.
    std::copy(ExtraCompileArgs.begin(), ExtraCompileArgs.end(),
              std::back_inserter(args));

    // The last thing before the next file is the file to be assembled.
    args.push_back(compiland.fileName());
  }
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

// Generate import def files (temp files), and build into lib files returned
// in importLibs to be linked.
bool PeBinaryPrinter::prepareImportLibs(
    gtirb::IR& ir, std::vector<std::string>& importLibs) const {
  std::map<std::string, std::vector<std::string>> importDefs;

  LOG_INFO << "Preparing Import libs...\n";
  for (gtirb::Module& m : ir.modules()) {
    // For each import in the AuxData table.
    LOG_INFO << "Module: " << m.getBinaryPath() << "\n";
    auto* pe_imports = m.getAuxData<gtirb::schema::ImportEntries>();
    if (!pe_imports) {
      LOG_INFO << "\tNo import entries.\n";
      continue;
    }
    for (const auto& [addr, ordinal, fnName, libName] : *pe_imports) {
      (void)addr; // unused binding
      std::map<std::string, std::vector<std::string>>::iterator itImportDef =
          importDefs.find(libName);
      if (itImportDef == importDefs.end()) {
        importDefs[libName] = std::vector<std::string>();
        itImportDef = importDefs.find(libName);
      }
      std::stringstream ss;
      if (ordinal != -1) {
        ss << fnName << " @ " << ordinal << " NONAME"
           << "\n";
      } else {
        ss << fnName << "\n";
      }
      itImportDef->second.push_back(ss.str());
    }

    for (auto& itLib : importDefs) {
      TempFile tf(".def");
      std::ostream& os = static_cast<std::ostream&>(tf);
      os << "LIBRARY \"" << itLib.first << "\"\n\nEXPORTS\n";
      for (auto& entry : itLib.second) {
        os << entry;
      }
      tf.close();

      std::vector<std::string> args;
      std::string libTool = "lib.exe";
      std::string libName = replaceExtension(itLib.first, ".lib");
      std::string Machine = m.getISA() == gtirb::ISA::IA32 ? "X86" : "X64";
      args.push_back(std::string("/DEF:") + tf.fileName());
      args.push_back(std::string("/OUT:") + libName);
      args.push_back(std::string("/MACHINE:" + Machine));
      if (std::optional<int> ret = execute(libTool, args)) {
        if (*ret) {
          std::cerr << "ERROR: lib returned: " << *ret << "\n";
          return false;
        } else {
          std::cout << "Generated " << replaceExtension(itLib.first, ".lib")
                    << "\n";
        }
        importLibs.push_back(libName);
      } else {
        std::cerr << "ERROR: Unable to find lib.exe\n";
        return false;
      }
    }
    // Sort by import name and generate a def file for each import name.
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

PeBinaryPrinter::PeBinaryPrinter(
    const gtirb_pprint::PrettyPrinter& prettyPrinter,
    const std::vector<std::string>& extraCompileArgs,
    const std::vector<std::string>& libraryPaths)
    : BinaryPrinter(prettyPrinter, extraCompileArgs, libraryPaths),
      compiler("ml64") {}

int PeBinaryPrinter::assemble(const std::string& outputFilename,
                              gtirb::Context& context,
                              gtirb::Module& mod) const {
  std::vector<TempFile> tempFiles(1);
  if (!prepareSource(context, mod, tempFiles[0])) {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  // Collect the arguments for invoking the assembler.
  std::vector<std::string> args;
  prepareAssemblerArguments(tempFiles, outputFilename,
                            {"/c", "/Fo", outputFilename}, args);

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

int PeBinaryPrinter::link(const std::string& outputFilename,
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

  // Prepare import definition files and generate import libraries for the
  // linker
  std::vector<std::string> importLibs;
  if (!prepareImportLibs(ir, importLibs)) {
    std::cerr << "ERROR: Unable to generate import libs.";
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

  // Collect the arguments for invoking the assembler.
  std::vector<std::string> args;
  prepareAssemblerArguments(tempFiles, outputFilename, {}, args);

  // Collect linker arguments
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

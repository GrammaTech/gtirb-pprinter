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
      LOG_ERROR << "\tNo import entries!\n";
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
        ss << libName << "@" << ordinal << " @ " << ordinal << " == " << fnName
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
      args.push_back(std::string("/DEF:") + tf.fileName());
      args.push_back(std::string("/OUT:") + libName);
      if (std::optional<int> ret = execute(libTool, args)) {
        if (*ret) {
          std::cerr << "ERROR: lib returned: " << *ret << "\n";
          return false;
        } else
          std::cout << "Generated " << replaceExtension(itLib.first, ".lib")
                    << "\n";
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
    gtirb::IR& ir, std::vector<std::string>& importLibs,
    std::vector<std::string>& args) const {
  // The command lines for ml and ml64 are different, but there are some common
  // features. The first thing are the options common to both ml and ml64,
  // followed by assembler-specific options, followed by the name of the file
  // to be assembled. For ml64 compilations, the linker arguments follow all of
  // the compliands.
  bool isML64 = compiler == "ml64";

  // Handle the linker options for ml64.
  if (isML64) {
    // Start the linker arguments.
    args.push_back("/link");

    // Disable the banner for the linker.
    args.push_back("/nologo");

    // If the user specified additional library paths, tell the linker about
    // them now. Note, there is no way to do this for ml, as it does not
    // accept linker command line arguments.
    for (const std::string& libPath : LibraryPaths)
      args.push_back("/LIBPATH:" + libPath);

    // If there's an entrypoint defined in any module, specify it on the
    // command line. This works around the fact that ml64 cannot automatically
    // determine what the entrypoint is.
    if (auto Iter = std::find_if(ir.modules_begin(), ir.modules_end(),
                                 [](const gtirb::Module& M) {
                                   return M.getEntryPoint() != nullptr;
                                 });
        Iter != ir.modules_end()) {
      // By convention, we name the entrypoint this way. See the constructor
      // for MasmPrettyPrinter for more information.
      args.push_back("/entry:__EntryPoint");

      // If we found a module with an entrypoint, we next want to determine if
      // this is a console or GUI app to be able to set the subsystem PE header
      // field correctly.  If the app depends on user32.dll it's likely a GUI
      // app.
      // FIXME : This should be based off the original PE header, but that's not
      // yet available.
      bool isGUI = std::find(importLibs.begin(), importLibs.end(),
                             "user32.lib") != importLibs.end();
      if (!isGUI)
        args.push_back("/subsystem:console");
      else
        args.push_back("/subsystem:windows");
    } else {
      // We could not find an entrypoint, so assume this is a resource-only
      // DLL with no entry point as a fallback.
      args.push_back("/DLL");
      args.push_back("/NOENTRY");
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
                          gtirb::Context& ctx, gtirb::IR& ir) const {
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

  // Collect the arguments for invoking the assembler.
  std::vector<std::string> args;
  prepareAssemblerArguments(tempFiles, outputFilename, {}, args);
  prepareLinkerArguments(ir, importLibs, args);

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

//===- ElfBinaryPrinter.cpp -------------------------------------*- C++ -*-===//
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
#include "ElfBinaryPrinter.hpp"

#include "AuxDataSchema.hpp"
#include "AuxDataUtils.hpp"
#include "ElfVersionScriptPrinter.hpp"
#include "FileUtils.hpp"
#include "driver/Logger.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

namespace gtirb_bprint {

std::optional<std::string>
ElfBinaryPrinter::getInfixLibraryName(const std::string& library) const {
  std::regex libsoRegex("^lib(.*)\\.so.*");
  std::smatch m;
  if (std::regex_match(library, m, libsoRegex)) {
    return m.str(1);
  }
  return std::nullopt;
}

std::optional<std::string>
ElfBinaryPrinter::findLibrary(const std::string& library,
                              const std::vector<std::string>& paths) const {
  for (const auto& path : paths) {
    if (std::optional<std::string> fp = resolveRegularFilePath(path, library))
      return fp;
  }
  return std::nullopt;
}

bool isBlackListedLib(std::string Library) {
  std::string Prefix = "ld-linux";
  return (Library.substr(0, Prefix.length()) == Prefix);
}

// These are symbols that otherwise pass our screen for undefined
// symbols but don't appear to need external linkage when rebuilding
// the binary. Some, for example __rela_iplt_start, are introduced
// by ddisasm.
bool isBlackListed(std::string sym) {
  static std::vector<std::string> blackList = {"",
                                               "__rela_iplt_start",
                                               "__rela_iplt_end",
                                               "__gmon_start__",
                                               "_ITM_registerTMCloneTable",
                                               "_ITM_deregisterTMCloneTable"};

  for (auto& name : blackList) {
    if (sym == name) {
      return true;
    }
  }
  return false;
}

bool ElfBinaryPrinter::generateDummySO(
    const gtirb::IR& ir, const std::string& libDir, const std::string& lib,
    std::vector<const gtirb::Symbol*>& syms) const {

  // Assume that lib is a filename w/ no path prefix
  assert(!boost::filesystem::path(lib).has_parent_path());
  std::string asmFileName = lib + ".s";
  auto asmFilePath = boost::filesystem::path(libDir) / asmFileName;
  auto libPath = boost::filesystem::path(libDir) / lib;
  bool emittedSymvers = false;

  {
    std::ofstream asmFile(asmFilePath.string());
    asmFile << "# Generated dummy file for .so undefined symbols\n";

    for (auto curr = syms.begin(); curr != syms.end(); ++curr) {
      const gtirb::Symbol* sym = *curr;

      std::string name = sym->getName();

      auto SymInfo = aux_data::getElfSymbolInfo(*sym);
      bool has_copy = false;
      if (!SymInfo) {
        // See if we have a symbol for "foo_copy", if so use its info
        std::string copyName = sym->getName() + "_copy";
        if (auto CopySymRange = sym->getModule()->findSymbols(copyName)) {
          if (CopySymRange.empty()) {
            LOG_WARNING << "Symbol not in symbol table [" << sym->getName()
                        << "] while generating dummy SO\n";
            assert(false); // Should've been filtered out in prepareDummySOLibs.
            return false;
          }
          has_copy = true;
          SymInfo = aux_data::getElfSymbolInfo(*(CopySymRange.begin()));
        } else {
          return false;
        }
      }
      uint64_t SymSize = SymInfo->Size;
      std::string SymType = SymInfo->Type;
      // TODO: Make use of syntax content in ElfPrettyPrinter?

      // Generate an appropriate symbol
      // Note: The following handles situations we've encountered
      // so far. If you're having an issue with a particular symbol,
      // this code is likely where a fix might be needed.
      if (SymType == "FUNC" || SymType == "GNU_IFUNC") {
        asmFile << ".text\n";
        asmFile << ".globl " << name << "\n";
      } else if (has_copy) {
        // Treat copy-relocation variables as common symbols
        asmFile << ".data\n";
        asmFile << ".comm " << name << ", " << SymSize << ", " << SymSize
                << "\n";

        // Don't need to do anything else below here for
        // common symbols.
        continue;
      } else {
        asmFile << ".data\n";
        asmFile << ".globl " << name << "\n";
      }

      static const std::unordered_map<std::string, std::string>
          TypeNameConversion = {
              {"FUNC", "function"},  {"OBJECT", "object"},
              {"NOTYPE", "notype"},  {"NONE", "notype"},
              {"TLS", "tls_object"}, {"GNU_IFUNC", "gnu_indirect_function"},
          };
      auto TypeNameIt = TypeNameConversion.find(SymType);
      if (TypeNameIt == TypeNameConversion.end()) {
        std::cerr << "Unknown type: " << SymType << " for symbol: " << name
                  << "\n";
        assert(!"unknown type in elfSymbolInfo!");
      } else {
        const auto& TypeName = TypeNameIt->second;
        asmFile << ".type " << name << ", @" << TypeName << "\n";
      }

      auto Version = aux_data::getSymbolVersionString(*sym);
      if (Version && !Printer.getIgnoreSymbolVersions()) {
        asmFile << ".symver " << name << "," << name << *Version << '\n';
        emittedSymvers = true;
      }

      asmFile << name << ":\n";
      uint64_t space = SymSize;
      if (space == 0) {
        space = 4;
      }
      asmFile << ".skip " << space << "\n";
    }
  }

  std::vector<std::string> args;
  args.push_back("-o");
  args.push_back(libPath.string());
  args.push_back("-shared");
  args.push_back("-fPIC");
  args.push_back("-nostartfiles");
  args.push_back("-nodefaultlibs");
  args.push_back(asmFilePath.string());

  TempFile VersionScript(".map");
  if (emittedSymvers) {
    if (!Printer.getIgnoreSymbolVersions()) {
      // A version script is only needed if we define versioned symbols.
      if (gtirb_pprint::printVersionScript(ir, VersionScript)) {
        args.push_back("-Wl,--version-script=" + VersionScript.fileName());
      }
    }
  }
  VersionScript.close();

  if (std::optional<int> ret = execute(compiler, args)) {
    if (*ret) {
      std::cerr << "ERROR: Compiler returned " << *ret
                << " for dummy .so: " << lib << "\n";
      return false;
    }

    return true;
  }

  std::cerr << "ERROR: Failed to run compiler for dummy .so: " << lib << "\n";
  return false;
}

// Generate dummy stand-in libraries for .so files that may not be present
// in the rewriting context (but would be expected to be present in the
// eventual runtime context.)
//
// Note: we're sort-of playing games with the linker here. Normally, in order
// to link an ELF-based executable that depends on dynamic libraries (.so
// files), one needs to include the .so files in the link. But we want to be
// able to relink a rewritten binary without necessarily having access to all
// the .so files the original was linked against. So this class will manage the
// process of creating fake .so files that export all the correct symbols, and
// we can link against those.
bool ElfBinaryPrinter::prepareDummySOLibs(
    const gtirb::IR& ir, const std::string& libDir,
    std::vector<std::string>& libArgs) const {
  // Collect all libs we need to handle
  std::vector<std::string> libs;
  for (const gtirb::Module& module : ir.modules()) {
    for (const auto& Library : aux_data::getLibraries(module)) {
      // Skip blacklisted libs
      if (isBlackListedLib(Library)) {
        continue;
      }

      // TODO: skip any explicit library that isn't just
      // a filename. Do these actually occur?
      if (boost::filesystem::path(Library).has_parent_path()) {
        std::cerr << "ERROR: Skipping explicit lib w/ parent directory: "
                  << Library << "\n";
        continue;
      }
      libs.push_back(Library);
    }
  }
  if (libs.empty()) {
    std::cerr << "Note: no dynamic libraries present.\n";
    return false;
  }

  // Now we need to assign imported symbols to all the libs.
  // For versioned symbols, we have a mapping of which library they belong to.
  // Otherwise, we do not, but the ELF format doesn't keep that information
  // either for unversioned symbols, so we can put them in any library.
  std::map<std::string, std::vector<const gtirb::Symbol*>> undefinedSymbols;

  for (const gtirb::Module& module : ir.modules()) {
    const auto SymbolVersions = aux_data::getSymbolVersions(module);

    for (const auto& sym : module.symbols()) {
      if (!sym.getAddress() &&
          (!sym.hasReferent() ||
           sym.getReferent<gtirb::ProxyBlock>() != nullptr) &&
          !isBlackListed(sym.getName())) {

        if (SymbolVersions) {
          auto& [SymVerDefs, SymVersNeeded, SymVersionEntries] =
              *SymbolVersions;
          auto SymVerEntry = SymVersionEntries.find(sym.getUUID());
          if (SymVerEntry != SymVersionEntries.end()) {
            // This symbol is versioned. There should be an entry for it in
            // SymVersNeeded.
            std::string LibName;
            for (auto& [CurLibName, SymVerMap] : SymVersNeeded) {
              auto VersionReq =
                  SymVerMap.find(std::get<0>(SymVerEntry->second));
              if (VersionReq != SymVerMap.end()) {
                LibName = CurLibName;
              }
            }
            if (LibName.empty()) {
              LOG_ERROR << "ERROR: Undefined symbol \"" << sym.getName()
                        << "\" is versioned, but not in needed versions.";
              return false;
            }
            undefinedSymbols[LibName].push_back(&sym);
            continue;
          }
        }

        // fallthrough: we don't have symbol version info for this symbol.
        auto SymInfo = aux_data::getElfSymbolInfo(sym);
        if (!SymInfo) {
          // See if we have a symbol for "foo_copy", if so use its info
          std::string copyName = sym.getName() + "_copy";
          if (auto CopySymRange = module.findSymbols(copyName)) {
            if (CopySymRange.empty()) {
              return false;
            }
            SymInfo = aux_data::getElfSymbolInfo(*CopySymRange.begin());
          } else {
            LOG_WARNING << "Symbol not in symbol table [" << sym.getName()
                        << "] while preparing dummy SO\n";
            continue;
          }
        }

        // Ignore some types of symbols
        if (SymInfo->Type != "FILE") {
          // Just put unversioned symbols in the first library.
          // It doesn't matter where they go.
          undefinedSymbols[libs[0]].push_back(&sym);
        }
      }
    }
  }

  // Generate the .so files
  for (const auto& lib : libs) {
    if (!generateDummySO(ir, libDir, lib, undefinedSymbols[lib])) {
      std::cerr << "ERROR: Failed generating dummy .so for " << lib << "\n";
      return false;
    }
  }

  // Determine the args that need to be passed to the linker.
  // Note that we build with -nodefaultlibs, since with --dummy-so it is
  // assumed that the libs we would need are not present. This may futher
  // require the --keep-function-symbol argument paired with -c -nostartfiles
  // to preserve startup code.
  libArgs.push_back("-L" + libDir);
  libArgs.push_back("-nodefaultlibs");
  for (const auto& lib : libs) {
    libArgs.push_back("-l:" + lib);
  }
  for (const auto& rpath : LibraryPaths) {
    libArgs.push_back("-Wl,-rpath," + rpath);
  }

  return true;
}

void ElfBinaryPrinter::addOrigLibraryArgs(
    const gtirb::IR& ir, std::vector<std::string>& args) const {
  // collect all the library paths
  std::vector<std::string> allBinaryPaths = LibraryPaths;

  for (const gtirb::Module& module : ir.modules()) {

    auto BinaryLibraryPaths = aux_data::getLibraryPaths(module);
    allBinaryPaths.insert(allBinaryPaths.end(), BinaryLibraryPaths.begin(),
                          BinaryLibraryPaths.end());
  }

  // add needed libraries
  for (const gtirb::Module& module : ir.modules()) {
    for (const auto& Library : aux_data::getLibraries(module)) {
      // if they're a blacklisted name, skip them
      if (isBlackListedLib(Library)) {
        continue;
      }
      // if they match the lib*.so pattern we let the compiler look for them
      std::optional<std::string> InfixLibraryName =
          getInfixLibraryName(Library);
      if (InfixLibraryName) {
        args.push_back("-l" + *InfixLibraryName);
      } else {
        // otherwise we try to find them here
        if (std::optional<std::string> LibraryLocation =
                findLibrary(Library, allBinaryPaths)) {
          args.push_back(*LibraryLocation);
        } else {
          std::cerr << "ERROR: Could not find library " << Library << std::endl;
        }
      }
    }
  }

  // add user library paths
  for (const auto& libraryPath : LibraryPaths) {
    args.push_back("-L" + libraryPath);
  }
  // add binary library paths (add them to rpath as well)
  for (const gtirb::Module& module : ir.modules()) {
    for (const auto& LibraryPath : aux_data::getLibraryPaths(module)) {
      args.push_back("-L" + LibraryPath);
      args.push_back("-Wl,-rpath," + LibraryPath);
    }
  }
}

std::vector<std::string> ElfBinaryPrinter::buildCompilerArgs(
    std::string outputFilename, const std::vector<TempFile>& asmPaths,
    gtirb::IR& ir, const std::vector<std::string>& libArgs) const {
  std::vector<std::string> args;
  // Start constructing the compile arguments, of the form
  // -o <output_filename> fileAXADA.s
  args.emplace_back("-o");
  args.emplace_back(outputFilename);
  std::transform(asmPaths.begin(), asmPaths.end(), std::back_inserter(args),
                 [](const TempFile& TF) { return TF.fileName(); });
  args.insert(args.end(), ExtraCompileArgs.begin(), ExtraCompileArgs.end());
  args.insert(args.end(), libArgs.begin(), libArgs.end());

  // add pie, no pie, or shared, depending on the binary type
  if (Printer.getShared()) {
    args.push_back("-shared");
  } else {
    for (gtirb::Module& M : ir.modules()) {
      // if DYN, pie. if EXEC, no-pie. if both, pie overrides no-pie. If none,
      // do not specify either argument.
      bool Pie = false;
      bool NoPie = false;

      for (const auto& BinTypeStr : aux_data::getBinaryType(M)) {
        if (BinTypeStr == "DYN") {
          Pie = true;
          NoPie = false;
        } else if (BinTypeStr == "EXEC") {
          if (!Pie) {
            NoPie = true;
            Pie = false;
          }
        } else {
          assert(!"Unknown binary type!");
        }
      }

      if (Pie) {
        args.push_back("-pie");
      }
      if (NoPie) {
        args.push_back("-no-pie");
      }
      if (Pie || NoPie) {
        break;
      }
    }
  }
  // add -m32 for x86 binaries
  for (gtirb::Module& module : ir.modules()) {
    if (module.getISA() == gtirb::ISA::IA32) {
      args.push_back("-m32");
    }
  }
  // add arguments given by the printing policy
  for (gtirb::Module& Module : ir.modules()) {
    const auto& Policy = Printer.getPolicy(Module);
    args.insert(args.end(), Policy.compilerArguments.begin(),
                Policy.compilerArguments.end());
  }

  if (debug) {
    std::cout << "Compiler arguments: ";
    for (auto i : args)
      std::cout << i << ' ';
    std::cout << std::endl;
  }
  return args;
}

int ElfBinaryPrinter::assemble(const std::string& outputFilename,
                               gtirb::Context& ctx, gtirb::Module& mod) const {
  TempFile tempFile;
  if (!prepareSource(ctx, mod, tempFile)) {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  std::vector<std::string> args{{"-o", outputFilename, "-c"}};
  args.insert(args.end(), ExtraCompileArgs.begin(), ExtraCompileArgs.end());
  args.push_back(tempFile.fileName());

  if (std::optional<int> ret = execute(compiler, args)) {
    if (*ret)
      std::cerr << "ERROR: assembler returned: " << *ret << "\n";
    return *ret;
  }

  std::cerr << "ERROR: could not find the assembler '" << compiler
            << "' on the PATH.\n";
  return -1;
}

int ElfBinaryPrinter::link(const std::string& outputFilename,
                           gtirb::Context& ctx, gtirb::IR& ir) const {
  if (debug)
    std::cout << "Generating binary file" << std::endl;
  std::vector<TempFile> tempFiles;
  if (!prepareSources(ctx, ir, tempFiles)) {
    std::cerr << "ERROR: Could not write assembly into a temporary file.\n";
    return -1;
  }

  // Prep stuff for dynamic library dependences
  // Note that this temporary directory has to survive
  // longer than the call to the compiler.
  std::optional<TempDir> dummySoDir;
  std::vector<std::string> libArgs;
  if (useDummySO) {
    // Create the temporary directory for storing the synthetic libraries.
    dummySoDir.emplace();
    if (!dummySoDir->created()) {
      std::cerr
          << "ERROR: Failed to create temp dir for synthetic .so files. Errno: "
          << dummySoDir->errno_code() << "\n";
      return -1;
    }

    if (!prepareDummySOLibs(ir, dummySoDir->dirName(), libArgs)) {
      std::cerr << "ERROR: Could not create dummy so files for linking.\n";
      return -1;
    }
    // add rpaths from original binary(ies)
    for (const gtirb::Module& module : ir.modules()) {
      if (const auto* binaryLibraryPaths =
              module.getAuxData<gtirb::schema::LibraryPaths>()) {
        for (const auto& libraryPath : *binaryLibraryPaths) {
          libArgs.push_back("-Wl,-rpath," + libraryPath);
        }
      }
    }
  } else {
    // If we're not using synthetic libraries, we just need to pass
    // along the appropriate arguments.

    addOrigLibraryArgs(ir, libArgs);
  }

  TempFile VersionScript(".map");
  if (aux_data::hasVersionedSymDefs(ir) && !Printer.getIgnoreSymbolVersions()) {
    // A version script is only needed if we define versioned symbols.
    if (gtirb_pprint::printVersionScript(ir, VersionScript)) {
      libArgs.push_back("-Wl,--version-script=" + VersionScript.fileName());
    }
  }
  VersionScript.close();

  if (std::optional<int> ret =
          execute(compiler,
                  buildCompilerArgs(outputFilename, tempFiles, ir, libArgs))) {
    if (*ret)
      std::cerr << "ERROR: assembler returned: " << *ret << "\n";
    return *ret;
  }

  std::cerr << "ERROR: could not find the assembler '" << compiler
            << "' on the PATH.\n";
  return -1;
}

} // namespace gtirb_bprint

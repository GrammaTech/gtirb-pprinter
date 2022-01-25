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
#include "driver/Logger.h"
#include "file_utils.hpp"
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

static std::unordered_set<std::string> BlacklistedLibraries{{
    "ld-linux-x86-64.so.2",
}};

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
    const std::string& libDir, const std::string& lib,
    std::vector<const gtirb::Symbol*>::const_iterator begin,
    std::vector<const gtirb::Symbol*>::const_iterator end) const {

  // Assume that lib is a filename w/ no path prefix
  assert(!boost::filesystem::path(lib).has_parent_path());
  std::string asmFileName = lib + ".s";
  auto asmFilePath = boost::filesystem::path(libDir) / asmFileName;
  auto libPath = boost::filesystem::path(libDir) / lib;

  {
    std::ofstream asmFile(asmFilePath.string());
    asmFile << "# Generated dummy file for .so undefined symbols\n";

    for (auto curr = begin; curr != end; ++curr) {
      const gtirb::Symbol* sym = *curr;
      const auto* SymbolInfoTable =
          sym->getModule()->getAuxData<gtirb::schema::ElfSymbolInfo>();
      if (!SymbolInfoTable) {
        return false;
      }

      std::string name = sym->getName();

      auto SymInfoIt = SymbolInfoTable->find(sym->getUUID());
      bool has_copy = false;
      if (SymInfoIt == SymbolInfoTable->end()) {
        // See if we have a symbol for "foo_copy", if so use its info
        std::string copyName = sym->getName() + "_copy";
        if (auto copySymRange = sym->getModule()->findSymbols(copyName);
            !copySymRange.empty()) {
          has_copy = true;
          SymInfoIt = SymbolInfoTable->find(copySymRange.begin()->getUUID());
        } else {
          LOG_WARNING << "Symbol not in symbol table [" << sym->getName()
                      << "] while generating dummy SO\n";
          assert(false); // Should've been filtered out in prepareDummySOLibs.
          return false;  // Or continue?
        }
      }
      auto SymInfo = SymInfoIt->second;
      uint64_t SymSize = std::get<0>(SymInfo);
      std::string SymType = std::get<1>(SymInfo);

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
    if (const auto* libraries = module.getAuxData<gtirb::schema::Libraries>()) {
      for (const auto& library : *libraries) {
        // Skip blacklisted libs
        if (BlacklistedLibraries.count(library)) {
          continue;
        }

        // TODO: skip any explicit library that isn't just
        // a filename. Do these actually occur?
        if (boost::filesystem::path(library).has_parent_path()) {
          std::cerr << "ERROR: Skipping explicit lib w/ parent directory: "
                    << library << "\n";
          continue;
        }
        libs.push_back(library);
      }
    }
  }
  if (libs.empty()) {
    std::cerr << "Note: no dynamic libraries present.\n";
    return false;
  }

  // Now we need to assign imported symbols to all the libs.
  // We don't have a map for which libs they belong to. But this
  // shouldn't matter, as the ELF format doesn't retain such a
  // mapping either (from what we can tell).
  // So assign k symbols to each of the k libs we need, and
  // dump the rest into the first lib.
  // TODO: The pretty printer has some rules about skipping
  // certain undefined symbols. Do we need similar rules here?
  std::vector<const gtirb::Symbol*> undefinedSymbols;
  for (const gtirb::Module& module : ir.modules()) {
    const auto* SymbolInfoTable =
        module.getAuxData<gtirb::schema::ElfSymbolInfo>();
    if (!SymbolInfoTable) {
      std::cerr << "ERROR: No symbol info for module: " << module.getName()
                << "\n";
      return false;
    }

    for (const auto& sym : module.symbols()) {
      if (!sym.getAddress() &&
          (!sym.hasReferent() ||
           sym.getReferent<gtirb::ProxyBlock>() != nullptr) &&
          !isBlackListed(sym.getName())) {

        auto SymInfoIt = SymbolInfoTable->find(sym.getUUID());
        if (SymInfoIt == SymbolInfoTable->end()) {
          // See if we have a symbol for "foo_copy", if so use its info
          std::string copyName = sym.getName() + "_copy";
          if (auto copySymRange = module.findSymbols(copyName);
              !copySymRange.empty()) {
            SymInfoIt = SymbolInfoTable->find(copySymRange.begin()->getUUID());
          } else {
            LOG_WARNING << "Symbol not in symbol table [" << sym.getName()
                        << "] while preparing dummy SO\n";
            continue;
          }
        }
        auto SymInfo = SymInfoIt->second;

        // Ignore some types of symbols
        if (std::get<1>(SymInfo) != "FILE") {
          undefinedSymbols.push_back(&sym);
        }
      }
    }
  }

  if (undefinedSymbols.size() < libs.size()) {
    std::cerr << "ERROR: More dynamic libs than undefined symbols!\n";
    return false;
  }

  size_t numFirstFile = 1 + undefinedSymbols.size() - libs.size();

  // Generate the .so files
  auto curr = undefinedSymbols.begin();
  auto next = curr + numFirstFile;
  for (const auto& lib : libs) {
    assert(curr != undefinedSymbols.end());
    if (!generateDummySO(libDir, lib, curr, next)) {
      std::cerr << "ERROR: Failed generating dummy .so for " << lib << "\n";
      return false;
    }
    curr = next;
    if (next != undefinedSymbols.end()) {
      ++next;
    }
  }
  assert(curr == undefinedSymbols.end());

  // Determine the args that need to be passed to the linker.
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

    if (const auto* binaryLibraryPaths =
            module.getAuxData<gtirb::schema::LibraryPaths>())
      allBinaryPaths.insert(allBinaryPaths.end(), binaryLibraryPaths->begin(),
                            binaryLibraryPaths->end());
  }

  // add needed libraries
  for (const gtirb::Module& module : ir.modules()) {
    if (const auto* libraries = module.getAuxData<gtirb::schema::Libraries>()) {
      for (const auto& library : *libraries) {
        // if they're a blacklisted name, skip them
        if (BlacklistedLibraries.count(library)) {
          continue;
        }
        // if they match the lib*.so pattern we let the compiler look for them
        std::optional<std::string> infixLibraryName =
            getInfixLibraryName(library);
        if (infixLibraryName) {
          args.push_back("-l" + *infixLibraryName);
        } else {
          // otherwise we try to find them here
          if (std::optional<std::string> libraryLocation =
                  findLibrary(library, allBinaryPaths)) {
            args.push_back(*libraryLocation);
          } else {
            std::cerr << "ERROR: Could not find library " << library
                      << std::endl;
          }
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
    if (const auto* binaryLibraryPaths =
            module.getAuxData<gtirb::schema::LibraryPaths>()) {
      for (const auto& libraryPath : *binaryLibraryPaths) {
        args.push_back("-L" + libraryPath);
        args.push_back("-Wl,-rpath," + libraryPath);
      }
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
      if (const auto* BinType = M.getAuxData<gtirb::schema::BinaryType>()) {
        // if DYN, pie. if EXEC, no-pie. if both, pie overrides no-pie. If none,
        // do not specify either argument.

        bool pie = false;
        bool noPie = false;

        for (const auto& BinTypeStr : *BinType) {
          if (BinTypeStr == "DYN") {
            pie = true;
            noPie = false;
          } else if (BinTypeStr == "EXEC") {
            if (!pie) {
              noPie = true;
              pie = false;
            }
          } else {
            assert(!"Unknown binary type!");
          }
        }

        if (pie) {
          args.push_back("-pie");
        }
        if (noPie) {
          args.push_back("-no-pie");
        }

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

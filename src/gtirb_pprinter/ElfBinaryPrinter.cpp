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

bool ElfBinaryPrinter::generateDummySO(
    const std::string& lib,
    std::vector<const gtirb::Symbol*>::const_iterator begin,
    std::vector<const gtirb::Symbol*>::const_iterator end) const {

  std::string asmFileName = boost::filesystem::basename(lib) + ".s";
  {
    std::ofstream asmFile(asmFileName);
    asmFile << "# Generated dummy file for .so undefined symbols\n";
    asmFile << ".text\n";
    for (auto curr = begin; curr != end; ++curr) {
      const gtirb::Symbol* sym = *curr;
      const auto* SymbolInfoTable =
          sym->getModule()->getAuxData<gtirb::schema::ElfSymbolInfo>();
      if (!SymbolInfoTable) {
        return false;
      }

      std::string name = sym->getName();

      auto SymInfoIt = SymbolInfoTable->find(sym->getUUID());
      if (SymInfoIt == SymbolInfoTable->end()) {
        return false;
      }
      auto SymbolInfo = SymInfoIt->second;

      // TODO: Make use of syntax content in ElfPrettyPrinter?

      // Note: we want to generate a global, regardless of
      // what the symbol's type is in the IR.
      asmFile << ".globl " << name << "\n";

      static const std::unordered_map<std::string, std::string>
          TypeNameConversion = {
              {"FUNC", "function"},  {"OBJECT", "object"},
              {"NOTYPE", "notype"},  {"NONE", "notype"},
              {"TLS", "tls_object"}, {"GNU_IFUNC", "gnu_indirect_function"},
          };
      auto TypeNameIt = TypeNameConversion.find(std::get<1>(SymbolInfo));
      if (TypeNameIt == TypeNameConversion.end()) {
        std::cerr << "Unknown type: " << std::get<1>(SymbolInfo)
                  << " for symbol: " << name << "\n";
        assert(!"unknown type in elfSymbolInfo!");
      } else {
        const auto& TypeName = TypeNameIt->second;
        asmFile << ".type " << name << ", @" << TypeName << "\n";
      }

      asmFile << name << ":\n";
      asmFile << "            .byte 0x0\n";
    }
  }

  std::vector<std::string> args;
  args.push_back("-o");
  args.push_back(lib);
  args.push_back("-shared");
  args.push_back("-fPIC");
  args.push_back(asmFileName);

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
std::optional<std::vector<std::string>>
ElfBinaryPrinter::prepareDummySOLibs(const gtirb::IR& ir) const {
  // Collect all libs we need to handle
  std::vector<std::string> dashLLibs;
  std::vector<std::string> explicitLibs;
  for (const gtirb::Module& module : ir.modules()) {
    if (const auto* libraries = module.getAuxData<gtirb::schema::Libraries>()) {
      for (const auto& library : *libraries) {
        // Skip blacklisted libs
        if (BlacklistedLibraries.count(library)) {
          continue;
        }

        std::optional<std::string> infixLibraryName =
            getInfixLibraryName(library);
        if (infixLibraryName) {
          dashLLibs.push_back(library);
        } else {
          // TODO: skip any explicit library that isn't just
          // a filename.
          if (boost::filesystem::path(library).has_parent_path()) {
            std::cerr << "ERROR: Skipping explicit lib w/ parent directory: "
                      << library << "\n";
            continue;
          }
          explicitLibs.push_back(library);
        }
      }
    }
  }
  if (dashLLibs.size() == 0 && explicitLibs.size() == 0) {
    std::cerr << "Note: no dynamic libraries present.\n";
    return std::nullopt;
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
      return std::nullopt;
    }

    for (const auto& sym : module.symbols()) {
      if (!sym.getAddress() &&
          (!sym.hasReferent() ||
           sym.getReferent<gtirb::ProxyBlock>() != nullptr) &&
          sym.getName() != "") {

        auto SymInfoIt = SymbolInfoTable->find(sym.getUUID());

        // Ignore special symbols that don't have SymbolInfo
        // TODO: Is this always correct?
        if (SymInfoIt == SymbolInfoTable->end()) {
          continue;
        }
        auto SymbolInfo = SymInfoIt->second;

        // Ignore some types of symbols
        if (std::get<1>(SymbolInfo) != "FILE") {
          undefinedSymbols.push_back(&sym);
        }
      }
    }
  }

  if (undefinedSymbols.size() < dashLLibs.size() + explicitLibs.size()) {
    std::cerr << "ERROR: More dynamic libs than undefined symbols!\n";
    return std::nullopt;
  }

  size_t numFirstFile =
      1 + undefinedSymbols.size() - dashLLibs.size() - explicitLibs.size();
  std::string firstLib = dashLLibs.size() > 0 ? dashLLibs[0] : explicitLibs[0];

  // Generate the .so files
  if (!generateDummySO(firstLib, undefinedSymbols.begin(),
                       undefinedSymbols.begin() + numFirstFile)) {
    std::cerr << "ERROR: Failed generating dummy .so for " << firstLib << "\n";
    return std::nullopt;
  }
  auto nextSymbol = undefinedSymbols.begin() + numFirstFile;
  for (const auto& lib : dashLLibs) {
    if (lib != firstLib) {
      if (!generateDummySO(lib, nextSymbol, nextSymbol + 1)) {
        std::cerr << "ERROR: Failed generating dummy .so for " << lib << "\n";
      }
      ++nextSymbol;
    }
  }
  for (const auto& lib : explicitLibs) {
    if (lib != firstLib) {
      if (!generateDummySO(lib, nextSymbol, nextSymbol + 1)) {
        std::cerr << "ERROR: Failed generating dummy .so for " << lib << "\n";
      }
      ++nextSymbol;
    }
  }

  // Determine the args that need to be passed to the linker.
  std::vector<std::string> args;
  args.push_back("-L.");
  for (const auto& lib : dashLLibs) {
    args.push_back("-l" + *getInfixLibraryName(lib));
  }
  for (const auto& lib : explicitLibs) {
    args.push_back(lib);
  }
  for (const auto& rpath : LibraryPaths) {
    args.push_back("-Wl,-rpath," + rpath);
  }

  return args;
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
    gtirb::IR& ir, const std::vector<std::string>& dummySoArgs) const {
  std::vector<std::string> args;
  // Start constructing the compile arguments, of the form
  // -o <output_filename> fileAXADA.s
  args.emplace_back("-o");
  args.emplace_back(outputFilename);
  std::transform(asmPaths.begin(), asmPaths.end(), std::back_inserter(args),
                 [](const TempFile& TF) { return TF.fileName(); });
  args.insert(args.end(), ExtraCompileArgs.begin(), ExtraCompileArgs.end());

  if (this->useDummySO) {
    args.insert(args.end(), dummySoArgs.begin(), dummySoArgs.end());
  } else {
    addOrigLibraryArgs(ir, args);
  }

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

  std::vector<std::string> dummySoArgs;
  if (useDummySO) {
    if (auto maybeArgs = prepareDummySOLibs(ir)) {
      dummySoArgs = std::move(*maybeArgs);
    } else {
      std::cerr << "ERROR: Could not create dummy so files for linking.\n";
      return -1;
    }
  }

  if (std::optional<int> ret =
          execute(compiler, buildCompilerArgs(outputFilename, tempFiles, ir,
                                              dummySoArgs))) {
    if (*ret)
      std::cerr << "ERROR: assembler returned: " << *ret << "\n";
    return *ret;
  }

  std::cerr << "ERROR: could not find the assembler '" << compiler
            << "' on the PATH.\n";
  return -1;
}

} // namespace gtirb_bprint

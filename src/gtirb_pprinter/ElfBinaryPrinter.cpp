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

#include "Arm64PrettyPrinter.hpp"
#include "ArmPrettyPrinter.hpp"
#include "AuxDataSchema.hpp"
#include "AuxDataUtils.hpp"
#include "ElfPrettyPrinter.hpp"
#include "ElfVersionScriptPrinter.hpp"
#include "FileUtils.hpp"
#include "Mips32PrettyPrinter.hpp"
#include "driver/Logger.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

namespace gtirb_bprint {

/**
Add build arguments to support additional architectures
*/
static void addArchBuildArgs(const gtirb::Module& Module,
                             std::vector<std::string>& Args) {
  // add -m32 for x86 binaries
  if (Module.getISA() == gtirb::ISA::IA32) {
    Args.push_back("-m32");
  }
}

bool ElfBinaryPrinter::isInfixLibraryName(const std::string& library) const {
  std::regex libsoRegex("^lib(.*)\\.so.*");
  std::smatch m;
  return std::regex_match(library, m, libsoRegex);
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

bool isLd(std::string Library) {
  std::string Prefix = "ld-linux";
  return (Library.substr(0, Prefix.length()) == Prefix);
}

// These are symbols that otherwise pass our screen for undefined
// symbols but don't appear to need external linkage when rebuilding
// the binary. Some, for example __rela_iplt_start, are introduced
// by ddisasm.
bool isBlackListed(std::string sym) {
  static std::vector<std::string> blackList = {"",
                                               "_GLOBAL_OFFSET_TABLE_",
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

/**
Get an appropriate syntax for an architecture
*/
static std::unique_ptr<gtirb_pprint::ElfSyntax>
getISASyntax(const gtirb::ISA ISA) {
  switch (ISA) {
  case gtirb::ISA::ARM64:
    return std::make_unique<gtirb_pprint::Arm64Syntax>();
  case gtirb::ISA::ARM:
    return std::make_unique<gtirb_pprint::ArmSyntax>();
  case gtirb::ISA::MIPS32:
    return std::make_unique<gtirb_pprint::Mips32Syntax>();
  case gtirb::ISA::X64:
  case gtirb::ISA::IA32:
  default:
    return std::make_unique<gtirb_pprint::ElfSyntax>();
  }
}

bool ElfBinaryPrinter::generateDummySO(
    const gtirb::Module& Module, const std::string& LibDir,
    const std::string& Lib, const std::vector<SymbolGroup>& SymGroups) const {

  // Assume that lib is a filename w/ no path prefix
  assert(!boost::filesystem::path(Lib).has_parent_path());
  std::string AsmFileName = Lib + ".s";
  auto AsmFilePath = boost::filesystem::path(LibDir) / AsmFileName;
  auto LibPath = boost::filesystem::path(LibDir) / Lib;
  bool EmittedSymvers = false;

  {
    std::ofstream AsmFile(AsmFilePath.string());
    AsmFile << "# Generated dummy file for .so undefined symbols\n";

    std::unique_ptr<gtirb_pprint::ElfSyntax> Syntax =
        getISASyntax(Module.getISA());

    std::map<std::string, int> VersionedSymNameCounts;
    for (auto& SymGroup : SymGroups) {
      std::optional<uint64_t> SymSize;

      for (auto Sym : SymGroup) {
        std::string Name = Sym->getName();

        auto SymInfo = aux_data::getElfSymbolInfo(*Sym);
        if (!SymInfo) {
          // See if we have a symbol for "foo_copy", if so use its info
          // TODO: We should not rely on symbol names semanitcally here.
          // When ddisasm makes the ElfSymbolInfo available on both the copy
          // and original symbol, this check should not be necessary.
          std::string CopyName = Sym->getName() + "_copy";
          if (auto CopySymRange = Sym->getModule()->findSymbols(CopyName)) {
            SymInfo = aux_data::getElfSymbolInfo(*(CopySymRange.begin()));
          } else {
            LOG_ERROR << "Symbol not in symbol table [" << Sym->getName()
                      << "] while generating dummy SO\n";
            return false;
          }
        }

        if (!SymSize) {
          SymSize = SymInfo->Size;
        } else if (*SymSize != SymInfo->Size) {
          LOG_ERROR << "Symbol group has mismatched sizes; " << Name << " is "
                    << SymInfo->Size << " bytes, but had " << *SymSize
                    << " bytes\n";
          return false;
        }

        std::string SymType = SymInfo->Type;
        if (SymType == "FUNC" || SymType == "GNU_IFUNC") {
          AsmFile << Syntax->text() << "\n";
        } else if (SymType == "TLS") {
          AsmFile << ".section .tdata, \"waT\"\n";
        } else {
          AsmFile << Syntax->data() << "\n";
        }

        if (!Printer.getIgnoreSymbolVersions()) {
          auto Version = aux_data::getSymbolVersionString(*Sym);
          if (Version) {
            // There may be multiple versioned symbols of the same name.
            // Generate unique names for them to prevent linking errors.
            std::string OriginalName = Name;
            auto It = VersionedSymNameCounts.find(Name);
            if (It == VersionedSymNameCounts.end()) {
              VersionedSymNameCounts[Name] = 1;
            } else {
              std::stringstream UniqueNameBuilder;
              UniqueNameBuilder << Name << "_disambig_" << ++It->second;
              Name = UniqueNameBuilder.str();
            }

            AsmFile << Syntax->symVer() << " " << Name << "," << OriginalName
                    << *Version << '\n';
            EmittedSymvers = true;
          }
        }

        std::string Binding;
        if (SymInfo->Binding == "WEAK") {
          Binding = Syntax->weak();
        } else {
          Binding = Syntax->global();
        }

        AsmFile << Binding << " " << Name << "\n";

        if ((SymType == "OBJECT" || SymType == "TLS") && SymInfo->Size != 0) {
          AsmFile << Syntax->symSize() << " " << Name << ", " << SymInfo->Size
                  << "\n";
        }

        static const std::unordered_map<std::string, std::string>
            TypeNameConversion = {
                {"FUNC", "function"},  {"OBJECT", "object"},
                {"NOTYPE", "notype"},  {"NONE", "notype"},
                {"TLS", "tls_object"}, {"GNU_IFUNC", "gnu_indirect_function"},
            };
        auto TypeNameIt = TypeNameConversion.find(SymType);
        if (TypeNameIt == TypeNameConversion.end()) {
          LOG_ERROR << "Unknown type: " << SymType
                    << " for symbol: " << Sym->getName() << "\n";
          return false;
        } else {
          const auto& TypeName = TypeNameIt->second;
          AsmFile << Syntax->type() << ' ' << Name << ", "
                  << Syntax->attributePrefix() << TypeName << "\n";
        }

        AsmFile << Name << ":\n";
      }

      // only emit one .skip directive for each symbol group, as symbol groups
      // represent symbols that refer to the same data.
      uint64_t Space = *SymSize;
      if (Space == 0) {
        Space = 4;
      }
      AsmFile << ".skip " << Space << "\n";
    }
  }

  std::vector<std::string> Args;
  Args.push_back("-o");
  Args.push_back(LibPath.string());
  Args.push_back("-shared");
  Args.push_back("-fPIC");
  Args.push_back("-nostartfiles");
  Args.push_back("-nodefaultlibs");
  Args.push_back(AsmFilePath.string());
  addArchBuildArgs(Module, Args);

  TempFile VersionScript(".map");
  if (EmittedSymvers) {
    if (!Printer.getIgnoreSymbolVersions()) {
      // A version script is only needed if we define versioned symbols.
      if (gtirb_pprint::printVersionScriptForDummySo(Module, VersionScript)) {
        Args.push_back("-Wl,--version-script=" + VersionScript.fileName());
      }
    }
  }
  VersionScript.close();

  if (std::optional<int> Ret = execute(compiler, Args)) {
    if (*Ret) {
      std::cerr << "ERROR: Compiler returned " << *Ret
                << " for dummy .so: " << Lib << "\n";
      return false;
    }

    return true;
  }

  std::cerr << "ERROR: Failed to run compiler for dummy .so: " << Lib << "\n";
  return false;
}

/**
Determines whether symbols from a symbol-forwarding entry represent a copy
relocation.
*/
static bool isCopyRelocation(const gtirb::Symbol* From,
                             const gtirb::Symbol* To) {
  if (!From->getAddress() || !To->hasReferent() ||
      !To->getReferent<gtirb::ProxyBlock>()) {
    return false;
  }

  auto SymInfo = aux_data::getElfSymbolInfo(*From);
  return SymInfo && SymInfo->Type == "OBJECT";
}

/**
Get a copy relocation's symbols given a symbol forwarding entry.

Returns std::nullopt if the given symbol forwarding entry is invalid or is not
a copy relocation.
*/
static std::optional<std::pair<const gtirb::Symbol*, const gtirb::Symbol*>>
getCopyRelocationSyms(const gtirb::Context& Context,
                      const std::pair<gtirb::UUID, gtirb::UUID>& Forward) {
  const gtirb::Symbol* From =
      gtirb_pprint::getByUUID<gtirb::Symbol>(Context, Forward.first);
  const gtirb::Symbol* To =
      gtirb_pprint::getByUUID<gtirb::Symbol>(Context, Forward.second);
  if (!From || !To || !isCopyRelocation(From, To)) {
    return std::nullopt;
  }
  return std::make_pair(From, To);
}

/**
 * Group symbols together if they must be printed in the dummy library as
 * referring to the same address. Currently, this is only known to be
 * necessary for COPY-relocated symbols.
 */
static std::vector<SymbolGroup>
buildDummySOSymbolGroups(const gtirb::Context& Context,
                         const gtirb::Module& Module) {
  std::vector<SymbolGroup> SymbolGroups;

  // This set allows efficient lookup of which symbols were added to groups.
  std::set<const gtirb::Symbol*> GroupedSymbols;

  // Build symbol groups for COPY-relocated symbols.
  // Collect copy-relocated symbols into groups by address
  std::map<gtirb::Addr, SymbolGroup> CopySymbolsByAddr;
  const auto& Forwarding = aux_data::getSymbolForwarding(Module);
  for (const auto& Forward : Forwarding) {
    if (auto OptPair = getCopyRelocationSyms(Context, Forward)) {
      auto& [From, To] = *OptPair;
      if (!isBlackListed(To->getName())) {
        CopySymbolsByAddr[*From->getAddress()].push_back(To);
      }
    }
  }

  // Keep finalized symbol groups in SymbolGroups, and record which symbols
  // have been grouped in GroupedSymbols (for faster lookup)
  for (auto It : CopySymbolsByAddr) {
    SymbolGroups.push_back(It.second);
    GroupedSymbols.insert(It.second.begin(), It.second.end());
  }

  // All other imported symbols belong in a group each by themselves.
  for (const auto& Sym : Module.symbols()) {
    if (!isBlackListed(Sym.getName())) {
      if (GroupedSymbols.find(&Sym) == GroupedSymbols.end()) {
        if (Sym.getAddress()) {
          // There are cases where a symbol is attached to an address in .plt.
          auto Section = gtirb_pprint::IsExternalPLTSym(Sym);
          if (Section) {
            SymbolGroups.push_back({&Sym});
          }
        } else if (!Sym.hasReferent() || Sym.getReferent<gtirb::ProxyBlock>()) {
          SymbolGroups.push_back({&Sym});
        }
      }
    }
  }

  return SymbolGroups;
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
    const gtirb::Context& Context, const gtirb::Module& Module,
    const std::string& LibDir, std::vector<std::string>& LibArgs) const {
  // Collect all libs we need to handle
  std::vector<std::string> Libs;
  for (const auto& Library : aux_data::getLibraries(Module)) {
    // TODO: skip any explicit library that isn't just
    // a filename. Do these actually occur?
    if (boost::filesystem::path(Library).has_parent_path()) {
      std::cerr << "ERROR: Skipping explicit lib w/ parent directory: "
                << Library << "\n";
      continue;
    }
    Libs.push_back(Library);
  }

  // Build with -nodefaultlibs to ensure we only link the generated dummy-so
  // libraries.
  LibArgs.push_back("-nodefaultlibs");
  for (const auto& RPath : LibraryPaths) {
    LibArgs.push_back("-Wl,-rpath," + RPath);
  }

  if (Libs.empty()) {
    return true;
  }
  // Get groups of symbols which must be printed together.
  std::vector<SymbolGroup> SymbolGroups =
      buildDummySOSymbolGroups(Context, Module);

  // Now we need to assign imported symbol groups to all the libs.
  // For any group that contains a versioned symbol, we have a mapping of which
  // library they belong to.
  // Otherwise, we do not, but the ELF format doesn't keep that information
  // either for unversioned symbols, so we put them in the first lib.
  std::map<std::string, std::vector<SymbolGroup>> AllocatedSymbols;
  const std::string& FirstLib = *Libs.begin();

  for (SymbolGroup& SymGroup : SymbolGroups) {
    std::optional<std::string> LibNameOpt = std::nullopt;
    for (const gtirb::Symbol* Sym : SymGroup) {
      auto VersionInfo = aux_data::getSymbolVersionInfo(*Sym);
      std::optional<std::string> CurLibName = std::visit(
          [Sym](auto& Arg) -> std::optional<std::string> {
            using T = std::decay_t<decltype(Arg)>;
            if constexpr (std::is_same_v<T, aux_data::ExternalSymbolVersion>) {
              return Arg.Library;
            } else if constexpr (std::is_same_v<
                                     T, aux_data::InternalSymbolVersion>) {
              // The symbol aux data doesn't seem correct here; we'll treat this
              // symbol as unversioned as a best effort, but emit a warning.
              LOG_WARNING
                  << "The symbol " << Sym->getName() << " appears to be "
                  << "external, but elfSymbolVersionInfo indicates it is "
                  << "internal\n";
              return std::nullopt;
            } else if constexpr (std::is_same_v<
                                     T, aux_data::UndefinedSymbolVersion>) {
              LOG_WARNING << "The symbol " << Sym->getName()
                          << " is versioned, "
                          << "but was not found in needed symbol versions\n";
              return std::nullopt;
            } else {
              // Symbol is unversioned.
              static_assert(
                  std::is_same_v<T, aux_data::NoSymbolVersionAuxData> ||
                      std::is_same_v<T, aux_data::NoSymbolVersion>,
                  "Unhandled return variant from getSymbolVersionInfo");
              return std::nullopt;
            }
          },
          VersionInfo);
      if (CurLibName && LibNameOpt && *CurLibName != *LibNameOpt) {
        // Symbol group disagrees on source library
        LOG_ERROR << "Symbol group containing " << Sym->getName()
                  << " cannot resolve source library conflict: " << *CurLibName
                  << " != " << *LibNameOpt << "\n";
        return false;
      } else if (CurLibName && !LibNameOpt) {
        LibNameOpt = CurLibName;
      }
    }
    if (LibNameOpt) {
      // We determined the source library from the symbol version information.
      std::string LibName = *LibNameOpt;
      AllocatedSymbols[LibName].push_back(SymGroup);
      continue;
    }

    // fallthrough: we don't have any symbol version info for this symbol group.

    if (SymGroup.size() == 1) {
      auto SymInfo = aux_data::getElfSymbolInfo(**SymGroup.begin());
      if (SymInfo && SymInfo->Type == "FILE") {
        // Ignore some types of symbols
        // We only check this for ungrouped symbols, as COPY-relocated symbols
        // are already known to be non-FILE type (they are differentiated by
        // having OBJECT-type SymInfo and in the SymbolForwarding table)
        continue;
      }
    }

    // Just put unversioned symbol groups in the first lib.
    AllocatedSymbols[FirstLib].push_back(SymGroup);
  }

  LibArgs.push_back("-L" + LibDir);

  // Generate the .so files
  for (const auto& Lib : Libs) {
    if (!generateDummySO(Module, LibDir, Lib, AllocatedSymbols[Lib])) {
      LOG_ERROR << "Failed generating dummy .so for " << Lib << "\n";
      return false;
    }

    LibArgs.push_back("-l:" + Lib);
  }

  return true;
}

void ElfBinaryPrinter::addOrigLibraryArgs(const gtirb::Module& module,
                                          std::vector<std::string>& args,
                                          const std::string& Location) const {
  // collect all the library paths
  std::vector<std::string> allBinaryPaths = LibraryPaths;

  auto BinaryLibraryPaths = aux_data::getLibraryPaths(module);
  allBinaryPaths.insert(allBinaryPaths.end(), BinaryLibraryPaths.begin(),
                        BinaryLibraryPaths.end());

  const auto& Policy = Printer.getPolicy(module);
  // add needed libraries
  for (const auto& Library : aux_data::getLibraries(module)) {
    // if they're a blacklisted name, skip them, unless -nodefaultlibs is passed
    if (isLd(Library)) {
      if (Policy.compilerArguments.count("-nodefaultlibs") == 0) {
        continue;
      } else {
        // ld does not match isInfixLibraryName, but we let the compiler find
        // it.
        args.push_back("-l:" + Library);
      }
    }
    // if they match the lib*.so.* pattern we let the compiler look for them
    else if (isInfixLibraryName(Library)) {
      args.push_back("-l:" + Library);
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

  // add user library paths
  for (const auto& libraryPath : LibraryPaths) {
    args.push_back("-L" + libraryPath);
  }
  std::string L = (Location == "" ? "." : Location);
  // add binary library paths (add them to rpath as well)
  std::regex OriginRegex{R"((\$ORIGIN\b)|($\{ORIGIN\}))"};
  for (const auto& LibraryPath : aux_data::getLibraryPaths(module)) {
    std::string LinkPath = std::regex_replace(LibraryPath, OriginRegex, L);
    args.push_back("-L" + LinkPath);
    args.push_back("-Wl,-rpath," + LibraryPath);
  }
}

static bool allGlobalVisibleSymsExported(gtirb::Context& Ctx,
                                         gtirb::Module& Module) {
  auto SymbolTabIdxInfo = aux_data::getElfSymbolTabIdxInfo(Module);
  for (auto& [SymUUID, Tables] : SymbolTabIdxInfo) {
    auto Symbol = gtirb_pprint::nodeFromUUID<gtirb::Symbol>(Ctx, SymUUID);
    if (!Symbol) {
      continue;
    }

    auto SymbolInfo = aux_data::getElfSymbolInfo(*Symbol);
    if (SymbolInfo->Binding != "GLOBAL") {
      continue;
    }
    if (SymbolInfo->Visibility == "HIDDEN") {
      continue;
    }

    if (Symbol->getReferent<gtirb::CodeBlock>() != nullptr) {
      bool SymIsExported = false;
      for (auto& [TableName, Idx] : Tables) {
        if (TableName == ".dynsym") {
          SymIsExported = true;
          break;
        }
      }

      if (!SymIsExported) {
        return false;
      }
    }
  }
  return true;
}

std::vector<std::string> ElfBinaryPrinter::buildCompilerArgs(
    std::string outputFilename, const std::vector<TempFile>& asmPaths,
    gtirb::Context& context, gtirb::Module& module,
    const std::vector<std::string>& libArgs) const {
  std::vector<std::string> args;
  // Start constructing the compile arguments, of the form
  // -o <output_filename> fileAXADA.s
  args.emplace_back("-o");
  args.emplace_back(outputFilename);
  std::transform(asmPaths.begin(), asmPaths.end(), std::back_inserter(args),
                 [](const TempFile& TF) { return TF.fileName(); });
  args.emplace_back("-Wl,--no-as-needed");
  args.insert(args.end(), ExtraCompileArgs.begin(), ExtraCompileArgs.end());
  args.insert(args.end(), libArgs.begin(), libArgs.end());

  // add pie, no pie, or shared, depending on the binary type
  gtirb_pprint::DynMode DM = Printer.getDynMode(module);
  switch (DM) {
  case gtirb_pprint::DYN_MODE_SHARED:
    args.push_back("-shared");
    break;
  case gtirb_pprint::DYN_MODE_PIE:
    args.push_back("-pie");
    break;
  case gtirb_pprint::DYN_MODE_NONE:
    args.push_back("-no-pie");
    break;
  default:
    assert(!"Unknown binary type!");
  }

  if (DM != gtirb_pprint::DYN_MODE_SHARED) {
    // append -Wl,--export-dynamic if needed; can occur for both DYN and EXEC.
    // TODO: if some symbols are exported, but not all, build a dynamic list
    // file and pass with `--dynamic-list`.
    if (allGlobalVisibleSymsExported(context, module)) {
      args.push_back("-Wl,--export-dynamic");
    }
  }

  addArchBuildArgs(module, args);

  // Add soname linker flag if applicable
  if (auto Soname = module.getAuxData<gtirb::schema::ElfSoname>()) {
    args.push_back("-Wl,-soname=" + *Soname);
  }

  // Add stack properties linker flags
  if (auto StackSize = module.getAuxData<gtirb::schema::ElfStackSize>()) {
    args.push_back("-Wl,-z,stack-size=" + std::to_string(*StackSize));
  }

  if (auto StackExec = module.getAuxData<gtirb::schema::ElfStackExec>()) {
    args.push_back(*StackExec ? "-Wl,-z,execstack" : "-Wl,-z,noexecstack");
  }

  // add arguments given by the printing policy
  const auto& Policy = Printer.getPolicy(module);
  args.insert(args.end(), Policy.compilerArguments.begin(),
              Policy.compilerArguments.end());

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
  TempDir tempOutputDir;
  boost::filesystem::path outputPath(outputFilename);
  boost::filesystem::path tmpOutputPath(tempOutputDir.dirName());
  tmpOutputPath /= outputPath.filename();

  std::vector<std::string> args{{"-o", tmpOutputPath.string(), "-c"}};
  args.insert(args.end(), ExtraCompileArgs.begin(), ExtraCompileArgs.end());
  args.push_back(tempFile.fileName());

  addArchBuildArgs(mod, args);

  if (std::optional<int> ret = execute(compiler, args)) {
    if (*ret) {
      std::cerr << "ERROR: assembler returned: " << *ret << "\n";
    } else {
      copyFile(tmpOutputPath.string(), outputFilename);
    }
    return *ret;
  }

  std::cerr << "ERROR: could not find the assembler '" << compiler
            << "' on the PATH.\n";
  return -1;
}

/**
Build ld arguments to reproduce DT_INIT or DT_FINI entries.

Returns std::nullopt if no argument can be created.

Emits warnings if it cannot build ld arguments for the tag, because many
binaries will still work without their DT_INIT/DT_FINI entries.
*/
std::optional<std::string> getDynamicTagArg(const gtirb::Module& Mod,
                                            const gtirb::CodeBlock* CB,
                                            const std::string& Arg) {
  if (!CB) {
    return std::nullopt;
  }
  auto It = Mod.findSymbols(*CB);
  std::string DefaultName = "_" + Arg;
  if (std::any_of(It.begin(), It.end(), [&](const gtirb::Symbol& S) {
        auto Info = aux_data::getElfSymbolInfo(S);
        return S.getName() == DefaultName && Info->Binding == "GLOBAL";
      })) {
    // if the default name exists, there is no need to specify the argument.
    return std::nullopt;
  }

  auto Result = aux_data::findSymWithBinding(It, "GLOBAL");
  if (!Result) {
    LOG_WARNING << "No viable symbol for -" << Arg << " linker argument\n";
    return std::nullopt;
  }

  // default does not exist - we must provide a linker argument.
  return "-Wl,-" + Arg + "=" + Result->getName();
}

int ElfBinaryPrinter::link(const std::string& outputFilename,
                           gtirb::Context& ctx, gtirb::Module& module) const {
  if (debug)
    std::cout << "Generating binary file" << std::endl;
  TempFile tempFile;
  if (!prepareSource(ctx, module, tempFile)) {
    LOG_ERROR << "Could not write assembly into a temporary file.\n";
    return -1;
  }

  // Prep stuff for dynamic library dependences
  // Note that this temporary directory has to survive
  // longer than the call to the compiler.
  std::optional<TempDir> dummySoDir;
  std::vector<std::string> libArgs;
  boost::filesystem::path outputPath(outputFilename);

  if (useDummySO) {
    // Create the temporary directory for storing the synthetic libraries.
    dummySoDir.emplace();
    if (!dummySoDir->created()) {
      LOG_ERROR << "Failed to create temp dir for synthetic .so files. Errno: "
                << dummySoDir->errno_code() << "\n";
      return -1;
    }

    if (!prepareDummySOLibs(ctx, module, dummySoDir->dirName(), libArgs)) {
      LOG_ERROR << "Could not create dummy so files for linking.\n";
      return -1;
    }
    // add rpaths from original binary(ies)
    if (const auto* binaryLibraryPaths =
            module.getAuxData<gtirb::schema::LibraryPaths>()) {
      for (const auto& libraryPath : *binaryLibraryPaths) {
        libArgs.push_back("-Wl,-rpath," + libraryPath);
      }
    }
  } else {
    // If we're not using synthetic libraries, we just need to pass
    // along the appropriate arguments.

    addOrigLibraryArgs(module, libArgs,
                       outputPath.parent_path().generic_string());
  }

  TempFile VersionScript(".map");
  if (aux_data::hasVersionedSymDefs(module) &&
      !Printer.getIgnoreSymbolVersions()) {
    // A version script is only needed if we define versioned symbols.
    if (gtirb_pprint::printVersionScript(ctx, module, VersionScript)) {
      libArgs.push_back("-Wl,--version-script=" + VersionScript.fileName());
    }
  }
  VersionScript.close();
  std::vector<TempFile> Files;
  Files.emplace_back(std::move(tempFile));

  // Add -Wl,-init= and -Wl,-fini= arguments if necessary.
  // This recreates DT_INIT and DT_FINI dynamic entries.
  if (auto Arg = getDynamicTagArg(
          module,
          aux_data::getCodeBlock<gtirb::schema::ElfDynamicInit>(ctx, module),
          "init")) {
    libArgs.push_back(*Arg);
  }
  if (auto Arg = getDynamicTagArg(
          module,
          aux_data::getCodeBlock<gtirb::schema::ElfDynamicFini>(ctx, module),
          "fini")) {
    libArgs.push_back(*Arg);
  }
  TempDir tempOutputDir;
  boost::filesystem::path tmpOutputPath(tempOutputDir.dirName());
  tmpOutputPath /= outputPath.filename();
  if (std::optional<int> ret =
          execute(compiler, buildCompilerArgs(tmpOutputPath.string(), Files,
                                              ctx, module, libArgs))) {
    if (*ret) {
      LOG_ERROR << "assembler returned: " << *ret << "\n";
    } else {
      copyFile(tmpOutputPath.string(), outputFilename);
    }
    return *ret;
  }

  LOG_ERROR << "could not find the assembler '" << compiler
            << "' on the PATH.\n";
  return -1;
}

} // namespace gtirb_bprint

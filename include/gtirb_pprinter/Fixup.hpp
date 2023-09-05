//===- Fixup.hpp ----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2022 GrammaTech, Inc.
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
#ifndef GT_PPRINTER_FIXUP_H
#define GT_PPRINTER_FIXUP_H
#include "Export.hpp"
#include <boost/filesystem.hpp>
#include <optional>

namespace fs = boost::filesystem;

namespace gtirb {
class Context;
class Module;
} // namespace gtirb

namespace gtirb_pprint {
class PrettyPrinter;

/// Transforms a GTIRB module to make it acceptable to
/// the assembler.
/// For ELF shared object modules, this consists of removing
/// any direct references to global symbols and replacing them
/// with indirect ones
/// For PE modules, this means ensuring that the entry symbols
/// are correctly named.
/// \param Ctx
/// \param Mod
/// \param Printer
void DEBLOAT_PRETTYPRINTER_EXPORT_API applyFixups(gtirb::Context& Ctx,
                                                  gtirb::Module& Mod,
                                                  const PrettyPrinter& Printer);

/// Turn any direct references to global symbols, which
/// are illegal relocations in shared objects, into
/// indirect references
void fixupSharedObject(gtirb::Context& Ctx, gtirb::Module& Mod);

/// Ensure that PE entry symbols are correctly named
void fixupPESymbols(gtirb::Context& Ctx, gtirb::Module& Mod);

/// Fixup ELF symbol bindings.
///
/// ELF symbol bindings can be changed by the linker from GLOBAL to LOCAL if
/// they have a HIDDEN visibility in the object file. We need to undo this
/// process before printing, so that the linker can use needed symbols. We do
/// this for a few symbols:
///
/// - main (only necessary for --policy=dynamic, but we fixup unconditionally)
/// - DT_INIT and DT_FINI functions
void fixupELFSymbols(gtirb::Context& Ctx, gtirb::Module& Mod);

struct ModulePrintingInfo {
  gtirb::Module* Module;
  std::optional<fs::path> AsmName;
  std::optional<fs::path> BinaryName;
  std::optional<fs::path> VersionScriptName;
  ModulePrintingInfo(gtirb::Module* M,
                     std::optional<fs::path> AN = std::nullopt,
                     std::optional<fs::path> BN = std::nullopt,
                     std::optional<fs::path> VN = std::nullopt)
      : Module(M), AsmName(AN), BinaryName(BN), VersionScriptName(VN){};
  ModulePrintingInfo() : ModulePrintingInfo(nullptr){};

  // Need to define these in order to use this struct with std::map
  auto operator<(const ModulePrintingInfo& Other) const {
    return (size_t)Module < (size_t)Other.Module;
  }

  auto operator==(const ModulePrintingInfo& Other) const {
    return (Module == Other.Module) && (AsmName == Other.AsmName) &&
           (BinaryName == Other.BinaryName);
  }
  operator bool() { return Module != nullptr; }
};

/// @brief Fixup Libraries and LibraryPaths AuxData tables
///
/// When modules M1 and M2 are being printed, and M1 links against M2, ensures
/// that the printed name of M2 is reflected in the `Libraries` of M1, and that
/// there is an entry in the LibraryPaths table of M1 including the directory M2
/// will be printed to. If the path M2 will be printed to is an absolute path,
/// the LibraryPaths entry will also be absolute; if it is relative, the entry
/// will also be relative.
///
/// @param ModuleInfos: A vector of structs that record the paths each module
/// should be printed to
/// @return The same vector, but sorted so that each module appears after all of
/// its dependencies
std::vector<ModulePrintingInfo> DEBLOAT_PRETTYPRINTER_EXPORT_API
fixupLibraryAuxData(std::vector<ModulePrintingInfo> ModuleInfos);

} // namespace gtirb_pprint

#endif

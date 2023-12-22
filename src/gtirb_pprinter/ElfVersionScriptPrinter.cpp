//===- ElfVersionScriptPrinter.cpp ------------------------------*- C++ -*-===//
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

#include "ElfVersionScriptPrinter.hpp"
#include "AuxDataSchema.hpp"
#include "AuxDataUtils.hpp"
#include "FileUtils.hpp"
#include "driver/Logger.h"

namespace gtirb_pprint {

bool printVersionScript(const gtirb::Module& Module,
                        std::ofstream& VersionScript) {
  LOG_INFO << "Preparing linker version script...\n";
  if (!VersionScript.is_open()) {
    LOG_ERROR << "Unable to open version script file \n";
    return false;
  }
  std::unordered_set<std::string> Defined;

  if (Module.getFileFormat() != gtirb::FileFormat::ELF) {
    LOG_WARNING << "Module: " << Module.getBinaryPath()
                << "is not ELF; cannot generate symbol versions.\n";
    return false;
  }

  // Collect versioned symbols with the binding info
  std::unordered_map<std::string,
                     std::map<std::string, std::set<const gtirb::Symbol*>>>
      VerToAttributeToSyms;
  for (const gtirb::Symbol& Symbol : Module.symbols()) {
    if (auto SymbolInfo = aux_data::getElfSymbolInfo(Symbol)) {
      auto Version = aux_data::getSymbolVersionString(Symbol);
      if (!Version) {
        continue;
      }
      std::string VerStr = *Version;
      if (VerStr.substr(0, 2) == "@@") {
        VerStr = VerStr.substr(2);
      } else if (VerStr.substr(0, 1) == "@") {
        VerStr = VerStr.substr(1);
      }

      std::map<std::string, std::set<const gtirb::Symbol*>> AttrToSyms;
      auto It = VerToAttributeToSyms.find(VerStr);
      if (It != VerToAttributeToSyms.end()) {
        AttrToSyms = It->second;
      }

      std::set<const gtirb::Symbol*> S;
      std::string Attribute;
      if (SymbolInfo->Binding != "LOCAL") {
        Attribute = "global";
      } else {
        Attribute = "local";
      }

      auto It2 = AttrToSyms.find(Attribute);
      if (It2 != AttrToSyms.end())
        S = It2->second;

      S.insert(&Symbol);
      AttrToSyms[Attribute] = S;
      VerToAttributeToSyms[VerStr] = AttrToSyms;
    }
  }

  auto SymbolVersions = aux_data::getSymbolVersions(Module);
  if (!SymbolVersions) {
    LOG_INFO << "Module: " << Module.getBinaryPath()
             << "contains no symbol versions\n";
    return true;
  }
  auto& [SymVerDefs, SymVersNeeded, SymVerEntries] = *SymbolVersions;

  for (auto& [VerId, VerDef] : SymVerDefs) {
    auto& VerNames = std::get<0>(VerDef);
    uint16_t VerDefFlags = std::get<1>(VerDef);

    // Ignore the base version, it just contains the name
    // of the module, not an actual symbol version.
    const uint16_t VER_FLG_BASE = 0x1;
    if ((VerDefFlags & VER_FLG_BASE) == VER_FLG_BASE) {
      continue;
    }
    const std::string& MainVersion = *VerNames.begin();
    auto Predecessors = ++VerNames.begin();

    VersionScript << MainVersion << " {\n";
    const auto& It = VerToAttributeToSyms.find(MainVersion);
    if (It != VerToAttributeToSyms.end()) {
      for (auto& [Attribute, Syms] : It->second) {
        if (Attribute != "local") {
          VersionScript << "  " << Attribute << ":\n";
          for (const auto* Symbol : Syms) {
            VersionScript << "    " << Symbol->getName() << ";\n";
          }
        }
      }
    }
    VersionScript << "\n  local:\n    *;\n";
    VersionScript << "}";

    Defined.insert(MainVersion);
    bool First = true;
    for (; Predecessors != VerNames.end(); Predecessors++) {
      if (!First) {
        VersionScript << ", ";
      }
      VersionScript << *Predecessors;
    }
    VersionScript << ";\n\n";
  }
  for (auto& [LibName, Versions] : SymVersNeeded) {
    for (auto& [VerId, VerName] : Versions) {
      if (Defined.find(VerName) == Defined.end()) {
        VersionScript << VerName << " {\n \n};\n";
        Defined.insert(VerName);
      }
    }
  }

  return VersionScript.tellp() > 0;
}

} // namespace gtirb_pprint

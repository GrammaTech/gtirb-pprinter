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

#include "AuxDataSchema.hpp"
#include "AuxDataUtils.hpp"
#include "FileUtils.hpp"
#include "driver/Logger.h"

namespace gtirb_pprint {

bool printVersionScript(const gtirb::IR& IR, std::ofstream& VersionScript) {
  LOG_INFO << "Preparing linker version script...\n";
  if (!VersionScript.is_open()) {
    LOG_ERROR << "Unable to open version script file \n";
    return false;
  }
  std::unordered_set<std::string> Defined;

  for (const gtirb::Module& Module : IR.modules()) {
    if (Module.getFileFormat() != gtirb::FileFormat::ELF) {
      continue;
    }
    auto SymbolVersions = aux_data::getSymbolVersions(Module);
    if (!SymbolVersions) {
      LOG_INFO << "Module: " << Module.getBinaryPath()
               << "contains no symbol versions\n";
      continue;
    }
    auto& [SymDefs, SymNeeded, SymVerEntries] = *SymbolVersions;

    for (auto& [VerId, VerNames] : SymDefs) {
      // ignore the base version, it just contains the name
      // of the module, not an actual symbol version.
      if (VerId == 1) {
        continue;
      }
      const std::string& MainVersion = *VerNames.begin();
      auto Predecessors = ++VerNames.begin();
      VersionScript << MainVersion << " {\n \n}";
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
    for (auto& [LibName, Versions] : SymNeeded) {
      for (auto& [VerId, VerName] : Versions) {
        if (Defined.find(VerName) == Defined.end()) {
          VersionScript << VerName << " {\n \n};\n";
          Defined.insert(VerName);
        }
      }
    }
  }

  return VersionScript.tellp();
}

} // namespace gtirb_pprint

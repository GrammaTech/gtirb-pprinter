//===- Registration.cpp -----------------------------------------*- C++ -*-===//
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

#include "Arm64PrettyPrinter.hpp"
#include "ArmPrettyPrinter.hpp"
#include "AttPrettyPrinter.hpp"
#include "AuxDataSchema.hpp"
#include "IntelIcxPrettyPrinter.hpp"
#include "IntelPrettyPrinter.hpp"
#include "MasmPrettyPrinter.hpp"
#include "Mips32PrettyPrinter.hpp"
#include "PrettyPrinter.hpp"
#include <gtirb/gtirb.hpp>

namespace gtirb_pprint {
void registerAuxDataTypes() {
  using namespace gtirb::schema;
  gtirb::AuxDataContainer::registerAuxDataType<Comments>();
  gtirb::AuxDataContainer::registerAuxDataType<FunctionEntries>();
  gtirb::AuxDataContainer::registerAuxDataType<FunctionBlocks>();
  gtirb::AuxDataContainer::registerAuxDataType<SymbolForwarding>();
  gtirb::AuxDataContainer::registerAuxDataType<Encodings>();
  gtirb::AuxDataContainer::registerAuxDataType<ElfSectionProperties>();
  gtirb::AuxDataContainer::registerAuxDataType<PeSectionProperties>();
  gtirb::AuxDataContainer::registerAuxDataType<CfiDirectives>();
  gtirb::AuxDataContainer::registerAuxDataType<Libraries>();
  gtirb::AuxDataContainer::registerAuxDataType<LibraryPaths>();
  gtirb::AuxDataContainer::registerAuxDataType<PeImportedSymbols>();
  gtirb::AuxDataContainer::registerAuxDataType<PeExportedSymbols>();
  gtirb::AuxDataContainer::registerAuxDataType<ExportEntries>();
  gtirb::AuxDataContainer::registerAuxDataType<ImportEntries>();
  gtirb::AuxDataContainer::registerAuxDataType<ElfSymbolInfo>();
  gtirb::AuxDataContainer::registerAuxDataType<SymbolicExpressionSizes>();
  gtirb::AuxDataContainer::registerAuxDataType<BinaryType>();
  gtirb::AuxDataContainer::registerAuxDataType<PEResources>();
}

void registerPrettyPrinters() {
  registerPrinter({"elf", "raw"}, {"x86", "x64"}, {"intel"}, {"gas"},
                  std::make_shared<IntelPrettyPrinterFactory>(), true, true);
  registerPrinter({"elf", "raw"}, {"x86", "x64"}, {"intel"}, {"icx"},
                  std::make_shared<IntelIcxPrettyPrinterFactory>());
  registerPrinter({"elf", "raw"}, {"x86", "x64"}, {"att"}, {"gas"},
                  std::make_shared<AttPrettyPrinterFactory>(), false, true);
  registerPrinter({"elf", "raw"}, {"arm"}, {"arm"}, {"gas"},
                  std::make_shared<ArmPrettyPrinterFactory>(), true, true);
  registerPrinter({"elf", "raw"}, {"arm64"}, {"arm64"}, {"gas"},
                  std::make_shared<Arm64PrettyPrinterFactory>(), true, true);
  registerPrinter({"elf", "raw"}, {"mips32"}, {"mips32"}, {"gas"},
                  std::make_shared<Mips32PrettyPrinterFactory>(), true, true);
  registerPrinter({"pe", "raw"}, {"x86", "x64"}, {"masm"}, {"gas"},
                  std::make_shared<MasmPrettyPrinterFactory>(), true, true);
  registerPrinter({"pe", "raw"}, {"x86", "x64"}, {"masm"}, {"uasm"},
                  std::make_shared<UasmPrettyPrinterFactory>(), false, false);
}
} // namespace gtirb_pprint

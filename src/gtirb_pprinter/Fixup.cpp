//===- Fixup.cpp ----------------------------------------*- C++ -*-===//
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

#include "Fixup.hpp"
#include "AuxDataUtils.hpp"
#include "PrettyPrinter.hpp"
#include <gtirb/gtirb.hpp>
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;
using namespace std::literals::string_literals;

namespace gtirb_pprint {

void applyFixups(gtirb::Context& Context, gtirb::Module& Module,
                 const PrettyPrinter& Printer) {
  auto format = std::get<0>(Printer.getTarget());
  if (format == "pe") {
    fixupPESymbols(Context, Module);
  }
  if (format == "elf") {
    fixupELFSymbols(Context, Module);
    if (Printer.getDynMode(Module) == DYN_MODE_SHARED) {
      fixupSharedObject(Context, Module);
    }
  }
}

void fixupSharedObject(gtirb::Context& Context, gtirb::Module& Module) {
  std::unordered_set<gtirb::Symbol*> SymbolsToAlias;
  std::vector<gtirb::ByteInterval::SymbolicExpressionElement> SEEsToAlias,
      SEEsToPLT;
  for (auto& CB : Module.code_blocks()) {
    // Previously, the changes here were not applied to any code blocks that
    // would be skipped by the PrettyPrinter. Now that these are being
    // separated, all code blocks are corrected and the printer can decide
    // whether to print them or not.
    for (auto SEE : CB.getByteInterval()->findSymbolicExpressionsAtOffset(
             CB.getOffset(), CB.getOffset() + CB.getSize())) {
      auto SymsToCheck = std::visit(
          [](const auto& SE) -> std::vector<gtirb::Symbol*> {
            using T = std::decay_t<decltype(SE)>;

            if (SE.Attributes.count(gtirb::SymAttribute::PLT) ||
                SE.Attributes.count(gtirb::SymAttribute::GOT)) {
              return {}; // PLT/GOT references are allowed in shared objects
            }

            if constexpr (std::is_same_v<T, gtirb::SymAddrAddr>) {
              return {SE.Sym1, SE.Sym2};
            } else if constexpr (std::is_same_v<T, gtirb::SymAddrConst>) {
              return {SE.Sym};
            }
          },
          SEE.getSymbolicExpression());

      for (auto* Symbol : SymsToCheck) {
        if (!Symbol->hasReferent() && Symbol->getAddress()) {
          continue; // integral symbols don't need fixed up
        }

        if (auto Info = aux_data::getElfSymbolInfo(*Symbol)) {
          if (Info->Binding != "LOCAL" && Info->Visibility == "DEFAULT") {
            // direct references to global symbols are not allowed in
            // shared objects
            if (!Symbol->hasReferent() ||
                Symbol->getReferent<gtirb::ProxyBlock>() ||
                aux_data::getForwardedSymbol(Symbol)) {
              if (Info->Type == "FUNC") {
                // need to turn into a PLT reference
                SEEsToPLT.push_back(SEE);
              }
            } else {
              // need to change to the hidden alias
              SymbolsToAlias.insert(Symbol);
              SEEsToAlias.push_back(SEE);
            }
          }
        }
      }
    }
  }

  // make a hidden alias for every global symbol that is called
  // directly by a code block
  using GlobalToHiddenSymsType =
      std::unordered_map<gtirb::Symbol*, gtirb::Symbol*>;
  GlobalToHiddenSymsType GlobalToHiddenSyms;

  for (auto* Symbol : SymbolsToAlias) {
    struct SetHiddenSymbolReferent {
      gtirb::Symbol* S;
      SetHiddenSymbolReferent(gtirb::Symbol* Sym) : S{Sym} {}
      void operator()(gtirb::Addr A) { S->setAddress(A); }
      void operator()(gtirb::CodeBlock* B) { S->setReferent(B); }
      void operator()(gtirb::DataBlock* B) { S->setReferent(B); }
      void operator()(gtirb::ProxyBlock* B) { S->setReferent(B); }
    };

    auto* HiddenSymbol = Module.addSymbol(
        Context, ".gtirb_pprinter.hidden_alias." + Symbol->getName());
    Symbol->visit(SetHiddenSymbolReferent(HiddenSymbol));
    auto SymInfo = *aux_data::getElfSymbolInfo(*Symbol);
    aux_data::ElfSymbolInfo NewSymInfo{SymInfo};
    NewSymInfo.Visibility = "HIDDEN";
    aux_data::setElfSymbolInfo(*HiddenSymbol, NewSymInfo);
    GlobalToHiddenSyms[Symbol] = HiddenSymbol;
  }

  // reassign bad code block references to hidden symbols
  for (auto SEE : SEEsToAlias) {
    auto SEToAdd = std::visit(
        [&GlobalToHiddenSyms](const auto& SE) -> gtirb::SymbolicExpression {
          using T = std::decay_t<decltype(SE)>;
          T NewSE{SE};

          if constexpr (std::is_same_v<T, gtirb::SymAddrAddr>) {
            if (auto It = GlobalToHiddenSyms.find(SE.Sym1);
                It != GlobalToHiddenSyms.end()) {
              NewSE.Sym1 = It->second;
            }
            if (auto It = GlobalToHiddenSyms.find(SE.Sym2);
                It != GlobalToHiddenSyms.end()) {
              NewSE.Sym2 = It->second;
            }
          } else if constexpr (std::is_same_v<T, gtirb::SymAddrConst>) {
            NewSE.Sym = GlobalToHiddenSyms.at(SE.Sym);
          }

          return {NewSE};
        },
        SEE.getSymbolicExpression());
    SEE.getByteInterval()->addSymbolicExpression(SEE.getOffset(), SEToAdd);
  }

  // make bad code block references to extern symbols go through the PLT
  for (auto SEE : SEEsToPLT) {
    auto SEToAdd = std::visit(
        [&Context](const auto& SE) -> gtirb::SymbolicExpression {
          using T = std::decay_t<decltype(SE)>;
          T NewSE{SE};
          NewSE.Attributes.insert(gtirb::SymAttribute::PLT);

          if constexpr (std::is_same_v<T, gtirb::SymAddrAddr>) {
            if (auto Target = aux_data::getForwardedSymbol(SE.Sym1)) {
              NewSE.Sym1 = getByUUID<gtirb::Symbol>(Context, *Target);
            }
            if (auto Target = aux_data::getForwardedSymbol(SE.Sym2)) {
              NewSE.Sym2 = getByUUID<gtirb::Symbol>(Context, *Target);
            }
          } else if constexpr (std::is_same_v<T, gtirb::SymAddrConst>) {
            if (auto Target = aux_data::getForwardedSymbol(SE.Sym)) {
              NewSE.Sym = getByUUID<gtirb::Symbol>(Context, *Target);
            }
          }

          return {NewSE};
        },
        SEE.getSymbolicExpression());
    SEE.getByteInterval()->addSymbolicExpression(SEE.getOffset(), SEToAdd);
  }
};

/**
Update an ELF symbol's binding/visibility to GLOBAL/HIDDEN
*/
static void promoteSymbolBinding(gtirb::Symbol& Sym) {
  auto SymInfo = aux_data::getElfSymbolInfo(Sym);
  aux_data::ElfSymbolInfo NewSymInfo{*SymInfo};
  NewSymInfo.Binding = "GLOBAL";
  // If the binding is not GLOBAL in the final linked binary, then
  // it was HIDDEN in the object file.
  NewSymInfo.Visibility = "HIDDEN";
  aux_data::setElfSymbolInfo(Sym, NewSymInfo);
}

void fixupELFSymbols(gtirb::Context& Context, gtirb::Module& Module) {
  // Promote main
  // Allows _start to reference main when using --policy=dynamic
  // With --policy=complete, this is unnecessary, but should have no impact on
  // the final binary.
  if (auto It = Module.findSymbols("main"); !It.empty()) {
    auto& Symbol = *It.begin();
    if (auto SymInfo = aux_data::getElfSymbolInfo(Symbol)) {
      if (SymInfo->Binding != "GLOBAL") {
        promoteSymbolBinding(Symbol);
      }
    }
  }

  // Promote or create symbols for DT_INIT and DT_FINI entries
  auto ensureGlobalSymbolAt = [&](gtirb::CodeBlock* Block,
                                  const std::string& DefaultName) {
    if (Block == nullptr) {
      return;
    }

    auto Symbols = Module.findSymbols(*Block);
    if (!aux_data::findSymWithBinding(Symbols, "GLOBAL")) {
      if (auto LocalSym = aux_data::findSymWithBinding(Symbols, "LOCAL")) {
        promoteSymbolBinding(*LocalSym);
      } else {
        std::string Name = DefaultName;
        for (unsigned int Count = 0; !Module.findSymbols(Name).empty();
             Count++) {
          Name = DefaultName + "_disambig_" + std::to_string(Count);
        }

        gtirb::Symbol* Symbol = Module.addSymbol(Context, Block, Name);
        aux_data::ElfSymbolInfo Info({0, "NOTYPE", "GLOBAL", "HIDDEN", 0});
        aux_data::setElfSymbolInfo(*Symbol, Info);
      }
    }
  };

  ensureGlobalSymbolAt(
      aux_data::getCodeBlock<gtirb::schema::ElfDynamicInit>(Context, Module),
      "_init");
  ensureGlobalSymbolAt(
      aux_data::getCodeBlock<gtirb::schema::ElfDynamicFini>(Context, Module),
      "_fini");
};

void fixupPESymbols(gtirb::Context& Context, gtirb::Module& Module) {
  if (auto It = Module.findSymbols("__ImageBase"); !It.empty()) {
    auto ImageBase = &*It.begin();
    ImageBase->setReferent(Module.addProxyBlock(Context));
    if (Module.getISA() == gtirb::ISA::IA32) {
      ImageBase->setName("___ImageBase");
    }
  }

  if (auto* Block = Module.getEntryPoint(); Block && Block->getAddress()) {
    if (auto It = Module.findSymbols(*Block->getAddress()); It.empty()) {
      auto* EntryPoint =
          gtirb::Symbol::Create(Context, *Block->getAddress(), "__EntryPoint");
      EntryPoint->setReferent<gtirb::CodeBlock>(Block);
      Module.addSymbol(EntryPoint);
    }
  }
};

const fs::path Origin("$ORIGIN");

/**
 * @brief Class for tracking dependency relations between modules
 * for the purpose of updating Libraries and LibraryPaths based on 
 * where each module is going to be printed
 */
class DependencyGraph{

  std::map<PrintedModule, std::vector<PrintedModule>> Uses, UsedBy;
  std::vector<PrintedModule> Modules;
  std::map<std::string, PrintedModule> ModulesByName;
  public:
  DependencyGraph(
    std::vector<PrintedModule> PrintedModules): Modules(PrintedModules){

    // TODO: what if two modules share a name?
    for (auto & PM: PrintedModules){
      ModulesByName[std::get<gtirb::Module *>(PM)->getName()] = PM;
    }

    for (auto& [M,Pth]: PrintedModules){
      auto Libraries = aux_data::getLibraries(*M);
      for (auto& LibName: Libraries){
          if (auto MIter = ModulesByName.find(LibName); MIter != ModulesByName.end()){
          Uses[{M,Pth}].push_back(MIter->second);
          UsedBy[MIter->second].emplace_back(M,Pth);
        }
      }
    }
  };

  /**
   * @brief Change the name of a module to match the file it will be printed to,
   * and update any Libraries AuxData that reference it.
   * 
   * @param M
   */
  void updateLibraryName(PrintedModule M){
    auto OldName = M.first->getName();
    auto NewName = M.second.filename().generic_string();
    for (auto UserPMod: UsedBy[M]){
      auto * Libraries = std::get<gtirb::Module*>(UserPMod)->getAuxData<gtirb::schema::Libraries>();
      std::replace(Libraries->begin(), Libraries->end(), M.first->getName(), NewName);
    }
    M.first->setName(NewName);
    ModulesByName.erase(OldName);
    ModulesByName[NewName] = M;
  };

  void updateLibraryPath(PrintedModule M){
    auto NewPath = M.second.parent_path();
    for (auto& [UserMod, UserPath]: UsedBy[M]){
      auto * LibraryPaths = UserMod->getAuxData<gtirb::schema::LibraryPaths>();
      auto RPath = Origin / fs::relative(NewPath, UserPath);
      LibraryPaths->push_back(RPath.generic_string());
    }
  }

  void fixNames(){
    for (auto& PM: Modules){
      updateLibraryName(PM);
    }
  }

  void fixPaths(){
    for (auto& PM: Modules) {
      updateLibraryPath(PM);
    }
  }


  std::vector<PrintedModule> sortedModules(){
    std::vector<PrintedModule> Sorted, Free;

    for (auto& [M,ULst]: Uses){
      if (ULst.empty()){
        Free.emplace_back(M);
      }
    }
    
    while(Free.size() > 0){
      auto M = Free.back();
      Free.pop_back();
      Sorted.push_back(M);
      for (auto & N: UsedBy[M]){
        auto UsesLst = Uses[N];
        if (auto MIter = std::find(UsesLst.begin(), UsesLst.end(), M);
          MIter != UsesLst.end()){
          UsesLst.erase(MIter);
        }
        if (UsesLst.size() == 0){
          Free.push_back(N);
        }
      }
    }
    return Sorted;
  }
};


std::vector<PrintedModule> fixupLibraryAuxData(std::vector<PrintedModule> PrintedModules){
  DependencyGraph DG(PrintedModules);
  DG.fixNames();
  DG.fixPaths();

  return DG.sortedModules();

}

} // namespace gtirb_pprint

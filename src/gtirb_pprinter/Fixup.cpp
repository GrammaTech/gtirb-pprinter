#include "Fixup.hpp"
#include "AuxDataUtils.hpp"
#include "PrettyPrinter.hpp"
#include <gtirb/gtirb.hpp>

namespace gtirb_pprint {

void applyFixups(gtirb::Context& Context, gtirb::Module& Module,
                 const PrettyPrinter& Printer) {
  auto format = std::get<0>(Printer.getTarget());
  if (format == "pe") {
    fixupPESymbols(Context, Module);
  }
  if (format == "elf" && Printer.getShared()) {
    fixupSharedObject(Context, Module);
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

            if (SE.Attributes.isFlagSet(gtirb::SymAttribute::PltRef) ||
                SE.Attributes.isFlagSet(gtirb::SymAttribute::GotRelPC)) {
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
              // need to turn into a PLT reference
              SEEsToPLT.push_back(SEE);
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
          NewSE.Attributes.addFlag(gtirb::SymAttribute::PltRef);

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

void fixupPESymbols(gtirb::Context& Context, gtirb::Module& Module) {
  if (auto It = Module.findSymbols("__ImageBase"); !It.empty()) {
    auto& ImageBase = *It.begin();
    ImageBase.setReferent(Module.addProxyBlock(Context));
    if (Module.getISA() == gtirb::ISA::IA32) {
      ImageBase.setName("___ImageBase");
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

} // namespace gtirb_pprint

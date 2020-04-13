//===- gtirb_layout.cpp -----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
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

#include "gtirb_layout.hpp"
#include <gtirb/gtirb.hpp>

using namespace gtirb;
using namespace gtirb_layout;

struct Edge {
  CfgNode* Source;
  CfgNode* Target;
  EdgeType Type;
  bool Conditional, Direct;
};

static CFG* getCFG(CfgNode* B) {
  if (auto* CB = dyn_cast<CodeBlock>(B)) {
    return &CB->getByteInterval()->getSection()->getModule()->getIR()->getCFG();
  } else if (auto* PB = dyn_cast<ProxyBlock>(B)) {
    return &PB->getModule()->getIR()->getCFG();
  } else {
    assert(!"getCFG received an unknown node kind!");
    return nullptr;
  }
}

static CFG::vertex_descriptor blockToCFGIndex(CFG& Cfg, CfgNode* B) {
  auto Pair = boost::vertices(Cfg);
  for (auto V : boost::make_iterator_range(Pair.first, Pair.second)) {
    if (Cfg[V] == B) {
      return V;
    }
  }

  assert(!"blockToCFGIndex failed!");
  return 0;
}

struct GetEdge {
  CFG* Cfg;
  GetEdge(CFG* Cfg_) : Cfg{Cfg_} {}
  Edge operator()(const CFG::edge_descriptor& E) const {
    return Edge{
        (*Cfg)[boost::source(E, *Cfg)],
        (*Cfg)[boost::target(E, *Cfg)],
        std::get<EdgeType>(*(*Cfg)[E]),
        std::get<ConditionalEdge>(*(*Cfg)[E]) == ConditionalEdge::OnTrue,
        std::get<DirectEdge>(*(*Cfg)[E]) == DirectEdge::IsDirect,
    };
  }
};

static boost::iterator_range<
    boost::transform_iterator<GetEdge, CFG::out_edge_iterator>>
getOutgoingEdges(CfgNode* B) {
  CFG* Cfg = getCFG(B);
  auto Pair = boost::out_edges(blockToCFGIndex(*Cfg, B), *Cfg);
  return boost::make_iterator_range(
      boost::make_transform_iterator(Pair.first, GetEdge(Cfg)),
      boost::make_transform_iterator(Pair.second, GetEdge(Cfg)));
}

static bool findAndMergeBIs(Section& S) {
  for (auto& SourceBI : S.byte_intervals()) {
    // Get the last code block in this interval.
    if (SourceBI.code_blocks().empty()) {
      continue;
    }
    auto* Source = &SourceBI.code_blocks().back();

    // If two code blocks have a fallthrough edge, they need to be merged.
    for (const auto& E : getOutgoingEdges(&*SourceBI.code_blocks_begin())) {
      if (E.Type != EdgeType::Fallthrough) {
        continue;
      }

      if (auto* Target = dyn_cast<CodeBlock>(E.Target)) {
        auto& TargetBI = *Target->getByteInterval();
        auto BaseOffset = SourceBI.getSize();

        // If they're already merged into one BI...
        if (&SourceBI == &TargetBI) {
          continue;
        }

        // Check that they're both from the same section.
        if (&S != TargetBI.getSection()) {
          assert(!"Block has fallthrough edge into a block in another "
                  "section!");
          return false;
        }

        // Check that, when merged, the two code blocks will be adjacent.
        if (Source->getOffset() + Source->getSize() != SourceBI.getSize()) {
          assert(!"fallthrough edge exists, but source is not at end of "
                  "interval!");
          return false;
        }

        if (Target->getOffset() != 0) {
          assert(!"fallthrough edge exists, but target is not at start of "
                  "interval!");
          return false;
        }

        // They can be merged. Merge them now.
        SourceBI.setSize(SourceBI.getSize() + TargetBI.getSize());

        std::vector<gtirb::CodeBlock*> CodeBlocks;
        for (auto& B : TargetBI.code_blocks()) {
          CodeBlocks.push_back(&B);
        }
        for (auto* B : CodeBlocks) {
          SourceBI.addBlock(BaseOffset + B->getOffset(), B);
        }

        std::vector<gtirb::DataBlock*> DataBlocks;
        for (auto& B : TargetBI.data_blocks()) {
          DataBlocks.push_back(&B);
        }
        for (auto* B : DataBlocks) {
          SourceBI.addBlock(BaseOffset + B->getOffset(), B);
        }

        for (auto SEE : TargetBI.symbolic_expressions()) {
          SourceBI.addSymbolicExpression(BaseOffset + SEE.getOffset(),
                                         SEE.getSymbolicExpression());
        }
        SourceBI.insertBytes<uint8_t>(
            SourceBI.bytes_begin<uint8_t>() + BaseOffset,
            TargetBI.bytes_begin<uint8_t>(), TargetBI.bytes_end<uint8_t>());
        S.removeByteInterval(&TargetBI);

        // We invalidated the BI iterator back there, so time to recurse.
        // Hopefully this tail calls.
        return findAndMergeBIs(S);
      } else {
        assert(!"Code block has fallthrough edge into proxy block!");
        return false;
      }
    }
  }

  return true;
}

// NOTE: Only checks for missing addresses, not overlapping addresses.
bool ::gtirb_layout::layoutRequired(IR& ir) {
  for (auto& M : ir.modules()) {
    if (!M.getAddress()) {
      return true;
    }
    for (auto& S : M.sections()) {
      if (!S.getAddress()) {
        return true;
      }
      for (auto& BI : S.byte_intervals()) {
        if (!BI.getAddress()) {
          return true;
        }
      }
    }
  }
  return false;
}

#if defined(_MSC_VER)
// Some versions of MSVC fail to properly work with range-based for loops
// (https://developercommunity.visualstudio.com/content/problem/859129/
// warning-c4702-for-range-based-for-loop.html), so in MSVC we disable the
// spurious warning where it is known to occur.
#pragma warning(push)
#pragma warning(disable : 4702) // unreachable code
#endif

void ::gtirb_layout::fixIntegralSymbols(gtirb::Context& Ctx, gtirb::Module& M) {
  // In general, we want as many integral symbols to not be integral as
  // possible. If they point to blocks, even 0-length ones, instead of raw
  // addresses, then they automatically get moved around when we adjust
  // addresses later in the layout process. This also removes the need
  // for the pretty-printer to check if it needs to print a symbol every time
  // the program counter increments.
  std::vector<Symbol*> IntSyms;
  for (auto& Sym : M.symbols()) {
    if (!Sym.hasReferent() && Sym.getAddress()) {
      IntSyms.push_back(&Sym);
    }
  }

  for (auto* Sym : IntSyms) {
    auto Addr = *Sym->getAddress();
    bool FoundReferent = false;

    // If a byte interval encompasses this address, then we can redirect
    // the symbol to point to it.
    for (auto& BI : M.findByteIntervalsOn(Addr)) {
      FoundReferent = true;

      // do we have a block at this exact address?
      Node* ExactMatch = nullptr;
      for (auto& Block : BI.findBlocksAt(Addr)) {
        ExactMatch = &Block;
        break;
      }
      if (ExactMatch) {
        // If so, set the referent to it.
        if (isa<CodeBlock>(ExactMatch)) {
          Sym->setReferent(cast<CodeBlock>(ExactMatch));
        } else if (isa<DataBlock>(ExactMatch)) {
          Sym->setReferent(cast<DataBlock>(ExactMatch));
        } else {
          assert(!"found non-block in block iterator!");
        }
        break;
      }

      // Do we have a block encompassing this exact address?
      Node* ApproxMatch = nullptr;
      for (auto& Block : BI.findBlocksOn(Addr)) {
        ApproxMatch = &Block;
        break;
      }
      if (ApproxMatch) {
        // If so, make a new 0-length block of the same type.
        if (isa<CodeBlock>(ApproxMatch)) {
          CodeBlock* NewRef =
              BI.addBlock<CodeBlock>(Ctx, Addr - *BI.getAddress(), 0);
          Sym->setReferent(NewRef);
        } else if (isa<DataBlock>(ApproxMatch)) {
          DataBlock* NewRef =
              BI.addBlock<DataBlock>(Ctx, Addr - *BI.getAddress(), 0);
          Sym->setReferent(NewRef);
        } else {
          assert(!"found non-block in block iterator!");
        }
        break;
      }

      // if all else fails, make it a new 0-length data block.
      DataBlock* NewRef =
          BI.addBlock<DataBlock>(Ctx, Addr - *BI.getAddress(), 0);
      Sym->setReferent(NewRef);
      break;
    }

    if (FoundReferent)
      continue;
    // This symbol may refer to the end of a byte interval.
    // If so, make a new 0-length data block pointing at the end of the BI.
    for (auto& BI : M.findByteIntervalsOn(Addr - 1)) {
      FoundReferent = true;
      DataBlock* NewRef =
          BI.addBlock<DataBlock>(Ctx, Addr - *BI.getAddress(), 0);
      Sym->setReferent(NewRef);
      break;
    }

    // TODO: if !FoundReferent, then emit a warning that an integral symbol
    // was not relocated.
  }
}

bool ::gtirb_layout::layoutModule(gtirb::Context& Ctx, Module& M) {
  // Fix symbols with integral referents that point to known objects.
  fixIntegralSymbols(Ctx, M);

  // Store a list of sections and then iterate over them, because
  // setting the address of a BI invalidates parent iterators.
  Addr A = Addr{0};
  std::vector<std::reference_wrapper<Section>> Sections(M.sections_begin(),
                                                        M.sections_end());
  for (auto& S : Sections) {
    // Merge together BIs with code blocks with fallthrough edges.
    if (!findAndMergeBIs(S)) {
      return false;
    }

    // (Re)assign nonoverlapping addresses to all BIs.
    for (auto& BI : S.get().byte_intervals()) {
      BI.setAddress(A);
      A += BI.getSize();
    }
  }

  return true;
}

#if defined(_MSC_VER)
// Some versions of MSVC fail to properly work with range-based for loops
// (https://developercommunity.visualstudio.com/content/problem/859129/
// warning-c4702-for-range-based-for-loop.html), so in MSVC we disable the
// spurious warning where it is known to occur.
#pragma warning(pop)
#endif

bool ::gtirb_layout::removeModuleLayout(gtirb::Context& Ctx, Module& M) {
  // Fix symbols with integral referents that point to known objects.
  fixIntegralSymbols(Ctx, M);

  // Remove addresses from all byte intervals. We can always re-layout
  // the module later, usually without loss to pretty-printability.
  std::vector<std::reference_wrapper<Section>> Sections(M.sections_begin(),
                                                        M.sections_end());
  for (auto& S : Sections) {
    for (auto& BI : S.get().byte_intervals()) {
      BI.setAddress(std::nullopt);
    }
  }

  return true;
}

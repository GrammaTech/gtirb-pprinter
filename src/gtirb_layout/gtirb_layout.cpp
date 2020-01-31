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
    assert(!"getEdges recieved an unknown node kind!");
    return nullptr;
  }
}

static std::size_t blockToCFGIndex(CFG& Cfg, CfgNode* B) {
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

// static boost::iterator_range<
//     boost::transform_iterator<GetEdge, CFG::in_edge_iterator>>
// getIncomingEdges(CfgNode* B) {
//   CFG* Cfg = getCFG(B);
//   auto Pair = boost::in_edges(blockToCFGIndex(*Cfg, B), *Cfg);
//   return boost::make_iterator_range(
//       boost::make_transform_iterator(Pair.first, GetEdge(Cfg)),
//       boost::make_transform_iterator(Pair.second, GetEdge(Cfg)));
// }

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
        for (auto& B : TargetBI.code_blocks()) {
          SourceBI.addBlock(BaseOffset + B.getOffset(), &B);
        }
        for (auto& B : TargetBI.data_blocks()) {
          SourceBI.addBlock(BaseOffset + B.getOffset(), &B);
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

bool ::gtirb_layout::layoutModule(Module& M) {
  Addr A = Addr{0};
  for (auto& S : M.sections()) {
    // Merge together BIs with code blocks with fallthrough edges.
    if (!findAndMergeBIs(S)) {
      return false;
    }

    // (Re)assign nonoverlapping addresses to all BIs.
    for (auto& BI : S.byte_intervals()) {
      BI.setAddress(A);
      A += BI.getSize();
    }
  }

  return true;
}

bool ::gtirb_layout::removeModuleLayout(Module& M) {
  for (auto& S : M.sections()) {
    for (auto& BI : S.byte_intervals()) {
      BI.setAddress(std::nullopt);
    }
  }

  return true;
}

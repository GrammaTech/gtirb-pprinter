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
#include <set>

using namespace gtirb;
using namespace gtirb_layout;

void ::gtirb_layout::registerAuxDataTypes() {
  using namespace gtirb::schema;
  gtirb::AuxDataContainer::registerAuxDataType<Alignment>();
}

/// Return the CFG containing the given block.
///
/// \param CB  CodeBlock to get the CFG for.
///
/// \return the CFG containing the given block or \c nullptr if the CFG does
/// not exist.
static CFG* getCFG(CodeBlock* CB) {
  if (auto* BI = CB->getByteInterval())
    if (auto* S = BI->getSection())
      if (auto* M = S->getModule())
        if (auto* Ir = M->getIR())
          return &Ir->getCFG();
  return nullptr;
}

/// Find the ByteInterval, if any, that falls through to the given interval.
///
/// Assumes that at most one fallthrough edge from another byte interval to
/// the given interval exists, that the source of that edge is the last block
/// in its byte interval, and that the target of that edge is the first block
/// in the given byte interval. Also assumes that both byte intervals are in
/// the same section. Some of these assumptions are checked by assertion.
///
/// \param TargetBI  ByteInterval to find the predecessor for.
///
/// \return a ByteInterval that contains the source of a fallthrough edge that
/// targets the given ByteInterval, or \c nullptr if no such source could be
/// found.
static ByteInterval* getPredecessorByteInterval(ByteInterval& TargetBI) {
  if (!TargetBI.code_blocks().empty()) {
    CodeBlock& Target = TargetBI.code_blocks().front();
    if (CFG* Cfg = getCFG(&Target)) {
      auto U = *getVertex(&Target, *Cfg);
      for (auto E : boost::make_iterator_range(in_edges(U, *Cfg))) {
        if (EdgeLabel Label = (*Cfg)[E];
            Label && std::get<EdgeType>(*Label) == EdgeType::Fallthrough) {
          CodeBlock* Source = dyn_cast<CodeBlock>((*Cfg)[source(E, *Cfg)]);

          // FIXME: These are not really safe assumptions; user-provided IR may
          // violate them. We should report an error to the caller rather than
          // failing an assertion if they're violated.

          assert(Source && "Code block has fallthrough edge from proxy block!");

          ByteInterval* SourceBI = Source->getByteInterval();
          assert(SourceBI && SourceBI->getSection() == TargetBI.getSection() &&
                 "Block has fallthrough edge from a block in another section!");
          assert(Source == &SourceBI->code_blocks().back() &&
                 "fallthrough edge exists, but source is not at end of "
                 "interval!");
          return SourceBI;
        }
      }
    }
  }
  return nullptr;
}

bool ::gtirb_layout::layoutRequired(
    Module& M, std::unordered_set<std::string> SkipSections) {
  // If the module has no sections, we don't care that it has no address.
  if (!M.sections().empty()) {
    for (auto SecIt = M.sections_begin(); SecIt != M.sections_end(); ++SecIt) {
      if (SkipSections.count(SecIt->getName())) {
        continue;
      }
      if (!SecIt->getAddress()) {
        // The pretty-printer requires that every section must have an address.
        return true;
      }
      if (auto Next = std::next(SecIt); Next != M.sections_end()) {
        // There is a section following this one. Because the module has an
        // address, we know all of the sections have addresses.
        if (addressRange(*Next)->lower() < addressRange(*SecIt)->upper()) {
          // Sections overlap.
          return true;
        }
      }

      // Because the section has an address, we know it has at least one byte
      // interval and each of its byte intervals has an address.
      for (auto BiIt = SecIt->byte_intervals_begin(), Next = std::next(BiIt);
           Next != SecIt->byte_intervals_end(); ++BiIt, ++Next) {
        if (addressRange(*Next)->lower() < addressRange(*BiIt)->upper()) {
          // Byte intervals overlap.
          return true;
        }
      }
      // FIXME: Should we also check that blocks are aligned according to the
      // "alignment" AuxData?
      // FIXME: Should we also check that CodeBlocks with a fallthrough edge
      // are in different ByteIntervals or are adjacent in the same
      // ByteInterval?
    }
  }
  return false;
}

namespace gtirb_layout {
std::vector<std::reference_wrapper<Section>>
sectionsToLayout(gtirb::Module& M) {
  std::vector<std::reference_wrapper<Section>> Sections;
  if (!M.sections().empty()) {
    for (auto SecIt = M.sections_begin(); SecIt != M.sections_end(); ++SecIt) {
      if (!SecIt->getAddress()) {
        // The pretty-printer requires that every section must have an address.
        Sections.push_back(*SecIt);
      }
      if (auto Next = std::next(SecIt); Next != M.sections_end()) {
        // There is a section following this one. Because the module has an
        // address, we know all of the sections have addresses.
        if (addressRange(*Next)->lower() < addressRange(*SecIt)->upper()) {
          // Sections overlap.
          Sections.push_back(*SecIt);
        }
      }

      // Because the section has an address, we know it has at least one byte
      // interval and each of its byte intervals has an address.
      for (auto BiIt = SecIt->byte_intervals_begin(), Next = std::next(BiIt);
           Next != SecIt->byte_intervals_end(); ++BiIt, ++Next) {
        if (addressRange(*Next)->lower() < addressRange(*BiIt)->upper()) {
          // Byte intervals overlap.
          Sections.push_back(*SecIt);
          break;
        }
      }
    }
  }
  return Sections;
}
} // namespace gtirb_layout

bool ::gtirb_layout::layoutRequired(IR& Ir) {
  for (auto& M : Ir.modules())
    if (layoutRequired(M))
      return true;
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

/// Compute the largest power of two (up to 16) that an address can be
/// considered aligned to.
///
/// \param A  address to get alignment from.
///
/// \return the largest power of 2 that the address is aligned to, or \c nullopt
/// if there is no address or it is unaligned to any power of two between 2 and
/// 16.
static std::optional<uint64_t> defaultAlignment(std::optional<Addr> A) {
  if (A) {
    uint64_t x{*A};
    if ((x & 0xf) == 0) {
      return 16;
    }
    if ((x & 0x7) == 0) {
      return 8;
    }
    if ((x & 0x3) == 0) {
      return 4;
    }
    if ((x & 0x1) == 0) {
      return 2;
    }
  }
  return std::nullopt;
}

/// Collect the required alignments for blocks in a module.
///
/// Uses the module's "alignment" AuxData, if present. For any ByteIntervals
/// with addresses that do not contain blocks with user-defined alignment, the
/// blocks in that ByteInterval will be assumed to be aligned to the largest
/// power of two that is consistent with their current alignment.
///
/// \param Ctx  used to look up the UUIDs in the "alignment" AuxData.
/// \param M    module to gather alignments for.
///
/// \return An alignment table for blocks in the module.
static gtirb::schema::Alignment::Type getAlignments(const Context& Ctx,
                                                    const Module& M) {
  using namespace gtirb::schema;

  Alignment::Type Alignments;

  // Start with the user-specified alignment, if possible.

  std::set<UUID> UserAligned;
  if (const auto* AuxData = M.getAuxData<Alignment>()) {
    for (const auto& Pair : *AuxData) {
      if (const auto* N = Node::getByUUID(Ctx, std::get<const UUID>(Pair))) {
        if (const auto* CB = dyn_cast<CodeBlock>(N)) {
          UserAligned.insert(CB->getByteInterval()->getUUID());
        } else if (const auto* DB = dyn_cast<DataBlock>(N)) {
          UserAligned.insert(DB->getByteInterval()->getUUID());
        }
        // Aligning other node types (e.g., Section) is not currently supported.
      }
    }
    Alignments.insert(AuxData->begin(), AuxData->end());
  }

  // Compute default alignment for blocks in byte intervals that were not
  // aligned by the user.

  for (const ByteInterval& BI : M.byte_intervals()) {
    if (BI.getAddress() && !UserAligned.count(BI.getUUID())) {
      for (const CodeBlock& Block : BI.code_blocks()) {
        if (auto Align = defaultAlignment(Block.getAddress())) {
          Alignments.emplace(Block.getUUID(), *Align);
        }
      }
      for (const DataBlock& Block : BI.data_blocks()) {
        if (auto Align = defaultAlignment(Block.getAddress())) {
          Alignments.emplace(Block.getUUID(), *Align);
        }
      }
    }
  }

  return Alignments;
}

/// Sort the ByteIntervals in a Section so that the sources of fallthrough edges
/// are returned before the targets of those edges.
///
/// If the CFG is well-behaved (each interval has at most one incoming and at
/// most one outgoing fallthrough edge and there are no cycles of fallthrough
/// edges) the sources and targets will be adjacent in the returned list. This
/// implementation does not confirm that the CFG is well-behaved.
///
/// \param S  Section containing the ByteIntervals to sort
///
/// \return a vector containing the sorted pointers to the byte intervals.
static std::vector<ByteInterval*> toposort(Section& S) {
  std::vector<ByteInterval*> Sorted;
  std::set<ByteInterval*> Visited;
  for (ByteInterval& BI : S.byte_intervals()) {
    std::vector<ByteInterval*> Pending;
    ByteInterval* Pred = &BI;
    while (Pred && !Visited.count(Pred)) {
      Visited.insert(Pred);
      Pending.push_back(Pred);
      Pred = getPredecessorByteInterval(*Pred);
    }
    Sorted.insert(Sorted.end(), Pending.rbegin(), Pending.rend());
  }
  return Sorted;
}

bool ::gtirb_layout::layoutModule(gtirb::Context& Ctx, Module& M) {
  using namespace gtirb::schema;

  // Fix symbols with integral referents that point to known objects.
  fixIntegralSymbols(Ctx, M);

  // Get the desired ByteInterval alignments.

  Alignment::Type Alignments = getAlignments(Ctx, M);

  // Store a list of sections and then iterate over them, because
  // setting the address of a BI invalidates parent iterators.
  uint64_t A = 0;
  std::vector<std::reference_wrapper<Section>> Sections(M.sections_begin(),
                                                        M.sections_end());
  for (auto& S : Sections) {
    for (ByteInterval* BI : toposort(S)) {
      // If this interval contains any blocks with requested alignment, update
      // the address to maintain the alignment of the first of them.
      for (auto& Block : BI->blocks()) {
        if (auto It = Alignments.find(Block.getUUID());
            It != Alignments.end()) {
          uint64_t Mask = It->second - 1;
          uint64_t OffsetAddr = 0;
          if (auto* CB = dyn_cast<CodeBlock>(&Block)) {
            OffsetAddr = A + CB->getOffset();
          } else if (auto* DB = dyn_cast<DataBlock>(&Block)) {
            OffsetAddr = A + DB->getOffset();
          } else {
            assert(!"Unexpected block type: neither CodeBlock nor DataBlock");
          }
          if (OffsetAddr & Mask) {
            A += Mask - (OffsetAddr & Mask) + 1;
          }
          break;
        }
      }
      BI->setAddress(Addr(A));
      A += BI->getSize();
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

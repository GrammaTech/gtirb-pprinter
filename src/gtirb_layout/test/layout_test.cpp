#include "gtirb_layout/gtirb_layout.hpp"

#include <gtest/gtest.h>

using namespace gtirb;
using namespace gtirb_layout;

TEST(Unit_Layout, layoutRequired) {
  Context C;
  IR* Ir = IR::Create(C);
  Module* M = Ir->addModule(C, "test");

  // No need to layout if there are no Sections.
  EXPECT_FALSE(layoutRequired(*Ir));

  // Every section must have an address.
  Section* S1 = M->addSection(C, ".test");
  EXPECT_TRUE(layoutRequired(*Ir));

  ByteInterval* BI = S1->addByteInterval(C, 10);
  EXPECT_TRUE(layoutRequired(*Ir));

  BI->setAddress(Addr(0x100));
  EXPECT_FALSE(layoutRequired(*Ir));

  // ByteIntervals within a section cannot overlap.
  S1->addByteInterval(C, Addr(0x100), 10);
  EXPECT_TRUE(layoutRequired(*Ir));

  BI->setAddress(Addr(0x110));
  EXPECT_FALSE(layoutRequired(*Ir));

  // Sections cannot overlap.
  Section* S2 = M->addSection(C, ".test2");
  S2->addByteInterval(C, Addr(0x50), 1);
  S2->addByteInterval(C, Addr(0x200), 1);
  EXPECT_TRUE(layoutRequired(*Ir));
}

TEST(Unit_Layout, fixIntegralSymbols) {
  Context C;
  Module* M = Module::Create(C, "test");
  Section* S = M->addSection(C, ".test");
  ByteInterval* BI = S->addByteInterval(C, Addr(0x100), 16);
  CodeBlock* CB = BI->addBlock<CodeBlock>(C, 0, 4);
  DataBlock* DB = BI->addBlock<DataBlock>(C, 4, 4);
  Symbol* S100 = M->addSymbol(C, Addr(0x100), "s100");
  Symbol* S102 = M->addSymbol(C, Addr(0x102), "s102");
  Symbol* S104 = M->addSymbol(C, Addr(0x104), "s104");
  Symbol* S106 = M->addSymbol(C, Addr(0x106), "s106");
  Symbol* S108 = M->addSymbol(C, Addr(0x108), "s108");
  Symbol* S110 = M->addSymbol(C, Addr(0x110), "s110");

  fixIntegralSymbols(C, *M);

  EXPECT_EQ(Addr(0x100), S100->getAddress());
  EXPECT_EQ(Addr(0x102), S102->getAddress());
  EXPECT_EQ(Addr(0x104), S104->getAddress());
  EXPECT_EQ(Addr(0x106), S106->getAddress());
  EXPECT_EQ(Addr(0x108), S108->getAddress());
  EXPECT_EQ(Addr(0x110), S110->getAddress());

  EXPECT_EQ(CB, S100->getReferent<CodeBlock>());
  EXPECT_TRUE(S102->getReferent<CodeBlock>());
  EXPECT_EQ(DB, S104->getReferent<DataBlock>());
  EXPECT_TRUE(S106->getReferent<DataBlock>());
  EXPECT_TRUE(S108->getReferent<DataBlock>());
  EXPECT_TRUE(S110->hasReferent());
  EXPECT_TRUE(S110->getReferent<DataBlock>());
}

TEST(Unit_Layout, removeModuleLayout) {
  Context C;
  IR* Ir = IR::Create(C);
  Module* M = Ir->addModule(C, "test");
  Section* S = M->addSection(C, ".test");
  ByteInterval* BI = S->addByteInterval(C, Addr(0x100), 10);
  Symbol* S105 = M->addSymbol(C, Addr(0x105), "s105");

  EXPECT_FALSE(layoutRequired(*Ir));

  removeModuleLayout(C, *M);

  EXPECT_TRUE(layoutRequired(*Ir));
  ASSERT_TRUE(S105->getReferent<DataBlock>());
  EXPECT_EQ(BI, S105->getReferent<DataBlock>()->getByteInterval());
}

TEST(Unit_Layout, layoutModuleNoCFG) {
  using namespace gtirb::schema;

  Context C;
  Module* M = Module::Create(C, "test");
  Section* S = M->addSection(C, ".test");
  ByteInterval* BI1 = S->addByteInterval(C, Addr(0x100), 10);
  ByteInterval* BI2 = S->addByteInterval(C, Addr(0x206), 10);
  ByteInterval* BI3 = S->addByteInterval(C, Addr(0x300), 10);
  auto* DB1A = BI1->addBlock<DataBlock>(C, 0, 5);
  auto* CB1B = BI1->addBlock<CodeBlock>(C, 5, 5);
  auto* CB2 = BI2->addBlock<CodeBlock>(C, 2, 8);
  auto* CB3A = BI3->addBlock<CodeBlock>(C, 0, 5);
  auto* DB3B = BI3->addBlock<DataBlock>(C, 5, 5);
  M->addSymbol(C, DB1A, "DB1A");
  M->addSymbol(C, CB1B, "CB1B");
  M->addSymbol(C, CB2, "CB2");
  M->addSymbol(C, CB3A, "CB3A");
  M->addSymbol(C, DB3B, "DB3B");

  M->addAuxData<Alignment>({{DB3B->getUUID(), 4}});

  layoutModule(C, *M);

  ASSERT_TRUE(BI1->getAddress());
  ASSERT_TRUE(BI2->getAddress());
  ASSERT_TRUE(BI3->getAddress());

  // Alignment of BI1 is sufficient to 16-align DB1A.
  EXPECT_EQ(0, static_cast<uint64_t>(*DB1A->getAddress()) & 0xf);

  // Alignment of BI2 is sufficient to 8-align CB2 despite its non-0 offset.
  EXPECT_EQ(0, static_cast<uint64_t>(*CB2->getAddress()) & 0x7);

  // Alignment of BI3 keeps the user-specified alignment for DB3B despite not
  // starting properly aligned.
  EXPECT_EQ(0, static_cast<uint64_t>(*DB3B->getAddress()) & 0x3);

  EXPECT_FALSE(layoutRequired(*M));
}

static void addFallthrough(CfgNode* Source, CfgNode* Target, CFG& Cfg) {
  if (auto E = addEdge(Source, Target, Cfg)) {
    Cfg[*E] = std::make_tuple(ConditionalEdge::OnFalse, DirectEdge::IsDirect,
                              EdgeType::Fallthrough);
  }
}

TEST(Unit_Layout, layoutModuleWithCFG) {
  using namespace gtirb::schema;

  Context C;
  IR* Ir = IR::Create(C);
  Module* M = Ir->addModule(C, "test");
  Section* S = M->addSection(C, ".test");
  ByteInterval* BI1 = S->addByteInterval(C, Addr(0), 16);
  ByteInterval* BI2 = S->addByteInterval(C, Addr(0x10), 16);
  ByteInterval* BI3 = S->addByteInterval(C, Addr(0x20), 16);
  ByteInterval* BI4 = S->addByteInterval(C, 10);
  ByteInterval* BI5 = S->addByteInterval(C, 7);
  auto* CB1 = BI1->addBlock<CodeBlock>(C, 0, 8);
  auto* CB2 = BI2->addBlock<CodeBlock>(C, 0, 8);
  auto* CB3 = BI3->addBlock<CodeBlock>(C, 0, 8);
  auto* CB4 = BI4->addBlock<CodeBlock>(C, 0, 10);
  auto* CB5 = BI5->addBlock<CodeBlock>(C, 0, 7);
  M->addSymbol(C, CB1, "CB1");
  M->addSymbol(C, CB2, "CB2");
  M->addSymbol(C, CB3, "CB3");
  M->addSymbol(C, CB4, "CB4");
  M->addSymbol(C, CB5, "CB5");

  M->addAuxData<Alignment>({{CB5->getUUID(), 16}});

  addFallthrough(CB5, CB4, Ir->getCFG());
  addFallthrough(CB3, CB2, Ir->getCFG());
  addFallthrough(CB2, CB1, Ir->getCFG());

  layoutModule(C, *M);

  EXPECT_LT(*CB3->getAddress(), *CB2->getAddress());
  EXPECT_LT(*CB2->getAddress(), *CB1->getAddress());

  EXPECT_LT(*CB5->getAddress(), *CB4->getAddress());
  EXPECT_EQ(0, static_cast<uint64_t>(*CB5->getAddress()) & 0xf);
  EXPECT_EQ(7, static_cast<uint64_t>(*CB4->getAddress()) & 0xf);

  EXPECT_FALSE(layoutRequired(*Ir));
}

int main(int argc, char** argv) {
  registerAuxDataTypes();

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

#include "../driver/printing_paths.hpp"
#include <gtest/gtest.h>
#include <gtirb/gtirb.hpp>
#include <gtirb_pprinter/AuxDataSchema.hpp>

using namespace std::literals;
using namespace gtirb_pprint;

TEST(Unit_Libraries, TestNull) {
  gtirb::Context Ctx;
  auto* M1 = gtirb::Module::Create(Ctx, "ex"s);
  M1->setFileFormat(gtirb::FileFormat::ELF);
  M1->setISA(gtirb::ISA::X64);

  M1->addAuxData<gtirb::schema::Libraries>({});
  M1->addAuxData<gtirb::schema::LibraryPaths>({});
  std::vector<ModulePrintingInfo> MPIs{{M1, std::nullopt, "ex"}};
  auto NewMPIs = fixupLibraryAuxData(MPIs);
  ASSERT_EQ(NewMPIs, MPIs);
  auto* Libs = M1->getAuxData<gtirb::schema::Libraries>();
  ASSERT_EQ(Libs->size(), 0);
  auto* LibraryPaths = M1->getAuxData<gtirb::schema::LibraryPaths>();
  ASSERT_EQ(LibraryPaths->size(), 0);
}

TEST(Unit_Libraries, TestSingleModule) {
  gtirb::Context Ctx;
  auto* M1 = gtirb::Module::Create(Ctx, "ex"s);
  M1->setFileFormat(gtirb::FileFormat::ELF);
  M1->setISA(gtirb::ISA::X64);

  M1->addAuxData<gtirb::schema::Libraries>({"libc.so.6"});
  M1->addAuxData<gtirb::schema::LibraryPaths>({"$ORIGIN"});
  std::vector<ModulePrintingInfo> MPIs{{M1, std::nullopt, "ex"}};
  auto NewMPIs = fixupLibraryAuxData(MPIs);
  ASSERT_EQ(NewMPIs, MPIs);
  auto* Libs = M1->getAuxData<gtirb::schema::Libraries>();
  ASSERT_EQ(Libs->size(), 1);
  ASSERT_EQ(Libs->at(0), "libc.so.6");

  auto* LibraryPaths = M1->getAuxData<gtirb::schema::LibraryPaths>();
  ASSERT_EQ(LibraryPaths->size(), 1);
  ASSERT_EQ(LibraryPaths->at(0), "$ORIGIN");
}

TEST(Unit_Libraries, TestLibraryName) {
  gtirb::Context Ctx;
  auto* M1 = gtirb::Module::Create(Ctx, "ex"s);
  M1->setFileFormat(gtirb::FileFormat::ELF);
  M1->setISA(gtirb::ISA::X64);

  auto* M2 = gtirb::Module::Create(Ctx, "libfoo.so"s);
  M2->setFileFormat(gtirb::FileFormat::ELF);
  M2->setISA(gtirb::ISA::X64);

  M1->addAuxData<gtirb::schema::Libraries>({"libfoo.so"s});
  M1->addAuxData<gtirb::schema::LibraryPaths>({});
  std::vector<ModulePrintingInfo> MPIs;
  MPIs.emplace_back(M1, std::nullopt, fs::path("ex"));
  MPIs.emplace_back(M2, std::nullopt, fs::path("libfoo_rw.so"));

  MPIs = fixupLibraryAuxData(MPIs);
  ASSERT_EQ(MPIs.size(), 2);
  EXPECT_EQ(MPIs[0].Module, M2);
  EXPECT_EQ(M1->getAuxData<gtirb::schema::Libraries>()->at(0), "libfoo_rw.so");
}

class LibraryModules : public ::testing::Test {
protected:
  gtirb::Context Ctx;
  gtirb::Module* M1;
  gtirb::Module* M2;
  std::vector<std::string>* LibPaths;
  std::vector<ModulePrintingInfo> MPIs;

public:
  LibraryModules() {
    M1 = gtirb::Module::Create(Ctx, "ex"s);
    M1->setFileFormat(gtirb::FileFormat::ELF);
    M1->setISA(gtirb::ISA::X64);
    M1->addAuxData<gtirb::schema::Libraries>({"libfoo.so"});
    M1->addAuxData<gtirb::schema::LibraryPaths>({});

    M2 = gtirb::Module::Create(Ctx, "libfoo.so"s);
    M2->setFileFormat(gtirb::FileFormat::ELF);
    M2->setISA(gtirb::ISA::X64);
  }
};

TEST_F(LibraryModules, Test_LibraryPath1) {

  MPIs.emplace_back(M1, std::nullopt, fs::path("ex"));
  MPIs.emplace_back(M2, std::nullopt, fs::path("libs/libfoo.so"));

  fixupLibraryAuxData(MPIs);
  LibPaths = M1->getAuxData<gtirb::schema::LibraryPaths>();

  EXPECT_EQ(LibPaths->size(), 1);
  EXPECT_EQ(LibPaths->at(0), "$ORIGIN/libs");
}

TEST_F(LibraryModules, Test_LibraryPath2) {

  MPIs.emplace_back(M1, std::nullopt, fs::path("rw/ex"));
  MPIs.emplace_back(M2, std::nullopt, fs::path("rw/libs/ex"));
  fixupLibraryAuxData(MPIs);
  LibPaths = M1->getAuxData<gtirb::schema::LibraryPaths>();

  EXPECT_EQ(LibPaths->size(), 1);
  EXPECT_EQ(LibPaths->at(0), "$ORIGIN/libs");
}

TEST_F(LibraryModules, Test_LibraryPath3) {

  MPIs.emplace_back(M1, std::nullopt, fs::path("ex"));
  MPIs.emplace_back(M2, std::nullopt, fs::absolute(fs::path("libfoo.so")));
  fixupLibraryAuxData(MPIs);
  LibPaths = M1->getAuxData<gtirb::schema::LibraryPaths>();

  EXPECT_TRUE(fs::path(LibPaths->at(0)).is_absolute()) << LibPaths->at(0);
}

TEST_F(LibraryModules, Test_LibraryPathExisting) {
  auto* LibraryPaths = M1->getAuxData<gtirb::schema::LibraryPaths>();
  LibraryPaths->push_back("$ORIGIN");
  MPIs.emplace_back(M1, std::nullopt, fs::path("rw/ex"));
  MPIs.emplace_back(M2, std::nullopt, fs::path("rw/libs/ex"));
  fixupLibraryAuxData(MPIs);
  LibraryPaths = M1->getAuxData<gtirb::schema::LibraryPaths>();
  ASSERT_EQ(LibraryPaths->size(), 2);
  ASSERT_EQ(LibraryPaths->at(1), "$ORIGIN");
}

TEST(Unit_Libraries, TestSorting) {
  gtirb::Context Ctx;
  auto* Ex1 = gtirb::Module::Create(Ctx, "ex1");
  auto* Ex2 = gtirb::Module::Create(Ctx, "ex2");

  auto* LibFoo = gtirb::Module::Create(Ctx, "libfoo.so");
  auto* LibBar = gtirb::Module::Create(Ctx, "libbar.so");
  auto* LibBaz = gtirb::Module::Create(Ctx, "libbaz.so");

  auto* LibFooDep = gtirb::Module::Create(Ctx, "libfoo-dep.so");

  gtirb::schema::Libraries::Type Ex1Libs;
  gtirb::schema::Libraries::Type Ex2Libs;
  gtirb::schema::Libraries::Type LibFooLibs;

  Ex1->addAuxData<gtirb::schema::Libraries>({"libfoo.so", "libbar.so"});
  Ex2->addAuxData<gtirb::schema::Libraries>({"libbar.so", "libbaz.so"});
  LibFoo->addAuxData<gtirb::schema::Libraries>({"libfoo-dep.so"});
  Ex1->addAuxData<gtirb::schema::LibraryPaths>({});
  Ex2->addAuxData<gtirb::schema::LibraryPaths>({});
  LibFoo->addAuxData<gtirb::schema::LibraryPaths>({});

  std::vector<ModulePrintingInfo> MPIs;
  for (auto* M : std::vector<gtirb::Module*>{Ex1, Ex2, LibFoo, LibBar, LibBaz,
                                             LibFooDep}) {
    MPIs.emplace_back(M, std::nullopt, M->getName());
  }

  MPIs = fixupLibraryAuxData(MPIs);

  auto IndexOf = [&MPIs](const gtirb::Module* M) -> auto {
    for (auto MPIter = MPIs.begin(); MPIter != MPIs.end(); MPIter++) {
      if (MPIter->Module == M) {
        return MPIter;
      }
    }
    return MPIs.end();
  };
  EXPECT_LT(IndexOf(LibFooDep), IndexOf(LibFoo));
  EXPECT_LT(IndexOf(LibFoo), IndexOf(Ex1));
  EXPECT_LT(IndexOf(LibBar), IndexOf(Ex1));
  EXPECT_LT(IndexOf(LibBar), IndexOf(Ex2));
  EXPECT_LT(IndexOf(LibBaz), IndexOf(Ex2));
}

TEST(Unit_Libraries, TestSortingCycle) {
  gtirb::Context Ctx;
  auto* Ex = gtirb::Module::Create(Ctx, "ex");
  auto* Lib1 = gtirb::Module::Create(Ctx, "lib1");
  auto* Lib2 = gtirb::Module::Create(Ctx, "lib2");
  auto* Lib3 = gtirb::Module::Create(Ctx, "lib3");

  Ex->addAuxData<gtirb::schema::Libraries>({"lib1"});
  Lib1->addAuxData<gtirb::schema::Libraries>({"lib2"});
  Lib2->addAuxData<gtirb::schema::Libraries>({"lib1", "lib3"});

  std::vector<ModulePrintingInfo> MPIs;
  for (auto* M : std::vector<gtirb::Module*>{Ex, Lib1, Lib2, Lib3}) {
    MPIs.emplace_back(M, std::nullopt, M->getName());
  }
  ASSERT_EQ(MPIs.size(), 4);
  MPIs = fixupLibraryAuxData(MPIs);
  EXPECT_EQ(MPIs.size(), 4);

  auto IndexOf = [&MPIs](const gtirb::Module* M) -> auto {
    for (auto MPIter = MPIs.begin(); MPIter != MPIs.end(); MPIter++) {
      if (MPIter->Module == M) {
        return MPIter;
      }
    }
    return MPIs.end();
  };

  EXPECT_EQ(MPIs[0].Module, Lib3);
  EXPECT_EQ(MPIs[3].Module, Ex);
  EXPECT_LT(IndexOf(Lib3), IndexOf(Lib2));
  EXPECT_LT(IndexOf(Lib3), IndexOf(Lib1));
  EXPECT_LT(IndexOf(Lib2), IndexOf(Ex));
  EXPECT_LT(IndexOf(Lib1), IndexOf(Ex));
}

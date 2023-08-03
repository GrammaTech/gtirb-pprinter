#include <gtest/gtest.h>
#include <gtirb/gtirb.hpp>
#include <gtirb_pprinter/AuxDataSchema.hpp>
#include <gtirb_pprinter/Fixup.hpp>

using namespace gtirb_pprint;
using namespace std::literals;

TEST(Unit_Libraries, TestLibraryName) {
  gtirb::Context Ctx;
  auto* M1 = gtirb::Module::Create(Ctx, "ex"s);
  M1->setFileFormat(gtirb::FileFormat::ELF);
  M1->setISA(gtirb::ISA::X64);

  auto* M2 = gtirb::Module::Create(Ctx, "libfoo.so"s);
  M2->setFileFormat(gtirb::FileFormat::ELF);
  M2->setISA(gtirb::ISA::X64);

  gtirb::schema::Libraries::Type Libraries{"libfoo.so"s};
  M1->addAuxData<gtirb::schema::Libraries>(std::vector<std::string>(Libraries));
  gtirb::schema::LibraryPaths::Type LibraryPaths;
  M1->addAuxData<gtirb::schema::LibraryPaths>(
      std::vector<std::string>(LibraryPaths));

  std::vector<ModulePrintingInfo> MPIs;
  MPIs.emplace_back(M1, std::nullopt, fs::path("ex"));
  MPIs.emplace_back(M2, std::nullopt, fs::path("libfoo_rw.so"));

  MPIs = gtirb_pprint::fixupLibraryAuxData(MPIs);

  EXPECT_EQ(M2->getName(), "libfoo_rw.so");
  EXPECT_EQ(M1->getAuxData<gtirb::schema::Libraries>()->at(0), "libfoo_rw.so");

  EXPECT_EQ(MPIs[0].Module, M2);
}

TEST(Unit_Libraries, Test_LibraryPath) {
  gtirb::Context Ctx;
  auto* M1 = gtirb::Module::Create(Ctx, "ex"s);
  M1->setFileFormat(gtirb::FileFormat::ELF);
  M1->setISA(gtirb::ISA::X64);

  auto* M2 = gtirb::Module::Create(Ctx, "libfoo.so"s);
  M2->setFileFormat(gtirb::FileFormat::ELF);
  M2->setISA(gtirb::ISA::X64);

  gtirb::schema::Libraries::Type Libraries{"libfoo.so"s};
  M1->addAuxData<gtirb::schema::Libraries>(std::vector<std::string>(Libraries));
  gtirb::schema::LibraryPaths::Type LibraryPaths;
  M1->addAuxData<gtirb::schema::LibraryPaths>(
      std::vector<std::string>(LibraryPaths));

  std::vector<ModulePrintingInfo> MPIs;
  MPIs.emplace_back(M1, std::nullopt, fs::path("ex"));
  MPIs.emplace_back(M2, std::nullopt, fs::path("libs/libfoo.so"));

  gtirb_pprint::fixupLibraryAuxData(MPIs);

  auto* LibPaths = M1->getAuxData<gtirb::schema::LibraryPaths>();
  EXPECT_EQ(LibPaths->size(), 1);
  EXPECT_EQ(LibPaths->at(0), "$ORIGIN/libs");

  LibPaths->clear();
  MPIs.clear();

  MPIs.emplace_back(M1, std::nullopt, fs::path("rw/ex"));
  MPIs.emplace_back(M2, std::nullopt, fs::path("rw/libs/ex"));
  gtirb_pprint::fixupLibraryAuxData(MPIs);

  EXPECT_EQ(LibPaths->at(0), "$ORIGIN/libs");

  LibPaths->clear();
  MPIs.clear();
  MPIs.emplace_back(M1, std::nullopt, fs::path("ex"));
  MPIs.emplace_back(M2, std::nullopt, fs::absolute(fs::path("libfoo.so")));
  gtirb_pprint::fixupLibraryAuxData(MPIs);
  EXPECT_TRUE(fs::path(LibPaths->at(0)).is_absolute()) << LibPaths->at(0);
}

TEST(Unit_Libraries, TestSorting) {
  gtirb::Context Ctx;
  auto* Ex1 = gtirb::Module::Create(Ctx, "ex1");
  auto* Ex2 = gtirb::Module::Create(Ctx, "ex2");

  auto* LibFoo = gtirb::Module::Create(Ctx, "libfoo.so");
  auto* LibBar = gtirb::Module::Create(Ctx, "libbar.so");
  auto* LibBaz = gtirb::Module::Create(Ctx, "libbaz.so");

  auto* LibFooDep = gtirb::Module::Create(Ctx, "libfoo-dep.so");

  gtirb::schema::Libraries::Type Ex1Libs{"libfoo.so", "libbar.so"};
  gtirb::schema::Libraries::Type Ex2Libs{"libbar.so", "libbaz.so"};
  gtirb::schema::Libraries::Type LibFooLibs{"libfoo-dep.so"};

  Ex1->addAuxData<gtirb::schema::Libraries>(std::move(Ex1Libs));
  Ex2->addAuxData<gtirb::schema::Libraries>(std::move(Ex2Libs));
  LibFoo->addAuxData<gtirb::schema::Libraries>(std::move(LibFooLibs));
  Ex1->addAuxData<gtirb::schema::LibraryPaths>(std::vector<std::string>());
  Ex2->addAuxData<gtirb::schema::LibraryPaths>(std::vector<std::string>());
  LibFoo->addAuxData<gtirb::schema::LibraryPaths>(std::vector<std::string>());

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

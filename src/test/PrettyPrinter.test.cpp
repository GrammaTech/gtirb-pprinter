#include <gtest/gtest.h>
#include <boost/archive/polymorphic_text_iarchive.hpp>
#include <boost/archive/polymorphic_text_oarchive.hpp>
#include <boost/crc.hpp>
#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <memory>
#include "PrettyPrinter.h"

class DisableConsoleOutput {
public:
  DisableConsoleOutput() {
    std::cout.setstate(std::ios_base::failbit);
    std::cerr.setstate(std::ios_base::failbit);
  }

  ~DisableConsoleOutput() {
    std::cout.clear();
    std::cerr.clear();
  }
};

// TestStructure is built by the CMake file and passed in as a preprocessor definition.
struct TestStructure {
  TestStructure(std::string n, std::string f) : Name(std::move(n)), Flags(std::move(f)) {}

  std::string Name;
  std::string Flags;
};

// This is modeled after utlities/Disasm/main.cpp
class System_PrettyPrinterF : public ::testing::TestWithParam<TestStructure> {
public:
  virtual void SetUp() override {
    // this->disasmPath = boost::filesystem::temp_directory_path();
    this->disasmPath = boost::filesystem::path("./temp/");
    this->gtirbPath = boost::filesystem::path("./temp/gtirb");

    if (boost::filesystem::is_directory(this->disasmPath) == false) {
      EXPECT_TRUE(boost::filesystem::create_directory(this->disasmPath))
          << "Could not create directory " << this->disasmPath << ".";
    }

    EXPECT_TRUE(boost::filesystem::status(this->disasmPath).permissions() |
                boost::filesystem::owner_write);

    this->exe = boost::filesystem::path(BOOST_PP_STRINGIZE(CMAKE_RUNTIME_OUTPUT_DIRECTORY)) /
                GetParam().Name;
    ASSERT_TRUE(boost::filesystem::is_regular_file(this->exe));
  }

  virtual void TearDown() override {
    boost::filesystem::remove(this->asmPath);
    boost::filesystem::remove(this->reasmPath);
  }

  int decode() {
    int result = EXIT_FAILURE;

    std::stringstream cmd;
    cmd << BOOST_PP_STRINGIZE(DEBLOAT_FOUND_DATALOG_DECODER) << " --file " << exe << " --dir "
        << disasmPath;
    cmd << " --sect .plt.got --sect .fini --sect .init --sect .plt --sect .text ";
    cmd << "--data_sect .data --data_sect .rodata --data_sect .fini_array --data_sect "
           ".init_array --data_sect .data.rel.ro --data_sect .got.plt --data_sect .got";

    EXPECT_NO_THROW(result = boost::process::system(cmd.str()))
        << "Make sure that \"datalog_decoder\" is in your PATH.";
    EXPECT_EQ(EXIT_SUCCESS, result) << cmd.str() << "\n\tResults written to " << disasmPath << ".";
    return result;
  }

  int souffle() {
    int result = EXIT_FAILURE;

    std::stringstream cmd;
    cmd << BOOST_PP_STRINGIZE(DEBLOAT_FOUND_SOUFFLE_DISASM) << " " << this->exe << " -F "
        << disasmPath << " -D " << disasmPath;

    EXPECT_NO_THROW(result = boost::process::system(cmd.str()))
        << "Make sure that \"datalog_decoder\" is in your PATH.";
    EXPECT_EQ(EXIT_SUCCESS, result) << cmd.str() << "\n\tResults written to " << disasmPath << ".";
    return result;
  }

  void disassemble() {
    const auto suppress = DisableConsoleOutput();
    std::ifstream in(this->gtirbPath.string());
    EXPECT_NO_THROW(this->ir = gtirb::IR::load(this->ctx, in));
  }

  void print() {
    const auto suppress = DisableConsoleOutput();
    PrettyPrinter pp;
    EXPECT_NO_THROW(this->assembly = pp.prettyPrint(this->ctx, this->ir));

    // This must be a ".s" extension for GCC / Clang.
    this->asmPath = this->disasmPath.string() + GetParam().Name + ".s";
    boost::filesystem::remove(this->asmPath);

    std::ofstream ofs;
    ofs.open(this->asmPath.c_str());
    ASSERT_TRUE(ofs.is_open());
    ofs << this->assembly;
    EXPECT_NO_THROW(ofs.close());
  }

  int crc() const {
    boost::crc_32_type result;
    EXPECT_NO_THROW(result.process_bytes(this->assembly.data(), this->assembly.length()));
    return result.checksum();
  }

  int reassemble() {
    int result = EXIT_FAILURE;
    std::stringstream cmd;

    this->reasmPath = this->asmPath.string() + ".exe";
    boost::filesystem::remove(this->reasmPath);

#ifdef WIN32
    result = EXIT_FAILURE;
#else
    cmd << BOOST_PP_STRINGIZE(CMAKE_CXX_COMPILER) << " " << asmPath << " " << GetParam().Flags
        << " -o " << reasmPath;
#endif

    EXPECT_NO_THROW(result = boost::process::system(cmd.str()));
    EXPECT_EQ(EXIT_SUCCESS, result) << cmd.str();

    return result;
  }

  int execute() {
    int result = EXIT_FAILURE;

    EXPECT_NO_THROW(result = boost::process::system(this->reasmPath.string()));
    EXPECT_EQ(EXIT_SUCCESS, result) << this->reasmPath;

    return result;
  }

  gtirb::Context ctx;
  gtirb::IR* ir;
  boost::filesystem::path exe;
  boost::filesystem::path disasmPath;
  boost::filesystem::path gtirbPath;
  boost::filesystem::path asmPath;
  boost::filesystem::path reasmPath;
  std::string assembly;
};

TEST(Unit_PrettyPrinter, ctor_0) { EXPECT_NO_THROW(PrettyPrinter()); }

TEST_P(System_PrettyPrinterF, Decode) { ASSERT_EQ(EXIT_SUCCESS, this->decode()); }

TEST_P(System_PrettyPrinterF, DecodeSouffle) {
  ASSERT_EQ(EXIT_SUCCESS, this->decode());
  ASSERT_EQ(EXIT_SUCCESS, this->souffle());
}

TEST_P(System_PrettyPrinterF, DecodeSouffleDisasm) {
  ASSERT_EQ(EXIT_SUCCESS, this->decode());
  ASSERT_EQ(EXIT_SUCCESS, this->souffle());
  this->disassemble();
}

TEST_P(System_PrettyPrinterF, DecodeSouffleDisasmPrint) {
  ASSERT_EQ(EXIT_SUCCESS, this->decode());
  ASSERT_EQ(EXIT_SUCCESS, this->souffle());

  this->disassemble();
  this->print();

  // JEF // How can we quickly test that the assembly is not completely junk at this stage?
  // JEF // Not sure how consistent this will be among different compilers.
  // EXPECT_EQ(-533041824, this->crc()) << "Assembly failed CRC check.";
}

TEST_P(System_PrettyPrinterF, Reassemble) {
  ASSERT_EQ(EXIT_SUCCESS, this->decode());
  ASSERT_EQ(EXIT_SUCCESS, this->souffle());

  this->disassemble();
  this->print();

  ASSERT_EQ(EXIT_SUCCESS, this->reassemble());
}

TEST_P(System_PrettyPrinterF, ReassembleAndExecute) {
  ASSERT_EQ(EXIT_SUCCESS, this->decode());
  ASSERT_EQ(EXIT_SUCCESS, this->souffle());

  this->disassemble();
  this->print();

  ASSERT_EQ(EXIT_SUCCESS, this->reassemble());
  ASSERT_EQ(EXIT_SUCCESS, this->execute());
}

std::vector<TestStructure> TestValueGenerator() {
  std::vector<TestStructure> tests;

  // These macros are defined inside CMake.
  std::vector<std::string> examples = {DEBLOAT_TEST_PRETTY_PRINTER_EXAMPLES};

  // Build a vector of the combinations of examples and compiler options.
  for (const auto& e : examples) {
    tests.push_back({e, "-O0"});
    tests.push_back({e, "-O1"});
    tests.push_back({e, "-O2"});
    tests.push_back({e, "-O3"});
  }

  return tests;
}

// DEBLOAT_TEST_PRETTY_PRINTER_EXAMPLES is built by CMake.
// It is built by scanning the /examples subdirectory.
// Each file gets its own test here.
INSTANTIATE_TEST_CASE_P(InstantiationName, System_PrettyPrinterF,
                        ::testing::ValuesIn(TestValueGenerator()));

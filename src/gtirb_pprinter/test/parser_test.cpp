#include "../driver/parser.hpp"
#include <gtest/gtest.h>
#include <iomanip>

using namespace gtirb_multimodule;

TEST(Unit_Parser, matchPatterns) {
  std::vector<std::pair<std::string, std::string>> cases{
      {"*", ".*"},
      {"hello", "hello"},
      {"{name:*.so}", "(.*\\.so)"},
      {"{n:*}", "(.*)"},
      {"{stem:libc}.{ext:so*}", "(libc)\\.(so.*)"},
      {"{stem:\\{*\\}}.*", "(\\{.*\\})\\..*"},
  };
  for (auto& [input, pattern] : cases) {
    Matcher M(input);
    EXPECT_EQ(M.getRegexStr(), pattern);
    if (M.getRegexStr() != pattern) {
      std::cerr << "Input " << input << " failed!\n";
    }
    try {
      std::regex(M.getRegexStr());
    } catch (const std::regex_error& err) {
      std::cerr << "Invalid regex: " << M.getRegexStr() << "\n"
                << err.what() << "\n";
    }
  }
}

TEST(Unit_Parser, matchCases) {
  std::vector<std::tuple<std::string, std::string>> cases{
      {"{stem:\\{*\\}}.*", "{hello}.world"},
      {"{stem:*}.{ext:so*}", "libc.so.0"},
      {"*.{ext:so*}", "libc.so.0"},
      {"{s:*}.{e:so*}", "libc.so.0"},
      {"libc.so", "libc.so"},
  };
  for (auto& [input, name] : cases) {
    Matcher M(input);
    EXPECT_TRUE(M.matches(name));
    if (!M.matches(name)) {
      std::cerr << "Pattern " << M.getRegexStr() << " doesn't match " << name
                << "\n";
    }
  }
}

TEST(Unit_Parser, matchNames) {
  auto input = "{stem:*}.{ext:so*}";
  Matcher M(input);
  ASSERT_EQ(M.getGroupIndexes().find("stem")->second, 1);
  ASSERT_EQ(M.getGroupIndexes().find("ext")->second, 2);
}

TEST(Unit_Parser, SubstitutionPatterns) {
  std::vector<std::pair<std::string, std::string>> cases{
      {"hello.c", "hello.c"},
      {"*=hello.c", "hello.c"},
      {"{name}", "$&"},
      {"*={name}", "$&"},
      {"{stem:lib*}.{ext:so*}=libs/{stem}.{ext}", "libs/$1.$2"}};
  for (auto& [input, expected] : cases) {
    FilePattern sub(input);
    ASSERT_EQ(sub.replacementPattern(), expected);
  }
}

TEST(Unit_Parser, Substitutions) {
  std::vector<std::tuple<std::string, std::string, std::string>> cases{
      {"*.{ext:so*}=example.{ext}", "hello.so", "example.so"},
      {"{s1:*}.{s2:*}.{s3:*}.{s4:*}={s3}/{s2}/{s4}/{s1}", "a.b.c.d", "c/b/d/a"},
      {"*={n}", "'try-to-[escape]'", "'try-to-[escape]'"},
      {R"({a:*}.{b:*}={a}\\{b})", "hello.world", R"(hello\world)"},
      {R"({a:*}.{b:*}=dir\{a}\\{b})", "hello.world", R"(dir{a}\world)"},
      {R"({a:*}.{b:*}=C:\dir\\{a})", "hello.world", R"(C:\dir\hello)"}};
  for (auto& [pattern, name, result] : cases) {
    EXPECT_EQ(*FilePattern(pattern).substitute(name), result);
  }
}

TEST(Unit_Parser, Mistakes) {
  std::vector<std::string> cases{
      "{s%:*}.so={s%}",         // group names are only allowed a-zA-Z0-9_
      "{g1:{hello}}.*={g1}",    // brackets in globs need to be escaped
      "{g1:hell\\0}*=lib/{g1}", // \0 is not a valid escape
      "{g1:*.so=hello_{g1}"     // unclosed brace
  };
  for (auto& s : cases) {
    ASSERT_ANY_THROW(FilePattern{s});
  }
}

TEST(Unit_Parser, E2E) {
  auto Subs = parseInput("{g1:h*o}*={g1},{n}"); // should be fine

  Subs = parseInput("{n},lib/{n}");
  ASSERT_EQ(Subs.size(), 2);
  ASSERT_TRUE(Subs[0].isDefault());
  ASSERT_TRUE(Subs[1].isDefault());

  Subs = parseInput("{n}.s");
  ASSERT_EQ(getOutputFileName(Subs, "ex")->generic_string(),
            std::string("ex.s"));

  Subs = parseInput("{s:*}.{ext:so*}={s}.rewritten.{ext},{n}");
  ASSERT_EQ(getOutputFileName(Subs, "libc.so.6"),
            fs::path("libc.rewritten.so.6"));
  ASSERT_EQ(getOutputFileName(Subs, "eq"), fs::path("eq"));

  Subs = parseInput("{s:*}.{ext:so*}={s}.rewritten.{ext}");
  ASSERT_EQ(getOutputFileName(Subs, "ex"), std::nullopt);
}

#include "../driver/parser.hpp"
#include <gtest/gtest.h>
#include <iomanip>

using namespace gtirb_pprint_parser;
using namespace std::literals;

TEST(Unit_Parser, matchPatterns) {
  std::vector<std::pair<std::string, std::string>> cases{
      {"*", ".*"},
      {"hello", "hello"},
      {"{name:*.so}", "(.*\\.so)"},
      {"{n:*}", "(.*)"},
      {"{stem:libc}.{ext:so*}", "(libc)\\.(so.*)"},
      {"{stem:\\{*\\}}.*", "(\\{.*\\})\\..*"},
      {"lib\\w.so", "lib\\\\w\\.so"},
      {"\\*.so", "\\*\\.so"},
  };
  for (auto& [input, pattern] : cases) {
    auto M = makePattern(input.begin(), input.end());
    EXPECT_EQ(M.RegexStr, pattern);
    EXPECT_NO_THROW(std::regex(M.RegexStr))
        << "Invalid regex: " << M.RegexStr << "\n";
  }
}

TEST(Unit_Parser, matchCases) {
  std::vector<std::tuple<std::string, std::string>> cases{
      {"{stem:\\{*\\}}.*", "{hello}.world"},
      {"{stem:*}.{ext:so*}", "libc.so.0"},
      {"*.{ext:so*}", "libc.so.0"},
      {"{s:*}.{e:so*}", "libc.so.0"},
      {"libc.so", "libc.so"},
      {"lib^.so", "lib^.so"},
      {"lib\\w.so", "lib\\w.so"},
      {"lib$.so", "lib$.so"},
      {"lib().so", "lib().so"},
      {"lib\\(", "lib\\("},
      {"(?:hello)", "(?:hello)"},
      {"lib?.so", "liba.so"},
      {"lib?.so", "lib..so"},
  };
  for (auto& [input, name] : cases) {
    auto M = makePattern(input.begin(), input.end());
    EXPECT_TRUE(M.matches(name))
        << "Pattern " << M.RegexStr << " doesn't match " << name << "\n";
  }

  // check that any regex special characters that aren't part of our language
  // are treated literally
  for (auto RegexChar : "^$.+()|"s) {
    auto Input = "lib"s + RegexChar;
    auto M = makePattern(Input.begin(), Input.end());
    EXPECT_TRUE(M.matches(Input))
        << "Character " << RegexChar << "handled wrong\n";
    Input = "lib\\"s + RegexChar;
    M = makePattern(Input.begin(), Input.end());
    EXPECT_TRUE(M.matches(Input))
        << "Character " << RegexChar << "handled wrong\n";
  }
}

TEST(Unit_Parser, matchNames) {
  std::string input{"{stem:*}.{ext:so*}"};
  auto M = makePattern(input.begin(), input.end());
  EXPECT_EQ(M.GroupIndexes.find("stem")->second, 1);
  EXPECT_EQ(M.GroupIndexes.find("ext")->second, 2);
}

TEST(Unit_Parser, Substitutions) {
  std::vector<std::tuple<std::string, std::string, std::string>> cases{
      {"*.{ext:so*}=example.{ext}", "hello.so", "example.so"},
      {"{s1:*}.{s2:*}.{s3:*}.{s4:*}={s3}/{s2}/{s4}/{s1}", "a.b.c.d", "c/b/d/a"},
      {"*={n}", "'try-to-[escape]'", "'try-to-[escape]'"},
      {"{a:*}-{b:*}={a}1-{b}2", "hello-world", "hello1-world2"},
      {R"({a:*}.{b:*}={a}\\{b})", "hello.world", R"(hello\world)"},
      {R"({a:*}.{b:*}=dir\{a}\\{b})", "hello.world", R"(dir{a}\world)"},
      {R"({a:*}.{b:*}=C:\dir\\{a})", "hello.world", R"(C:\dir\hello)"},
      {"{g1:hell\\\\\\=0}*=lib/{g1}", "hell\\=0_world", "lib/hell\\=0"},
  };
  for (auto& [pattern, name, result] : cases) {
    EXPECT_EQ(
        *FileTemplateRule(pattern.begin(), pattern.end()).substitute(name),
        result)
        << "Applying " << pattern << "to " << name << " does not give "
        << result << "\n";
  }
}

TEST(Unit_Parser, Mistakes) {
  std::vector<std::string> cases{
      "{s%:*}.so={s%}",      // group names are only allowed a-zA-Z0-9_
      "{g1:{hello}}.*={g1}", // brackets in globs need to be escaped
      "{g1:*.so=hello_{g1}", // unclosed brace
      "{g1:[*]}",            // brackets need to be escaped
      "{g1:hell=0}",         // as does '='
  };
  for (auto& s : cases) {
    EXPECT_ANY_THROW(FileTemplateRule(s.begin(), s.end()))
        << "case " << s << " failed to crash";
  }

  // One of the two '='s needs to be escaped
  EXPECT_ANY_THROW(parseInput("{g1:yes}=4={g1}.s"));
}

TEST(Unit_Parser, E2E) {
  auto Subs = parseInput("{g1:h*o}*={g1},{n}"); // should be fine

  Subs = parseInput("{n},lib/{n}");
  EXPECT_EQ(Subs.size(), 2);

  Subs = parseInput("{n}.s");
  EXPECT_EQ(getOutputFileName(Subs, "ex")->generic_string(),
            std::string("ex.s"));

  Subs = parseInput("{s:*}.{ext:so*}={s}.rewritten.{ext},{n}");
  EXPECT_EQ(getOutputFileName(Subs, "libc.so.6"),
            fs::path("libc.rewritten.so.6"));
  EXPECT_EQ(getOutputFileName(Subs, "eq"), fs::path("eq"));

  Subs = parseInput("{s:*}.{ext:so*}={s}.rewritten.{ext}");
  EXPECT_EQ(getOutputFileName(Subs, "ex"), std::nullopt);

  Subs = parseInput(R"(\{{s:*}\}\{{t:*}\}={s}.{t})");
  EXPECT_EQ(getOutputFileName(Subs, "{hello}{world}"), "hello.world");

  Subs = parseInput(R"(\{\[$.\,\=\]\}={name})");
  auto Name = "{[$.,=]}";
  EXPECT_EQ(getOutputFileName(Subs, Name), Name)
      << "Expected " << Name << ", got "
      << getOutputFileName(Subs, Name)->generic_string();
}

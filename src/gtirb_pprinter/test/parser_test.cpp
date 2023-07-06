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
      {"{stem:\\{*\\}}.*","(\\{.*\\})\\..*"},
  };
  for (auto& [input, pattern] : cases) {
    Matcher M(input);
    EXPECT_EQ(M.Pattern, pattern);
    if (M.Pattern != pattern) {
      std::cerr << "Input " << input << " failed!\n";
    }
    try{
      std::regex(M.Pattern);
    } catch (const std::regex_error& err){
      std::cerr << "Invalid regex: "<< M.Pattern<<"\n"<<err.what()<<"\n";
    }
  }
}

TEST(Unit_Parser, matchCases) {
  std::vector<std::tuple<std::string, std::string>> cases{
      {"{stem:\\{*\\}}.*","{hello}.world"},
      {"{stem:*}.{ext:so*}", "libc.so.0"},
      {"*.{ext:so*}", "libc.so.0"},
      {"{s:*}.{e:so*}", "libc.so.0"},
      {"libc.so", "libc.so"},
  };
  for (auto& [input, name] : cases) {
    Matcher M(input);
    EXPECT_TRUE(M.matches(name));
    if (!M.matches(name)) {
      std::cerr << "Pattern " << M.Pattern << " doesn't match " << name << "\n";
    }
  }
}

TEST(Unit_Parser, matchNames){
  auto input = "{stem:*}.{ext:so*}";
  Matcher M(input);
  ASSERT_EQ(M.GroupIndexes["stem"],1);
  ASSERT_EQ(M.GroupIndexes["ext"],2); 
}

TEST(Unit_Parser, SubstitutionPatterns){
  std::vector<std::pair<std::string,std::string>> cases {
   {"hello.c","hello.c"},
   {"*=hello.c", "hello.c"}, 
   {"{name}","$0"},
   {"*={name}","$0"},
   {"{stem:lib*}.{ext:so*}=libs/{stem}.{ext}", "libs/$1.$2"}
  };
  for (auto& [input, expected]: cases){
    Substitution sub(input);
    ASSERT_EQ(sub.ReplacementPattern,expected);
  }
}

TEST(Unit_Parser, Substitutions){
  std::vector<std::tuple<std::string,std::string,std::string>> cases {
    {"*.{ext:so*}=example.{ext}", "hello.so","example.so"},
    {"{s1:*}.{s2:*}.{s3:*}.{s4:*}={s3}/{s2}/{s4}/{s1}","a.b.c.d","c/b/d/a"},
    {"*={n}", "'try-to-[escape]'", "'try-to-[escape]'"},
  };
  for (auto& [pattern, name, result]: cases){
    ASSERT_EQ(Substitution(pattern).substitute(name), result);
  }
}


TEST(Unit_Parser,Mistakes){
  std::vector<std::string> cases {
     "{s%:*}.so={s%}", // group names are only allowed a-zA-Z0-9_
     "{g1:{hello}}.*={g1}", // brackets in globs need to be escaped 
     "{g1:{hell\\0}}*=lib/{g1}", // \0 is not a valid escape
     "{g1:*.so=hello_{g1}" // unclosed brace
  };
  for (auto& s: cases){
    ASSERT_ANY_THROW(Substitution{s});
  }
}

TEST(Unit_Parser, E2E){
  auto Subs = parseInput("{g1:h*o}*={g1},{n}");
  ASSERT_ANY_THROW(parseInput("{n},lib/{n}"));
}
#include "../driver/parser.hpp"
#include <iomanip>
#include <gtest/gtest.h>

using namespace gtirb_pprint;
using MatchKind = Matcher::MatchKind;


TEST(Unit_Parser, Filters){
    auto r1 = Matcher::field_regex;
    std::vector<std::pair<std::string,bool>> testCases {
        {"{name}", true},
        {"{stem}", true},
        {"{name:hello}", true},
        {"{#0}", true},
        {"{n:*.so.1}", true},
        {"{*}", true},
        {"{*.so.*}", true},
        {"{libc.so.*}", true},
        {"{stem:*}.{ext:*}", true},
        {"{s:hello}.{e:dll*}", true},
        {"{name", false},
        {"libc.so.6", false},
        {"{s}.{e}.{s}.{e}", false}
    };
    for (auto& [arg, result]: testCases){
        EXPECT_EQ(std::regex_match(arg,r1),result);
        if (std::regex_match(arg,r1) != result){
            std::cerr << "match("<<arg<<") is not " <<std::boolalpha<<result<<std::noboolalpha<<"\n";
        }
    }
}


TEST(Unit_Parser,matchKinds){
    std::vector<std::pair<std::string, MatchKind>> cases{
        {"{name}", MatchKind::Name},
        {"{name:*.so}", MatchKind::Name},
        {"{n:*}", MatchKind::Name},
        {"{*.so.*}", MatchKind::Name},
        {"{stem}", MatchKind::Stem},
        {"{stem:foo*}",MatchKind::Stem},
        {"{s:libc*}", MatchKind::Stem},
        {"{ext}", MatchKind::Extension},
        {"{ext:so*}", MatchKind::Extension},
        {"{e:so*}", MatchKind::Extension},
        {"{#0}", MatchKind::Number},
        {"{stem:libc}.{ext:so*}", MatchKind::StemExtension}
    };
    for (auto& [input, kind] : cases){
        Matcher M(input);
        EXPECT_EQ(M.kind,kind);
        if (M.kind != kind){
            std::cerr << "Input " << input << " failed!\n";
        }
    }
}

TEST(Unit_Parser,matchPatterns){
    std::vector<std::pair<std::string, std::string>> cases{
        {"{name}", "(.*)"},
        {"{name:*.so}", "(.*)\\.so"},
        {"{n:*}", "(.*)"},
        {"{*.so.*}", "(.*)\\.so\\.(.*)"},
        {"{#0}", "0"},
        {"{stem:libc}.{ext:so*}", "libc\\.so(.*)"},
    };
    for (auto& [input, pattern] : cases){
        Matcher M(input);
        EXPECT_EQ(M.pattern,pattern);
        if (M.pattern != pattern){
            std::cerr << "Input " << input << " failed!\n";
        }
    }
}


TEST(Unit_Parser, matchCases){
    std::vector<std::tuple<std::string,std::string,ulong>> cases {
        {"{stem:*}.{ext:so*}", "libc.so.0",0},
        {"{ext:so*}", "libc.so.0",0},
        {"{s:*}.{e:so*}","libc.so.0",0},
        {"libc.so", "libc.so",0},
        {"{#0}", "libc.so.0",0},
        {"{#2}", "libc.so.0",2},
    };
    for (auto& [input, name, index]: cases){
        Matcher M(input);
        EXPECT_TRUE(M.matches(name,index));
        if (!M.matches(name,index)){
            std::cerr << "Pattern " <<M.pattern<<" doesn't match " << name <<"@"<<index<<"\n";
        }
    }
}


TEST(Unit_Parser,pathTemplates){
    std::vector<std::tuple<std::string,std::string,std::string>> cases {
        {"{name}.rewritten","hello","hello.rewritten"},
        {"{stem}.rewritten.{ext}","hello.world","hello.rewritten.world"},
        {"libs/{name}", "hello", "libs/hello"},
        {"    ", "hello", "hello"},
        {"libs/hello.rewritten", "hello", "libs/hello.rewritten"}
    };

    for (auto& [pattern, name, expected] : cases){
        PathTemplate tmpl(pattern);
        auto output = tmpl.makePath(name).generic_string();
        EXPECT_EQ(output, expected);
    }
}


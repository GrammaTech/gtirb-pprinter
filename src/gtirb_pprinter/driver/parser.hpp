#ifndef GTPPRINT_PARSER_H
#define GTPPRINT_PARSER_H
#include <boost/filesystem.hpp>
#include <optional>
#include <regex>

namespace fs = boost::filesystem;


namespace gtirb_pprint {

    struct Matcher{
        enum class MatchKind{
            Literal,
            Name,
            Stem,
            Extension,
            StemExtension,
        };
        static const std::regex FieldRegex;
        MatchKind Kind;
        std::string Pattern;
        Matcher(const std::string& Field);
        bool matches(const std::string& Name) const;
    };


    struct PathTemplate{
        static const std::regex Components;
        std::string Spec;
        PathTemplate(const std::string& S):Spec(S){};
        fs::path makePath(const std::string& ModuleName) const;
    };


    typedef std::pair<Matcher, PathTemplate> Substitution;
    std::vector<Substitution> parseInput(const std::string& Input);
    

    std::optional<fs::path> getOutputFileName(const std::vector<Substitution>& Subs, 
        const std::string& ModuleName);
}

#endif
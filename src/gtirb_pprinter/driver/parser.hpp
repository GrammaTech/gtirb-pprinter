#ifndef GTPPRINT_PARSER_H
#define GTPPRINT_PARSER_H
#include <boost/filesystem.hpp>
#include <optional>
#include <regex>

namespace fs = boost::filesystem;


namespace gtirb_pprint {

    class Matcher{
        public:
        enum class MatchKind{
            Literal,
            Name,
            Stem,
            Extension,
            StemExtension,
            Number
        };
        private:
        static const std::regex field_regex;
        MatchKind kind;
        std::regex pattern;
        public:
        Matcher(const std::string& Field);
        bool matches(const std::string& Name, ulong index) const;
    };


    class PathTemplate{
        static const std::regex components;
        std::string spec;
        public:
        PathTemplate(const std::string& Spec):spec(Spec){};
        fs::path makePath(const std::string& ModuleName) const;
    };


    typedef std::pair<Matcher, PathTemplate> Substitution;
    std::vector<Substitution> parse_input(const std::string& input);
    

    fs::path substitueOutputFileName(const std::vector<Substitution>& subs, 
        const std::string& moduleName, int index);
}

#endif
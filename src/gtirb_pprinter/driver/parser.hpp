#ifndef GTPPRINT_PARSER_H
#define GTPPRINT_PARSER_H
#include <boost/filesystem.hpp>
#include <optional>
#include <regex>

namespace fs = boost::filesystem;


namespace gtirb_pprint {


    static const std::regex kv_regex{
        "(?:([^,=]+)=)?([^,=]+)" // (key=)value
    };

    class Matcher{
        static const std::regex field_regex;
        std::regex pattern;
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
        MatchKind kind;
        public:
        Matcher(const std::string& Field);
        bool matches(const std::string& Name, ulong index);
    };

    const std::regex Matcher::field_regex{
            "(?:^\\{(?:stem|s)(:.+)?\\}.\\{(?:ext|e)(:.+)?\\})$" // two tags: stem and extension, separated by . (1-2)
            "|(?:^\\{(?:(?:" // one tag:
                      "(name|n)" // name (3)
                      "|(stem|s)" // stem (4)
                      "|(ext|e))" // extension (5)
                    "(:.+)?" // optional wildcard expression (6)
                    "|(#\\d+))\\}$)" // module number (7)
                "|(\\{[^=,{}*]*\\*[^=,{}*]*\\}$)" // untagged wildcard expression (8)
    };

    static const std::regex name_regex{
        "(^\\.?[^.]+)" // stem
        "(?\\.(.*))?" // extension
    };

    typedef std::pair<std::string, std::string> Substitution;
    std::vector<Substitution> parse_input(const std::string& input);


    bool isMatch(const std::string& key, const std::string& modName, unsigned long i){
        if (key == ""){
            return true;
        }
        // split the name;
        std::smatch nameMatch;
        std::regex_search(modName,nameMatch,name_regex);
        std::sregex_iterator match_end;
        std::sregex_iterator match_begin(key.begin(), key.end(), field_regex);
        std::string substKey = key;
        for(auto miter = match_begin; miter != match_end; miter++){
            auto match = *miter;
            if (match[5] != ""){
                auto match_index = std::stoul(match[5].str());
                return match_index == i;
            }
            if (match[4].length() > 0){
                substKey = std::regex_replace(substKey, std::regex(match.str()),match[4].str());
                continue;
            } else {

            for (int i=0; i<3; i++){
                if (match[i+1] != ""){
                    auto part = nameMatch[i].str();
                    std::stringstream ss;
                    ss << "{" << match[i+1] << "}";
                    std::regex_replace(substKey,std::regex(ss.str()),part);
                    break;
                    };
                }
            }
        }
        return std::regex_match(modName,std::regex(substKey));
    }
    
    fs::path getPath(const std::string& path_template, const std::string& name, int i);

    fs::path getOutputFileName(const std::vector<Substitution>& subs, 
        const std::string& moduleName, int index){
        for (const auto & [key, value]: subs){
            if (isMatch(key, moduleName, index)){
                return getPath(value, moduleName, index);
            }
        }
        return moduleName;
    }


}

#endif
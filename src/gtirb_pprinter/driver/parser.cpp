#include "parser.hpp"

namespace gtirb_pprint {

    const std::regex Matcher::FieldRegex{
            R"((?:^\{(?:stem|s):(.+?)\}.\{(?:ext|e):(.+?)\})$)" // two tags: stem and extension, separated by . (1-2)
            R"(|(?:^\{(?:(?:)" // one tag:
                      "(name|n)" // name (3)
                      "|(stem|s)" // stem (4)
                      "|(ext|e))" // extension (5)
                    "(?::(.+))?" // optional wildcard expression (6)
                    R"(|(?:#(\d+)))\}$))" // module number (7)
                R"(|(?:\{([^=,{}]+)\}$))" // untagged wildcard expression (8)
    };

    const std::regex PathTemplate::Components{
        "\\{(?:" 
        "(name|n)"  // name (1)
        "|(stem|s)" // stem (2)
        "|(ext|e)"  // extension (3)
        ")\\}"}; 

    std::vector<Substitution> parseInput(const std::string& Input){    
        std::regex KvRegex{
            "(?:([^,=]+)=)?([^,=]+)" // (key=)value
        };
        std::sregex_iterator MatchEnd;
        std::sregex_iterator MatchBegin(Input.begin(), Input.end(), KvRegex);
        std::vector<Substitution> Subs;
        for (auto MIter=MatchBegin; MIter != MatchEnd; MIter++){
            auto Prefix = MIter->prefix().str();
            if (MIter != MatchBegin && ! std::regex_match(Prefix.begin(), Prefix.end(), std::regex("\\w*,\\w*"))){
                throw std::runtime_error("input must be either paths or key-value pairs, separated by commas");
            }
            Subs.emplace_back((*MIter)[1].str(), (*MIter)[2].str());
        }
        return Subs;
    }
    
    std::optional<fs::path> substitueOutputFileName(const std::vector<Substitution>& Subs, 
        const std::string& ModuleName, int I){
        for (const auto & [Match, PT]: Subs){
            if (Match.matches(ModuleName, I)){
                return PT.makePath(ModuleName);
            }
        }
        return {};
    }

    std::string WildcardStrToRegex(const std::string& WC){
        std::string Escaped = std::regex_replace(WC, std::regex("[{}().]"),R"(\$&)");
        return std::regex_replace(Escaped, std::regex("\\*"), "(.*)");
    }

    Matcher::Matcher(const std::string& Field): Kind(MatchKind::Literal), Pattern("(.*)"){
        std::smatch M;
        if (std::regex_match(Field,M,FieldRegex)){
            // kind
            if (M[1].matched || M[2].matched){
                Kind = MatchKind::StemExtension;
                // {stem}.{extension}
            } else if (M[3].matched || M[8].matched){
                // name
                Kind = MatchKind::Name;
            } else if (M[4].matched){
                // stem
                Kind = MatchKind::Stem;
            } else if (M[5].matched){
                Kind = MatchKind::Extension;
            } else if (M[7].matched){
                Kind = MatchKind::Number;
            }
            // pattern
            if (M[1].matched){
                Pattern = WildcardStrToRegex(M[1].str() + "." + M[2].str());
            } else if (M[3].matched || M[4].matched || M[5].matched){
                if (M[6].matched){
                    Pattern = WildcardStrToRegex(M[6].str());
                }
            } else if (M[7].matched){
                Pattern = M[7].str();
            } else if (M[8].matched){
                Pattern = WildcardStrToRegex(M[8].str());
            }
        } else if (Field.length() > 0) {
            Pattern =std::regex_replace(
               Field, std::regex("[{}().]"),"\\$&"
            );
        }
    };

    std::smatch parseName(const std::string& ModName){
        std::smatch ModNameComponents;
        std::regex NameRegex{
            "^(\\.?[^.]+)" // stem
            "(?:\\.(.*))?" // extension
        };
        std::regex_match(ModName,ModNameComponents,NameRegex);
        return ModNameComponents;
    }

    bool Matcher::matches(const std::string& Name, ulong Index) const{
        auto Components = parseName(Name);
        auto Stem = Components[1].str();
        auto Extension = Components[2].str();
        switch (Kind){
            case MatchKind::Number:
                return std::regex_match(std::to_string(Index),std::regex(Pattern));
            case MatchKind::Stem:
                return std::regex_match(Stem,std::regex(Pattern));
            case MatchKind::Extension:
                return std::regex_match(Extension, std::regex(Pattern));
            default: 
                return std::regex_match(Name,std::regex(Pattern));
        }
    }

    fs::path PathTemplate::makePath(const std::string& ModName) const{
        auto NameParts = parseName(ModName);
        std::string path;
        std::sregex_iterator ComponentsEnd;
        std::sregex_iterator ComponentsBegin(Spec.begin(), Spec.end(), Components);
        if (std::regex_match(Spec,std::regex(R"(\s*)"))){
            return fs::path(ModName);
        }
        int i=0;
        auto n = std::distance(ComponentsBegin, ComponentsEnd);
        if (n==0){
            return Spec;
        }
        for (auto MatchIter=ComponentsBegin; MatchIter != ComponentsEnd; i++,MatchIter++){
            auto Match = *MatchIter;
            path += Match.prefix();
            if (Match[1].matched){
                path += NameParts[0].str();
            } else if (Match[2].matched){
                path += NameParts[1].str();
            } else if (Match[3].matched){
                path += NameParts[2].str();
            }
            if (i+1 == n){
                path += Match.suffix().str();
            }
        }
        return fs::path(path);
    }
}
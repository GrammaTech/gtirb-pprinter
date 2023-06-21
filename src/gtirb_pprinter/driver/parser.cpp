#include "parser.hpp"

namespace gtirb_pprint {

    const std::regex Matcher::field_regex{
            R"((?:^\{(?:stem|s):(.+?)\}.\{(?:ext|e):(.+?)\})$)" // two tags: stem and extension, separated by . (1-2)
            R"(|(?:^\{(?:(?:)" // one tag:
                      "(name|n)" // name (3)
                      "|(stem|s)" // stem (4)
                      "|(ext|e))" // extension (5)
                    "(?::(.+))?" // optional wildcard expression (6)
                    R"(|(?:#(\d+)))\}$))" // module number (7)
                R"(|(?:\{([^=,{}]+)\}$))" // untagged wildcard expression (8)
    };

    const std::regex PathTemplate::components{
        "\\{(?:" 
        "(name|n)"  // name (1)
        "|(stem|s)" // stem (2)
        "|(ext|e)"  // extension (3)
        ")\\}"}; 

    std::vector<Substitution> parse_input(const std::string& input){    
        std::regex kv_regex{
            "(?:([^,=]+)=)?([^,=]+)" // (key=)value
        };
        std::sregex_iterator match_end;
        std::sregex_iterator match_begin(input.begin(), input.end(), kv_regex);
        std::vector<Substitution> subs;
        for (auto miter=match_begin; miter != match_end; miter++){
            auto prefix = miter->prefix().str();
            if (miter != match_begin && ! std::regex_match(prefix.begin(), prefix.end(), std::regex("\\w*,\\w*"))){
                throw std::runtime_error("input must be either paths or key-value pairs, separated by commas");
            }
            subs.emplace_back((*miter)[1].str(), (*miter)[2].str());
        }
        return subs;
    }
    
    std::optional<fs::path> substitueOutputFileName(const std::vector<Substitution>& subs, 
        const std::string& moduleName, int index){
        for (const auto & [Match, PT]: subs){
            if (Match.matches(moduleName, index)){
                return PT.makePath(moduleName);
            }
        }
        return {};
    }

    std::string WildcardStrToRegex(const std::string& WC){
        std::string escaped = std::regex_replace(WC, std::regex("[{}().]"),R"(\$&)");
        return std::regex_replace(escaped, std::regex("\\*"), "(.*)");
    }

    Matcher::Matcher(const std::string& Field): kind(MatchKind::Literal), pattern("(.*)"){
        std::smatch m;
        if (std::regex_match(Field,m,field_regex)){
            // kind
            if (m[1].matched || m[2].matched){
                kind = MatchKind::StemExtension;
                // {stem}.{extension}
            } else if (m[3].matched || m[8].matched){
                // name
                kind = MatchKind::Name;
            } else if (m[4].matched){
                // stem
                kind = MatchKind::Stem;
            } else if (m[5].matched){
                kind = MatchKind::Extension;
            } else if (m[7].matched){
                kind = MatchKind::Number;
            }
            // pattern
            if (m[1].matched){
                pattern = WildcardStrToRegex(m[1].str() + "." + m[2].str());
            } else if (m[3].matched || m[4].matched || m[5].matched){
                if (m[6].matched){
                    pattern = WildcardStrToRegex(m[6].str());
                }
            } else if (m[7].matched){
                pattern = m[7].str();
            } else if (m[8].matched){
                pattern = WildcardStrToRegex(m[8].str());
            }
        } else if (Field.length() > 0) {
            pattern =std::regex_replace(
               Field, std::regex("[{}().]"),"\\$&"
            );
        }
    };

    std::smatch parseName(const std::string& ModName){
        std::smatch ModNameComponents;
        std::regex name_regex{
            "^(\\.?[^.]+)" // stem
            "(?:\\.(.*))?" // extension
        };
        std::regex_match(ModName,ModNameComponents,name_regex);
        return ModNameComponents;
    }

    bool Matcher::matches(const std::string& Name, ulong Index) const{
        auto Components = parseName(Name);
        auto Stem = Components[1].str();
        auto Extension = Components[2].str();
        switch (kind){
            case MatchKind::Number:
                return std::regex_match(std::to_string(Index),std::regex(pattern));
            case MatchKind::Stem:
                return std::regex_match(Stem,std::regex(pattern));
            case MatchKind::Extension:
                return std::regex_match(Extension, std::regex(pattern));
            default: 
                return std::regex_match(Name,std::regex(pattern));
        }
    }

    fs::path PathTemplate::makePath(const std::string& ModName) const{
        auto Components = parseName(ModName);
        std::string path;
        std::sregex_iterator ComponentsEnd;
        std::sregex_iterator ComponentsBegin(spec.begin(), spec.end(), components);
        if (std::regex_match(spec,std::regex(R"(\s*)"))){
            return fs::path(ModName);
        }
        int i=0;
        auto n = std::distance(ComponentsBegin, ComponentsEnd);
        if (n==0){
            return spec;
        }
        for (auto MatchIter=ComponentsBegin; MatchIter != ComponentsEnd; i++,MatchIter++){
            auto Match = *MatchIter;
            path += Match.prefix();
            if (Match[1].matched){
                path += Components[0].str();
            } else if (Match[2].matched){
                path += Components[1].str();
            } else if (Match[3].matched){
                path += Components[2].str();
            }
            if (i+1 == n){
                path += Match.suffix().str();
            }
        }
        return fs::path(path);
    }
}
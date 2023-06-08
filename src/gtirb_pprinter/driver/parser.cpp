#include "parser.hpp"

namespace gtirb_pprint {

    std::vector<Substitution> parse_input(const std::string& input){
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


    Matcher::Matcher(const std::string& Field){
            std::smatch m;
            if (std::regex_match(Field,m,field_regex)){
                std::string patternStr;
                if ((m[1] != "" | )

            } else {
                // literal match
            }
        };

    bool Matcher::matches(const std::string& Name, ulong Index){
        switch (kind){
            case MatchKind::Number:
                return std::regex_match(std::to_string(Index),pattern);

        }
    }

}
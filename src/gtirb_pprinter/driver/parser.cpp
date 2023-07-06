#include "parser.hpp"

namespace gtirb_multimodule {

std::vector<Substitution> parseInput(const std::string& Input) {
  std::regex KvRegex{
      "(?:([^,=]+)=)?([^,=]+)" // (key=)value
  };
  std::sregex_iterator MatchEnd;
  std::sregex_iterator MatchBegin(Input.begin(), Input.end(), KvRegex);
  std::vector<Substitution> Subs;
  bool HasDefault = false;
  for (auto MIter = MatchBegin; MIter != MatchEnd; MIter++) {
    auto Prefix = MIter->prefix().str();
    if (MIter != MatchBegin && !std::regex_match(Prefix.begin(), Prefix.end(),
                                                 std::regex("\\w*,\\w*"))) {
      throw std::runtime_error(
          "input must be either paths or key-value pairs, separated by commas");
    }
    Subs.emplace_back((*MIter)[0].str());
    if (HasDefault && Subs.back().IsDefault){
      throw std::runtime_error("Only one default pattern allowed");
    }
  }
  return Subs;
}

std::optional<fs::path> getOutputFileName(const std::vector<Substitution>& Subs,
                                          const std::string& ModuleName) {
  for (const auto& Sub : Subs) {
    if (Sub.Match.matches(ModuleName)) {
      return std::regex_replace(ModuleName,std::regex(Sub.Match.Pattern),Sub.ReplacementPattern);
    }
  }
  return {};
}

Matcher::Matcher(
  std::string::const_iterator FieldBegin, std::string::const_iterator FieldEnd){
  /*
  Grammar for module patterns:

  MODULE ::= GLOB | GLOB GLOBS

  GLOB ::= NAMEDGLOB | ANONYMOUSGLOB

  NAMEDGLOB ::= '{' NAME ':' ANONYMOUSGLOB '}'

  NAME ::= alpha numeric characters, plus `_`

  ANONYMOUSGLOB ::= EXPR | EXPR EXPRS

  EXPR ::= '*' | '?' | LITERAL

  LITERAL ::= '\\' | '\*' | '\?' | '\=' | '\,' | '\{' | '\}' | '\['
            | any unescaped character except the special characters above

  */

  GroupIndexes["name"] = 0;
  GroupIndexes["n"] = 0;
  auto i = FieldBegin;
  State CurrentState = State::Glob;
  std::vector<std::string> GroupNames;
  std::regex WordChars("\\w|_");
  std::string SpecialChars("\\=,{}:*?");
  std::string NeedEscaping("[].+|<>()");
  bool OpenGroup = false;
  while(i != FieldEnd){
    if (CurrentState == State::Name){
      switch (*i){
        case ':':
          CurrentState = State::Glob;
          break;
        default:
          if (std::regex_match(i,i+1,WordChars)){
            GroupNames.back().push_back(*i);
          } else {
            throw std::runtime_error("Invalid character in group name: "+*i);
        }
      }
    } else if (CurrentState == State::Escape){
      for (auto c: SpecialChars){
        if (*i == c){
          Pattern.push_back(c);
          CurrentState = State::Glob;
          break;
        }
      }
      if (CurrentState != State::Glob){
        throw std::runtime_error("Invalid character in escape sequence: "+*i);
      }
    }
    else { // CurrentState == State::Glob
      switch (*i){
        case '{':
          // begin NAMEDGLOB
          CurrentState = State::Name;
          GroupNames.push_back("");
          if (OpenGroup){
            throw std::runtime_error("Invalid character in pattern: "+*i);
          }
          OpenGroup = true;
          Pattern.append("(");
          break;
        case '}':
          if (OpenGroup){
            Pattern.append(")");
            OpenGroup = false;  
            break;
          } else {
            throw std::runtime_error("Invalid character in pattern: "+*i);
          }
        case '*':
          Pattern.append(".*");
          break;
        case '?':
          Pattern.push_back('.');
          break;
        case '\\':
          Pattern.push_back('\\');
          CurrentState = State::Escape;
          break;
        default:
        for (auto c: NeedEscaping){
          if (*i == c){
            Pattern.push_back('\\');
            break;
          }
        }
        Pattern.push_back(*i);
      }
    };
    ++i;
  }
  if (OpenGroup){
    throw std::runtime_error("Unclosed '}'");
  }
  for (size_t s = 0; s < GroupNames.size(); s++){
    auto & Name = GroupNames[s];
    // if (GroupIndexes.count(Name) > 0){
    //   throw std::runtime_error("Duplicate group names not allowed");
    // }
    GroupIndexes[Name] = s+1;
  }
}

Matcher::Matcher(const std::string& Field): Matcher(Field.begin(), Field.end()){};

bool Matcher::matches(const std::string& Name) const {
    return std::regex_match(Name, std::regex(Pattern));
}

Substitution::Substitution(const std::string& Spec): 
  Match("*"), IsDefault(true){
  auto SpecIter = Spec.begin();
  bool Escape = false;
  while (SpecIter != Spec.end()){
    if (Escape){
      ++SpecIter;
      continue;
    }
    if (*SpecIter == '\\'){
      Escape=true;
    }

    if (*SpecIter=='='){
      Match = gtirb_multimodule::Matcher(Spec.begin(),SpecIter);
      IsDefault = false;
      ReplacementPattern = makeReplacementPattern(++SpecIter,Spec.end());
      return;
    }
    ++SpecIter;
  }
  ReplacementPattern = makeReplacementPattern(Spec);
}

std::string Substitution::makeReplacementPattern(std::string::const_iterator PBegin,
std::string::const_iterator PEnd){
  State CurrentState = State::Name;
  std::string Pattern;
  std::string GroupName;
  for (auto I = PBegin; I != PEnd; I++){
    if (CurrentState == State::Name){
      switch (*I){
        case '{':
          CurrentState = State::Glob;
          GroupName = "";
          continue;
        case '\\':
          CurrentState = State::Escape;
          continue;
        default: 
          Pattern.push_back(*I);
      }
    } else if (CurrentState == State::Glob){
      if (*I == '}'){
        auto GroupIndexesIter = Match.GroupIndexes.find(GroupName);
        if (GroupIndexesIter == Match.GroupIndexes.end()){
          throw std::runtime_error("Undefined group: "+ GroupName);
        }
        Pattern.push_back('$');
        Pattern.append(std::to_string(GroupIndexesIter->second));
        CurrentState = State::Name;
      }
      else {
        GroupName.push_back(*I);
      }
    } else if (CurrentState == State::Escape){
      for (auto c: std::string("[].+|<>()") ){
        if (*I == c){
          Pattern.append("\\"+*I);
          break;
          }
        }
        if (*I == '{' || *I == '}'){
            Pattern.push_back(*I);
        } else {
          throw std::runtime_error("Unknown escape character: "+*I);
        };
      CurrentState = State::Name;
      }
    }
    return Pattern;
   }

std::string Substitution::makeReplacementPattern(const std::string& P){
  return makeReplacementPattern(P.begin(), P.end());
}

std::string Substitution::substitute(const std::string& P){
  std::regex MatchRegex(Match.Pattern);
  return std::regex_replace(P,MatchRegex,ReplacementPattern);
}


} // namespace gtirb_multimodule

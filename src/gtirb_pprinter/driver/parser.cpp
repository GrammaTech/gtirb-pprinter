#include "parser.hpp"
using namespace std::literals;

namespace gtirb_multimodule {

std::vector<Substitution> parseInput(const std::string& Input) {
  std::vector<Substitution> Subs;
  int NDefaults = 0;
  bool Escaped = false;
  auto Start = Input.begin();
  for (auto In = Input.begin(); In != Input.end(); In++) {
    if (Escaped) {
      continue;
    }
    if (*In == '\\') {
      Escaped = true;
      continue;
    }
    if (*In == ',') {
      Subs.emplace_back(Start, In);
      if (Subs.back().IsDefault) {
        NDefaults++;
        if (NDefaults > 1) {
          throw std::runtime_error("Only one default pattern allowed");
        }
      }
      Start = In + 1;
    }
  }
  Subs.emplace_back(Start, Input.end());
  return Subs;
}

std::optional<fs::path> getOutputFileName(const std::vector<Substitution>& Subs,
                                          const std::string& ModuleName) {
  for (const auto& Sub : Subs) {
    if (auto M = Sub.Match.matches(ModuleName)) {
      return fs::path(M->format(Sub.ReplacementPattern));
    }
  }
  return {};
}

Matcher::Matcher(std::string::const_iterator FieldBegin,
                 std::string::const_iterator FieldEnd) {
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
  while (i != FieldEnd) {
    if (CurrentState == State::Name) {
      switch (*i) {
      case ':':
        CurrentState = State::Glob;
        break;
      default:
        if (std::regex_match(i, i + 1, WordChars)) {
          GroupNames.back().push_back(*i);
        } else {
          throw std::runtime_error("Invalid character in group name: "s + *i);
        }
      }
    } else if (CurrentState == State::Escape) {
      for (auto c : SpecialChars) {
        if (*i == c) {
          Pattern.push_back(c);
          CurrentState = State::Glob;
          break;
        }
      }
      if (CurrentState != State::Glob) {
        throw std::runtime_error("Invalid character in escape sequence: "s +
                                 *i);
      }
    } else { // CurrentState == State::Glob
      switch (*i) {
      case '{':
        // begin NAMEDGLOB
        CurrentState = State::Name;
        GroupNames.push_back("");
        if (OpenGroup) {
          throw std::runtime_error("Invalid character in pattern: "s + *i);
        }
        OpenGroup = true;
        Pattern.append("(");
        break;
      case '}':
        if (OpenGroup) {
          Pattern.append(")");
          OpenGroup = false;
          break;
        } else {
          throw std::runtime_error("Invalid character in pattern: "s + *i);
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
        for (auto c : NeedEscaping) {
          if (*i == c) {
            Pattern.push_back('\\');
            break;
          }
        }
        Pattern.push_back(*i);
      }
    };
    ++i;
  }
  if (OpenGroup) {
    throw std::runtime_error("Unclosed '}'");
  }
  for (size_t s = 0; s < GroupNames.size(); s++) {
    auto& Name = GroupNames[s];
    // if (GroupIndexes.count(Name) > 0){
    //   throw std::runtime_error("Duplicate group names not allowed");
    // }
    GroupIndexes[Name] = s + 1;
  }
}

Matcher::Matcher(const std::string& Field)
    : Matcher(Field.begin(), Field.end()){};

std::optional<std::smatch> Matcher::matches(const std::string& Name) const {
  std::smatch M;
  bool IsMatch = std::regex_match(Name, M, std::regex(Pattern));
  if (IsMatch) {
    return M;
  } else {
    return {};
  }
}

Substitution::Substitution(std::string::const_iterator SpecBegin,
                           std::string::const_iterator SpecEnd)
    : Match("*"), IsDefault(true) {
  auto SpecIter = SpecBegin;
  bool Escape = false;
  while (SpecIter != SpecEnd) {
    if (Escape) {
      ++SpecIter;
      continue;
    }
    if (*SpecIter == '\\') {
      Escape = true;
    }

    if (*SpecIter == '=') {
      Match = gtirb_multimodule::Matcher(SpecBegin, SpecIter);
      IsDefault = false;
      ReplacementPattern = makeReplacementPattern(++SpecIter, SpecEnd);
      return;
    }
    ++SpecIter;
  }
  ReplacementPattern = makeReplacementPattern(SpecBegin, SpecEnd);
}

std::string
Substitution::makeReplacementPattern(std::string::const_iterator PBegin,
                                     std::string::const_iterator PEnd) {
  auto SpecialChars = "{}\\=,"s;
  State CurrentState = State::Name;
  std::string Pattern;
  std::string GroupName;
  for (auto I = PBegin; I != PEnd; I++) {
    if (CurrentState == State::Name) {
      switch (*I) {
      case '{':
        CurrentState = State::Glob;
        GroupName = "";
        continue;
      case '\\':
        CurrentState = State::Escape;
        continue;
      case '$':
        Pattern.append("$$");
        continue;
      default:
        Pattern.push_back(*I);
        continue;
      }
    } else if (CurrentState == State::Glob) {
      if (*I == '}') {
        auto GroupIndexesIter = Match.GroupIndexes.find(GroupName);
        if (GroupIndexesIter == Match.GroupIndexes.end()) {
          throw std::runtime_error("Undefined group: "s + GroupName);
        }
        auto GI = GroupIndexesIter->second;
        Pattern.push_back('$');
        if (GI == 0) {
          Pattern.push_back('&');
        } else {
          Pattern.append(std::to_string(GroupIndexesIter->second));
        }
        CurrentState = State::Name;
      } else {
        GroupName.push_back(*I);
      }
    } else if (CurrentState == State::Escape) {
      for (auto& C : SpecialChars) {
        if (*I == C) {
          Pattern.push_back(C);
          CurrentState = State::Name;
          continue;
        }
      }
      Pattern.push_back('\\');
      if (*I == '$') {
        Pattern.push_back('$');
      }
      Pattern.push_back(*I);
      CurrentState = State::Name;
    }
  }
  return Pattern;
}

Substitution::Substitution(const std::string& Spec)
    : Substitution(Spec.begin(), Spec.end()){};

std::string Substitution::makeReplacementPattern(const std::string& P) {
  return makeReplacementPattern(P.begin(), P.end());
}

std::string Substitution::substitute(const std::string& P) {
  std::regex MatchRegex(Match.Pattern);
  return std::regex_replace(P, MatchRegex, ReplacementPattern);
}

} // namespace gtirb_multimodule

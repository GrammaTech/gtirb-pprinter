#include "parser.hpp"

using namespace std::literals;

namespace gtirb_multimodule {

std::string quote(char C){
  static const std::string NeedEscapingForRegex("^$\\.*+?()[]{}|");
  if (NeedEscapingForRegex.find(C) != std::string::npos){
    return "\\"s + C;
  } else return ""s + C;
}


std::optional<fs::path> getOutputFileName(const std::vector<FilePattern>& Subs,
                                          const std::string& ModuleName) {
  for (const auto& Sub : Subs) {
    if (auto Path = Sub.substitute(ModuleName)) {
      return fs::path(*Path);
    }
  }
  return {};
}

std::vector<FilePattern> parseInput(const std::string& Input) {
  std::vector<FilePattern> Subs;
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
      if (Subs.back().isDefault()) {
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

FilePattern::FilePattern(std::string::const_iterator SpecBegin,
                         std::string::const_iterator SpecEnd)
    : Match("*"), IsDefault(true) {
  /**
   * Grammar for substitutions:
   *
   * SUB := FILE | MODULE=FILE
   *
   *
   */
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
FilePattern::makeReplacementPattern(std::string::const_iterator PBegin,
                                    std::string::const_iterator PEnd) {
  /**
   * Grammar for file patterns:
   *
   * FILE := TERM | TERM TERMS
   * TERM := {NAME} | LITERAL
   * NAME := any alphanumeric character or `_`
   * LITERAL := \{ | \, | \= | \\ | any unescaped character
   *
   * `\` only needs to be escaped when it would otherwise form an escape
   * sequence
   */
  std::string SpecialChars{"{,=\\"};
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
      if (SpecialChars.find(*I) != std::string::npos){
        Pattern.push_back(*I);
      } else {
        Pattern.push_back('\\');
        --I;
      }
      CurrentState = State::Name;
    }
  }
  return Pattern;
}

std::optional<std::string> FilePattern::substitute(const std::string& P) const {
  if (auto M = Match.matches(P)) {
    return M->format(ReplacementPattern);
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
  std::string SpecialChars{"\\=,{}:*?"};

  GroupIndexes["name"] = 0;
  GroupIndexes["n"] = 0;
  State CurrentState = State::Glob;
  std::vector<std::string> GroupNames;
  std::regex WordChars("\\w", std::regex::optimize);
  bool OpenGroup = false;
  for (auto i = FieldBegin; i!= FieldEnd; i++) {
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
      if (SpecialChars.find(*i) != std::string::npos){
          RegexStr.append(quote(*i));
      } else {
        RegexStr.append("\\\\");
        --i;
      }
      CurrentState = State::Glob;
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
        RegexStr.push_back('(');
        break;
      case '}':
        if (OpenGroup) {
          RegexStr.push_back(')');
          OpenGroup = false;
        } else {
          RegexStr.append("\\}");
        }
          break;
      case '*':
        RegexStr.append(".*");
        break;
      case '?':
        RegexStr.push_back('.');
        break;
      case '\\':
        CurrentState = State::Escape;
        break;
      default:
        RegexStr.append(quote(*i));
      }
    };
  }
  if (OpenGroup) {
    throw std::runtime_error("Unclosed '{' in group"s + GroupNames.back());
  }
  for (size_t s = 0; s < GroupNames.size(); s++) {
    auto& Name = GroupNames[s];
    GroupIndexes[Name] = s + 1;
  }
}

std::optional<std::smatch> Matcher::matches(const std::string& Name) const {
  std::smatch M;
  bool IsMatch = std::regex_match(Name, M, std::regex(RegexStr));
  if (IsMatch) {
    return M;
  } else {
    return {};
  }
}

} // namespace gtirb_multimodule

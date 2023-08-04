#include "parser.hpp"
#include <iomanip>

using namespace std::literals;

namespace gtirb_pprint_parser {

std::string quote(char C) {
  static const std::string NeedEscapingForRegex("^$\\.*+?()[]{}|");
  if (NeedEscapingForRegex.find(C) != std::string::npos) {
    return "\\"s + C;
  } else
    return ""s + C;
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

enum class State {
  Name,
  Glob,
  Escape,
};

/**
 * Grammar for substitutions:
 * INPUT := SUB | SUB,SUBS
 * SUB := FILE | MODULE=FILE
 *
 */

std::vector<FilePattern> parseInput(const std::string& Input) {
  /**
   * @brief Parse a string into a list of substitutions to be made
   *
   * Substitution patterns are presumed to be separated by commas;
   * literal commas need to be escaped
   *
   */
  std::vector<FilePattern> Subs;
  bool Escaped = false;
  auto Start = Input.begin();
  for (auto In = Input.begin(); In != Input.end(); In++) {
    if (Escaped) {
      Escaped = false;
      continue;
    }
    if (*In == '\\') {
      Escaped = true;
      continue;
    }
    if (*In == ',') {
      Subs.emplace_back(Start, In);
      Start = In + 1;
    }
  }
  Subs.emplace_back(Start, Input.end());
  return Subs;
}

FilePattern::FilePattern(std::string::const_iterator SpecBegin,
                         std::string::const_iterator SpecEnd)
    : MPattern{".*", {{"name", 0}, {"n", 0}}} {
  auto SpecIter = SpecBegin;
  bool Escape = false;
  while (SpecIter != SpecEnd) {
    if (Escape) {
      ++SpecIter;
      Escape = false;
      continue;
    }
    if (*SpecIter == '\\') {
      Escape = true;
    }

    if (*SpecIter == '=') {
      MPattern = makePattern(SpecBegin, SpecIter);
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
  std::string SpecialChars{"{\\,="};
  State CurrentState = State::Name;
  std::string Pattern;
  std::string GroupName;
  for (auto I = PBegin; I != PEnd; I++) {
    if (CurrentState == State::Name) {
      switch (*I) {
      case '{':
        CurrentState = State::Glob;
        continue;
      case '\\':
        CurrentState = State::Escape;
        continue;
      case '$':
        Pattern.append("$$");
        continue;
      case ',':
      case '=':
        throw parse_error("Character "s + *I + " must be escaped");
      default:
        Pattern.push_back(*I);
        continue;
      }
    } else if (CurrentState == State::Glob) {
      if (auto J = std::find(I, PEnd, '}'); J != PEnd) {
        GroupName = std::string(I, J);
        auto GroupIndexesIter = MPattern.GroupIndexes.find(GroupName);
        if (GroupIndexesIter == MPattern.GroupIndexes.end()) {
          throw parse_error("Undefined group: {"s + GroupName + "}");
        }
        auto GI = GroupIndexesIter->second;
        Pattern.push_back('$');
        if (GI == 0) {
          Pattern.push_back('&');
        } else if (GI < 10) {
          Pattern.append("0"s + std::to_string(GI));
        } else {
          Pattern.append(std::to_string(GI));
        }
        CurrentState = State::Name;
        I = J;
      } else {
        throw parse_error("Unclosed `{` in file template");
      }
    } else if (CurrentState == State::Escape) {
      if (SpecialChars.find(*I) != std::string::npos) {
        Pattern.push_back(*I);
      } else {
        Pattern.push_back('\\');
        --I;
      }
      CurrentState = State::Name;
    }
  }
  if (CurrentState == State::Escape) { // Terminal character is '\'
    Pattern.push_back('\\');
  }
  return Pattern;
}

std::optional<std::string> FilePattern::substitute(const std::string& P) const {
  if (auto M = matches(P)) {
    return M->format(ReplacementPattern);
  }
  return {};
}

ModulePattern makePattern(std::string::const_iterator FieldBegin,
                          std::string::const_iterator FieldEnd) {
  /*
  Grammar for module patterns:

  MODULE ::= GLOB | GLOB GLOBS

  GLOB ::= NAMEDGLOB | ANONYMOUSGLOB

  NAMEDGLOB ::= '{' NAME ':' ANONYMOUSGLOB '}'

  NAME ::= alpha numeric characters, plus `_`

  ANONYMOUSGLOB ::= EXPR | EXPR EXPRS

  EXPR ::= '*' | '?' | LITERAL

  LITERAL ::= '\\' | '\*' | '\?' | '\=' | '\,' | '\{' | '\}' | '\[' | '\]'
            | any unescaped character except the special characters above

  */
  ModulePattern Pattern;
  Pattern.GroupIndexes["name"] = 0;
  Pattern.GroupIndexes["n"] = 0;

  std::string SpecialChars{"\\=,{}:*?[]"};
  State CurrentState = State::Glob;
  std::vector<std::string> GroupNames;
  std::regex WordChars("^\\w+", std::regex::optimize);
  bool OpenGroup = false;
  for (auto i = FieldBegin; i != FieldEnd; i++) {
    if (CurrentState == State::Name) {
      std::smatch M;
      std::regex_search(i, FieldEnd, M, WordChars);
      GroupNames.push_back(M.str());
      i += M.str().length();
      if (i == FieldEnd) {
        throw parse_error("Unclosed '{' in group "s + GroupNames.back());
      }
      if (*i != ':') {
        throw parse_error("Invalid character in group name: '"s + *i + "'");
      }
      if (M.str().length() == 0) {
        throw parse_error("All groups must be named");
      }
      CurrentState = State::Glob;
    } else if (CurrentState == State::Escape) {
      if (SpecialChars.find(*i) != std::string::npos) {
        Pattern.RegexStr.append(quote(*i));
      } else {
        Pattern.RegexStr.append("\\\\");
        --i;
      }
      CurrentState = State::Glob;
    } else { // CurrentState == State::Glob
      switch (*i) {
      case '{':
        // begin NAMEDGLOB
        CurrentState = State::Name;
        if (OpenGroup) {
          throw parse_error("Invalid character in pattern: "s + *i);
        }
        OpenGroup = true;
        Pattern.RegexStr.push_back('(');
        break;
      case '}':
        if (OpenGroup) {
          Pattern.RegexStr.push_back(')');
          OpenGroup = false;
        } else {
          Pattern.RegexStr.append("\\}");
        }
        break;
      case '*':
        Pattern.RegexStr.append(".*");
        break;
      case '?':
        Pattern.RegexStr.push_back('.');
        break;
      case '\\':
        CurrentState = State::Escape;
        break;
      default:
        Pattern.RegexStr.append(quote(*i));
      }
    };
  }
  if (OpenGroup) {
    throw parse_error("Unclosed '{' in group"s + GroupNames.back());
  }
  for (size_t s = 0; s < GroupNames.size(); s++) {
    auto& Name = GroupNames[s];
    Pattern.GroupIndexes[Name] = s + 1;
  }
  return Pattern;
}

} // namespace gtirb_pprint_parser

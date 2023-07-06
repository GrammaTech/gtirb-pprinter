#ifndef GTPPRINT_PARSER_H
#define GTPPRINT_PARSER_H
#include <boost/filesystem.hpp>
#include <optional>
#include <regex>
#include <string_view>

namespace fs = boost::filesystem;

namespace gtirb_multimodule {

static const std::string_view module_help_message{
    "PRINTING MULTIPLE MODULES\n\n"
    "Filenames are specified as "
    "[MODULE_PATTERN1=]FILE_PATTERN1[,MODULE_PATTERN2=FILE_PATTERN2...]."
    "FILE_PATTERN is the name of a path, with one or more selectors. When "
    "printing each module,"
    "the selector will be replaced by the appropriate portion of the module "
    "name\n"
    "MODULE_PATTERN can be: \n"
    "- The name of a module\n"
    "- A wildcard pattern matching one or more modules, e.g. lib*.so*\n"
    "- A selector followed by a wildcard pattern, e.g {ext:so*}."
    "The available selectors are: \n"
    "{name}: the full module name\n"
    "{stem}: the portion of the module name before the first '.';"
    "For example, if the module is named 'libc.so.6', the stem would be "
    "'libc'\n"
    "{ext}: the portion of the module name after the first '.'."
    "For example, if the module is named 'libc.so.6', the extension would be "
    "'so.6'\n"
    "For matching, the {stem} and {ext} selectors can be used together: "
    "{stem:lib*}.ext:{so*}"};

struct Matcher {
  std::map<std::string, size_t> GroupIndexes;
  std::string Pattern;

  Matcher(std::string::const_iterator Begin, std::string::const_iterator End);
  Matcher(const std::string& Field);
  bool matches(const std::string& Name) const;
};

enum class State {
    Name,
    Glob,
    Escape,
};


struct Substitution {
  Matcher Match;
  Substitution(const std::string& Spec);
  bool IsDefault;
  std::string ReplacementPattern;
  std::string makeReplacementPattern(std::string::const_iterator PBegin,
    std::string::const_iterator PEnd);
  std::string makeReplacementPattern(const std::string& P);
  std::string substitute(const std::string& Name);
};

std::vector<Substitution> parseInput(const std::string& Input);

std::optional<fs::path> getOutputFileName(const std::vector<Substitution>& Subs,
                                          const std::string& ModuleName);

} // namespace gtirb_multimodule

#endif

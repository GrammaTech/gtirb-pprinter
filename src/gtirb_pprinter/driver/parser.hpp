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
    "MODULE_PATTERN1=FILE_PATTERN1[,MODULE_PATTERN2=FILE_PATTERN2...]."
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
  enum class MatchKind {
    Literal,
    Name,
    Stem,
    Extension,
    StemExtension,
  };
  static const std::regex FieldRegex;
  MatchKind Kind;
  std::string Pattern;
  Matcher(const std::string& Field);
  bool matches(const std::string& Name) const;
};

struct PathTemplate {
  static const std::regex Components;
  std::string Spec;
  PathTemplate(const std::string& S) : Spec(S){};
  fs::path makePath(const std::string& ModuleName) const;
};

typedef std::pair<Matcher, PathTemplate> Substitution;
std::vector<Substitution> parseInput(const std::string& Input);

std::optional<fs::path> getOutputFileName(const std::vector<Substitution>& Subs,
                                          const std::string& ModuleName);

} // namespace gtirb_multimodule

#endif

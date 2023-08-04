#ifndef GTPPRINT_PARSER_H
#define GTPPRINT_PARSER_H
#include <boost/filesystem.hpp>
#include <optional>
#include <regex>
#include <string_view>

namespace fs = boost::filesystem;

namespace gtirb_pprint_parser {

/**
 * @file Defines the syntax for the command-line arguments
 * defining the final assembly or binary file. See below for
 * details
 */

static const std::string_view module_help_message{R"""(
The options `--asm` and `--binary` both accept arguments of the
following form:

  [module pattern 1=]file template 1[,[module pattern 2=]file template 2]...

Since the syntax for file templates and module patterns is very similar to
what many shells use for file expansion, one should typically enclose the
entire argument in quotes.

Each file template describes a path the file may be written to, and can
be either:

 1. A filename. Each module will be written to that file. If an IR has
    more than one module, this will raise an error.

 2. A template of filenames, based on the module name.

    If the file template has a corresponding
    module pattern (see below), the capture groups from that pattern
    can be also be used in the template. Each module will be written
    to the first file template with a module pattern that matches its
    name. The groups `{name}` and `{n}` can always be used as placeholders
    for the entire module name in a file template: `my_dir/{n}_rewritten`

The characters `{`, `,`, and `=` need to be escaped in all file templates
by preceding them with a `\`. The character `\` needs
to be escaped if it would otherwise be the beginning of an
escape sequence, otherwise it is treated literally.


A file template can optionally be preceded by a module pattern, with an `=`
joining the two. A module pattern describes which modules will be printed
to the file described by its file template. It may contain the following:

1.  Ordinary text. All whitespace is considered as a part of the pattern.
    The following characters need to be escaped in module patterns,
    by preceding them with a `\`:

      `[`, `]`, `{`, `}`, `\`, `=`, `,`, `*`, and `?`

2.  Wildcards. The wildcard character `?` will match any single character, and
    the wildcard character `*` will match any number of characters.

    For example: the module pattern `lib?.so*` will match a module named
    `libc.so` or `libc.so.6`, but not modules named `myexe` or `libfoobar.so`.
    The module pattern `hello` will only match a module named `hello`, and no others.

3.  Named capture groups. A portion of a module pattern can be enclosed in curly
    braces and given a name, as in `{libname:lib*}`. These groups can then be
    referenced in the module pattern's corresponding file template.

    For example:

        `lib{stem:*}.{ext:so*}=libs/{stem}.rewritten.{ext}`

    will print the module `libfoo.so.1` to `libs/libfoo.rewritten.so.1`, with
    the group `{stem}` matching `foo` and the group `{ext}` matching `so.1`.

    Only letters, numbers, and `_` are allowed in group names.

)"""};

class FileTemplateRule;

/**
 * @brief Turn a command-line argument into a list of file patterns
 *
 * @param Input
 * @return std::vector<FilePattern>
 */
std::vector<FileTemplateRule> parseInput(const std::string& Input);

/**
 * @brief Produce a filename from the first pattern that matches
 * the module name
 *
 * @param Subs
 * @param ModuleName
 * @return std::optional<fs::path>
 */
std::optional<fs::path>
getOutputFileName(const std::vector<FileTemplateRule>& Subs,
                  const std::string& ModuleName);

/**
 * @brief Translates a wildcard expression, given by the user,
 *  into a regular expression for matching and parsing module names
 *
 */
struct ModulePattern {
  std::string RegexStr;
  std::map<std::string, size_t> GroupIndexes;

  /// Returns a match group that matches the pattern in Name,
  /// or std::nullopt if there is no match
  std::optional<std::smatch> matches(const std::string& Name) const {
    std::smatch Match;
    std::regex ModuleRegex{RegexStr};
    if (std::regex_match(Name, Match, ModuleRegex)) {
      return Match;
    }
    return {};
  }
};

/**
 * @brief Translates a character sequence representing a module pattern
 * into an ECMAScript regex, along with a map from names to
 * group numbers
 *
 * @param Begin An iterator pointing to the beginning of the sequence
 * @param End An iterator pointing to one past the end of the sequence
 * @return ModulePattern
 */
ModulePattern makePattern(std::string::const_iterator Begin,
                          std::string::const_iterator End);

/**
 * @brief Represents a rule for turning module names into file names,
 * consisting of a file template and a module pattern
 */

class FileTemplateRule {
  ModulePattern MPattern;

  std::string FileTemplate;
  std::string makeFileTemplate(std::string::const_iterator PBegin,
                               std::string::const_iterator PEnd);
  std::string makeFileTemplate(const std::string& P) {
    return makeFileTemplate(P.begin(), P.end());
  };
  std::optional<std::smatch> matches(const std::string& Name) const {
    return MPattern.matches(Name);
  }

public:
  /**
   * @brief Construct a new File Template object by iterating through
   * a string
   *
   * @param SpecBegin
   * @param SpecEnd
   */
  FileTemplateRule(std::string::const_iterator SpecBegin,
                   std::string::const_iterator SpecEnd);

  /**
   * @brief Returns the path for a module named `Name` if
   * `Name` matches the module pattern, or `std::nullopt` if it doesn't.
   *
   * @param Name
   * @return std::optional<std::string>
   */
  std::optional<std::string> substitute(const std::string& Name) const;
};

struct parse_error : public std::runtime_error {
  template <typename... Args>
  parse_error(Args&&... args) : std::runtime_error(args...){};
};

} // namespace gtirb_pprint_parser

#endif // GPPRINT_PARSER_H

#ifndef GTPPRINT_PARSER_H
#define GTPPRINT_PARSER_H
#include <boost/filesystem.hpp>
#include <optional>
#include <regex>
#include <string_view>

namespace fs = boost::filesystem;

namespace gtirb_pprint_parser {

/**
 * @brief This module defines the syntax for the command-line arguments
 * defining the final assembly or binary file. See below for
 * details
 */

static const std::string_view module_help_message{R"""(
 The arguments `--asm` and `--binary` both use a a shell-like syntax
 for users to specify which file each module in the IR will be printed to.

 You can pass these arguments the following:

 1. A filename. Each module will be written to that file. If an IR has
   more than one module, this will raise an error.

 2. A pattern of filenames, based on the module name.
    Use {name} or {n} as a placeholder for the module name, as in:
    `my_dir/{n}_rewritten`. One file will be written for each module.

    The characters `{`, `,`, and `=` need to be escaped in file names
    and patterns by preceding them with a `\`. The character `\` needs
    to be escaped if it would otherwise be the beginning of an
    escape sequence.

 3. A module pattern followed by a filename pattern,
    to specify which modules in an IR should be printed following that
    pattern. Module patterns use `*` to match any number of characters,
    and `?` to match any single character. For example:  `lib*.so*=libs/{name}`
    will print a module named `libfoo.so` to `libs/libfoo.so`, and
    `libc.so.6` to `libs/libc.so.6`, but will skip modules named
    `myexe` or `mylibrary.dll`. A module pattern can also just match a single name:
    `hello=bin/hello` will print the module named `hello` and no others.

    The following characters need to be escaped in module patterns,
    by preceding them with a `\`:

    `[`,`]`,`{`,`}`, `\`,`=`,`,`,`*`, and `?`

    You can name different groups in a module pattern and use them
    in the file pattern. For example:
    `lib{stem:*}.{ext:so*}=libs/{stem}.rewritten.{ext}` will print the module
    `libfoo.so.1` to `libs/libfoo.rewritten.so.1` -- the group `{stem}`
    matches `foo`, and the group `{ext}` matches `so.1`.

    Only letters, numbers, and `_` are allowed in group names.

 4. A list of filename patterns, with or without corresponding module patterns,
    separated by commas. Each module in the IR will be printed to the first
    pattern that matches its name; a file pattern with no module pattern
    matches everything.

    Example:
    `hello=hello,libhello.so=libs/{n}` will print the module named `hello`
    to the file `hello`, the module `libhello.so` to the file `libs/libhello.so`,
    and ignore any other modules.

 All whitespace is considered as part of a name or pattern.

 Since these arguments use symbols that get expanded by most shells, you should
 put them in quotes.

)"""};

class FilePattern;

/**
 * @brief Turn a command-line argument into a list of file patterns
 *
 * @param Input
 * @return std::vector<FilePattern>
 */
std::vector<FilePattern> parseInput(const std::string& Input);

/**
 * @brief Produce a filename from the first pattern that matches
 * the module name
 *
 * @param Subs
 * @param ModuleName
 * @return std::optional<fs::path>
 */

std::optional<fs::path> getOutputFileName(const std::vector<FilePattern>& Subs,
                                          const std::string& ModuleName);

/**
 * @brief Translates a wildcard expression, given by the user,
 *  into a regular expression for matching and parsing module names
 *
 */
struct ModulePattern {
  std::string RegexStr;
  std::map<std::string, size_t> GroupIndexes;
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
 * @brief Represents a rule for turning module names into file names
 *
 */
class FilePattern {
  ModulePattern MPattern;

  std::string ReplacementPattern;
  std::string makeReplacementPattern(std::string::const_iterator PBegin,
                                     std::string::const_iterator PEnd);
  std::string makeReplacementPattern(const std::string& P) {
    return makeReplacementPattern(P.begin(), P.end());
  };
  std::optional<std::smatch> matches(const std::string& Name) const {
    return MPattern.matches(Name);
  }

public:
  FilePattern(std::string::const_iterator SpecBegin,
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

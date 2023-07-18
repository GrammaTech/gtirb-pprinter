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
 * defining the final assembly or binary file. See `--help-modules` for
 * details
 */

static const std::string_view module_help_message{R"""(
 The arguments `--asm` and `--binary` both use a a shell-like
 syntax for users to specify which file each module in the IR
 will be printed to.

 You can pass these arguments the following:

 1. A filename. Each module will be written to that file.
    If there's only one module in your IR, great!
    If not, the last module (by name, alphabetically)
    will be the one written to that file at the end,
    which is probably not what you wanted

 2. A pattern of filenames, based on the module name.
    Use {name} or {n} as a placeholder for the module name, as in:
    `my_dir/{n}_rewritten`. One file will be written for each module.

    The characters `{`, `,`, and `=` need to be escaped in file names
    and patterns by preceding them with a `\`. The character `\` needs
    to be escaped if it would otherwise be the beginning of an
    escape sequence.

 3. You can use a wildcard expression to only print modules with a
    certain kind of name. For example:  `lib*.so*=libs/{name}`
    will print a module named `libfoo.so` to `libs/libfoo.so`, and
    `libc.so.6` to `libs/libc.so.6`, but will skip modules named
    `myexe` or `mylibrary.dll`. You can also use `?` to match any
    single character. Wildcards can also just match a single name:
    `hello=bin/hello` will print the module named `hello` and no others.

    The following characters need to be escaped in wildcards,
    by preceding them with a `\`:

    `[`,`]`,`{`,`}`, `\`,`=`,`,`,`*`, and `?`

 4. You can name different parts of your wildcard expression, and use them
    in your file pattern. For example:
    `lib{stem:*}.{ext:so*}=libs/{stem}.rewritten.{ext}` will print the module
    `libfoo.so.1` to `libs/libfoo.rewritten.so.1`. Only letters, numbers, and
    `_` are allowed in group names.

 5. You can use commas to separate multiple patterns. Each module will use the
    first pattern that it matches.

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
 * @brief Translates a string representing a module pattern
 * into an ECMAScript regex, along with a map from names to
 * group numbers
 *
 * @param Begin
 * @param End
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

} // namespace gtirb_multimodule

#endif // GPPRINT_PARSER_H

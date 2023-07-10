#ifndef GTPPRINT_PARSER_H
#define GTPPRINT_PARSER_H
#include <boost/filesystem.hpp>
#include <optional>
#include <regex>
#include <string_view>

namespace fs = boost::filesystem;

namespace gtirb_multimodule {

/**
 * @brief This module defines the syntax for the command-line arguments
 * defining the final assembly or binary file.
 *
 * You can pass these arguments the following:
 *
 * 1. A filename. Each module will be written to that file. If there's only
 *    one module in your IR, great! If not, the last module (by name,
 * alphabetically) will be the one written to that file at the end, which is
 * probably not what you wanted
 *
 * 2. A pattern of filenames, based on the module name.
 *    Use {name} or {n} as a placeholder for the module name, as in:
 * `my_dir/{n}_rewritten`. One file per module will be written per module.
 *
 *    The characters `{`, `,`, and `=` need to be escaped in file names and
 * patterns by preceding them with a `\`. The character `\` needs to be escaped
 * if it would otherwise be the beginning of an escape sequence.
 *
 * 3. You can use a wildcard expression to only print modules with a certain
 * kind of name. For example: `lib*.so*=libs/{name}` will print a module module
 * named `libfoo.so` to `libs/libfoo.so`, and `libc.so.6` to `libs/libc.so.6`,
 * but will skip modules named `myexe` or `mylibrary.dll`. You can also use `?`
 * to match any single character. "Wildcards" can also just match a single name:
 * `hello=bin/hello` will print the module named `hello` and no others.
 *
 *    The following characters need to be escaped in wildcards, by preceding
 * them with a `\`:
 *    `[`,`]`,`{`,`}`, `\`,`=`,`,`,`*`, and `?`
 *
 * 4. You can name different parts of your wildcard expression, and use them
 * like {name} in your file pattern. For example:
 * `lib{stem:*}.{ext:so*}=libs/{stem}.rewritten.{ext} will print the module
 * `libfoo.so.1` to `libs/libfoo.rewritten.so.1`. Only letters, numbers, and `_`
 * are allowed in group names.
 *
 * 5. You can use commas to separate multiple patterns. Each module will use the
 * first pattern that it matches.
 *
 *    Example: `hello=hello,libhello.so=libs/{n}` will print the module name
 * `hello` to the file `hello`, the module `libhello.so` to the file
 * `libs/libhello.so`, and ignore any other modules.
 *
 *    Note: there can be at most 1 default pattern, i.e. one without any
 * wildcards. Having more than 1 will produce an error message.
 *
 * This machine /will/ treat whitespace as part of a name or pattern, so watch
 * out for that.
 *
 */

static const std::string_view module_help_message{R"""(
 This module defines the syntax for the command-line arguments
 defining the final assembly or binary file.

 You can pass these arguments the following:

 1. A filename. Each module will be written to that file. If there's only
    one module in your IR, great! If not, the last module (by name, alphabetically)
    will be the one written to that file at the end, which is probably not what you wanted

 2. A pattern of filenames, based on the module name.
    Use {name} or {n} as a placeholder for the module name, as in: `my_dir/{n}_rewritten`.
    One file per module will be written per module.

    The characters `{`, `,`, and `=` need to be escaped in file names and patterns by preceding them with a `\`.
    The character `\` needs to be escaped if it would otherwise be the beginning of an
    escape sequence.

 3. You can use a wildcard expression to only print modules with a certain kind of name.
    For example: `lib*.so*=libs/{name}` will print a module module named `libfoo.so` to `libs/libfoo.so`,
    and `libc.so.6` to `libs/libc.so.6`, but will skip modules named `myexe` or `mylibrary.dll`.
    You can also use `?` to match any single character.
    "Wildcards" can also just match a single name: `hello=bin/hello` will print the module named `hello`
    and no others.

    The following characters need to be escaped in wildcards, by preceding them with a `\`:
    `[`,`]`,`{`,`}`, `\`,`=`,`,`,`*`, and `?`

 4. You can name different parts of your wildcard expression, and use them like {name} in your file pattern.
    For example: `lib{stem:*}.{ext:so*}=libs/{stem}.rewritten.{ext} will print the module `libfoo.so.1` to
    `libs/libfoo.rewritten.so.1`. Only letters, numbers, and `_` are allowed in group names.

 5. You can use commas to separate multiple patterns. Each module will use the first pattern that it matches.

    Example: `hello=hello,libhello.so=libs/{n}` will print the module name `hello` to the file `hello`,
    the module `libhello.so` to the file `libs/libhello.so`, and ignore any other modules.

    Note: there can be at most 1 default pattern, i.e. one without any wildcards. Having more than 1 will
    produce an error message. There can be any number of patterns that begin with "*=" but only the first
    one will ever be used.

 All whitespace is considered as part of a name or pattern.
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
class Matcher {
  friend FilePattern;

  std::map<std::string, size_t> GroupIndexes;
  std::string RegexStr;

public:
  Matcher(std::string::const_iterator Begin, std::string::const_iterator End);
  Matcher(const std::string& Field) : Matcher(Field.begin(), Field.end()){};
  std::optional<std::smatch> matches(const std::string& Name) const;

  const std::string& getRegexStr() const { return RegexStr; };
  const auto& getGroupIndexes() const { return GroupIndexes; };
};

/**
 * @brief Represents a rule for turning module names into file names
 *
 */
class FilePattern {
  Matcher Match;
  bool IsDefault;
  std::string ReplacementPattern;
  std::string makeReplacementPattern(std::string::const_iterator PBegin,
                                     std::string::const_iterator PEnd);
  std::string makeReplacementPattern(const std::string& P) {
    return makeReplacementPattern(P.begin(), P.end());
  };

public:
  FilePattern(std::string::const_iterator SpecBegin,
              std::string::const_iterator SpecEnd);
  FilePattern(const std::string& Spec)
      : FilePattern(Spec.begin(), Spec.end()){};
  std::optional<std::string> substitute(const std::string& Name) const;
  bool isDefault() const { return IsDefault; };
  std::optional<std::smatch> matches(const std::string& Name) const {
    return Match.matches(Name);
  };
  const std::string& replacementPattern() const { return ReplacementPattern; };
};

enum class State {
  Name,
  Glob,
  Escape,
};

} // namespace gtirb_multimodule

#endif

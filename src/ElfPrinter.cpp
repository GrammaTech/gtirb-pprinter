//===- ElfPrinter.cpp -------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2019 GrammaTech, Inc.
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "ElfPrinter.h"

namespace gtirb_pprint {
///
/// Print a comment that automatically scopes.
///
class BlockAreaComment {
public:
  BlockAreaComment(std::ostream& ss, std::string m = std::string{},
                   std::function<void()> f = []() {})
      : ofs{ss}, message{std::move(m)}, func{std::move(f)} {
    ofs << '\n';

    if (!message.empty()) {
      ofs << "# BEGIN - " << this->message << '\n';
    }

    func();
  }

  ~BlockAreaComment() {
    func();

    if (!message.empty()) {
      ofs << "# END   - " << this->message << '\n';
    }

    ofs << '\n';
  }

  std::ostream& ofs;
  const std::string message;
  std::function<void()> func;
};

ElfPrettyPrinter::ElfPrettyPrinter(gtirb::Context& context_, gtirb::IR& ir_,
                                   const string_range& keep_funcs,
                                   DebugStyle dbg_)
    : PrettyPrinterBase(context_, ir_, dbg_) {

  for (const auto& [k, v] : m_syntax)
    syntax[k] = v;

  for (const auto functionName : keep_funcs)
    m_skip_funcs.erase(functionName);

  if (this->ir.modules()
          .begin()
          ->getAuxData<
              std::map<gtirb::Offset,
                       std::vector<std::tuple<std::string, std::vector<int64_t>,
                                              gtirb::UUID>>>>(
              "cfiDirectives")) {
    m_skip_sects.insert(".eh_frame");
  }
}

const std::unordered_set<std::string>&
ElfPrettyPrinter::getSkippedSections() const {
  return m_skip_sects;
}

const std::unordered_set<std::string>&
ElfPrettyPrinter::getSkippedFunctions() const {
  return m_skip_funcs;
}

void ElfPrettyPrinter::printFunctionHeader(std::ostream& os, gtirb::Addr addr) {
  const std::string& name = this->getFunctionName(addr);

  if (!name.empty()) {
    const BlockAreaComment bac(os, "Function Header",
                               [this, &os]() { printBar(os, false); });
    printAlignment(os, addr);
    os << syntax[Asm::Directive::Global] << ' ' << name << '\n';
    os << ".type" << ' ' << name << ", @function\n";
    os << name << ":\n";
  }
}

} // namespace gtirb_pprint

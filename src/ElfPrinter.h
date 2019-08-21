//===- ElfPrinter.h -------------------------------------------*- C++ -*-===//
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
#ifndef GTIRB_PP_ELF_PRINTER_H
#define GTIRB_PP_ELF_PRINTER_H

#include "PrettyPrinter.h"

namespace gtirb_pprint {

class ElfPrettyPrinter : public PrettyPrinterBase {
public:
  ElfPrettyPrinter(gtirb::Context& context, gtirb::IR& ir,
                   const string_range& keep_funcs, DebugStyle dbg);

protected:
  void printSectionHeaderDirective(std::ostream& os,
                                   const gtirb::Section& section) override;
  void printSectionProperties(std::ostream& os,
                              const gtirb::Section& section) override;
  void printSectionFooterDirective(std::ostream& os,
                                   const gtirb::Section& addr) override;
  void printFunctionHeader(std::ostream& os, gtirb::Addr ea) override;

private:
  /// Constants table of target-specific assembler syntax.
  Syntax m_syntax = {
      {Asm::Style::Comment, "#"},         {Asm::Directive::Section, ".section"},
      {Asm::Directive::Text, ".text"},    {Asm::Directive::Data, ".data"},
      {Asm::Directive::BSS, ".bss"},      {Asm::Directive::Align, ".align"},
      {Asm::Directive::Global, ".globl"},
  };

  /// Sections to avoid printing.
  std::unordered_set<std::string> m_skip_sects{
      ".comment", ".plt",     ".init",    ".fini",        ".got",
      ".plt.got", ".got.plt", ".plt.sec", ".eh_frame_hdr"};

  /// Functions to avoid printing.
  std::unordered_set<std::string> m_skip_funcs{"_start",
                                               "deregister_tm_clones",
                                               "register_tm_clones",
                                               "__do_global_dtors_aux",
                                               "frame_dummy",
                                               "__libc_csu_fini",
                                               "__libc_csu_init",
                                               "_dl_relocate_static_pie"};

  // Data objects to avoid printing.
  std::unordered_set<std::string> m_skip_data{".init_array", ".fini_array"};
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_ELF_PRINTER_H */

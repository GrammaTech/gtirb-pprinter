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
#ifndef GTIRB_PP_SYNTAX_H
#define GTIRB_PP_SYNTAX_H

#include <string>

namespace gtirb_pprint {

class Syntax {
public:
  Syntax(const std::string commentStyle_,  //
         const std::string textDirective_, //
         const std::string dataDirective_, //
         const std::string bssDirective_,  //
         const std::string sectionDirective_,
         const std::string globalDirective_,
         const std::string alignDirective_, //
         const std::string tabStyle_ = "          ",
         const std::string nopDirective_ = "nop",
         const std::string zeroByteDirective_ = ".byte 0x00",
         const std::string textSection_ = ".text",
         const std::string dataSection_ = ".data",
         const std::string bssSection_ = ".bss",
         const std::string byteDirective_ = ".byte",
         const std::string longDirective_ = ".long",
         const std::string quadDirective_ = ".quad",
         const std::string wordDirective_ = ".word");
  virtual ~Syntax();

  // Styles
  virtual const std::string& Tab() const;
  virtual const std::string& Comment() const;

  // Sections
  virtual const std::string& TextSection() const;
  virtual const std::string& DataSection() const;
  virtual const std::string& BssSection() const;

  // Directives
  virtual const std::string& Nop() const;
  virtual const std::string& ZeroByte() const;

  virtual const std::string& Byte() const;
  virtual const std::string& Long() const;
  virtual const std::string& Quad() const;
  virtual const std::string& Word() const;

  virtual const std::string& Text() const;
  virtual const std::string& Data() const;
  virtual const std::string& Bss() const;

  virtual const std::string& Section() const;
  virtual const std::string& Global() const;
  virtual const std::string& Align() const;

private:
  const std::string commentStyle;
  const std::string tabStyle;

  const std::string nopDirective;
  const std::string zeroByteDirective;

  const std::string textSection;
  const std::string dataSection;
  const std::string bssSection;

  const std::string byteDirective;
  const std::string longDirective;
  const std::string quadDirective;
  const std::string wordDirective;

  const std::string textDirective;
  const std::string dataDirective;
  const std::string bssDirective;

  const std::string sectionDirective;
  const std::string globalDirective;
  const std::string alignDirective;
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_SYNTAX_H */

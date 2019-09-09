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
  Syntax() = default;
  virtual ~Syntax();

  // Styles
  virtual const std::string& Tab() const;
  virtual const std::string& Comment() const = 0;

  // Sections
  virtual const std::string& TextSection() const;
  virtual const std::string& DataSection() const;
  virtual const std::string& BssSection() const;

  // Directives
  virtual const std::string& Nop() const;
  virtual const std::string& ZeroByte() const;

  virtual const std::string& Byte() const = 0;
  virtual const std::string& Long() const = 0;
  virtual const std::string& Quad() const = 0;
  virtual const std::string& Word() const = 0;

  virtual const std::string& Text() const = 0;
  virtual const std::string& Data() const = 0;
  virtual const std::string& Bss() const = 0;

  virtual const std::string& Section() const = 0;
  virtual const std::string& Global() const = 0;
  virtual const std::string& Align() const = 0;

protected:
  std::string tabStyle{"          "};

  std::string nopDirective{"nop"};
  std::string zeroByteDirective{".byte 0x00"};

  std::string textSection{".text"};
  std::string dataSection{".data"};
  std::string bssSection{".bss"};
};

} // namespace gtirb_pprint

#endif /* GTIRB_PP_SYNTAX_H */

#include "Syntax.h"

namespace gtirb_pprint {

Syntax::Syntax(
    const std::string commentStyle_, const std::string textDirective_,
    const std::string dataDirective_, const std::string bssDirective_,
    const std::string sectionDirective_, const std::string globalDirective_,
    const std::string alignDirective_, const std::string tabStyle_,
    const std::string nopDirective_, const std::string zeroByteDirective_,
    const std::string textSection_, const std::string dataSection_,
    const std::string bssSection_, const std::string byteDirective_,
    const std::string longDirective_, const std::string quadDirective_,
    const std::string wordDirective_)
    : commentStyle(commentStyle_), tabStyle(tabStyle_),
      nopDirective(nopDirective_), zeroByteDirective(zeroByteDirective_),
      textSection(textSection_), dataSection(dataSection_),
      bssSection(bssSection_), byteDirective(byteDirective_),
      longDirective(longDirective_), quadDirective(quadDirective_),
      wordDirective(wordDirective_), textDirective(textDirective_),
      dataDirective(dataDirective_), bssDirective(bssDirective_),
      sectionDirective(sectionDirective_), globalDirective(globalDirective_),
      alignDirective(alignDirective_) {}

Syntax::~Syntax() {}

const std::string& Syntax::Tab() const { return tabStyle; }
const std::string& Syntax::Comment() const { return commentStyle; }

const std::string& Syntax::TextSection() const { return textSection; }
const std::string& Syntax::DataSection() const { return dataSection; }
const std::string& Syntax::BssSection() const { return bssSection; }

const std::string& Syntax::Nop() const { return nopDirective; }
const std::string& Syntax::ZeroByte() const { return zeroByteDirective; }

const std::string& Syntax::Byte() const { return byteDirective; }
const std::string& Syntax::Long() const { return longDirective; }
const std::string& Syntax::Quad() const { return quadDirective; }
const std::string& Syntax::Word() const { return wordDirective; }

const std::string& Syntax::Text() const { return textDirective; }
const std::string& Syntax::Data() const { return dataDirective; }
const std::string& Syntax::Bss() const { return bssDirective; }

const std::string& Syntax::Section() const { return sectionDirective; }
const std::string& Syntax::Global() const { return globalDirective; }
const std::string& Syntax::Align() const { return alignDirective; }

} // namespace gtirb_pprint

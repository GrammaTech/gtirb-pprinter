#include "Syntax.h"

namespace gtirb_pprint {

Syntax::~Syntax() {}

const std::string& Syntax::Tab() const { return tabStyle; }

const std::string& Syntax::TextSection() const { return textSection; }
const std::string& Syntax::DataSection() const { return dataSection; }
const std::string& Syntax::BssSection() const { return bssSection; }

const std::string& Syntax::Nop() const { return nopDirective; }
const std::string& Syntax::ZeroByte() const { return zeroByteDirective; }

} // namespace gtirb_pprint

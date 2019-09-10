#include "Syntax.h"

namespace gtirb_pprint {

Syntax::~Syntax() {}

const std::string& Syntax::tab() const { return TabStyle; }

const std::string& Syntax::textSection() const { return TextSection; }
const std::string& Syntax::dataSection() const { return DataSection; }
const std::string& Syntax::bssSection() const { return BssSection; }

const std::string& Syntax::nop() const { return NopDirective; }
const std::string& Syntax::zeroByte() const { return ZeroByteDirective; }

} // namespace gtirb_pprint

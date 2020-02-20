#include <gtirb_pprinter/PrettyPrinter.hpp>
#include <iostream>

int main() {
  auto defaultSyntax = gtirb_pprint::getDefaultSyntax("elf");
  std::cout << "default syntax for elf: " << *defaultSyntax << "\n";
  return 0;
}

#include <gtirb_pprinter/PrettyPrinter.hpp>
#include <iostream>

int main() {
  auto defaultSyntax = gtirb_pprint::getDefaultSyntax("elf", "x64");
  if (!defaultSyntax) {
    return 1;
  }
  std::cout << "default syntax for elf: " << *defaultSyntax << "\n";
  return 0;
}

#include <gtirb_pprinter/PrettyPrinter.hpp>
#include <iostream>

int main() {
  gtirb_pprint::PrettyPrinter pprinter;
  pprinter.setDebug(true);
  std::cout << pprinter.getDebug() << "\n";
  return 0;
}

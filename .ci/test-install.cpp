#include <fstream>
#include <gtirb_layout/gtirb_layout.hpp>
#include <gtirb_pprinter/ElfBinaryPrinter.hpp>
#include <gtirb_pprinter/PrettyPrinter.hpp>
#include <iostream>
#include <vector>
int main(int argc, char* argv[]) {

  if (argc != 2) {
    std::cerr << "Usage: ./test-install [gtirb-file]\n\n";
    return 1;
  }

  const char* filename = argv[1];

  gtirb_pprint::registerAuxDataTypes();
  gtirb_layout::registerAuxDataTypes();
  gtirb_pprint::registerPrettyPrinters();
  gtirb_pprint::PrettyPrinter pp;
  std::vector<std::string> extraCompileArgs, libraryPaths;
  auto binaryPrinter = std::make_unique<gtirb_bprint::ElfBinaryPrinter>(
      pp, extraCompileArgs, libraryPaths, true, false);

  // load gtirb
  gtirb::IR* ir = nullptr;
  gtirb::Context ctx;
  std::ifstream in(filename, std::ios::in | std::ios::binary);
  if (!in.good()) {
    std::cerr << "Unable to open file: " << filename << "\n\n";
    return 1;
  }
  if (gtirb::ErrorOr<gtirb::IR*> iOrE = gtirb::IR::load(ctx, in)) {
    ir = *iOrE;
  }

  // pass it into the binary printer:
  return binaryPrinter->assemble("test-binary", ctx, *ir->modules_begin());
}

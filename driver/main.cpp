#include "ElfBinaryPrinter.h"
#include "Logger.h"
#include "PrettyPrinter.h"
#include <boost/program_options.hpp>
#include <experimental/filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>

namespace fs = std::experimental::filesystem;
namespace po = boost::program_options;

int main(int argc, char** argv) {
  po::options_description desc("Allowed options");
  desc.add_options()("help,h", "Produce help message.");
  desc.add_options()("ir,i", po::value<std::string>(), "gtirb file to print.");
  desc.add_options()("asm,a", po::value<std::string>(),
                     "The name of the assembly output file.");
  desc.add_options()("binary,b", po::value<std::string>(),
                     "The name of the binary output file.");
  desc.add_options()("format,f", po::value<std::string>(),
                     "The format of the target binary object.");
  desc.add_options()("syntax,s", po::value<std::string>(),
                     "The syntax of the assembly file to generate.");
  desc.add_options()("debug,d", "Turn on debugging (will break assembly)");
  desc.add_options()("keep-functions,k",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Print the given functions even if they are skipped by "
                     "default (e.g. _start)");
  desc.add_options()("skip-functions,n",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Do not print the given functions.");
  desc.add_options()("library-paths,L",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Library paths to be passed to the linker");
  po::positional_options_description pd;
  pd.add("ir", -1);
  po::variables_map vm;
  try {
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(pd).run(),
        vm);
    if (vm.count("help") != 0) {
      std::cout << desc << "\n";
      return 1;
    }
  } catch (std::exception& e) {
    std::cerr << "Error: " << e.what() << "\nTry '" << argv[0]
              << " --help' for more information.\n";
    return 1;
  }
  po::notify(vm);

  gtirb::Context ctx;
  gtirb::IR* ir;

  if (vm.count("ir") != 0) {
    fs::path irPath = vm["ir"].as<std::string>();
    if (fs::exists(irPath)) {
      LOG_INFO << std::setw(24) << std::left << "Reading IR: " << irPath
               << std::endl;
      std::ifstream in(irPath.string());
      ir = gtirb::IR::load(ctx, in);
    } else {
      LOG_ERROR << "IR not found: \"" << irPath << "\".";
      return EXIT_FAILURE;
    }
  } else {
    ir = gtirb::IR::load(ctx, std::cin);
  }

  // Perform the Pretty Printing step.
  gtirb_pprint::PrettyPrinter pp;
  pp.setDebug(vm.count("debug"));
  const std::string& format = vm.count("format")
                                  ? vm["format"].as<std::string>()
                                  : gtirb_pprint::getIRFileFormat(*ir);
  const std::string& syntax =
      vm.count("syntax") ? vm["syntax"].as<std::string>()
                         : gtirb_pprint::getDefaultSyntax(format).value_or("");
  const auto target = std::make_tuple(format, syntax);
  if (gtirb_pprint::getRegisteredTargets().count(target) == 0) {
    LOG_ERROR << "Unsupported combination: format '" << format
              << "' and syntax '" << syntax << "'\n";
    LOG_ERROR << "Available combinations:\n";
    LOG_ERROR << "    " << std::setw(10) << "format"
              << "syntax\n";
    for (const auto& [f, s] : gtirb_pprint::getRegisteredTargets())
      LOG_ERROR << "    " << std::setw(10) << f << s << '\n';
    return EXIT_FAILURE;
  }
  pp.setTarget(std::move(target));

  if (vm.count("keep-functions") != 0) {
    for (const auto& keep :
         vm["keep-functions"].as<std::vector<std::string>>()) {
      pp.keepFunction(keep);
    }
  }

  if (vm.count("skip-functions") != 0) {
    for (const auto& skip :
         vm["skip-functions"].as<std::vector<std::string>>()) {
      pp.skipFunction(skip);
    }
  }

  // Do we write it to a file?
  if (vm.count("asm") != 0) {
    const auto asmPath = fs::path(vm["asm"].as<std::string>());
    std::ofstream ofs;
    ofs.open(asmPath.string());

    if (ofs.is_open() == true) {
      pp.print(ofs, ctx, *ir);
      ofs.close();
      LOG_INFO << "Assembly written to: " << asmPath << "\n";
    } else {
      LOG_ERROR << "Could not output assembly output file: " << asmPath << "\n";
    }
  }
  if (vm.count("binary") != 0) {
    gtirb_bprint::ElfBinaryPrinter binaryPrinter(true);
    const auto binaryPath = fs::path(vm["binary"].as<std::string>());
    std::vector<std::string> libraryPaths;
    if (vm.count("library-paths") != 0)
      libraryPaths = vm["library-paths"].as<std::vector<std::string>>();
    binaryPrinter.link(binaryPath.string(), libraryPaths, pp, ctx, *ir);
  }

  if (vm.count("asm") == 0 && vm.count("binary") == 0) {
    pp.print(std::cout, ctx, *ir);
  }

  return EXIT_SUCCESS;
}

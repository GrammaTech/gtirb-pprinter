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
  desc.add_options()("out,o", po::value<std::string>(),
                     "The name of the assembly output file.");
  desc.add_options()("binary,b", po::value<std::string>(),
                     "The name of the binary output file.");
  desc.add_options()("syntax,s",
                     po::value<std::string>()->default_value("intel"),
                     "The syntax of the assembly file to generate.");
  desc.add_options()("debug,d", "Turn on debugging (will break assembly)");
  desc.add_options()("keep-functions,k",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Print the given functions even if they are skipped by "
                     "default (e.g. _start)");
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
  if (vm.count("syntax") != 0) {
    const std::string& syntax = vm["syntax"].as<std::string>();
    if (gtirb_pprint::getRegisteredSyntaxes().count(syntax) == 0) {
      LOG_ERROR << "Unknown assembly syntax: '" << syntax << "'\n";
      LOG_ERROR << "Available syntaxes:\n";
      for (const std::string& s : gtirb_pprint::getRegisteredSyntaxes())
        LOG_ERROR << "    " << s << '\n';
      return EXIT_FAILURE;
    }
    pp.setSyntax(syntax);
  }

  if (vm.count("keep-functions") != 0) {
    for (auto keep : vm["keep-functions"].as<std::vector<std::string>>()) {
      pp.keepFunction(keep);
    }
  }

  // Do we write it to a file?
  if (vm.count("out") != 0) {
    const auto asmPath = fs::path(vm["out"].as<std::string>());
    std::ofstream ofs;
    ofs.open(asmPath.string());

    if (ofs.is_open() == true) {
      pp.print(ofs, ctx, *ir);
      ofs.close();
      LOG_INFO << "Assembly written to: " << asmPath << "\n";
    } else {
      LOG_ERROR << "Could not output assembly output file: " << asmPath << "\n";
    }
  } else if (vm.count("binary") != 0) {
    const auto binaryPath = fs::path(vm["binary"].as<std::string>());
    pp.linkAssembly(binaryPath.string(), ctx, *ir);
  } else {
    pp.print(std::cout, ctx, *ir);
  }

  return EXIT_SUCCESS;
}

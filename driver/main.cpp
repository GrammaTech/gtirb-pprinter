#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/program_options.hpp>
#include <iomanip>
#include <iostream>
#include "DisasmData.h"
#include "Logger.h"
#include "PrettyPrinter.h"

namespace po = boost::program_options;

int main(int argc, char** argv) {
  po::options_description desc("Allowed options");
  desc.add_options()("help,h", "Produce help message.");
  desc.add_options()("ir,i", po::value<std::string>(), "gtirb file to print.");
  desc.add_options()("out,o", po::value<std::string>(), "The name of the assembly output file.");
  desc.add_options()("syntax,s", po::value<std::string>(),
                     "The syntax of the assembly file to generate.");
  desc.add_options()("debug,d", "Turn on debugging (will break assembly)");
  desc.add_options()("keep-functions,k", po::value<std::vector<std::string>>()->multitoken(),
                     "Print the given functions even if they are skipped by default (e.g. _start)");
  po::positional_options_description pd;
  pd.add("ir", -1);
  po::variables_map vm;
  try {
    po::store(po::command_line_parser(argc, argv).options(desc).positional(pd).run(), vm);
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
    boost::filesystem::path irPath = vm["ir"].as<std::string>();
    if (boost::filesystem::exists(irPath) == true) {
      LOG_INFO << std::setw(24) << std::left << "Reading IR: " << irPath << std::endl;
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
  PrettyPrinter pp;
  pp.setDebug(vm.count("debug"));
  if (vm.count("syntax") != 0) {
    try {
      pp.setSyntax(vm["syntax"].as<std::string>());
    } catch (std::out_of_range&) {
      LOG_ERROR << "Unknown assembly syntax: '" << vm["syntax"].as<std::string>() << "'\n";
      LOG_ERROR << "Available syntaxes:\n";
      for (const auto& syntax : PrettyPrinter::getRegisteredSyntaxes()) {
        LOG_ERROR << "    " << syntax << '\n';
      }
      return EXIT_FAILURE;
    }
  }
  if (vm.count("keep-functions") != 0) {
    for (auto keep : vm["keep-functions"].as<std::vector<std::string>>()) {
      pp.keepFunction(keep);
    }
  }
  const auto assembly = pp.prettyPrint(ctx, *ir);

  // Do we write it to a file?
  if (vm.count("out") != 0) {
    const auto asmPath = boost::filesystem::path(vm["out"].as<std::string>());
    std::ofstream ofs;
    ofs.open(asmPath.string());

    if (ofs.is_open() == true) {
      ofs << assembly;
      ofs.close();
      LOG_INFO << "Assembly written to: " << asmPath << "\n";
    } else {
      LOG_ERROR << "Could not output assembly output file: " << asmPath << "\n";
    }
  } else {
    std::cout << assembly << std::endl;
  }

  return EXIT_SUCCESS;
}

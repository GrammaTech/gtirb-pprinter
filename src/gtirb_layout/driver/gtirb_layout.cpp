#include "Logger.h"
#include <boost/program_options.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fstream>
#include <gtirb/gtirb.hpp>
#include <gtirb_layout/gtirb_layout.hpp>
#include <iomanip>
#include <iostream>

#ifdef USE_STD_FILESYSTEM_LIB
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif // USE_STD_FILESYSTEM_LIB

namespace po = boost::program_options;

int main(int argc, char** argv) {
  po::options_description desc("gtirb-layout - a tool to prepare GTIRB files "
                               "for pretty printers.\n\n"
                               "Allowed options");
  desc.add_options()("help,h", "Produce this help message.");
  desc.add_options()("in,i", po::value<std::string>()->required(),
                     "Input GTIRB file.");
  desc.add_options()("out,o", po::value<std::string>()->required(),
                     "Output GTIRB file.");
  desc.add_options()("remove,r", "Remove layout instead of adding it.");

  po::positional_options_description pd;
  pd.add("in", 1);
  pd.add("out", 1);

  po::variables_map vm;
  try {
    po::store(
        po::command_line_parser(argc, argv).options(desc).positional(pd).run(),
        vm);
    if (vm.count("help") != 0) {
      std::cout << desc << std::endl;
      return EXIT_FAILURE;
    }
    po::notify(vm);
  } catch (std::exception& e) {
    LOG_ERROR << e.what() << ". Try '" << argv[0]
              << " --help' for more information." << std::endl;
    return EXIT_FAILURE;
  }

  gtirb::Context ctx;
  gtirb::IR* ir;

  auto irString = vm["in"].as<std::string>();
  if (irString == "-") {
    ir = gtirb::IR::load(ctx, std::cin);
  } else {
    fs::path irPath = irString;
    if (fs::exists(irPath)) {
      LOG_INFO << "Reading GTIRB file: " << irPath << std::endl;
      std::ifstream in(irPath.string(), std::ios::in | std::ios::binary);
      ir = gtirb::IR::load(ctx, in);
    } else {
      LOG_ERROR << "GTIRB file not found: " << irPath << std::endl;
      return EXIT_FAILURE;
    }
  }

  if (vm.count("remove") == 0) {
    for (auto& M : ir->modules()) {
      LOG_INFO << "Laying out module " << M.getUUID() << "..." << std::endl;
      if (!gtirb_layout::layoutModule(ctx, M)) {
        LOG_ERROR << "Laying out module failed!" << std::endl;
        return EXIT_FAILURE;
      }
    }
  } else {
    for (auto& M : ir->modules()) {
      LOG_INFO << "Removing layout from module " << M.getUUID() << "..."
               << std::endl;
      if (!gtirb_layout::removeModuleLayout(ctx, M)) {
        LOG_ERROR << "Removing layout from module failed!" << std::endl;
        return EXIT_FAILURE;
      }
    }
  }

  auto outString = vm["out"].as<std::string>();
  if (outString == "-") {
    ir->save(std::cout);
    return std::cout ? EXIT_SUCCESS : EXIT_FAILURE;
  } else {
    fs::path outPath = outString;
    LOG_INFO << "Writing to GTIRB file: " << outPath << std::endl;
    std::ofstream fileOut(outPath.string(), std::ios::out | std::ios::binary);
    ir->save(fileOut);
    if (!fileOut) {
      LOG_ERROR << "Failed to write output!" << std::endl;
      return EXIT_FAILURE;
    } else {
      LOG_INFO << "Output written successfully. " << std::endl;
      return EXIT_SUCCESS;
    }
  }
}

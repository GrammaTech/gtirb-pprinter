#include "Logger.h"
#include <boost/program_options.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fstream>
#include <gtirb_layout/gtirb_layout.hpp>
#include <gtirb_pprinter/ElfBinaryPrinter.hpp>
#include <gtirb_pprinter/PrettyPrinter.hpp>
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

static fs::path getAsmFileName(const fs::path& InitialPath, int Index) {
  if (Index == 0)
    return InitialPath;
  std::string Filename = InitialPath.filename().generic_string();
  // If the name does not have an extension, we add the number at the end.
  size_t LastDot = Filename.rfind('.');
  if (LastDot == std::string::npos)
    Filename.append(std::to_string(Index));
  // Otherwise, we add the number before the extension.
  Filename.insert(LastDot, std::to_string(Index));
  return fs::path(InitialPath).replace_filename(Filename);
}

int main(int argc, char** argv) {
  gtirb_pprint::registerAuxDataTypes();

  po::options_description desc("Allowed options");
  desc.add_options()("help,h", "Produce help message.");
  desc.add_options()("ir,i", po::value<std::string>(), "gtirb file to print.");
  desc.add_options()(
      "asm,a", po::value<std::string>(),
      "The name of the assembly output file. If none is given, gtirb-pprinter "
      "prints to the standard output. If the IR has more "
      "than one module, files of the form FILE, FILE_2 ... "
      "FILE_n with the content of each of the modules");
  desc.add_options()("module,m", po::value<int>()->default_value(0),
                     "The index of the module to be printed if printing to the "
                     "standard output.");
  desc.add_options()("format,f", po::value<std::string>(),
                     "The format of the target binary object.");
  desc.add_options()("syntax,s", po::value<std::string>(),
                     "The syntax of the assembly file to generate.");
  desc.add_options()("debug,d", "Turn on debugging (will break assembly)");

  desc.add_options()("keep-symbol",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Print the given symbol even if they are skipped by "
                     "default (e.g. _start).");
  desc.add_options()("skip-symbol",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Do not print the given symbol.");
  desc.add_options()("keep-all-symbols",
                     "Do not use the default list of symbols to skip.");

  desc.add_options()("keep-section",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Print the given section even if they are skipped by "
                     "default (e.g. .text).");
  desc.add_options()("skip-section",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Do not print the given section.");
  desc.add_options()("keep-all-sections",
                     "Do not use the default list of sections to skip.");

  desc.add_options()(
      "keep-array-section", po::value<std::vector<std::string>>()->multitoken(),
      "Print the given array section even if they are skipped by "
      "default (e.g. .fini_array).");
  desc.add_options()("skip-array-section",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Do not print the contents of the given array section.");
  desc.add_options()("keep-all-array-sections",
                     "Do not use the default list of array sections to skip.");

  desc.add_options()("keep-all,k",
                     "Combination of --keep-all-symbols, --keep-all-sections, "
                     "and --keep-all-array-sections.");

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
      std::ifstream in(irPath.string(), std::ios::in | std::ios::binary);
      ir = gtirb::IR::load(ctx, in);
    } else {
      LOG_ERROR << "IR not found: \"" << irPath << "\".";
      return EXIT_FAILURE;
    }
  } else {
    ir = gtirb::IR::load(ctx, std::cin);
  }
  if (ir->modules().empty()) {
    LOG_ERROR << "IR has no modules";
    return EXIT_FAILURE;
  }

  // Layout the modules so that evereything has nonoverlapping addresses if
  // needed.
  for (auto& M : ir->modules()) {
    if (!M.getAddress() || std::any_of(M.symbols_begin(), M.symbols_end(),
                                       [](const gtirb::Symbol& Sym) {
                                         return !Sym.hasReferent() &&
                                                Sym.getAddress();
                                       })) {
      // FIXME: There could be other kinds of invalid layouts than one in which
      // an interval has no address; for example, one where sections overlap...
      LOG_INFO << "Module " << M.getUUID()
               << " has invalid layout; laying out module automatically..."
               << std::endl;
      gtirb_layout::layoutModule(M);
    }
  }

  // Perform the Pretty Printing step.
  gtirb_pprint::PrettyPrinter pp;
  pp.setDebug(vm.count("debug"));
  const std::string& format =
      vm.count("format")
          ? vm["format"].as<std::string>()
          : gtirb_pprint::getModuleFileFormat(*ir->modules().begin());
  const std::string& syntax =
      vm.count("syntax") ? vm["syntax"].as<std::string>()
                         : gtirb_pprint::getDefaultSyntax(format).value_or("");
  auto target = std::make_tuple(format, syntax);
  if (gtirb_pprint::getRegisteredTargets().count(target) == 0) {
    LOG_ERROR << "Unsupported combination: format '" << format
              << "' and syntax '" << syntax << "'\n";
    std::string::size_type width = 0;
    for (const auto& [f, s] : gtirb_pprint::getRegisteredTargets())
      width = std::max({width, f.size(), s.size()});
    width += 2; // add "gutter" between columns
    LOG_ERROR << "Available combinations:\n";
    LOG_ERROR << "    " << std::setw(width) << "format"
              << "syntax\n";
    for (const auto& [f, s] : gtirb_pprint::getRegisteredTargets())
      LOG_ERROR << "    " << std::setw(width) << f << s << '\n';
    return EXIT_FAILURE;
  }
  pp.setTarget(std::move(target));

  if (vm.count("keep-all") != 0) {
    pp.symbolPolicy().useDefaults(false);
    pp.sectionPolicy().useDefaults(false);
    pp.arraySectionPolicy().useDefaults(false);
  }

  if (vm.count("keep-all-symbols") != 0) {
    pp.symbolPolicy().useDefaults(false);
  }
  if (vm.count("keep-symbol") != 0) {
    for (const auto& S : vm["keep-symbol"].as<std::vector<std::string>>()) {
      pp.symbolPolicy().keep(S);
    }
  }
  if (vm.count("skip-symbol") != 0) {
    for (const auto& S : vm["skip-symbol"].as<std::vector<std::string>>()) {
      pp.symbolPolicy().skip(S);
    }
  }

  if (vm.count("keep-all-sections") != 0) {
    pp.sectionPolicy().useDefaults(false);
  }
  if (vm.count("keep-section") != 0) {
    for (const auto& S : vm["keep-section"].as<std::vector<std::string>>()) {
      pp.sectionPolicy().keep(S);
    }
  }
  if (vm.count("skip-section") != 0) {
    for (const auto& S : vm["skip-section"].as<std::vector<std::string>>()) {
      pp.sectionPolicy().skip(S);
    }
  }

  if (vm.count("keep-all-array-sections") != 0) {
    pp.sectionPolicy().useDefaults(false);
  }
  if (vm.count("keep-array-section") != 0) {
    for (const auto& S :
         vm["keep-array-section"].as<std::vector<std::string>>()) {
      pp.arraySectionPolicy().keep(S);
    }
  }
  if (vm.count("skip-array-section") != 0) {
    for (const auto& S :
         vm["skip-array-section"].as<std::vector<std::string>>()) {
      pp.arraySectionPolicy().skip(S);
    }
  }

  // Do we write it to a file?
  if (vm.count("asm") != 0) {
    const auto asmPath = fs::path(vm["asm"].as<std::string>());
    if (!asmPath.has_filename()) {
      LOG_ERROR << "The given path " << asmPath << " has no filename"
                << std::endl;
      return EXIT_FAILURE;
    }
    int i = 0;
    for (gtirb::Module& m : ir->modules()) {
      fs::path name = getAsmFileName(asmPath, i);
      std::ofstream ofs(name);
      if (ofs) {
        pp.print(ofs, ctx, m);
        LOG_INFO << "Module " << i << "'s assembly written to: " << name
                 << "\n";
      } else {
        LOG_ERROR << "Could not output assembly output file: " << asmPath
                  << "\n";
      }
      ++i;
    }
    // or to the standard output
  } else {
    gtirb::Module* module = nullptr;
    int i = 0;
    for (gtirb::Module& m : ir->modules()) {
      if (i == vm["module"].as<int>()) {
        module = &m;
        break;
      }
      ++i;
    }
    if (!module) {
      LOG_ERROR << "The ir has " << i << " modules, module with index "
                << vm["module"].as<int>() << " cannot be printed" << std::endl;
      return EXIT_FAILURE;
    }
    pp.print(std::cout, ctx, *module);
  }

  return EXIT_SUCCESS;
}

#include "Logger.h"
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fcntl.h>
#include <fstream>
#include <gtirb_layout/gtirb_layout.hpp>
#include <gtirb_pprinter/ElfBinaryPrinter.hpp>
#include <gtirb_pprinter/PeBinaryPrinter.hpp>
#include <gtirb_pprinter/PrettyPrinter.hpp>
#include <gtirb_pprinter/version.h>
#if defined(_MSC_VER)
#include <io.h>
#endif
#include <iomanip>
#include <iostream>
#if defined(__unix__)
#include <unistd.h>
#endif

namespace fs = boost::filesystem;
namespace po = boost::program_options;

static bool isStreamATerminal(FILE* stream) {
#if defined(_MSC_VER)
  return _isatty(_fileno(stream));
#else
  return isatty(fileno(stream));
#endif
}

static bool setStdStreamToBinary(FILE* stream) {
  // Check to see if we're running a tty vs a pipe. If a tty, then we
  // want to warn the user if we're going to open in binary mode.
  if (isStreamATerminal(stream))
    return false;

#if defined(_MSC_VER)
  _setmode(_fileno(stream), _O_BINARY);
#else
  if (stream == stdout) {
    stdout = freopen(NULL, "wb", stdout);
    assert(stdout && "Failed to reopen stdout");
  } else if (stream == stdin) {
    stdin = freopen(NULL, "rb", stdin);
    assert(stdin && "Failed to reopen stdin");
  } else {
    std::cerr << "Refusing to set non-stdout/stdin stream to binary mode\n";
  }
#endif
  return true;
}

static fs::path getAsmFileName(const fs::path& InitialPath, int Index) {
  if (Index == 0)
    return InitialPath;

  // Add the number to the end of the stem of the filename.
  std::string Filename = InitialPath.stem().generic_string();
  Filename.append(std::to_string(Index));
  Filename.append(InitialPath.extension().generic_string());
  fs::path FinalPath = InitialPath.parent_path();
  FinalPath /= Filename;
  return FinalPath;
}

static std::unique_ptr<gtirb_bprint::BinaryPrinter>
getBinaryPrinter(const std::string& format,
                 const gtirb_pprint::PrettyPrinter& pp,
                 const std::vector<std::string>& extraCompileArgs,
                 const std::vector<std::string>& libraryPaths, bool dummySO) {
  std::unique_ptr<gtirb_bprint::BinaryPrinter> binaryPrinter;
  if (format == "elf")
    return std::make_unique<gtirb_bprint::ElfBinaryPrinter>(
        pp, extraCompileArgs, libraryPaths, true, dummySO);
  if (format == "pe")
    return std::make_unique<gtirb_bprint::PeBinaryPrinter>(pp, extraCompileArgs,
                                                           libraryPaths);
  return nullptr;
}

int main(int argc, char** argv) {
  gtirb_layout::registerAuxDataTypes();
  gtirb_pprint::registerAuxDataTypes();
  gtirb_pprint::registerPrettyPrinters();

  po::options_description desc("Allowed options");
  desc.add_options()("help,h", "Produce help message.");
  desc.add_options()("version", "Print version info and exit.");
  desc.add_options()("ir,i", po::value<std::string>(), "GTIRB file to print.");
  desc.add_options()(
      "asm,a", po::value<std::string>(),
      "The name of the assembly output file. If none is given, gtirb-pprinter "
      "prints to the standard output. If the IR has more "
      "than one module, files of the form FILE, FILE_2 ... "
      "FILE_n with the content of each of the modules");
  desc.add_options()("binary,b", po::value<std::string>(),
                     "The name of the binary output file.");
  desc.add_options()(
      "binaries", po::value<std::string>(),
      "The name of the assembled output. If the IR has more than one module, "
      "files of the form FILE, FILE_2, ..., FILE_n are produced with the "
      "assembled content of each of the modules.");
  desc.add_options()("compiler-args,c",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Additional arguments to pass to the compiler. Only used "
                     "for binary printing.");
  desc.add_options()("library-paths,L",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Library paths to be passed to the linker. Only used "
                     "for binary printing.");
  desc.add_options()("module,m", po::value<int>()->default_value(0),
                     "The index of the module to be printed if printing to the "
                     "standard output.");
  desc.add_options()("format,f", po::value<std::string>(),
                     "The format of the target binary object.");
  desc.add_options()("isa,I", po::value<std::string>(),
                     "The ISA of the target binary object.");
  desc.add_options()("syntax,s", po::value<std::string>(),
                     "The syntax of the assembly file to generate.");
  desc.add_options()("assembler", po::value<std::string>(),
                     "The assembler to use for rewriting.");
  desc.add_options()("layout,l", "Layout code and data in memory to "
                                 "avoid overlap");
  desc.add_options()(
      "listing-mode", po::value<std::string>(),
      "The mode of use for the listing: assembler, ui, or debug");
  desc.add_options()(
      "policy,p", po::value<std::string>(),
      "The default set of objects to skip when printing assembly. To modify "
      "this set further, use the --keep and --skip options.");
  desc.add_options()("shared,S", "Output a shared library, or assembly "
                                 "that can be compiled to a shared library.");

  desc.add_options()("keep-function",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Print the given function even if they are skipped"
                     " by default (e.g. _start).");
  desc.add_options()("skip-function",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Do not print the given function.");
  desc.add_options()("keep-all-functions",
                     "Do not use the default list of functions to skip.");

  desc.add_options()("keep-symbol",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Print the given symbol even if they are skipped"
                     " by default (e.g. __TMC_END__).");
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

  desc.add_options()("keep-all,k", "Combination of --keep-all-functions, "
                                   "--keep-all-symbols, --keep-all-sections, "
                                   "and --keep-all-array-sections.");
  desc.add_options()("dummy-so", po::value<bool>()->default_value(false),
                     "Use artificial .so files for linking rather than actual "
                     "libraries. Only relevant for ELF executables.");

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
    if (vm.count("version") != 0) {
      std::cout << GTIRB_PPRINTER_VERSION_STRING << " ("
                << GTIRB_PPRINTER_BUILD_REVISION << " "
                << GTIRB_PPRINTER_BUILD_DATE << ")\n";
      return 0;
    }
  } catch (std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\nTry '" << argv[0]
              << " --help' for more information.\n";
    return 1;
  }
  po::notify(vm);

  class ContextForgetter {
    gtirb::Context ctx;

  public:
    ~ContextForgetter() { ctx.ForgetAllocations(); }
    operator gtirb::Context&() { return ctx; }
    operator const gtirb::Context&() const { return ctx; }
  };

  ContextForgetter ctx;
  gtirb::IR* ir = nullptr;

  if (vm.count("ir") != 0) {
    fs::path irPath = vm["ir"].as<std::string>();
    LOG_INFO << std::setw(24) << std::left << "Reading GTIRB file: " << irPath
             << std::endl;
    std::ifstream in(irPath.string(), std::ios::in | std::ios::binary);
    if (in) {
      if (gtirb::ErrorOr<gtirb::IR*> iOrE = gtirb::IR::load(ctx, in))
        ir = *iOrE;
    } else {
      LOG_ERROR << "GTIRB file could not be opened: \"" << irPath << "\".\n";
      return EXIT_FAILURE;
    }
  } else {
    if (!setStdStreamToBinary(stdin)) {
      std::cout << desc << "\n";
      return EXIT_FAILURE;
    }
    if (gtirb::ErrorOr<gtirb::IR*> iOrE = gtirb::IR::load(ctx, std::cin)) {
      ir = *iOrE;
    }
  }
  if (!ir) {
    LOG_ERROR << "Failed to load the GTIRB data from the file.\n";
    return EXIT_FAILURE;
  }
  if (ir->modules().empty()) {
    LOG_ERROR << "GTIRB file contains no modules.\n";
    return EXIT_FAILURE;
  }

  // Layout IR in memory without overlap.
  if (vm.count("layout") || gtirb_layout::layoutRequired(*ir)) {
    for (auto& M : ir->modules()) {
      LOG_INFO << "Applying new layout to module " << M.getUUID() << "..."
               << std::endl;
      gtirb_layout::layoutModule(ctx, M);
    }
  } else {
    for (auto& M : ir->modules()) {
      if (std::any_of(M.symbols_begin(), M.symbols_end(),
                      [](const gtirb::Symbol& Sym) {
                        return !Sym.hasReferent() && Sym.getAddress();
                      })) {
        LOG_INFO << "Module " << M.getUUID()
                 << " has integral symbols; attempting to assign referents..."
                 << std::endl;
        gtirb_layout::fixIntegralSymbols(ctx, M);
      }
    }
  }

  // Perform the Pretty Printing step.
  gtirb_pprint::PrettyPrinter pp;
  std::string LstMode =
      vm.count("listing-mode") ? vm["listing-mode"].as<std::string>() : "";
  if (!pp.setListingMode(LstMode)) {
    LOG_ERROR << "Invalid listing-mode: " << LstMode << "\n";
    return EXIT_FAILURE;
  }
  const std::string& format =
      vm.count("format")
          ? vm["format"].as<std::string>()
          : gtirb_pprint::getModuleFileFormat(*ir->modules().begin());
  const std::string& isa =
      vm.count("isa") ? vm["isa"].as<std::string>()
                      : gtirb_pprint::getModuleISA(*ir->modules().begin());
  const std::string& syntax =
      vm.count("syntax")
          ? vm["syntax"].as<std::string>()
          : gtirb_pprint::getDefaultSyntax(format, isa).value_or("");
  const std::string& assembler =
      vm.count("assembler")
          ? vm["assembler"].as<std::string>()
          : gtirb_pprint::getDefaultAssembler(format, isa, syntax).value_or("");
  auto target = std::make_tuple(format, isa, syntax, assembler);
  if (gtirb_pprint::getRegisteredTargets().count(target) == 0) {
    LOG_ERROR << "Unsupported combination: format \"" << format << "\" ISA \""
              << isa << "\" syntax \"" << syntax << "\" and assembler \""
              << assembler << "\".\n";
    std::string::size_type width = std::strlen("syntax");
    for (const auto& [f, i, s, a] : gtirb_pprint::getRegisteredTargets())
      width = std::max({width, f.size(), i.size(), s.size(), a.size()});
    width += 2; // add "gutter" between columns
    LOG_ERROR << "Available combinations:\n";
    LOG_ERROR << std::left << std::setw(width) << "format" << std::setw(width)
              << "ISA" << std::setw(width) << "syntax" << std::setw(width)
              << "assembler"
              << "\n";
    for (const auto& [f, i, s, a] : gtirb_pprint::getRegisteredTargets())
      LOG_ERROR << std::left << std::setw(width) << f << std::setw(width) << i
                << std::setw(width) << s << std::setw(width) << a << '\n';
    return EXIT_FAILURE;
  }
  pp.setTarget(std::move(target));

  if (vm.count("policy") != 0) {
    auto Policy = vm["policy"].as<std::string>();

    if (Policy != "default" && !pp.namedPolicyExists(Policy)) {
      LOG_ERROR << "Unknown policy '" << Policy << "'. Available policies:\n";
      LOG_ERROR << "\tdefault\n";
      for (const auto& Name : pp.policyNames()) {
        LOG_ERROR << "\t" << Name << "\n";
      }
      return EXIT_FAILURE;
    }

    pp.setPolicyName(Policy);
  }

  if (vm.count("keep-all") != 0) {
    pp.functionPolicy().useDefaults(false);
    pp.symbolPolicy().useDefaults(false);
    pp.sectionPolicy().useDefaults(false);
    pp.arraySectionPolicy().useDefaults(false);
  }

  if (vm.count("keep-all-functions") != 0) {
    pp.functionPolicy().useDefaults(false);
  }
  if (vm.count("keep-function") != 0) {
    for (const auto& S : vm["keep-function"].as<std::vector<std::string>>()) {
      pp.functionPolicy().keep(S);
    }
  }
  if (vm.count("skip-function") != 0) {
    for (const auto& S : vm["skip-function"].as<std::vector<std::string>>()) {
      pp.functionPolicy().skip(S);
    }
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
    pp.arraySectionPolicy().useDefaults(false);
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

  if (vm.count("shared") != 0) {
    pp.setShared(true);
  }

  // Write ASM to a file.
  if (vm.count("asm") != 0) {
    const auto asmPath = fs::path(vm["asm"].as<std::string>());
    if (!asmPath.has_filename()) {
      LOG_ERROR << "The given path \"" << asmPath << "\" has no filename.\n";
      return EXIT_FAILURE;
    }
    int i = 0;
    for (gtirb::Module& m : ir->modules()) {
      fs::path name = getAsmFileName(asmPath, i);
      std::ofstream ofs(name.generic_string());
      if (ofs) {
        pp.print(ofs, ctx, m);
        LOG_INFO << "Module " << i << "'s assembly written to: " << name
                 << "\n";
      } else {
        LOG_ERROR << "Could not output assembly output file: \"" << asmPath
                  << "\".\n";
      }
      ++i;
    }
  }

  // Write out assembled object files for the given IR, but do not link into a
  // final executable.
  if (vm.count("binaries") != 0) {
    const auto asmPath = fs::path(vm["binaries"].as<std::string>());
    if (!asmPath.has_filename()) {
      LOG_ERROR << "The given path \"" << asmPath << "\" has no filename.\n";
      return EXIT_FAILURE;
    }

    std::vector<std::string> extraCompilerArgs;
    if (vm.count("compiler-args") != 0)
      extraCompilerArgs = vm["compiler-args"].as<std::vector<std::string>>();
    std::vector<std::string> libraryPaths;
    if (vm.count("library-paths") != 0)
      libraryPaths = vm["library-paths"].as<std::vector<std::string>>();

    std::unique_ptr<gtirb_bprint::BinaryPrinter> binaryPrinter =
        getBinaryPrinter(format, pp, extraCompilerArgs, libraryPaths,
                         vm["dummy-so"].as<bool>());
    if (!binaryPrinter) {
      LOG_ERROR << "'" << format
                << "' is an unsupported binary printing format.\n";
      return EXIT_FAILURE;
    }

    int i = 0;
    for (gtirb::Module& m : ir->modules()) {
      fs::path name = getAsmFileName(asmPath, i);
      if (binaryPrinter->assemble(name.string(), ctx, m)) {
        LOG_ERROR << "Unable to assemble '" << name.string() << "'.\n";
        return EXIT_FAILURE;
      }
      ++i;
    }
  }

  // Link directly to a binary.
  if (vm.count("binary") != 0) {
    const auto binaryPath = fs::path(vm["binary"].as<std::string>());

    std::vector<std::string> extraCompilerArgs;
    if (vm.count("compiler-args") != 0)
      extraCompilerArgs = vm["compiler-args"].as<std::vector<std::string>>();

    std::vector<std::string> libraryPaths;
    if (vm.count("library-paths") != 0)
      libraryPaths = vm["library-paths"].as<std::vector<std::string>>();

    std::unique_ptr<gtirb_bprint::BinaryPrinter> binaryPrinter =
        getBinaryPrinter(format, pp, extraCompilerArgs, libraryPaths,
                         vm["dummy-so"].as<bool>());

    if (!binaryPrinter) {
      LOG_ERROR << "'" << format
                << "' is an unsupported binary printing format.\n";
      return EXIT_FAILURE;
    }
    if (binaryPrinter->link(binaryPath.string(), ctx, *ir)) {
      return EXIT_FAILURE;
    }
  }

  // Write ASM to the standard output if no other action was taken.
  if ((vm.count("asm") == 0) && (vm.count("binary") == 0) &&
      (vm.count("binaries") == 0)) {
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
      LOG_ERROR << "The IR has " << i << " modules, module with index "
                << vm["module"].as<int>() << " cannot be printed.\n";
      return EXIT_FAILURE;
    }
    pp.print(std::cout, ctx, *module);
  }

  return EXIT_SUCCESS;
}

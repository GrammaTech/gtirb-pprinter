#include "Logger.h"
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fcntl.h>
#include <fstream>
#include <gtirb/Module.hpp>
#include <gtirb_layout/gtirb_layout.hpp>
#include <gtirb_pprinter/ElfBinaryPrinter.hpp>
#include <gtirb_pprinter/ElfVersionScriptPrinter.hpp>
#include <gtirb_pprinter/Fixup.hpp>
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
                 const std::vector<std::string>& libraryPaths,
                 const std::string& gccExecutable, bool dummySO) {
  std::unique_ptr<gtirb_bprint::BinaryPrinter> binaryPrinter;
  if (format == "elf")
    return std::make_unique<gtirb_bprint::ElfBinaryPrinter>(
        pp, gccExecutable, extraCompileArgs, libraryPaths, true, dummySO);
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
      "Print IR as assembly code to FILE."
      "If there is more than one module, each one after the first"
      "will have a numerical suffix added to the stem."
      "If a file is not given, the code will be printed to stdout.");
  desc.add_options()("binary,b", po::value<std::string>(),
                     "Print IR as one or more binary files,"
                     "either exectuables or (with --shared) shared libraries");
  desc.add_options()("compiler-args,c",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Additional arguments to pass to the compiler. Only used "
                     "for binary printing.");
  desc.add_options()("library-paths,L",
                     po::value<std::vector<std::string>>()->multitoken(),
                     "Library paths to be passed to the linker. Only used "
                     "for binary printing.");
  desc.add_options()("module,m", po::value<size_t>(),
                     "The index of the module to be printed if printing to the "
                     "standard output.");
  desc.add_options()("format,f", po::value<std::string>(),
                     "The format of the target binary object: elf, pe, or raw");
  desc.add_options()("syntax,s", po::value<std::string>(),
                     "The syntax of the assembly file to generate: "
                     "arm, arm64, att, intel, masm, mips32");
  desc.add_options()("layout,l", "Layout code and data in memory to "
                                 "avoid overlap");
  desc.add_options()(
      "listing-mode", po::value<std::string>(),
      "The mode of use for the listing: assembler, ui, or debug");
  desc.add_options()(
      "policy,p", po::value<std::string>(),
      "The default set of objects to skip when printing assembly. To modify "
      "this set further, use the --keep and --skip options. "
      "Valid policies are 'static', 'dynamic', and 'complete'");
  desc.add_options()(
      "shared,S", po::value<std::string>(),
      "Output shared libraries, or assembly "
      "that can be compiled to shared libraries: yes, no, or auto");
  desc.add_options()("object,O", "Output  object files, but do not link them");
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
  desc.add_options()("use-gcc", po::value<std::string>(),
                     "Specify the gcc binary to use for ELF binary printing.");
  desc.add_options()(
      "symbol-versions", po::value<bool>()->default_value(true),
      "Enable symbol versions. If symbol versions are considered many "
      "binaries will require a version linker script. Only relevant for ELF "
      "executables.");
  desc.add_options()("version-script", po::value<std::string>(),
                     "Generate a version script file on the given path. Only "
                     "relevant for ELF executables.");

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
    operator gtirb::Context &() { return ctx; }
    operator const gtirb::Context &() const { return ctx; }
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

  // Configure the pretty-printer
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
  const std::string& isa = gtirb_pprint::getModuleISA(*ir->modules().begin());
  const std::string& syntax =
      vm.count("syntax")
          ? vm["syntax"].as<std::string>()
          : gtirb_pprint::getDefaultSyntax(format, isa, LstMode).value_or("");
  auto target = std::make_tuple(format, isa, syntax);
  if (gtirb_pprint::getRegisteredTargets().count(target) == 0) {
    LOG_ERROR << "Unsupported combination: format \"" << format << "\" ISA \""
              << isa << "\" and syntax \"" << syntax << "\".\n";
    std::string::size_type width = std::strlen("syntax");
    for (const auto& [f, i, s] : gtirb_pprint::getRegisteredTargets())
      width = std::max({width, f.size(), i.size(), s.size()});
    width += 2; // add "gutter" between columns
    LOG_ERROR << "Available combinations:\n";
    LOG_ERROR << std::left << std::setw(width) << "format" << std::setw(width)
              << "ISA" << std::setw(width) << "syntax" << std::setw(width)
              << "\n";
    for (const auto& [f, i, s] : gtirb_pprint::getRegisteredTargets())
      LOG_ERROR << std::left << std::setw(width) << f << std::setw(width) << i
                << std::setw(width) << s << '\n';
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

  const std::string& shared =
      vm.count("shared") ? vm["shared"].as<std::string>() : "auto";
  if (shared == "yes") {
    pp.setShared(true);
  } else if (shared == "no") {
    pp.setShared(false);
  } else if (shared == "auto") {
    pp.setShared(false);
    // If there's at least one DYN module in the IR, set shared.
    for (gtirb::Module& M : ir->modules()) {
      for (const auto& BinTypeStr : aux_data::getBinaryType(M)) {
        if (BinTypeStr == "DYN") {
          pp.setShared(true);
          break;
        }
      }
    }
  } else {
    LOG_ERROR << "Invalid option for 'shared': " << shared
              << " (should be either 'yes', 'no', or 'auto')"
              << "\n";
    return EXIT_FAILURE;
  }

  bool EnableSymbolVersions = vm["symbol-versions"].as<bool>();
  if (!EnableSymbolVersions) {
    pp.setIgnoreSymbolVersions(!EnableSymbolVersions);
  }

  if (vm.count("version-script") != 0) {
    if (!EnableSymbolVersions) {
      LOG_ERROR
          << "Cannot emit a version script while ignoring symbol versions\n";
      return EXIT_FAILURE;
    }

    if (!aux_data::hasVersionedSymDefs(*ir)) {
      LOG_INFO << "Generating version script, but it is not needed.\n";
    }

    const auto versionScriptPath = vm["version-script"].as<std::string>();
    std::ofstream VersionStream(versionScriptPath);
    gtirb_pprint::printVersionScript(*ir, VersionStream);
  }

  std::vector<gtirb::Module*> Modules;
  for (auto& module : ir->modules()) {
    Modules.push_back(&module);
  }
  if (vm.count("module")) {
    auto Index = vm["module"].as<size_t>();
    if (Index >= Modules.size()) {
      LOG_ERROR << "The IR has " << Modules.size()
                << " modules, module with index " << Index
                << " cannot be printed.\n";
      return EXIT_FAILURE;
    }
    Modules = {Modules[Index]};
  } else {
    // Modules should always be printed after
    // any other module that they link against
    std::stable_sort(Modules.begin(), Modules.end(),
                     [](const gtirb::Module* M1, const gtirb::Module* M2) {
                       const auto& Libraries = aux_data::getLibraries(*M2);
                       return std::find(Libraries.begin(), Libraries.end(),
                                        M1->getName()) != Libraries.end();
                     });
  }
  bool new_layout = false;
  for (size_t i = 0; i < Modules.size(); ++i) {
    auto& M = *Modules[i];
    // Layout IR in memory without overlap.
    if (vm.count("layout")) {
      LOG_INFO << "Applying new layout to module " << M.getUUID() << "..."
               << std::endl;
      gtirb_layout::layoutModule(ctx, M);
      new_layout = true;
    } else {
      auto SkipSections = pp.getPolicy(M).skipSections;
      pp.sectionPolicy().apply(SkipSections);
      if (gtirb_layout::layoutRequired(M, SkipSections)) {
        gtirb_layout::layoutModule(ctx, M);
        new_layout = true;
      }
    }
    if (!new_layout) {
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
    // Apply any needed fixups
    applyFixups(ctx, M, pp);
    // Write ASM to a file.
    if (vm.count("asm") != 0) {
      const auto asmPath = fs::path(vm["asm"].as<std::string>());
      fs::path name = getAsmFileName(asmPath, i);
      if (!asmPath.has_filename()) {
        LOG_ERROR << "The given path \"" << asmPath << "\" has no filename.\n";
        return EXIT_FAILURE;
      }

      std::ofstream ofs(name.generic_string());
      if (ofs) {
        if (pp.print(ofs, ctx, M)) {
          LOG_INFO << "Module " << i << "'s assembly written to: " << name
                   << "\n";
        }
      } else {
        LOG_ERROR << "Could not output assembly output file: \"" << asmPath
                  << "\".\n";
      }
    }

    if (vm.count("binary") != 0) {
      const auto asmPath = fs::path(vm["binary"].as<std::string>());
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
      std::string gccExecutable;
      if (vm.count("use-gcc") != 0)
        gccExecutable = vm["use-gcc"].as<std::string>();

      std::unique_ptr<gtirb_bprint::BinaryPrinter> binaryPrinter =
          getBinaryPrinter(format, pp, extraCompilerArgs, libraryPaths,
                           gccExecutable, vm["dummy-so"].as<bool>());
      if (!binaryPrinter) {
        LOG_ERROR << "'" << format
                  << "' is an unsupported binary printing format.\n";
        return EXIT_FAILURE;
      }

      fs::path name = getAsmFileName(asmPath, i);
      int Errc;
      if (vm.count("object") == 0) {
        Errc = binaryPrinter->link(name.string(), ctx, M);
      } else {
        Errc = binaryPrinter->assemble(name.string(), ctx, M);
      }
      if (Errc) {
        LOG_ERROR << "Unable to assemble '" << name.string() << "'.\n";
        return EXIT_FAILURE;
      }
    }

    // Write ASM to the standard output if no other action was taken.
    if ((vm.count("asm") == 0) && (vm.count("binary") == 0)) {
      pp.print(std::cout, ctx, M);
    }
  }
  return EXIT_SUCCESS;
}

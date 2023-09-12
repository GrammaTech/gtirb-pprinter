#ifndef GTIRB_PPRINT_PRINTING_PATHS_H
#define GTIRB_PPRINT_PRINTING_PATHS_H
#include <boost/filesystem.hpp>
#include <gtirb/Module.hpp>
#include <vector>

namespace fs = boost::filesystem;
namespace gtirb_pprint{
    struct ModulePrintingInfo {
    gtirb::Module* Module;
    std::optional<fs::path> AsmName;
    std::optional<fs::path> BinaryName;
    std::optional<fs::path> VersionScriptName;
    ModulePrintingInfo(gtirb::Module* M,
                        std::optional<fs::path> AN = std::nullopt,
                        std::optional<fs::path> BN = std::nullopt,
                        std::optional<fs::path> VN = std::nullopt)
        : Module(M), AsmName(AN), BinaryName(BN), VersionScriptName(VN){};
    ModulePrintingInfo() : ModulePrintingInfo(nullptr){};

    // Need to define these in order to use this struct with std::map
    auto operator<(const ModulePrintingInfo& Other) const {
        if (Module == Other.Module) {
        if (AsmName == Other.AsmName) {
            if (BinaryName == Other.BinaryName) {
            return VersionScriptName < Other.VersionScriptName;
            }
            return BinaryName < Other.BinaryName;
        }
        return AsmName < Other.AsmName;
        }
        return (size_t)Module < (size_t)Other.Module;
    }

    auto operator==(const ModulePrintingInfo& Other) const {
        return (Module == Other.Module) && (AsmName == Other.AsmName) &&
            (BinaryName == Other.BinaryName) &&
            (VersionScriptName == Other.VersionScriptName);
    }

    operator bool() { return Module != nullptr; }
    };

    /// @brief Fixup Libraries and LibraryPaths AuxData tables
    ///
    /// When modules M1 and M2 are being printed, and M1 links against M2, ensures
    /// that the printed name of M2 is reflected in the `Libraries` of M1, and that
    /// there is an entry in the LibraryPaths table of M1 including the directory M2
    /// will be printed to. If the path M2 will be printed to is an absolute path,
    /// the LibraryPaths entry will also be absolute; if it is relative, the entry
    /// will also be relative.
    ///
    /// @param ModuleInfos: A vector of structs that record the paths each module
    /// should be printed to
    /// @return The same vector, but sorted so that each module appears after all of
    /// its dependencies
    std::vector<ModulePrintingInfo>
    fixupLibraryAuxData(std::vector<ModulePrintingInfo> ModuleInfos);

} // gtirb_pprint
#endif // GTIRB_PPRINT_PRINTING_PATHS_H
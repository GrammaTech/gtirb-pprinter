#include "printing_paths.hpp"
#include <gtirb/gtirb.hpp>
#include <gtirb_pprinter/AuxDataSchema.hpp>
#include <gtirb_pprinter/AuxDataUtils.hpp>

namespace gtirb_pprint{

const fs::path Origin("$ORIGIN");

using ModuleIndex = std::map<std::string,ModulePrintingInfo>; 
/**
 * @brief produce the RPATH necessary for a binary at ModuleLocation
 * to load a library at LibraryLocation
 *
 * @param LibraryLocation The directory containing the target library
 * @param ModuleLocation The directory containing the module that loads it
 * @return std::string
 */
std::string toRpath(const fs::path& LibraryLocation,
                    const fs::path& ModuleLocation) {

    if (LibraryLocation.is_absolute()) {
    return LibraryLocation.generic_string();
    } else {
    auto LibPath = fs::path(".") / LibraryLocation;
    auto ModulePath = ModuleLocation.is_relative()
                            ? fs::path(".") / ModuleLocation
                            : ModuleLocation;
    auto Rpath = Origin / fs::relative(LibPath, ModulePath);
    return Rpath.generic_string();
    }
}

/**
 * @brief Change the name of a module to match the file it will be printed to,
 * and update any Libraries AuxData that reference it.
 *
 * @param M
 * @param ModulesByName
 */

void updateLibraries(ModulePrintingInfo M, 
const ModuleIndex& ModulesByName) {
    std::vector<std::string> NewLibraries;
    std::set<std::string> NewLibraryPaths;
    auto Libraries = aux_data::getLibraries(*M.Module);
    auto LibraryPaths = aux_data::getLibraryPaths(*M.Module);
    for (auto& L : Libraries) {
        if (ModulesByName.count(L) == 0 || ModulesByName.at(L).BinaryName == std::nullopt) {
            NewLibraries.push_back(L);
            continue;
        } else {
            auto LibPath = ModulesByName.at(L).BinaryName;
            NewLibraries.push_back(LibPath->filename().generic_string());
            if (M.BinaryName) {
                NewLibraryPaths.insert(
                    toRpath(LibPath->parent_path(), M.BinaryName->parent_path()));
            }
        }
    }
    std::copy(NewLibraryPaths.begin(), NewLibraryPaths.end(), 
        std::inserter(LibraryPaths,LibraryPaths.begin()));
    M.Module->addAuxData<gtirb::schema::Libraries>(std::move(NewLibraries));
    M.Module->addAuxData<gtirb::schema::LibraryPaths>(std::move(LibraryPaths));
};

/// @brief Topologically sort the dependency graph,
/// so that each module appears after all of its dependencies
/// @return
std::vector<ModulePrintingInfo> sortedModules(const ModuleIndex& ModulesByName) {

    std::vector<ModulePrintingInfo> Sorted, Pending;
    std::set<ModulePrintingInfo> Started, Visited;
    for (auto& [K, V] : ModulesByName) {
    Pending.push_back(V);
    }

    while (Pending.size() > 0) {
        auto M = Pending.back();
        auto Libraries = aux_data::getLibraries(*M.Module);
        Pending.pop_back();
        if (Started.count(M) == 0) {
            Started.insert(M);
            Pending.push_back(M);
            for (auto& Dep : Libraries) {
                if (ModulesByName.count(Dep)){
                    Pending.push_back(ModulesByName.at(Dep));
                }
            }
        } else if (Visited.count(M) == 0) {
            Visited.insert(M);
            Sorted.push_back(M);
        }
    }
    return Sorted;
}

std::vector<ModulePrintingInfo>
fixupLibraryAuxData(std::vector<ModulePrintingInfo> ModuleInfos) {
    ModuleIndex ModulesByName;
    for (auto& MPI : ModuleInfos) {
        ModulesByName[MPI.Module->getName()] = MPI;
    }

    auto Sorted = sortedModules(ModulesByName);
    for (auto MI : Sorted) {
        updateLibraries(MI, ModulesByName);
    }
    return Sorted;
}

} // gtirb_pprint
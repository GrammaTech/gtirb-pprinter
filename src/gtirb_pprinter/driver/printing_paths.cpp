#include "printing_paths.hpp"
#include <gtirb/gtirb.hpp>
#include <gtirb_pprinter/AuxDataSchema.hpp>
const fs::path Origin("$ORIGIN");

/**
 * @brief Class for tracking dependency relations between modules
 * for the purpose of updating Libraries and LibraryPaths based on
 * where each module is going to be printed
 */
struct DependencyGraph {

  std::map<ModulePrintingInfo, std::vector<ModulePrintingInfo>> Uses, UsedBy;
  std::map<std::string, ModulePrintingInfo> ModulesByName;

  DependencyGraph(std::vector<ModulePrintingInfo> ModuleInfos) {

    // TODO: what if two modules share a name?
    for (auto& MPI : ModuleInfos) {
      ModulesByName[MPI.Module->getName()] = MPI;
    }
    for (auto& MPI : ModuleInfos) {
      auto* Libraries = MPI.Module->getAuxData<gtirb::schema::Libraries>();
      if (Libraries) {
        for (auto& L : *Libraries) {
          if (ModulesByName.count(L)) {
            Uses[MPI].push_back(ModulesByName[L]);
          }
        }
      }
    }
  };

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
   */
  void updateLibraries(ModulePrintingInfo M) {
    std::vector<std::string> NewLibraries, NewLibraryPaths;
    auto* Libraries = M.Module->getAuxData<gtirb::schema::Libraries>();
    auto* LibraryPaths = M.Module->getAuxData<gtirb::schema::LibraryPaths>();
    if (!Libraries || !LibraryPaths) {
      return;
    }
    for (auto& L : *Libraries) {
      if (ModulesByName.count(L) == 0) {
        NewLibraries.push_back(L);
        continue;
      }

      auto LibPath = ModulesByName[L].BinaryName;
      if (!LibPath) {
        continue;
      }
      NewLibraries.push_back(LibPath->filename().generic_string());
      if (M.BinaryName) {
        NewLibraryPaths.push_back(
            toRpath(LibPath->parent_path(), M.BinaryName->parent_path()));
      }
    }
    for (auto& Path : *LibraryPaths) {
      NewLibraryPaths.push_back(Path);
    }
    *Libraries = NewLibraries;
    *LibraryPaths = NewLibraryPaths;
  };

  /// @brief Topologically sort the dependency graph,
  /// so that each module appears after all of its dependencies
  /// @return
  std::vector<ModulePrintingInfo> sortedModules() {

    std::vector<ModulePrintingInfo> Sorted, Pending;
    std::set<ModulePrintingInfo> Started, Visited;
    for (auto& [K, V] : ModulesByName) {
      Pending.push_back(V);
    }

    while (Pending.size() > 0) {
      auto M = Pending.back();
      Pending.pop_back();
      if (Started.count(M) == 0) {
        Started.insert(M);
        Pending.push_back(M);
        if (Uses.count(M)) {
          for (auto& Dep : Uses[M]) {
            Pending.push_back(Dep);
          }
        }
      } else if (Visited.count(M) == 0) {
        Visited.insert(M);
        Sorted.push_back(M);
      }
    }
    return Sorted;
  }
};

std::vector<ModulePrintingInfo>
fixupLibraryAuxData(std::vector<ModulePrintingInfo> ModuleInfos) {
  DependencyGraph DG(ModuleInfos);
  auto Sorted = DG.sortedModules();
  for (auto MI : Sorted) {
    DG.updateLibraries(MI);
  }
  return Sorted;
}

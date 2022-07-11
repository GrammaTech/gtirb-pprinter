#ifndef GTIRB_PP_GTIRB_UTILS_H
#define GTIRB_PP_GTIRB_UTILS_H
#include <gtirb/Node.hpp>
#include <optional>
#include <set>
#include <string>

namespace gtirb {
class Addr;
class Module;
class Symbol;
} // namespace gtirb

namespace gtirb_pprint {
struct PrintingPolicy;

template <typename T>
T* getByUUID(gtirb::Context& context, const gtirb::UUID& Uuid) {
  return dyn_cast_or_null<T>(gtirb::Node::getByUUID(context, Uuid));
}

template <typename T>
const T* getByUUID(const gtirb::Context& context, const gtirb::UUID& Uuid) {
  return dyn_cast_or_null<T>(gtirb::Node::getByUUID(context, Uuid));
}

template <class T> T* nodeFromUUID(gtirb::Context& C, gtirb::UUID id) {
  return dyn_cast_or_null<T>(gtirb::Node::getByUUID(C, id));
}

struct ModuleInfo {
  const gtirb::Module& Module;
  std::set<gtirb::Addr> functionEntry;
  std::set<gtirb::Addr> functionLastBlock;
  std::map<const gtirb::Symbol*, std::string> AmbiguousSymbols;

public:
  ModuleInfo(gtirb::Context& Ctx, const gtirb::Module& Mod);

  /// Get the name of the function containing an effective address. This
  /// implementation assumes that functions are tightly packed within a
  /// module; that is, it assumes that all addresses from the start of one
  /// function to the next is part of the first. It also assumes that the
  /// body of the last function in a module extends to the end of the module.
  ///
  /// The locations of the functions are found in the "functionEntry" AuxData
  /// table.
  ///
  /// \param x the address to check
  ///
  /// \return the name of the containing function if one is found.
  std::optional<std::string> getContainerFunctionName(gtirb::Addr Addr) const;
  bool isFunctionEntry(gtirb::Addr Addr) const;
  bool isFunctionLastBlock(gtirb::Addr Addr) const;

  std::string getFunctionName(gtirb::Addr Addr) const;

  std::string disambiguateName(const gtirb::Symbol* Symbol) const;

  bool shouldSkip(const PrintingPolicy& Policy,
                  const gtirb::Section& section) const;
  bool shouldSkip(const PrintingPolicy& Policy,
                  const gtirb::Symbol& symbol) const;
  bool shouldSkip(const PrintingPolicy& Policy,
                  const gtirb::CodeBlock& block) const;
  bool shouldSkip(const PrintingPolicy& Policy,
                  const gtirb::DataBlock& block) const;
};

} // namespace gtirb_pprint

#endif

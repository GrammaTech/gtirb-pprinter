#include "DisasmData.h"
#include <boost/algorithm/string/trim.hpp>
#include <boost/archive/polymorphic_text_iarchive.hpp>
#include <boost/archive/polymorphic_text_oarchive.hpp>
#include <boost/lexical_cast.hpp>
#include <fstream>
#include <gsl/gsl>
#include <gtirb/gtirb.hpp>
#include <iostream>
#include <variant>

void DisasmData::parseDirectory(std::string x) {
  boost::trim(x);

  this->loadIRFromFile(x + "/gtirb");

  // These things aren't stored in gtirb yet.
  this->parseDecodedInstruction(x + "/instruction.facts");
  this->parseOpRegdirect(x + "/op_regdirect.facts");
  this->parseOpImmediate(x + "/op_immediate.facts");
  this->parseOpIndirect(x + "/op_indirect.facts");
}

void DisasmData::loadIRFromFile(std::string path) {
  std::ifstream in(path);
  this->ir.load(in);
  this->functionEAs = std::get<std::vector<gtirb::EA>>(*this->ir.getTable("functionEAs"));
  this->main_function = std::get<std::vector<gtirb::EA>>(*this->ir.getTable("mainFunction"));
  this->start_function = std::get<std::vector<gtirb::EA>>(*this->ir.getTable("mainFunction"));
  this->ambiguous_symbol =
      std::get<std::vector<std::string>>(*this->ir.getTable("ambiguousSymbol"));
}

void DisasmData::saveIRToFile(std::string path) {
  std::ofstream out(path);
  this->ir.save(out);
}

void DisasmData::parseDecodedInstruction(const std::string& x) {
  Table fromFile{8};
  fromFile.parseFile(x);

  for (const auto& ff : fromFile) {
    DecodedInstruction inst(ff);
    this->instruction.emplace(inst.EA, std::move(inst));
  }

  std::cerr << " # Number of instruction: " << this->instruction.size() << std::endl;
}

void DisasmData::parseOpRegdirect(const std::string& x) {
  Table fromFile{2};
  fromFile.parseFile(x);

  for (const auto& ff : fromFile) {
    this->op_regdirect.push_back(OpRegdirect(ff));
  }

  std::cerr << " # Number of op_regdirect: " << this->op_regdirect.size() << std::endl;
}

void DisasmData::parseOpImmediate(const std::string& x) {
  Table fromFile{2};
  fromFile.parseFile(x);

  for (const auto& ff : fromFile) {
    OpImmediate op(ff);
    this->op_immediate.emplace(op.N, std::move(op));
  }

  std::cerr << " # Number of op_immediate: " << this->op_immediate.size() << std::endl;
}

void DisasmData::parseOpIndirect(const std::string& x) {
  Table fromFile{7};
  fromFile.parseFile(x);

  for (const auto& ff : fromFile) {
    OpIndirect op(ff);
    this->op_indirect.emplace(op.N, std::move(op));
  }

  std::cerr << " # Number of op_indirect: " << this->op_indirect.size() << std::endl;
}

const std::vector<gtirb::Section>& DisasmData::getSections() const {
  return this->ir.getModules()[0].getSections();
}

std::map<gtirb::EA, DecodedInstruction>* DisasmData::getDecodedInstruction() {
  return &this->instruction;
}

std::vector<OpRegdirect>* DisasmData::getOPRegdirect() { return &this->op_regdirect; }

std::map<uint64_t, OpImmediate>* DisasmData::getOPImmediate() { return &this->op_immediate; }

std::map<uint64_t, OpIndirect>* DisasmData::getOPIndirect() { return &this->op_indirect; }

std::vector<gtirb::table::InnerMapType>& DisasmData::getDataSections() {
  return std::get<std::vector<gtirb::table::InnerMapType>>(*this->ir.getTable("dataSections"));
}

std::string DisasmData::getSectionName(uint64_t x) const {
  const auto& sections = this->getSections();
  const auto& match =
      find_if(sections.begin(), sections.end(), [x](const auto& s) { return s.getAddress() == x; });

  if (match != sections.end()) {
    return match->getName();
  }

  return std::string{};
}

bool DisasmData::isFunction(const gtirb::Symbol& sym) const {
  return std::binary_search(this->functionEAs.begin(), this->functionEAs.end(), sym.getEA());
}

// function_complete_name
std::string DisasmData::getFunctionName(gtirb::EA x) const {
  for (auto& s : gtirb::findSymbols(this->getSymbols(), x)) {
    if (isFunction(*s)) {
      std::stringstream name;
      name << s->getName();

      if (this->getIsAmbiguousSymbol(s->getName()) == true) {
        name << "_" << std::hex << x;
      }

      return name.str();
    }
  }

  if (x == this->main_function[0]) {
    return "main";
  } else if (x == this->start_function[0]) {
    return "_start";
  }

  // or is this a funciton entry?
  for (auto f : this->function_entry) {
    if (x == f) {
      std::stringstream ss;
      ss << "unknown_function_" << std::hex << x;
      return ss.str();
    }
  }

  return std::string{};
}

std::string DisasmData::getGlobalSymbolReference(uint64_t ea) const {
  auto end = getSymbols().rend();
  for (auto it = std::reverse_iterator<gtirb::SymbolSet::const_iterator>(
           getSymbols().upper_bound(gtirb::EA(ea))); //
       it != end && it->second.getEA() <= ea; it++) {
    const auto& sym = it->second;
    auto data = sym.getDataReferent();

    /// \todo This will need looked at again to cover the logic
    if (data && containsEA(*data, gtirb::EA(ea))) {
      uint64_t displacement = ea - sym.getEA().get();

      // in a function with non-zero displacement we do not use the relative addressing
      if (displacement > 0 && isFunction(sym)) {
        return std::string{};
      }
      if (sym.getStorageKind() != gtirb::Symbol::StorageKind::Local) {
        // %do not print labels for symbols that have to be relocated
        const auto name = DisasmData::CleanSymbolNameSuffix(sym.getName());

        if (DisasmData::GetIsReservedSymbol(name) == false) {
          if (displacement > 0) {
            return DisasmData::AvoidRegNameConflicts(name) + "+" + std::to_string(displacement);
          } else {
            return DisasmData::AvoidRegNameConflicts(name);
          }
        }
      }
    }
  }

  const auto& relocations =
      std::get<std::map<gtirb::EA, gtirb::table::ValueType>>(*ir.getTable("relocations"));
  if (auto found = relocations.find(gtirb::EA(ea)); found != relocations.end()) {
    const auto& r = std::get<gtirb::table::InnerMapType>(found->second);
    const auto& name = std::get<std::string>(r.at("name"));

    if (std::get<std::string>(r.at("type")) == std::string{"R_X86_64_GLOB_DAT"}) {
      return DisasmData::AvoidRegNameConflicts(name) + "@GOTPCREL";
    } else {
      return DisasmData::AvoidRegNameConflicts(name);
    }
  }

  return std::string{};
}

std::string DisasmData::getGlobalSymbolName(uint64_t ea) const {
  for (const auto sym : findSymbols(getSymbols(), gtirb::EA(ea))) {
    if (sym->getEA() == ea) {
      if ((sym->getStorageKind() != gtirb::Symbol::StorageKind::Local)) {
        // %do not print labels for symbols that have to be relocated
        const auto name = DisasmData::CleanSymbolNameSuffix(sym->getName());

        // if it is not relocated...
        if (!this->isRelocated(name) && !DisasmData::GetIsReservedSymbol(name)) {
          return std::string{DisasmData::AvoidRegNameConflicts(name)};
        }
      }
    }
  }

  return std::string{};
}

bool DisasmData::isRelocated(const std::string& x) const {
  const auto& relocations =
      std::get<std::map<gtirb::EA, gtirb::table::ValueType>>(*ir.getTable("relocations"));
  const auto found =
      std::find_if(std::begin(relocations), std::end(relocations), [x](const auto& element) {
        const auto& r = std::get<gtirb::table::InnerMapType>(element.second);
        return std::get<std::string>(r.at("name")) == x;
      });

  return found != std::end(relocations);
}

const gtirb::SymbolSet& DisasmData::getSymbols() const {
  return this->ir.getModules()[0].getSymbols();
}

const gtirb::Section* DisasmData::getSection(const std::string& x) const {
  const auto found = std::find_if(getSections().begin(), getSections().end(),
                                  [x](const auto& element) { return element.getName() == x; });

  if (found != getSections().end()) {
    return &(*found);
  }

  return nullptr;
}

const DecodedInstruction* DisasmData::getDecodedInstruction(uint64_t ea) const {
  const auto inst = this->instruction.find(gtirb::EA(ea));

  if (inst != this->instruction.end()) {
    return &(inst->second);
  }

  return nullptr;
}

const OpIndirect* DisasmData::getOpIndirect(uint64_t x) const {
  if (const auto found = this->op_indirect.find(x); found != std::end(this->op_indirect)) {
    return &found->second;
  }

  return nullptr;
}

const OpRegdirect* DisasmData::getOpRegdirect(uint64_t x) const {
  const auto found = std::find_if(std::begin(this->op_regdirect), std::end(this->op_regdirect),
                                  [x](const auto& element) { return element.N == x; });

  if (found != std::end(this->op_regdirect)) {
    return &(*found);
  }

  return nullptr;
}

uint64_t DisasmData::getOpRegdirectCode(std::string x) const {
  const auto found = std::find_if(std::begin(this->op_regdirect), std::end(this->op_regdirect),
                                  [x](const auto& element) { return element.Register == x; });

  if (found != std::end(this->op_regdirect)) {
    return found->N;
  }

  return 0;
}

const OpImmediate* DisasmData::getOpImmediate(uint64_t x) const {
  if (const auto found = this->op_immediate.find(x); found != std::end(this->op_immediate)) {
    return &found->second;
  }

  return nullptr;
}

bool DisasmData::getIsAmbiguousSymbol(const std::string& name) const {
  const auto found =
      std::find(std::begin(this->ambiguous_symbol), std::end(this->ambiguous_symbol), name);
  return found != std::end(this->ambiguous_symbol);
}

void DisasmData::AdjustPadding(std::vector<gtirb::Block*>& blocks) {
  for (auto i = std::begin(blocks); i != std::end(blocks); ++i) {
    auto next = i;
    ++next;
    if (next != std::end(blocks)) {
      const auto gap = (*next)->getAddress() - addressLimit(**i);

      // If we have overlap, erase the next element in the list.
      if (addressLimit(**i) > (*next)->getAddress()) {
        blocks.erase(next);
      } else if (gap > 0) {
        // insert a block with no instructions.
        // This should be interpreted as nop's.

        // FIXME: this will leak. We should insert the new Block into the CFG
        // instead so it has an owner.
        blocks.insert(next, new gtirb::Block{addressLimit(**i), (*next)->getAddress()});
      }
    }
  }
}

std::string DisasmData::CleanSymbolNameSuffix(std::string x) {
  return x.substr(0, x.find_first_of('@'));
}

std::string DisasmData::AdaptOpcode(const std::string& x) {
  const std::map<std::string, std::string> adapt{{"movsd2", "movsd"}, {"imul2", "imul"},
                                                 {"imul3", "imul"},   {"imul1", "imul"},
                                                 {"cmpsd3", "cmpsd"}, {"out_i", "out"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  return x;
}

std::string DisasmData::AdaptRegister(const std::string& x) {
  const std::map<std::string, std::string> adapt{
      {"R8L", "R8B"},   {"R9L", "R9B"},   {"R10L", "R10B"}, {"R11L", "R11B"}, {"R12L", "R12B"},
      {"R13L", "R13B"}, {"R14L", "R14B"}, {"R15L", "R15B"}, {"R12L", "R12B"}, {"R13L", "R13B"},
      {"ST0", "ST(0)"}, {"ST1", "ST(1)"}, {"ST2", "ST(2)"}, {"ST3", "ST(3)"}, {"ST4", "ST(4)"},
      {"ST5", "ST(5)"}, {"ST6", "ST(6)"}, {"ST7", "ST(7)"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  return x;
}

std::string DisasmData::GetSizeName(uint64_t x) {
  return DisasmData::GetSizeName(std::to_string(x));
}

std::string DisasmData::GetSizeName(const std::string& x) {
  const std::map<std::string, std::string> adapt{
      {"128", ""},         {"0", ""},          {"80", "TBYTE PTR"}, {"64", "QWORD PTR"},
      {"32", "DWORD PTR"}, {"16", "WORD PTR"}, {"8", "BYTE PTR"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  assert("Unknown Size");

  return x;
}

std::string DisasmData::GetSizeSuffix(const OpIndirect& x) {
  return DisasmData::GetSizeSuffix(x.Size);
}

std::string DisasmData::GetSizeSuffix(uint64_t x) {
  return DisasmData::GetSizeSuffix(std::to_string(x));
}

std::string DisasmData::GetSizeSuffix(const std::string& x) {
  const std::map<std::string, std::string> adapt{{"128", ""}, {"0", ""},   {"80", "t"}, {"64", "q"},
                                                 {"32", "d"}, {"16", "w"}, {"8", "b"}};

  if (const auto found = adapt.find(x); found != std::end(adapt)) {
    return found->second;
  }

  assert("Unknown Size");

  return x;
}

bool DisasmData::GetIsReservedSymbol(const std::string& x) {
  if (x.length() > 2) {
    return ((x[0] == '_') && (x[1] == '_'));
  }

  return false;
}

std::string DisasmData::AvoidRegNameConflicts(const std::string& x) {
  const std::vector<std::string> adapt{"FS", "MOD", "DIV", "NOT", "mod", "div", "not", "and", "or"};

  if (const auto found = std::find(std::begin(adapt), std::end(adapt), x);
      found != std::end(adapt)) {
    return x + "_renamed";
  }

  return x;
}

// Name, Alignment.
const std::array<std::pair<std::string, int>, 7> DataSectionDescriptors{{
    {".got", 8},         //
    {".got.plt", 8},     //
    {".data.rel.ro", 8}, //
    {".init_array", 8},  //
    {".fini_array", 8},  //
    {".rodata", 16},     //
    {".data", 16}        //
}};

const std::pair<std::string, int>* getDataSectionDescriptor(const std::string& name) {
  const auto foundDataSection =
      std::find_if(std::begin(DataSectionDescriptors), std::end(DataSectionDescriptors),
                   [name](const auto& dsd) { return dsd.first == name; });
  if (foundDataSection != std::end(DataSectionDescriptors))
    return foundDataSection;
  else
    return nullptr;
}
